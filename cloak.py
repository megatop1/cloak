import os
import subprocess
import socket
import re
import time
from questionary import Style, select, text

# Define custom style
custom_style = Style([("choice", "fg:blue")])

ascii_art = """
═════════════════════════════════════════════════════════
│  _________ .____    ________      _____   ____  __.   │
│  \_   ___ \|    |   \_____  \    /  _  \ |    |/ _|   │
│  /    \  \/|    |    /   |   \  /  /_\  \|      <     │
│  \     \___|    |___/    |    \/    |    \    |  \    │
│   \______  /_______ \_______  /\____|__  /____|__ \   │
│          \/        \/       \/         \/        \/   │
═════════════════════════════════════════════════════════
"""

# Global variable to hold SSH key directory
ssh_key_directory = None

# Protocol-to-port mapping
protocol_port_map = {
    "WinRM": 5985,
    "RDP": 3389,
    "SSH": 22,
    "SFTP": 22,
    "SMB": 445,
}

# Helper functions
def get_free_port():
    """Find an available port on the local machine."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]

def get_active_port(process_name):
    """Fetch the active port used by the specified process."""
    try:
        result = subprocess.run(["ss", "-tulpn"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout.strip()
        print(f"DEBUG: Output of `ss -tulpn`:\n{output}")

        # Use regex to match the desired process and extract the port
        pattern = rf"127\.0\.0\.1:(\d+).*users:\(\(\"{process_name}\""
        match = re.search(pattern, output)

        if match:
            port = match.group(1)
            print(f"Active port for {process_name}: {port}")
            return port
        else:
            print(f"No active port found for process: {process_name}")
            return None
    except Exception as e:
        print(f"Error fetching active port: {e}")
        return None

def list_ssh_keys(directory=os.path.expanduser("~/.ssh")):
    """List available SSH keys in the specified directory."""
    try:
        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        return files if files else []
    except (FileNotFoundError, PermissionError) as e:
        print(f"Error accessing directory {directory}: {e}")
        return []


def select_ssh_key(directory=os.path.expanduser("~/.ssh")):
    """Prompt the user to select an SSH key."""
    keys = list_ssh_keys(directory)
    if not keys:
        print("No SSH keys found.")
        return None
    return select("Select your SSH private key:", choices=keys, style=custom_style).ask()


def select_ssh_key():
    """Prompt user to select an SSH key from the global directory."""
    keys = list_ssh_keys()
    if not keys:
        print(f"No SSH keys found in {ssh_key_directory}")
        return None

    return select(
        "Select your SSH private key:",
        choices=keys,
        style=custom_style,
    ).ask()

def execute_command(command):
    """Run a shell command."""
    print(f"Executing: {command}")
    subprocess.run(command, shell=True)

# Tunnel setup
def setup_tunnel_chain(tunnel_count, protocol, target_ip, target_port):
    """Set up SSH tunnels sequentially."""
    global ssh_key_directory
    tunnels = []
    local_port = target_port

    for i in range(tunnel_count):
        print(f"Configuring Tunnel {i + 1}:")
        ssh_tunnel_ip = text(f"Enter SSH Tunnel {i + 1} IP:").ask()
        ssh_tunnel_port = text(f"Enter SSH Tunnel {i + 1} Port (default: 22):").ask() or "22"
        ssh_tunnel_user = text(f"Enter SSH Tunnel {i + 1} Username:").ask()
        ssh_key_name = select_ssh_key()

        if not ssh_key_name:
            print("No valid SSH key selected. Exiting.")
            return None

        ssh_key_path = os.path.join(ssh_key_directory, ssh_key_name)
        new_local_port = get_free_port()

        if i == 0:
            # First tunnel connects to the target IP and target port
            command = (
                f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i {ssh_key_path} -N "
                f"-L 127.0.0.1:{new_local_port}:{target_ip}:{target_port} "
                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} &"
            )
        else:
            # Subsequent tunnels chain through the previous tunnel
            command = (
                f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i {ssh_key_path} -N "
                f"-L 127.0.0.1:{new_local_port}:127.0.0.1:{local_port} "
                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} &"
            )

        execute_command(command)
        time.sleep(2)  # Allow the tunnel to establish

        # Fetch active port
        active_port = get_active_port("ssh")
        if active_port:
            print(f"Active port for tunnel {i + 1}: {active_port}")
            local_port = active_port
        else:
            print(f"Failed to fetch the active port for tunnel {i + 1}. Exiting.")
            return None

    return local_port

# Masquerade functions
def winrm_masq():
    print("Initializing WinRM masquerade...")
    target_ip = text("Enter Target IP of WinRM:").ask()
    username = text("Enter Username:").ask()
    password = text("Enter Password:").ask()

    if text("Do you need to tunnel the connection? (Y/N):").ask().lower() == "y":
        tunnel_count = int(select(
            "Select the Number of Tunnels Required:",
            choices=["1", "2", "3"], style=custom_style
        ).ask())
        local_port = setup_tunnel_chain(tunnel_count, "WinRM", target_ip, protocol_port_map["WinRM"])
        winrm_command = f"evil-winrm -i 127.0.0.1 -u {username} -p {password} -P {local_port}"
    else:
        winrm_command = f"evil-winrm -i {target_ip} -u {username} -p {password}"

    execute_command(winrm_command)

# Main menu
def main():
    global ssh_key_directory
    print(f"\033[35m{ascii_art}\033[0m")

    # Ensure the SSH key directory is set correctly
    if ssh_key_directory is None:
        ssh_key_directory = "/home/kali/.ssh"  # Replace this with a default value or passed argument.

    choice = select(
        "Select a Masquerade Type:",
        choices=["WinRM", "RDP", "SSH", "SFTP", "Exit"],
        style=custom_style,
    ).ask()

    options = {
        "WinRM": winrm_masq,
        # Add other masquerade functions for RDP, SSH, SFTP here
    }

    if choice in options:
        options[choice]()
    else:
        print("Exiting. Goodbye!")

if __name__ == "__main__":
    main()

