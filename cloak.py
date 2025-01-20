import os
import subprocess
import socket
import time
import re
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

# Global directory for SSH keys
ssh_key_directory = None

# Port mappings for predefined protocols
protocol_port_map = {
    "WinRM": 5985,
    "RDP": 3389,
    "SSH": 22,
    "SFTP": 22,
    "SMB": 445,
}

# Predefined tunnel ports for each protocol
predefined_tunnel_ports = {
    "WinRM": [56375, 34617],
    "RDP": [33890, 33891],
    "SSH": [22001, 22002],
    "SFTP": [40000, 40001],
    "SMB": [44500, 44501],
}


def get_free_port():
    """Find an available port on the local machine."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]

def get_active_port(process_name="ssh"):
    """Find the active local port for a given process."""
    try:
        result = subprocess.run(
            ["ss", "-tulpn"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        output = result.stdout
        print(f"DEBUG: Output of `ss -tulpn`:\n{output}")
        
        # Parse the output to find the process and port
        for line in output.splitlines():
            if process_name in line:
                # Extract the local address:port field
                match = re.search(r'127\.0\.0\.1:(\d+)', line)
                if match:
                    port = match.group(1)
                    print(f"DEBUG: Found active port for {process_name}: {port}")
                    return int(port)
    except Exception as e:
        print(f"Error fetching active port: {e}")
    
    print(f"No active port found for process: {process_name}")
    return None


def list_ssh_keys(directory=os.path.expanduser("~/.ssh")):
    """List available SSH keys in the specified directory."""
    try:
        return [
            f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))
        ]
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


def execute_command(command):
    """Run a shell command."""
    print(f"Executing: {command}")
    subprocess.run(command, shell=True)

def setup_tunnel_chain_dynamic_with_ports(tunnel_count, target_ip, target_port):
    if tunnel_count == 2:
        # First Tunnel
        print("Setting up Tunnel 1...")
        ssh_tunnel1_ip = text("Enter SSH Tunnel 1 IP:").ask()
        ssh_tunnel1_port = text("Enter SSH Tunnel 1 Port (default: 22):").ask() or "22"
        ssh_tunnel1_user = text("Enter SSH Tunnel 1 Username:").ask()
        ssh_key1_name = select_ssh_key()

        if not ssh_key1_name:
            print("No valid SSH key selected for Tunnel 1. Exiting.")
            return None, None

        ssh_key1_path = os.path.join(ssh_key_directory, ssh_key1_name)
        tunnel1_local_port = 5986

        tunnel1_command = (
            f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-i {ssh_key1_path} -N -L 127.0.0.1:{tunnel1_local_port}:{target_ip}:{target_port} "
            f"{ssh_tunnel1_user}@{ssh_tunnel1_ip} -p {ssh_tunnel1_port} &"
        )
        print(f"DEBUG: Executing command for Tunnel 1: {tunnel1_command}")
        execute_command(tunnel1_command)

        # Second Tunnel
        print("Setting up Tunnel 2...")
        ssh_tunnel2_ip = text("Enter SSH Tunnel 2 IP:").ask()
        ssh_tunnel2_port = text("Enter SSH Tunnel 2 Port (default: 22):").ask() or "22"
        ssh_tunnel2_user = text("Enter SSH Tunnel 2 Username:").ask()
        ssh_key2_name = select_ssh_key()

        if not ssh_key2_name:
            print("No valid SSH key selected for Tunnel 2. Exiting.")
            return None, None

        ssh_key2_path = os.path.join(ssh_key_directory, ssh_key2_name)
        tunnel2_local_port = 5985

        tunnel2_command = (
            f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-i {ssh_key2_path} -N -L 127.0.0.1:{tunnel2_local_port}:{target_ip}:{target_port} "
            f"{ssh_tunnel2_user}@{ssh_tunnel2_ip} -p {ssh_tunnel2_port} "
            f"-o ProxyCommand='ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-i {ssh_key1_path} -W %h:%p {ssh_tunnel1_user}@{ssh_tunnel1_ip} -p {ssh_tunnel1_port}' &"
        )
        print(f"DEBUG: Executing command for Tunnel 2: {tunnel2_command}")
        execute_command(tunnel2_command)

        return tunnel1_local_port, tunnel2_local_port

def setup_two_hop_tunnel(target_ip, target_port):
    """
    Set up a two-hop SSH tunnel chain using only forward tunnels.
    :param target_ip: Final target IP address (e.g., WinRM target).
    :param target_port: Final target port (e.g., 5985 for WinRM).
    :return: Last tunnel port to use for the final connection.
    """
    print("Configuring a two-hop tunnel...")

    # Tunnel 1 configuration
    print("Setting up Tunnel 1...")
    ssh_tunnel1_ip = text("Enter SSH Tunnel 1 IP:").ask()  # Hop 1 IP
    ssh_tunnel1_port = text("Enter SSH Tunnel 1 Port (default: 22):").ask() or "22"
    ssh_tunnel1_user = text("Enter SSH Tunnel 1 Username:").ask()
    ssh_key1_name = select_ssh_key()

    if not ssh_key1_name:
        print("No valid SSH key selected for Tunnel 1. Exiting.")
        return None

    ssh_key1_path = os.path.join(ssh_key_directory, ssh_key1_name)
    tunnel1_local_port = 56375  # Static or dynamically chosen port

    tunnel1_command = (
        f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-i {ssh_key1_path} -N -L 127.0.0.1:{tunnel1_local_port}:{target_ip}:{target_port} "
        f"{ssh_tunnel1_user}@{ssh_tunnel1_ip} -p {ssh_tunnel1_port} &"
    )

    print(f"DEBUG: Executing command for Tunnel 1: {tunnel1_command}")
    execute_command(tunnel1_command)

    # Verify Tunnel 1 is established
    for retry in range(5):
        active_port = get_active_port("ssh")
        if active_port == tunnel1_local_port:
            print(f"Tunnel 1 successfully established on port {tunnel1_local_port}.")
            break
        print(f"Retrying to establish Tunnel 1... ({retry + 1}/5)")
        time.sleep(2)
    else:
        print("ERROR: Failed to establish Tunnel 1. Exiting.")
        return None

    # Tunnel 2 configuration
    print("Setting up Tunnel 2...")
    ssh_tunnel2_ip = text("Enter SSH Tunnel 2 IP:").ask()  # Hop 2 IP
    ssh_tunnel2_port = text("Enter SSH Tunnel 2 Port (default: 22):").ask() or "22"
    ssh_tunnel2_user = text("Enter SSH Tunnel 2 Username:").ask()
    ssh_key2_name = select_ssh_key()

    if not ssh_key2_name:
        print("No valid SSH key selected for Tunnel 2. Exiting.")
        return None

    ssh_key2_path = os.path.join(ssh_key_directory, ssh_key2_name)
    tunnel2_local_port = 34617  # Static or dynamically chosen port

    tunnel2_command = (
        f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"-i {ssh_key2_path} -N -L 127.0.0.1:{tunnel2_local_port}:127.0.0.1:{tunnel1_local_port} "
        f"{ssh_tunnel2_user}@{ssh_tunnel2_ip} -p {ssh_tunnel2_port} &"
    )

    print(f"DEBUG: Executing command for Tunnel 2: {tunnel2_command}")
    execute_command(tunnel2_command)

    # Verify Tunnel 2 is established
    for retry in range(5):
        active_port = get_active_port("ssh")
        if active_port == tunnel2_local_port:
            print(f"Tunnel 2 successfully established on port {tunnel2_local_port}.")
            break
        print(f"Retrying to establish Tunnel 2... ({retry + 1}/5)")
        time.sleep(2)
    else:
        print("ERROR: Failed to establish Tunnel 2. Exiting.")
        return None

    # Return the port of the final tunnel for the WinRM connection
    return tunnel2_local_port

def winrm_masq():
    """
    Set up a WinRM masquerade dynamically for tunneling.
    """
    print("Initializing WinRM masquerade...")
    target_ip = text("Enter Target IP of WinRM:").ask()
    username = text("Enter Username:").ask()
    password = text("Enter Password:").ask()
    target_port = int(text("Enter the destination port of the target (e.g., 5985 for WinRM):").ask())

    # Prompt for tunneling
    if text("Do you need to tunnel the connection? (Y/N):").ask().lower() == "y":
        tunnel_count = int(select(
            "Select the Number of Tunnels Required:",
            choices=["1", "2"],
            style=custom_style,
        ).ask())

        first_tunnel_port, last_tunnel_port = setup_tunnel_chain_dynamic_with_ports(
            tunnel_count=tunnel_count,
            target_ip=target_ip,
            target_port=target_port,
        )

        if not last_tunnel_port:
            print("Failed to set up tunnels. Exiting.")
            return

        winrm_command = f"evil-winrm -i 127.0.0.1 -u {username} -p {password} -P {last_tunnel_port}"
    else:
        # No tunneling
        winrm_command = f"evil-winrm -i {target_ip} -u {username} -p {password}"

    print(f"Executing: {winrm_command}")
    execute_command(winrm_command)


def main():
    global ssh_key_directory
    print(f"\033[35m{ascii_art}\033[0m")

    if ssh_key_directory is None:
        ssh_key_directory = os.path.expanduser("~/.ssh")

    choice = select(
        "Select a Masquerade Type:",
        choices=["WinRM", "RDP", "SSH", "SFTP", "Exit"],
        style=custom_style,
    ).ask()

    options = {
        "WinRM": winrm_masq,
        # Add additional protocols here as needed
    }

    if choice in options:
        options[choice]()
    else:
        print("Exiting. Goodbye!")


if __name__ == "__main__":
    main()

