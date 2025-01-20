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

def setup_tunnel_chain_dynamic_with_ports(tunnel_count, target_ip, target_port, custom_ports=None):
    """
    Set up a chain of tunnels dynamically based on the user-defined number of hops.

    :param tunnel_count: Number of tunnels to set up.
    :param target_ip: Final destination IP for the target service.
    :param target_port: Final destination port for the target service.
    :param custom_ports: List of custom local ports to use for each tunnel.
    :return: Tuple of the first and last tunnel ports.
    """
    print("Setting up tunnel chain...")

    # Validate custom_ports
    if not custom_ports or len(custom_ports) < tunnel_count:
        print("ERROR: Invalid custom ports list provided. Exiting.")
        return None, None

    first_tunnel_port = custom_ports[0]
    last_tunnel_port = custom_ports[-1]

    if tunnel_count == 1:
        # Single tunnel logic
        print("Setting up a single tunnel...")
        ssh_tunnel_ip = text("Enter SSH Tunnel IP:").ask()
        ssh_tunnel_port = text("Enter SSH Tunnel Port (default: 22):").ask() or "22"
        ssh_tunnel_user = text("Enter SSH Tunnel Username:").ask()
        ssh_key_name = select_ssh_key()

        if not ssh_key_name:
            print("No valid SSH key selected. Exiting.")
            return None, None

        ssh_key_path = os.path.join(ssh_key_directory, ssh_key_name)

        command = (
            f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-i {ssh_key_path} -N -L 127.0.0.1:{last_tunnel_port}:{target_ip}:{target_port} "
            f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} &"
        )

        print(f"DEBUG: Executing command for single tunnel: {command}")
        execute_command(command)

        return last_tunnel_port, last_tunnel_port  # Both first and last ports are the same for one tunnel

    elif tunnel_count == 2:
        # Two-hop tunnel logic
        print("Setting up a two-hop tunnel...")

        # First tunnel configuration
        print("Setting up Tunnel 1...")
        ssh_tunnel1_ip = text("Enter SSH Tunnel 1 IP:").ask()
        ssh_tunnel1_port = text("Enter SSH Tunnel 1 Port (default: 22):").ask() or "22"
        ssh_tunnel1_user = text("Enter SSH Tunnel 1 Username:").ask()
        ssh_key1_name = select_ssh_key()

        # Second tunnel configuration
        print("Setting up Tunnel 2...")
        ssh_tunnel2_ip = text("Enter SSH Tunnel 2 IP:").ask()
        ssh_tunnel2_port = text("Enter SSH Tunnel 2 Port (default: 22):").ask() or "22"
        ssh_tunnel2_user = text("Enter SSH Tunnel 2 Username:").ask()
        ssh_key2_name = select_ssh_key()

        if not ssh_key1_name:
            print("No valid SSH key selected for Tunnel 1. Exiting.")
            return None, None

        ssh_key1_path = os.path.join(ssh_key_directory, ssh_key1_name)

        tunnel1_command = (
            f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-i {ssh_key1_path} -N -L 127.0.0.1:{first_tunnel_port}:{ssh_tunnel2_ip}:{ssh_tunnel2_port} "
            f"{ssh_tunnel1_user}@{ssh_tunnel1_ip} -p {ssh_tunnel1_port} &"
        )

        print(f"DEBUG: Executing command for Tunnel 1: {tunnel1_command}")
        execute_command(tunnel1_command)

        # Add 5-second sleep after starting Tunnel 1
        print("Sleeping for 5 seconds to ensure Tunnel 1 is established...")
        time.sleep(5)

        if not ssh_key2_name:
            print("No valid SSH key selected for Tunnel 2. Exiting.")
            return None, None

        ssh_key2_path = os.path.join(ssh_key_directory, ssh_key2_name)

        tunnel2_command = (
            f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-i {ssh_key2_path} -N -L 127.0.0.1:{last_tunnel_port}:{target_ip}:{last_tunnel_port} "
            f"{ssh_tunnel2_user}@127.0.0.1 -p {first_tunnel_port} &"
        )


        print(f"DEBUG: Executing command for Tunnel 2: {tunnel2_command}")
        execute_command(tunnel2_command)

        # Add 5-second sleep after starting Tunnel 2
        print("Sleeping for 5 seconds to ensure Tunnel 2 is established...")
        time.sleep(5)

        return first_tunnel_port, last_tunnel_port  # Return both ports for use by the caller

    else:
        print(f"ERROR: Unsupported number of tunnels: {tunnel_count}")
        return None, None

def winrm_masq():
    """
    Set up a WinRM masquerade dynamically for tunneling.
    """
    print("Initializing WinRM masquerade...")
    target_ip = text("Enter Target IP of WinRM:").ask()
    winrm_username = text("Enter Username:").ask()
    #password = text("Enter Password:").ask()

    # Prompt for tunneling
    if text("Do you need to tunnel the connection? (Y/N):").ask().lower() == "y":
        tunnel_count = int(select(
            "Select the Number of Tunnels Required:",
            choices=["1", "2"],
            style=custom_style,
        ).ask())

        # Set predefined ports based on the tunnel count
        predefined_ports = [5985] if tunnel_count == 1 else [5986, 5985]

        # Dynamically assign the target port based on the tunnel count
        target_port = 5985 if tunnel_count == 1 else 5986

        # Set up tunnels and dynamically retrieve listening ports
        first_tunnel_port, last_tunnel_port = setup_tunnel_chain_dynamic_with_ports(
            tunnel_count=tunnel_count,
            target_ip=target_ip,
            target_port=target_port,  # Automatically assigned
            custom_ports=predefined_ports
        )

        # Debug: Ensure the correct ports are being used
        print(f"DEBUG: First tunnel port: {first_tunnel_port}, Last tunnel port: {last_tunnel_port}")

        if not first_tunnel_port or not last_tunnel_port:
            print("Failed to set up tunnels. Exiting.")
            return

        # Use the first tunnel port for Evil-WinRM
        winrm_command_port = first_tunnel_port if tunnel_count > 1 else last_tunnel_port

        # Prompt for authentication type
        auth_choice = select(
            "How do you want to authenticate?",
            choices=["Password", "Hashes"],
            style=custom_style,
        ).ask()

        if auth_choice == "Password":
            winrm_password = input("Enter WinRM Password: ")
            command = (
                f"evil-winrm -i 127.0.0.1 -u {winrm_username} -p {winrm_password}"
            )
        elif auth_choice == "Hashes":
            winrm_hash = input("Enter NTLM Hash: ")
            command = (
                f"evil-winrm -i 127.0.0.1 -u {winrm_username} -H {winrm_hash}"
            )
    else:
        # No tunneling
        auth_choice = select(
            "How do you want to authenticate?",
            choices=["Password", "Hashes"],
            style=custom_style,
        ).ask()

        if auth_choice == "Password":
            winrm_password = input("Enter WinRM Password: ")
            command = f"evil-winrm -i {winrm_target} -u {winrm_username} -p {winrm_password}"
        elif auth_choice == "Hashes":
            winrm_hash = input("Enter NTLM Hash: ")
            command = f"evil-winrm -i {winrm_target} -u {winrm_username} -H {winrm_hash}"

    # Execute the command
    print("Executing:", command)
    subprocess.run(command, shell=True)

def smb_masq():
    """
    Set up a SMB masquerade dynamically for tunneling.
    """
    print("Initializing SMB masquerade...")
    target_ip = text("Enter Target IP of SMB:").ask()
    smb_username = text("Enter Username:").ask()
    #password = text("Enter Password:").ask()

   # Prompt for tunneling
    if text("Do you need to tunnel the connection? (Y/N):").ask().lower() == "y":
        tunnel_count = int(select(
            "Select the Number of Tunnels Required:",
            choices=["1", "2"],
            style=custom_style,
        ).ask())

        # Set predefined ports based on the tunnel count
        predefined_ports = [445] if tunnel_count == 1 else [446, 445]


        # Dynamically assign the target port based on the tunnel count
        target_port = 445 if tunnel_count == 1 else 446

        # Set up tunnels and dynamically retrieve listening ports
        first_tunnel_port, last_tunnel_port = setup_tunnel_chain_dynamic_with_ports(
            tunnel_count=tunnel_count,
            target_ip=target_ip,
            target_port=target_port,  # Automatically assigned
            custom_ports=predefined_ports
        )

        # Debug: Ensure the correct ports are being used
        print(f"DEBUG: First tunnel port: {first_tunnel_port}, Last tunnel port: {last_tunnel_port}")

        if not first_tunnel_port or not last_tunnel_port:
            print("Failed to set up tunnels. Exiting.")
            return

        # Use the first tunnel port for Evil-WinRM
        smb_command_port = first_tunnel_port if tunnel_count > 1 else last_tunnel_port

        # Prompt for authentication type
        auth_choice = select(
            "How do you want to authenticate?",
            choices=["Password", "Hashes"],
            style=custom_style,
        ).ask()

        if auth_choice == "Password":
            smb_password = input("Enter SMB Password: ")
            command = (
                f"python /app/slinger/build/scripts-3.12/slinger.py -host 127.0.0.1 --username {smb_username} --password {smb_password}"
            )
        elif auth_choice == "Hashes":
            smb_hash = input("Enter NTLM Hash: ")
            command = (
                f"python /app/slinger/build/scripts-3.12/slinger.py -host 127.0.0.1 --username {smb_username} -ntlm :{smb_hash}"
            )

    else:
        # No tunneling
        auth_choice = select(
            "How do you want to authenticate?",
            choices=["Password", "Hashes"],
            style=custom_style,
        ).ask()

        if auth_choice == "Password":
            smb_password = input("Enter SMB Password: ")
            command = f"python /app/slinger/build/scripts-3.12/slinger.py -host 127.0.0.1 --username {smb_username} --password {smb_password}"
        elif auth_choice == "Hashes":
            winrm_hash = input("Enter NTLM Hash: ")
            command = f"python /app/slinger/build/scripts-3.12/slinger.py -host 127.0.0.1 --username {smb_username} -ntlm :{smb_hash}"

    # Execute the command
    print("Executing:", command)
    subprocess.run(command, shell=True)

def rdp_masq():
    """
    Set up a RDP masquerade dynamically for tunneling.
    """
    print("Initializing RDP masquerade...")
    target_ip = text("Enter Target IP of RDP:").ask()
    rdp_username = text("Enter Username:").ask()
    #password = text("Enter Password:").ask()

   # Prompt for tunneling
    if text("Do you need to tunnel the connection? (Y/N):").ask().lower() == "y":
        tunnel_count = int(select(
            "Select the Number of Tunnels Required:",
            choices=["1", "2"],
            style=custom_style,
        ).ask())

        # Set predefined ports based on the tunnel count
        predefined_ports = [3389] if tunnel_count == 1 else [3390, 3389]


        # Dynamically assign the target port based on the tunnel count
        target_port = 3389 if tunnel_count == 1 else 3390

        # Set up tunnels and dynamically retrieve listening ports
        first_tunnel_port, last_tunnel_port = setup_tunnel_chain_dynamic_with_ports(
            tunnel_count=tunnel_count,
            target_ip=target_ip,
            target_port=target_port,  # Automatically assigned
            custom_ports=predefined_ports
        )

        # Debug: Ensure the correct ports are being used
        print(f"DEBUG: First tunnel port: {first_tunnel_port}, Last tunnel port: {last_tunnel_port}")

        if not first_tunnel_port or not last_tunnel_port:
            print("Failed to set up tunnels. Exiting.")
            return

        # Use the first tunnel port for Evil-WinRM
        smb_command_port = first_tunnel_port if tunnel_count > 1 else last_tunnel_port

        # Prompt for authentication type
        auth_choice = select(
            "How do you want to authenticate?",
            choices=["Password", "Hashes"],
            style=custom_style,
        ).ask()

        if auth_choice == "Password":
            rdp_password = input("Enter RDP Password: ")
            command = (
                f"xfreerdp /cert-ignore /u:{rdp_username} /p:{rdp_password} /v:127.0.0.1"
            )
        elif auth_choice == "Hashes":
            rdp_hash = input("Enter NTLM Hash: ")
            command = (
                f"xfreerdp /cert-ignore /u:{rdp_username} /pth:{rdp_hash} /v:127.0.0.1"
            )

    else:
        # No tunneling
        auth_choice = select(
            "How do you want to authenticate?",
            choices=["Password", "Hashes"],
            style=custom_style,
        ).ask()

        if auth_choice == "Password":
            rdp_password = input("Enter RDP Password: ")
            command = f"xfreerdp /cert-ignore /u:{rdp_username} /p:{rdp_password} /v:{target_ip}"
        elif auth_choice == "Hashes":
            rdp_hash = input("Enter NTLM Hash: ")
            command = f"xfreerdp /cert-ignore /u:{rdp_username} /pth:{rdp_hash} /v:{target_ip}"

    # Execute the command
    print("Executing:", command)
    subprocess.run(command, shell=True)

def ssh_masq():
    """
    Set up a SSH masquerade dynamically for tunneling.
    """
    print("Initializing SSH masquerade...")
    target_ip = text("Enter Target IP of SSH:").ask()
    ssh_username = text("Enter Username:").ask()
    #password = text("Enter Password:").ask()

   # Prompt for tunneling
    if text("Do you need to tunnel the connection? (Y/N):").ask().lower() == "y":
        tunnel_count = int(select(
            "Select the Number of Tunnels Required:",
            choices=["1", "2"],
            style=custom_style,
        ).ask())

        # Set predefined ports based on the tunnel count
        predefined_ports = [22] if tunnel_count == 1 else [2222, 22]


        # Dynamically assign the target port based on the tunnel count
        target_port = 22 if tunnel_count == 1 else 2222

        # Set up tunnels and dynamically retrieve listening ports
        first_tunnel_port, last_tunnel_port = setup_tunnel_chain_dynamic_with_ports(
            tunnel_count=tunnel_count,
            target_ip=target_ip,
            target_port=target_port,  # Automatically assigned
            custom_ports=predefined_ports
        )

        # Debug: Ensure the correct ports are being used
        print(f"DEBUG: First tunnel port: {first_tunnel_port}, Last tunnel port: {last_tunnel_port}")

        if not first_tunnel_port or not last_tunnel_port:
            print("Failed to set up tunnels. Exiting.")
            return

        # Use the first tunnel port for Evil-WinRM
        ssh_command_port = first_tunnel_port if tunnel_count > 1 else last_tunnel_port

        # Prompt for authentication type
        auth_choice = select(
            "How do you want to authenticate?",
            choices=["Password", "Key"],
            style=custom_style,
        ).ask()

        if auth_choice == "Password":
            command = (
                f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {ssh_username}@127.0.0.1 /bin/bash"
            )
        elif auth_choice == "Key":
            # Select SSH Key
            selected_ssh_key = select_ssh_key(os.path.expanduser("~/.ssh"))

            if not selected_ssh_key:
                print("No valid SSH key selected. Exiting.")
                return  # Exit if no key is selected

             # Construct the command using the selected SSH key
            command = (
                f"ssh -i ~/.ssh/{selected_ssh_key} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"{ssh_username}@127.0.0.1 /bin/bash"
             )

    else:
        # No tunneling
                # Prompt for authentication type
        auth_choice = select(
            "How do you want to authenticate?",
            choices=["Password", "Key"],
            style=custom_style,
        ).ask()

        if auth_choice == "Password":
            command = (
                f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {ssh_username}@127.0.0.1 /bin/bash"
            )
        elif auth_choice == "Key":
            # Select SSH Key
            selected_ssh_key = select_ssh_key(os.path.expanduser("~/.ssh"))

            if not selected_ssh_key:
                print("No valid SSH key selected. Exiting.")
                return  # Exit if no key is selected

             # Construct the command using the selected SSH key
            command = (
                f"ssh -i ~/.ssh/{selected_ssh_key} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"{ssh_username}@127.0.0.1 /bin/bash"
             )

    # Execute the command
    print("Executing:", command)
    subprocess.run(command, shell=True)


def main():
    global ssh_key_directory
    print(f"\033[35m{ascii_art}\033[0m")

    if ssh_key_directory is None:
        ssh_key_directory = os.path.expanduser("~/.ssh")

    choice = select(
        "Select a Masquerade Type:",
        choices=["WinRM", "SMB", "RDP", "SSH", "SFTP", "Exit"],
        style=custom_style,
    ).ask()

    options = {
        "WinRM": winrm_masq,
        "SMB": smb_masq,
        "RDP": rdp_masq,
        "SSH": ssh_masq,
        # Add additional protocols here as needed
    }

    if choice in options:
        options[choice]()
    else:
        print("Exiting. Goodbye!")


if __name__ == "__main__":
    main()

