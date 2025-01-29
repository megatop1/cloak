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

def loot():
    loot_dir = "/app/loot"
    payloads_dir = "/app/payloads"

    for directory in [loot_dir, payloads_dir]:
        if not os.path.exists(directory):
            print(f"Creating directory: {directory}")
            os.makedirs(directory, exist_ok=True)
        else:
            print(f"Directory '{directory}' already exists.")

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

def prompt_for_tunnel():
    """
    Prompt the user to check if tunneling is needed, select tunnel type, and return tunnel details.
    :return: Tuple (tunnel_type, tunnel_count), or (None, None) if tunneling is not needed.
    """
    if text("Do you need to tunnel the connection? (Y/N):").ask().lower() == "y":
        # Ask for the type of tunnel
        tunnel_type = select(
            "Select the Tunnel Type:",
            choices=["SSH Tunnel", "SOCKS"],
            style=custom_style,
        ).ask()

        # Ask for the number of tunnels required
        tunnel_count = int(select(
            "Select the Number of Tunnels Required:",
            choices=["1", "2"],
            style=custom_style,
        ).ask())

        return tunnel_type, tunnel_count

    return None, None

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

def setup_socks_tunnel(tunnel_count, target_ip, target_port):
    """
    Set up a SOCKS proxy tunnel.
    :param tunnel_count: Number of tunnels to create.
    :param target_ip: The target IP address for the SOCKS tunnel.
    :param target_port: The target port for the SOCKS tunnel.
    """
    print("Setting up a SOCKS proxy tunnel...")

    if tunnel_count == 1:
        print("SOCKS Proxy Tunnel NOT Supported over single tunnel")
        return None, None

    elif tunnel_count == 2:
        # Step 1: Setup SSH tunnel for SOCKS5
        socks_ssh_tunnel_ip = text("Enter SOCKS Server IP:").ask()
        socks_ssh_tunnel_port = text("Enter SOCKS Server SSH Port (default: 22):").ask() or "22"
        socks_ssh_tunnel_user = text("Enter SOCKS Server SSH Username:").ask()
        local_socks_port = text("Enter Desired Local SOCKS Port (default: 1080):").ask() or "1080"
        ssh_key_name = select_ssh_key()

        if not ssh_key_name:
            print("No valid SSH key selected. Exiting.")
            return None, None

        ssh_key_path = os.path.join(ssh_key_directory, ssh_key_name)

        ssh_command = (
            f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"-i {ssh_key_path} -D 127.0.0.1:{local_socks_port} -q -C -N -f "
            f"{socks_ssh_tunnel_user}@{socks_ssh_tunnel_ip} -p {socks_ssh_tunnel_port}"
        )
        print(f"DEBUG: Executing SSH command for SOCKS tunnel: {ssh_command}")
        execute_command(ssh_command)
        print(f"SOCKS proxy established at 127.0.0.1:{local_socks_port}")

        # Step 2: Setup Chisel tunnel
        chisel_redirector_ip = text("Enter Redirector IP (Chisel Server):").ask()
        chisel_redirector_port = text("Enter Redirector Port (default: 8000):").ask() or "8000"
        chisel_username = text("Enter SOCKS Proxy Username:").ask()
        chisel_password = text("Enter SOCKS Proxy Password:").ask()

        chisel_command = (
            f"chisel client --proxy socks5h://{chisel_username}:{chisel_password}@127.0.0.1:{local_socks_port} "
            f"{chisel_redirector_ip}:{chisel_redirector_port} R:socks &"
        )
        print(f"DEBUG: Executing Chisel client command: {chisel_command}")
        execute_command(chisel_command)
        print("Chisel client connected to redirector.")

        # Step 3: Update /etc/proxychains.conf
        proxychains_config_path = "/etc/proxychains.conf"

        try:
            # Use sed to remove the socks4 line
            sed_remove_socks4 = f"sed -i '/^socks4 /d' {proxychains_config_path}"
            print(f"DEBUG: Executing command to remove socks4 line: {sed_remove_socks4}")
            execute_command(sed_remove_socks4)

            # Use sed to add or replace the socks5 line
            sed_update_socks5 = (
                f"if grep -q '^socks5 ' {proxychains_config_path}; then "
                f"sed -i 's|^socks5 .*|socks5  127.0.0.1 {local_socks_port}|' {proxychains_config_path}; "
                f"else echo 'socks5  127.0.0.1 {local_socks_port}' >> {proxychains_config_path}; fi"
            )
            print(f"DEBUG: Executing command to update socks5 line: {sed_update_socks5}")
            execute_command(sed_update_socks5)

            print(f"Updated {proxychains_config_path} to use local SOCKS port: {local_socks_port}")

        except Exception as e:
            print(f"Error updating {proxychains_config_path}: {e}")

        return local_socks_port, None  # Return the SOCKS proxy port

    else:
        print("ERROR: Multi-hop SOCKS tunneling is not yet implemented.")
        return None, None

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

    tunnel_type, tunnel_count = prompt_for_tunnel()
    if tunnel_type and tunnel_count:
        print(f"Tunneling Type: {tunnel_type}, Tunnels: {tunnel_count}")
        if tunnel_type == "SOCKS":
            # Redirect to SOCKS setup
            local_socks_port, _ = setup_socks_tunnel(tunnel_count, target_ip, 5985)
            if not local_socks_port:
                print("Failed to set up SOCKS tunnel. Exiting.")
                return

            auth_choice = select(
                "How do you want to authenticate?: ",
                choices=["Password", "Hashes"],
                style=custom_style
            ).ask()

            if auth_choice == "Password":
                winrm_password = input("Enter WinRM Password: ")
                command = (
                    f"proxychains evil-winrm -i {target_ip} -u {winrm_username} -p {winrm_password}"
                )
            elif auth_choice == "Hashes":
                winrm_hash = input("Enter NTLM Hash: ")
                command = (

                )

        elif tunnel_type == "SSH Tunnel":
            # Proceed with SSH tunnel setup
            predefined_ports = [5985] if tunnel_count == 1 else [5986, 5985]
            target_port = 5985 if tunnel_count == 1 else 5986

            first_tunnel_port, last_tunnel_port = setup_tunnel_chain_dynamic_with_ports(
                tunnel_count=tunnel_count,
                target_ip=target_ip,
                target_port=target_port,
                custom_ports=predefined_ports
            )

            if not first_tunnel_port or not last_tunnel_port:
                print("Failed to set up tunnels. Exiting.")
                return

            winrm_command_port = first_tunnel_port if tunnel_count > 1 else last_tunnel_port
            # Continue with authentication and command setup

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
            command = f"evil-winrm -i {target_ip} -u {winrm_username} -p {winrm_password}"
        elif auth_choice == "Hashes":
            winrm_hash = input("Enter NTLM Hash: ")
            command = f"evil-winrm -i {target_ip} -u {winrm_username} -H {winrm_hash}"

    # Execute the command
    print("Executing:", command)
    subprocess.run(command, shell=True)

def smb_masq():
    """
    Set up an SMB masquerade dynamically for tunneling.
    """
    print("Initializing SMB masquerade...")
    target_ip = text("Enter Target IP of SMB:").ask()
    smb_username = text("Enter Username:").ask()

    # Prompt for tunnel type and count
    tunnel_type, tunnel_count = prompt_for_tunnel()
    if tunnel_type and tunnel_count:
        print(f"Tunneling Type: {tunnel_type}, Tunnels: {tunnel_count}")

        if tunnel_type == "SOCKS":
            # Redirect to SOCKS setup
            local_socks_port, _ = setup_socks_tunnel(tunnel_count, target_ip, 445)
            if not local_socks_port:
                print("Failed to set up SOCKS tunnel. Exiting.")
                return

        elif tunnel_type == "SSH Tunnel":
            # Proceed with SSH tunnel setup
            predefined_ports = [445] if tunnel_count == 1 else [446, 445]
            target_port = 445 if tunnel_count == 1 else 446

            first_tunnel_port, last_tunnel_port = setup_tunnel_chain_dynamic_with_ports(
                tunnel_count=tunnel_count,
                target_ip=target_ip,
                target_port=target_port,
                custom_ports=predefined_ports
            )

            if not first_tunnel_port or not last_tunnel_port:
                print("Failed to set up tunnels. Exiting.")
                return
            target_ip = "127.0.0.1"

    # Prompt for authentication type
    auth_choice = select(
        "How do you want to authenticate?",
        choices=["Password", "Hashes"],
        style=custom_style,
    ).ask()

    if auth_choice == "Password":
        smb_password = input("Enter SMB Password: ")
        if tunnel_type == "SOCKS":
            command = (
                f"proxychains python /app/slinger/src/slinger.py -host {target_ip} --username {smb_username} --password {smb_password}"
            )
        elif tunnel_type == "SSH Tunnel" or not tunnel_type:
            command = (
                f"python /app/slinger/src/slinger.py -host {target_ip} --username {smb_username} --password {smb_password}"
            )

    elif auth_choice == "Hashes":
        smb_hash = input("Enter NTLM Hash: ")
        if tunnel_type == "SOCKS":
            command = (
                f"proxychains python /app/slinger/src/slinger.py -host {target_ip} --username {smb_username} -ntlm :{smb_hash}"
            )
        elif tunnel_type == "SSH Tunnel" or not tunnel_type:
            command = (
                f"python /app/slinger/src/slinger.py -host {target_ip} --username {smb_username} -ntlm :{smb_hash}"
            )

    else:
        print("Invalid authentication choice. Exiting.")
        return

    # Execute the command
    print("Executing:", command)
    subprocess.run(command, shell=True)

def rdp_masq():
    """
    Set up an RDP masquerade dynamically for tunneling.
    """
    print("Initializing RDP masquerade...")
    target_ip = text("Enter Target IP of RDP:").ask()
    rdp_username = text("Enter Username:").ask()

    # Prompt for tunnel type and count
    tunnel_type, tunnel_count = prompt_for_tunnel()
    if tunnel_type and tunnel_count:
        print(f"Tunneling Type: {tunnel_type}, Tunnels: {tunnel_count}")

        if tunnel_type == "SOCKS":
            # Redirect to SOCKS setup
            local_socks_port, _ = setup_socks_tunnel(tunnel_count, target_ip, 3389)
            if not local_socks_port:
                print("Failed to set up SOCKS tunnel. Exiting.")
                return

        elif tunnel_type == "SSH Tunnel":
            # Proceed with SSH tunnel setup
            predefined_ports = [3389] if tunnel_count == 1 else [3390, 3389]
            target_port = 3389 if tunnel_count == 1 else 3390

            first_tunnel_port, last_tunnel_port = setup_tunnel_chain_dynamic_with_ports(
                tunnel_count=tunnel_count,
                target_ip=target_ip,
                target_port=target_port,
                custom_ports=predefined_ports
            )

            if not first_tunnel_port or not last_tunnel_port:
                print("Failed to set up tunnels. Exiting.")
                return
            target_ip = "127.0.0.1"

    # Prompt for authentication type
    auth_choice = select(
        "How do you want to authenticate?",
        choices=["Password", "Hashes"],
        style=custom_style,
    ).ask()

    command = None  # Initialize command variable to prevent unbound errors

    if auth_choice == "Password":
        rdp_password = input("Enter RDP Password: ")
        if tunnel_type == "SOCKS":
            command = (
                f"proxychains xfreerdp /cert-ignore /u:{rdp_username} /p:{rdp_password} /v:{target_ip}"
            )
        elif tunnel_type == "SSH Tunnel" or not tunnel_type:
            command = (
                f"xfreerdp /cert-ignore /u:{rdp_username} /p:{rdp_password} /v:127.0.0.1"
            )

    elif auth_choice == "Hashes":
        rdp_hash = input("Enter NTLM Hash: ")
        if tunnel_type == "SOCKS":
            command = (
                f"proxychains xfreerdp /cert-ignore /u:{rdp_username} /pth:{rdp_hash} /v:{target_ip}"
            )
        elif tunnel_type == "SSH Tunnel" or not tunnel_type:
            command = (
                f"xfreerdp /cert-ignore /u:{rdp_username} /pth:{rdp_hash} /v:127.0.0.1"
            )

    if not command:
        print("Failed to generate a valid command. Exiting.")
        return

    # Execute the command
    print("Executing:", command)
    subprocess.run(command, shell=True)

def ssh_masq():
    """
    Set up an SSH masquerade dynamically for tunneling.
    """
    print("Initializing SSH masquerade...")
    target_ip = text("Enter Target IP of SSH:").ask()
    ssh_username = text("Enter Username:").ask()

    # Prompt for tunnel type and count
    tunnel_type, tunnel_count = prompt_for_tunnel()
    if tunnel_type and tunnel_count:
        print(f"Tunneling Type: {tunnel_type}, Tunnels: {tunnel_count}")

        if tunnel_type == "SOCKS":
            # Redirect to SOCKS setup
            local_socks_port, _ = setup_socks_tunnel(tunnel_count, target_ip, 22)
            if not local_socks_port:
                print("Failed to set up SOCKS tunnel. Exiting.")
                return

        elif tunnel_type == "SSH Tunnel":
            # Proceed with SSH tunnel setup
            predefined_ports = [22] if tunnel_count == 1 else [2222, 22]
            target_port = 22 if tunnel_count == 1 else 2222

            first_tunnel_port, last_tunnel_port = setup_tunnel_chain_dynamic_with_ports(
                tunnel_count=tunnel_count,
                target_ip=target_ip,
                target_port=target_port,
                custom_ports=predefined_ports
            )

            if not first_tunnel_port or not last_tunnel_port:
                print("Failed to set up tunnels. Exiting.")
                return
            target_ip = "127.0.0.1"

    # Prompt for authentication type
    auth_choice = select(
        "How do you want to authenticate?",
        choices=["Password", "SSH Key"],
        style=custom_style,
    ).ask()

    if auth_choice == "Password":
        if tunnel_type == "SOCKS":
            command = (
                f"proxychains ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {ssh_username}@{target_ip} /bin/bash"
            )
        elif tunnel_type == "SSH Tunnel" or not tunnel_type:
            command = (
                f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {ssh_username}@127.0.0.1 /bin/bash"
            )

    elif auth_choice == "SSH Key":
        selected_ssh_key = select_ssh_key(os.path.expanduser("~/.ssh"))
        if not selected_ssh_key:
            print("No valid SSH key selected. Exiting.")
            return  # Exit if no key is selected

        if tunnel_type == "SOCKS":
            command = (
                f"proxychains ssh -i ~/.ssh/{selected_ssh_key} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"{ssh_username}@{target_ip} /bin/bash"
            )
        elif tunnel_type == "SSH Tunnel" or not tunnel_type:
            command = (
                f"ssh -i ~/.ssh/{selected_ssh_key} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"{ssh_username}@127.0.0.1 /bin/bash"
            )

    else:
        print("Invalid authentication choice. Exiting.")
        return

    # Execute the command
    print("Executing:", command)
    subprocess.run(command, shell=True)

def sftp_masq():
    """
    Set up an SFTP masquerade dynamically for tunneling.
    """
    print("Initializing SFTP  masquerade...")
    target_ip = text("Enter Target IP of SFTP:").ask()
    sftp_username = text("Enter Username:").ask()

    # Prompt for tunnel type and count
    tunnel_type, tunnel_count = prompt_for_tunnel()
    if tunnel_type and tunnel_count:
        print(f"Tunneling Type: {tunnel_type}, Tunnels: {tunnel_count}")

        if tunnel_type == "SOCKS":
            # Redirect to SOCKS setup
            local_socks_port, _ = setup_socks_tunnel(tunnel_count, target_ip, 22)
            if not local_socks_port:
                print("Failed to set up SOCKS tunnel. Exiting.")
                return

        elif tunnel_type == "SSH Tunnel":
            # Proceed with SSH tunnel setup
            predefined_ports = [22] if tunnel_count == 1 else [2222, 22]
            target_port = 22 if tunnel_count == 1 else 2222

            first_tunnel_port, last_tunnel_port = setup_tunnel_chain_dynamic_with_ports(
                tunnel_count=tunnel_count,
                target_ip=target_ip,
                target_port=target_port,
                custom_ports=predefined_ports
            )

            if not first_tunnel_port or not last_tunnel_port:
                print("Failed to set up tunnels. Exiting.")
                return
            target_ip = "127.0.0.1"

    # Prompt for authentication type
    auth_choice = select(
        "How do you want to authenticate?",
        choices=["Password", "SSH Key"],
        style=custom_style,
    ).ask()

    if auth_choice == "Password":
        if tunnel_type == "SOCKS":
            command = (
                f"proxychains sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {sftp_username}@{target_ip}"
            )
        elif tunnel_type == "SSH Tunnel" or not tunnel_type:
            command = (
                f"sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
				f"{sftp_username}@127.0.0.1"
            )

    elif auth_choice == "SSH Key":
        selected_ssh_key = select_ssh_key(os.path.expanduser("~/.ssh"))
        if not selected_ssh_key:
            print("No valid SSH key selected. Exiting.")
            return  # Exit if no key is selected

        if tunnel_type == "SOCKS":
            command = (
                f"proxychains sftp -i ~/.ssh/{selected_ssh_key} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"{ssh_username}@{target_ip} /bin/bash"
            )
        elif tunnel_type == "SSH Tunnel" or not tunnel_type:
            command = (
                f"sftp -i ~/.ssh/{selected_ssh_key} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                f"{ssh_username}@127.0.0.1 /bin/bash"
            )

    else:
        print("Invalid authentication choice. Exiting.")
        return

    # Execute the command
    print("Executing:", command)
    subprocess.run(command, shell=True)

def main():
    global ssh_key_directory
    print(f"\033[35m{ascii_art}\033[0m")

    if ssh_key_directory is None:
        ssh_key_directory = os.path.expanduser("~/.ssh")

    loot()

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
        "SFTP": sftp_masq,
        # Add additional protocols here as needed
    }

    if choice in options:
        options[choice]()
    else:
        print("Exiting. Goodbye!")


if __name__ == "__main__":
    main()

