import os
import subprocess
from questionary import Style, select

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

# Protocol to Port Mapping
protocol_port_map = {
    "RDP": 3389,
    "WinRM": 5985,
    "SMB": 445,
    "WMI": [135, 445, "50000-51000"],  # WMI requires specific ports and a range
    "SSH/SFTP": 22
}


# Helper Functions
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


def authenticate():
    """Prompt for authentication choice and return credentials."""
    choice = select("How do you want to authenticate?", choices=["Password", "Hashes"], style=custom_style).ask()
    if choice == "Password":
        return {"type": "password", "value": input("Enter Password: ")}
    elif choice == "Hashes":
        return {"type": "hash", "value": input("Enter NTLM Hash: ")}

def setup_tunnel(protocol_port_map, target_ip):
    """Set up multiple tunnels dynamically based on user input."""
    tunnel_amount = select(
        "Select the Number of Tunnels Required:",
        choices=["1", "2", "3", "Exit"],
        style=custom_style
    ).ask()

    if tunnel_amount == "Exit":
        return None

    tunnels = []
    local_ports = [5986, 5985]  # Ports for intermediate and final hops

    for i in range(int(tunnel_amount)):
        print(f"Configuring Tunnel {i + 1}:")
        ssh_ip = input("Enter SSH Tunnel IP: ")
        ssh_port = input("Enter SSH Tunnel Port (default: 22): ").strip() or "22"
        ssh_user = input("Enter SSH Username: ")

        auth_method = select(
            "Select Authentication Method:",
            choices=["Password", "SSH Key"],
            style=custom_style
        ).ask()

        if auth_method == "Password":
            ssh_pass = input("Enter SSH Password: ")
        elif auth_method == "SSH Key":
            ssh_key = select_ssh_key()
            if not ssh_key:
                print("No valid SSH key selected.")
                return None

        if i == 0:
            # First hop: Forward to the next server
            remote_target = "172.20.85.100:22"
            local_port = local_ports[0]
        elif i == 1:
            # Second hop: Use the first tunnel's output
            remote_target = f"{target_ip}:5985"
            local_port = local_ports[1]
            ssh_ip = "127.0.0.1"  # Use the first tunnel's output
            ssh_port = local_ports[0]

        # Generate the tunnel command
        if auth_method == "Password":
            tunnels.append(
                f"sshpass -p '{ssh_pass}' ssh -N -L 127.0.0.1:{local_port}:{remote_target} {ssh_user}@{ssh_ip} -p {ssh_port}"
            )
        elif auth_method == "SSH Key":
            tunnels.append(
                f"ssh -i {os.path.expanduser(f'~/.ssh/{ssh_key}')} -N -L 127.0.0.1:{local_port}:{remote_target} {ssh_user}@{ssh_ip} -p {ssh_port}"
            )

    return " & sleep 2 && ".join(tunnels)


# Masquerade Functions
def masquerade(service_name, command_template, default_port):
    print(f"Initializing {service_name} masquerade...")
    target_ip = input(f"Enter Target IP of {service_name}: ")
    username = input(f"Enter Username: ")

    if input("Do you need to tunnel the connection? (Y/N): ").strip().lower() == "y":
        tunnel_command = setup_tunnel(protocol_port_map, target_ip)
        if not tunnel_command:
            return
    else:
        tunnel_command = ""

    auth = authenticate()
    if auth["type"] == "password":
        service_command = command_template.format(username=username, target_ip=target_ip, password=auth['value'], port=default_port)
    elif auth["type"] == "hash":
        service_command = command_template.format(username=username, target_ip=target_ip, hash=auth['value'], port=default_port)

    # Combine tunnel and service commands
    if tunnel_command:
        full_command = f"{tunnel_command} & sleep 5 && {service_command}"
    else:
        full_command = service_command

    print(f"Generated Command: {full_command}")
    subprocess.run(full_command, shell=True)


# Specific Service Functions
def winrm_masq():
    masquerade("WinRM", "evil-winrm -i 127.0.0.1 -u {username} -p {password}", 5985)


def smb_masq():
    masquerade("SMB", "python3 /app/slinger/build/scripts-3.12/slinger.py -host 127.0.0.1 --username {username} --password {password}", 445)


def rdp_masq():
    masquerade("RDP", "xfreerdp /cert:ignore /u:{username} /p:{password} /v:127.0.0.1:{port}", 3389)


def ssh_masq():
    masquerade("SSH", "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null {username}@127.0.0.1 -p {port} /bin/bash", 22)


def sftp_masq():
    masquerade("SFTP", "sftp {username}@127.0.0.1:{port}", 22)


# Main Program
if __name__ == "__main__":
    print(f"\033[35m{ascii_art}\033[0m")
    choice = select("Select a Masquerade Type:", choices=["WinRM", "SMB", "RDP", "SSH", "SFTP", "Exit"], style=custom_style).ask()

    options = {
        "WinRM": winrm_masq,
        "SMB": smb_masq,
        "RDP": rdp_masq,
        "SSH": ssh_masq,
        "SFTP": sftp_masq,
    }

    if choice in options:
        options[choice]()
    else:
        print("Exiting. Goodbye!")

