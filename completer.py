from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.styles import Style
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.completion import WordCompleter

available_protocols = ["WinRM", "SMB", "RDP", "SSH", "SFTP"]
available_credential_types = ["password", "key", "hash"]

class CloakCompleter(Completer):
    def get_completions(self, document, complete_event):
        text = document.text
        words = text.strip().split()

        # Stop suggesting after full credential is entered
        if words[:2] == ["set", "credential"] and len(words) >= 4:
            return

        # cloak > set → suggest subkeys
        if len(words) == 1 and words[0] == "set":
            for option in ["protocol", "target", "port", "credential"]:
                yield Completion(option, start_position=0)

        # cloak > set <partial_key>
        elif len(words) == 2 and words[0] == "set" and not text.endswith(" "):
            for option in ["protocol", "target", "port", "credential"]:
                if option.startswith(words[1].lower()):
                    yield Completion(option, start_position=-len(words[1]))

        # cloak > set protocol [TAB]
        elif text.startswith("set protocol ") and (len(words) == 2 or (len(words) == 3 and text.endswith(" "))):
            for proto in available_protocols:
                yield Completion(proto, start_position=0)

        # cloak > set protocol <partial>
        elif len(words) == 3 and words[0] == "set" and words[1] == "protocol":
            already_typed = words[2]
            for proto in available_protocols:
                if proto.lower().startswith(already_typed.lower()):
                    yield Completion(proto, start_position=-len(already_typed))

        # cloak > set credential <username> [TAB]
        elif len(words) == 3 and words[0] == "set" and words[1] == "credential" and text.endswith(" "):
            for ctype in available_credential_types:
                yield Completion(ctype, start_position=0)

        # cloak > set credential <username> <partial_type>
        elif len(words) == 4 and words[0] == "set" and words[1] == "credential":
            already_typed = words[3]
            for ctype in available_credential_types:
                if ctype.lower().startswith(already_typed.lower()):
                    yield Completion(ctype, start_position=-len(already_typed))


# Flags Set to Null
current_protocol = None
target_ip = None
target_port = None
credential_type = None
credential_value = None

# CLI Style to Look Cool and Fancy Like Sliver and Metasploit
cloak_style = Style.from_dict({
    "prompt": "ansiblue bold"
})

ssh_key_directory = None  # <-- define this here

available_protocols = ["WinRM", "SMB", "RDP", "SSH", "SFTP"]
available_credential_types = ["password", "key", "hash"]
credentials = {}  # { username: (type, value) }
protocol_completer = WordCompleter(available_protocols, ignore_case=True)

