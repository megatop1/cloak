from prompt_toolkit.completion import Completer, Completion

available_protocols = ["WinRM", "SMB", "RDP", "SSH", "SFTP"]
available_credential_types = ["password", "key", "hash"]

# This function will be set externally in cloak.py
default_index_provider = lambda: []
credential_index_provider = default_index_provider

class CloakCompleter(Completer):
    def get_completions(self, document, complete_event):
        text = document.text
        words = text.strip().split()

        if words[:2] == ["set", "credential"] and len(words) >= 4:
            return

        # cloak > set
        if len(words) == 1 and words[0] == "set":
            for option in ["protocol", "target", "port", "credential"]:
                yield Completion(option, start_position=0)

        # cloak > set <partial>
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

        # cloak > use [TAB]
        elif len(words) == 1 and words[0] == "use":
            yield Completion("credential", start_position=0)

        # cloak > use credential [TAB] → show credential indexes
        elif len(words) == 2 and words[0] == "use" and words[1] == "credential" and text.endswith(" "):
            indexes = credential_index_provider()
            for idx in indexes:
                yield Completion(str(idx), start_position=0)

        # cloak > use credential <partial index>
        elif len(words) == 3 and words[0] == "use" and words[1] == "credential":
            already_typed = words[2]
            indexes = credential_index_provider()
            for idx in indexes:
                if str(idx).startswith(already_typed):
                    yield Completion(str(idx), start_position=-len(already_typed))

