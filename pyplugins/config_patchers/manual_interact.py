from penguin.static_plugin import ConfigPatcherPlugin

class ManualInteract(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "manual"
        self.enabled = True

    def generate(self, patches: dict) -> dict:
        return {
            "core": {
                "root_shell": True
            },
            "plugins": {
                "nmap": {
                    "enabled": False,
                },
                "vpn": {
                    "enabled": True,
                },
                "netbinds":
                {
                    "enabled": True,
                    "shutdown_on_www": False,
                },

            }
        }
