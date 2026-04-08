from penguin.static_plugin import ConfigPatcherPlugin

class DynamicExploration(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "auto_explore"
        self.enabled = False

    def generate(self, patches: dict) -> dict:
        return {
            "core": {
                "root_shell": False,
            },
            "plugins": {
                "nmap": {
                    "enabled": True,
                },
                "vpn": {
                    "enabled": True,
                    "log": True,
                },
                "netbinds":
                {
                    "enabled": True,
                    "shutdown_on_www": False,
                },
            }
        }
