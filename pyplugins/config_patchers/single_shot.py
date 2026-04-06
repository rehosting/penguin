from penguin.static_plugin import ConfigPatcherPlugin

class SingleShot(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "single_shot"
        self.enabled = False

    def generate(self, patches: dict) -> dict:
        return {
            "core": {
                "root_shell": False,
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
                "fetch_web": {
                    "enabled": True,
                    "shutdown_after_www": True,
                },

            }
        }
