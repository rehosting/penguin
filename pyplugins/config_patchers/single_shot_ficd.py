from penguin.static_plugin import ConfigPatcherPlugin

class SingleShotFICD(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "single_shot_ficd"
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
                "ficd": {
                    "enabled": True,
                    "stop_on_if": True,
                },
                "fetch_web": {
                    "enabled": True,
                    "shutdown_after_www": True,
                },
            }
        }
