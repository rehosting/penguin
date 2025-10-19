from . import PatchGenerator

class SingleShotFICD(PatchGenerator):
    '''
    We are doing a single-shot, automated evaluation. Disable root shell,
    but keep VPN on and measure FICD
    '''
    def __init__(self) -> None:
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
                    "shutdown_on_www": False,  # FICD or www success results in shutdown
                },
                "ficd": {
                    "enabled": True,
                    "stop_on_if": True,
                },
                "fetch_web": {
                    "enabled": True,
                    "shutdown_after_www": True,  # FICD or www success results in shutdown
                },
            }
        }
