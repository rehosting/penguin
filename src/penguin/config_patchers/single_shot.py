from .patch_generator import PatchGenerator

class SingleShot(PatchGenerator):
    '''
    We are doing a single-shot, automated evaluation. Disable root shell,
    leave coverage/nmap, but keep VPN on and use fetch_web to collect responses
    '''
    def __init__(self) -> None:
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
                    "shutdown_on_www": False,  # We want fetch_web to do the shutdown
                },
                "fetch_web": {
                    "enabled": True,
                    "shutdown_after_www": True,
                },

            }
        }
