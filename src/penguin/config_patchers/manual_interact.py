from . import PatchGenerator

class ManualInteract(PatchGenerator):
    '''
    Interactive for manual exploration. Enable root shell, enable
    vpn. Do not terminate on www bind.
    '''
    def __init__(self) -> None:
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
