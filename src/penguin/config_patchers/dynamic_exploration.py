from . import PatchGenerator

class DynamicExploration(PatchGenerator):
    '''
    We are dynamically evaluating and refining a configuration. We need
    to collect data programatically. Disable root shell, enable
    coverage-tracking and nmap for coverage generation. Enable VPN
    so nmap has something to talk to.

    Ideally this will also be paired with ShimBusybox to get shell-level
    instrumentation.
    '''
    def __init__(self) -> None:
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
