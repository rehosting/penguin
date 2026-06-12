"""
Interaction-mode patches: root shell, automated exploration, single-shot
evaluation, and manual interaction.
"""

from penguin.init_plugin import InitContext, InitPlugin


class RootShell(InitPlugin):
    '''
    Add root shell
    '''
    patch_name = "root_shell"
    order = 20
    enabled = False

    def patch(self, ctx: InitContext) -> dict:
        return {
            "core": {
                "root_shell": False,
            },
        }


class DynamicExploration(InitPlugin):
    '''
    We are dynamically evaluating and refining a configuration. We need
    to collect data programatically. Disable root shell, enable
    coverage-tracking and nmap for coverage generation. Enable VPN
    so nmap has something to talk to.

    Ideally this will also be paired with ShimBusybox to get shell-level
    instrumentation.
    '''
    patch_name = "auto_explore"
    order = 30
    enabled = False

    def patch(self, ctx: InitContext) -> dict:
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


class SingleShotFICD(InitPlugin):
    '''
    We are doing a single-shot, automated evaluation. Disable root shell,
    but keep VPN on and measure FICD
    '''
    patch_name = "single_shot_ficd"
    order = 40
    enabled = False

    def patch(self, ctx: InitContext) -> dict:
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


class SingleShot(InitPlugin):
    '''
    We are doing a single-shot, automated evaluation. Disable root shell,
    leave coverage/nmap, but keep VPN on and use fetch_web to collect responses
    '''
    # NOTE: not registered in the built-in init plugin list (matching the
    # historic generator list, which never instantiated SingleShot)
    patch_name = "single_shot"
    order = 45
    enabled = False

    def patch(self, ctx: InitContext) -> dict:
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


class ManualInteract(InitPlugin):
    '''
    Interactive for manual exploration. Enable root shell, enable
    vpn. Do not terminate on www bind.
    '''
    patch_name = "manual"
    order = 50

    def patch(self, ctx: InitContext) -> dict:
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
