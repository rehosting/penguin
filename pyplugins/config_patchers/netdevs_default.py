from penguin.static_plugin import ConfigPatcherPlugin
from penguin.defaults import default_netdevs

class NetdevsDefault(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enabled = True
        self.patch_name = "netdevs.default"

    def generate(self, patches: dict) -> dict:
        return {'netdevs': default_netdevs}
