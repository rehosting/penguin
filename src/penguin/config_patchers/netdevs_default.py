from . import PatchGenerator
from penguin.defaults import default_netdevs

class NetdevsDefault(PatchGenerator):
    '''
    Add list of default network device names.
    '''
    def __init__(self) -> None:
        self.enabled = True
        self.patch_name = "netdevs.default"

    def generate(self, patches: dict) -> dict:
        return {'netdevs': default_netdevs}
