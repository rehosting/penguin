"""
Network device name patches: defaults plus interfaces observed in analysis.
"""

from penguin.defaults import default_netdevs
from penguin.init_plugin import InitContext, InitPlugin


class NetdevsDefault(InitPlugin):
    '''
    Add list of default network device names.
    '''
    patch_name = "netdevs.default"
    order = 60

    def patch(self, ctx: InitContext) -> dict:
        return {'netdevs': default_netdevs}


class NetdevsTailored(InitPlugin):
    '''
    Add list of network device names observed in static analysis.
    '''
    patch_name = "netdevs.dynamic"
    order = 70

    def patch(self, ctx: InitContext) -> dict | None:
        netdevs = self.plugins.InterfaceFinder.interfaces
        values = set()
        if not netdevs:
            return
        for src, devs in netdevs.items():
            values.update(devs)
        if len(values):
            return {'netdevs': sorted(list(values))}
