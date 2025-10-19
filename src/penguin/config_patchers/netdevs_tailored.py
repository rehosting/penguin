from . import PatchGenerator

class NetdevsTailored(PatchGenerator):
    '''
    Add list of network device names observed in static analysis.
    '''
    def __init__(self, netdevs: dict) -> None:
        self.enabled = True
        self.patch_name = "netdevs.dynamic"
        self.netdevs = netdevs

    def generate(self, patches: dict) -> dict | None:
        values = set()
        if not self.netdevs:
            return
        for src, devs in self.netdevs.items():
            values.update(devs)
        if len(values):
            return {'netdevs': sorted(list(values))}
