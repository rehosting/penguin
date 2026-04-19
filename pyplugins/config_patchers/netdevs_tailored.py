from penguin.static_plugin import ConfigPatcherPlugin

class NetdevsTailored(ConfigPatcherPlugin):
    depends_on = ['InterfaceFinder']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enabled = True
        self.patch_name = "netdevs.dynamic"

    def generate(self, patches: dict) -> dict | None:
        netdevs = self.prior_results.get('InterfaceFinder')
        values = set()
        if not netdevs:
            return
        for src, devs in netdevs.items():
            values.update(devs)
        if len(values):
            return {'netdevs': sorted(list(values))}
