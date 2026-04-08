from penguin.static_plugin import ConfigPatcherPlugin
from penguin.defaults import default_lib_aliases

class LibInjectFixedAliases(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enabled = False
        self.patch_name = 'lib_inject.fixed_models'

    def generate(self, patches: dict) -> dict:
        return {'lib_inject': {'aliases': default_lib_aliases}}
