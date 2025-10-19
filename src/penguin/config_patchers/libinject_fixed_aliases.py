from . import PatchGenerator
from penguin.defaults import default_lib_aliases

class LibInjectFixedAliases(PatchGenerator):
    '''
    Set all aliases in libinject from our defaults.
    '''
    def __init__(self) -> None:
        self.enabled = False
        self.patch_name = 'lib_inject.fixed_models'

    def generate(self, patches: dict) -> dict:
        return {'lib_inject': {'aliases': default_lib_aliases}}
