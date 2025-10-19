from . import PatchGenerator
from penguin.defaults import default_libinject_string_introspection

class LibInjectStringIntrospection(PatchGenerator):
    '''
    Add LibInject aliases for string introspection (e.g., for comparison detection).
    For each method we see in the filesystem that's in our list of shim targets, add the shim
    '''
    def __init__(self, library_info: dict) -> None:
        self.enabled = True
        self.patch_name = 'lib_inject.string_introspection'
        self.library_info = library_info

    def generate(self, patches: dict) -> dict:
        aliases = {}
        for _, exported_syms in self.library_info.get("symbols", {}).items():
            for sym in exported_syms:
                if sym in default_libinject_string_introspection:
                    aliases[sym] = default_libinject_string_introspection[sym]

        return {'lib_inject': {'aliases': aliases}}
