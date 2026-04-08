from penguin.static_plugin import ConfigPatcherPlugin
from penguin.defaults import default_libinject_string_introspection

class LibInjectStringIntrospection(ConfigPatcherPlugin):
    depends_on = ['LibrarySymbols']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enabled = True
        self.patch_name = 'lib_inject.string_introspection'

    def generate(self, patches: dict) -> dict:
        library_info = self.prior_results.get('LibrarySymbols', {})
        aliases = {}
        for _, exported_syms in library_info.get("symbols", {}).items():
            for sym in exported_syms:
                if sym in default_libinject_string_introspection:
                    aliases[sym] = default_libinject_string_introspection[sym]

        return {'lib_inject': {'aliases': aliases}}
