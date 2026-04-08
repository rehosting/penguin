import os
from penguin.static_plugin import ConfigPatcherPlugin

class ShimCrypto(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "static.shims.crypto"
        self.enabled = False

    def generate(self, patches: dict) -> dict | None:
        from .tar_helper import TarHelper
        from .shim_binaries import ShimBinaries
        import penguin
        RESOURCES = os.path.join(os.path.dirname(penguin.__file__), "resources")

        files = TarHelper.get_all_members(self.fs_archive)
        result = ShimBinaries(files).make_shims({
            "openssl": "openssl",
            "ssh-keygen": "ssh-keygen"
        })

        if not len(result.get("static_files", [])):
            return

        result["static_files"]["/igloo/keys/*"] = {
            "type": "host_file",
            "mode": 0o444,
            "host_path": os.path.join(*[RESOURCES, "static_keys", "*"])
        }

        return result
