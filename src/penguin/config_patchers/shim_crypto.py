from .shim_binaries import ShimBinaries
from . import PatchGenerator
import os
from penguin.defaults import RESOURCES

class ShimCrypto(ShimBinaries, PatchGenerator):
    def __init__(self, files: list) -> None:
        super().__init__(files)
        self.patch_name = "static.shims.crypto"
        self.enabled = False

    def generate(self, patches: dict) -> dict | None:
        result = self.make_shims({
            "openssl": "openssl",
            "ssh-keygen": "ssh-keygen"
        })

        if not len(result.get("static_files", [])):
            # Nothing to shim, don't add the key copy
            return

        result["static_files"]["/igloo/keys/*"] = {
            "type": "host_file",
            "mode": 0o444,
            "host_path": os.path.join(*[RESOURCES, "static_keys", "*"])
        }

        return result
