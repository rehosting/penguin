from .shim_binaries import ShimBinaries
from . import PatchGenerator

class ShimNoModules(ShimBinaries, PatchGenerator):
    def __init__(self, files: list) -> None:
        super().__init__(files)
        self.patch_name = "static.shims.no_modules"
        self.enabled = True

    def generate(self, patches: dict) -> dict:
        return self.make_shims({
            "insmod": "exit0.sh"
        })
