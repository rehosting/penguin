from .shim_binaries import ShimBinaries
from . import PatchGenerator

class ShimBusybox(ShimBinaries, PatchGenerator):
    def __init__(self, files: list) -> None:
        super().__init__(files)
        self.patch_name = "static.shims.busybox"
        self.enabled = False

    def generate(self, patches: dict) -> dict:
        return self.make_shims({
            "ash": "busybox",
            "sh": "busybox",
            "bash": "bash",
        })
