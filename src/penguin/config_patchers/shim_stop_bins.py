from .shim_binaries import ShimBinaries
from . import PatchGenerator

class ShimStopBins(ShimBinaries, PatchGenerator):
    def __init__(self, files: list) -> None:
        super().__init__(files)
        self.patch_name = "static.shims.stop_bins"
        self.enabled = True

    def generate(self, patches: dict) -> dict:
        return self.make_shims({
            "reboot": "exit0.sh",
            "halt": "exit0.sh",
        })
