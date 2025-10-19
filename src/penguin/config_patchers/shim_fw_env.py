from .shim_binaries import ShimBinaries
from . import PatchGenerator

class ShimFwEnv(ShimBinaries, PatchGenerator):
    '''
    Replace fw_printenv/getenv/setenv with hypercall based alternatives
    Work in progress. Needs testing
    '''
    def __init__(self, files: list) -> None:
        raise NotImplementedError("Untested shim type")
        super().__init__(files)
        self.patch_name = "static.shims.fw_env"

    def generate(self, patches: dict) -> dict:
        return self.make_shims({
            "fw_printenv": "fw_printenv",
            "fw_getenv": "fw_printenv",
            "fw_setenv": "fw_printenv",
        })
