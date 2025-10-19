from .patch_generator import PatchGenerator
from .nvram_helper import NvramHelper

class NvramDefaults(PatchGenerator):
    """
    Add default nvram values from Firmadyne and FirmAE
    """
    def __init__(self) -> None:
        self.patch_name = "nvram.04_defaults"
        self.enabled = True

    def generate(self, patches: dict) -> dict | None:
        result = NvramHelper._get_default_nvram_values()
        if len(result):
            return {'nvram': result}
