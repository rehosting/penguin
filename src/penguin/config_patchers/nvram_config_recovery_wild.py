from .patch_generator import PatchGenerator
from .nvram_helper import NvramHelper

class NvramConfigRecoveryWild(PatchGenerator):
    """
    Search for files that contain nvram keys and values to populate NVRAM defaults.
    This version relaxes the search to allow for basename matches instead of full path
    matches.
    """
    def __init__(self, extract_dir: str) -> None:
        self.extract_dir = extract_dir
        self.patch_name = "nvram.03_config_paths_basename"
        self.enabled = True

    def generate(self, patches: dict) -> dict | None:
        result = NvramHelper.nvram_config_analysis(self.extract_dir, False)
        if len(result):
            return {'nvram': result}
