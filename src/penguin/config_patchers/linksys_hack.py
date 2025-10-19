from . import PatchGenerator
from collections import defaultdict
import os

class LinksysHack(PatchGenerator):
    '''
    Linksys specific hack from FirmAE with pseudofile model.
    '''
    def __init__(self, extract_dir: str) -> None:
        self.patch_name = "pseudofiles.linksys"
        self.enabled = True
        self.extract_dir = extract_dir

    def generate(self, patches: dict) -> dict:
        result = defaultdict(dict)
        # TODO: The following changes from FirmAE should likely be disabled by default
        # as we can't consider this information as part of our search if it's in the initial config
        # Linksys specific hack from firmae
        if all(
            os.path.isfile(os.path.join(self.extract_dir, x[1:]))
            for x in ["/bin/gpio", "/usr/lib/libcm.so", "/usr/lib/libshared.so"]
        ):
            result["pseudofiles"]["/dev/gpio/in"] = {
                "read": {
                    "model": "return_const",
                    "val": 0xFFFFFFFF,
                }
            }

        return result
