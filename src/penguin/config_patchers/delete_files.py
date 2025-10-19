from . import PatchGenerator
from collections import defaultdict
import os

class DeleteFiles(PatchGenerator):
    '''
    Delete some files we don't want.
    '''
    def __init__(self, extract_dir: str) -> None:
        self.patch_name = "static.delete_files"
        self.enabled = True
        self.extract_dir = extract_dir

    def generate(self, patches: dict) -> dict:
        result = defaultdict(dict)
        # Delete some files that we don't want. securetty is general, limits shell access.
        # 'sys_resetbutton' is some FW-specific hack from FirmAE

        # TODO: does securetty matter if our root shell is disabled?
        for f in ["/etc/securetty", "/etc/scripts/sys_resetbutton"]:
            if os.path.isfile(os.path.join(self.extract_dir, f[1:])):
                result["static_files"][f] = {
                    "type": "delete",
                }
        return result
