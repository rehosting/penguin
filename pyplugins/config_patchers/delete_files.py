import os
from collections import defaultdict
from penguin.static_plugin import ConfigPatcherPlugin

class DeleteFiles(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "static.delete_files"
        self.enabled = True

    def generate(self, patches: dict) -> dict:
        result = defaultdict(dict)
        for f in ["/etc/securetty", "/etc/scripts/sys_resetbutton"]:
            if os.path.isfile(os.path.join(self.extracted_fs, f[1:])):
                result["static_files"][f] = {
                    "type": "delete",
                }
        return result
