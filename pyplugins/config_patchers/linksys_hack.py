import os
from collections import defaultdict
from penguin.static_plugin import ConfigPatcherPlugin

class LinksysHack(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "pseudofiles.linksys"
        self.enabled = True

    def generate(self, patches: dict) -> dict:
        result = defaultdict(dict)
        if all(
            os.path.isfile(os.path.join(self.extracted_fs, x[1:]))
            for x in ["/bin/gpio", "/usr/lib/libcm.so", "/usr/lib/libshared.so"]
        ):
            result["pseudofiles"]["/dev/gpio/in"] = {
                "read": {
                    "model": "return_const",
                    "val": 0xFFFFFFFF,
                }
            }
        return result
