from . import PatchGenerator
from collections import defaultdict
from penguin.helpers.file_helper import FileHelper

class GenerateReferencedDirs(PatchGenerator):
    '''
    FirmAE "Boot mitigation": find path strings in binaries, make their directories
    if they don't already exist.
    '''

    def __init__(self, extract_dir):
        self.patch_name = "static.binary_paths"
        self.enabled = True
        self.extract_dir = extract_dir

    def generate(self, patches: dict) -> dict:
        result = defaultdict(dict)
        for f in FileHelper.find_executables(
            self.extract_dir, {"/bin", "/sbin", "/usr/bin", "/usr/sbin"}
        ):
            # For things that look like binaries, find unique strings that look like paths
            for dest in list(
                set(FileHelper.find_strings_in_file(f, "^(/var|/etc|/tmp)(.+)([^\\/]+)$"))
            ):
                if any([x in dest for x in ["%s", "%c", "%d", "/tmp/services"]]):
                    # Ignore these paths, printf format strings aren't real directories to create
                    # Not sure what /tmp/services is or where we got that from?
                    continue
                result["static_files"][dest] = {
                    "type": "dir",
                    "mode": 0o755,
                }
        return result
