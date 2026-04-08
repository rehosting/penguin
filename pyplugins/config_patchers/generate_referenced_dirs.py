from collections import defaultdict
from penguin.static_plugin import ConfigPatcherPlugin

class GenerateReferencedDirs(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "static.binary_paths"
        self.enabled = True

    def generate(self, patches: dict) -> dict:
        from .file_helper import FileHelper
        result = defaultdict(dict)
        for f in FileHelper.find_executables(
            self.extracted_fs, {"/bin", "/sbin", "/usr/bin", "/usr/sbin"}
        ):
            for dest in list(
                set(FileHelper.find_strings_in_file(f, "^(/var|/etc|/tmp)(.+)([^\\/]+)$"))
            ):
                if any([x in dest for x in ["%s", "%c", "%d", "/tmp/services"]]):
                    continue
                result["static_files"][dest] = {
                    "type": "dir",
                    "mode": 0o755,
                }
        return result
