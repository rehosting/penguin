import os
from collections import defaultdict
from penguin.static_plugin import ConfigPatcherPlugin

class GenerateShellMounts(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "static.shell_script_mounts"
        self.enabled = True

    def generate(self, patches: dict) -> dict:
        from .file_helper import FileHelper
        from .tar_helper import TarHelper
        existing = {member.name[1:] for member in TarHelper.get_all_members(self.fs_archive)}
        result = defaultdict(dict)

        for f in FileHelper.find_shell_scripts(self.extracted_fs):
            for dest in list(
                set(FileHelper.find_strings_in_file(f, "^/mnt/[a-zA-Z0-9._/]+$"))
            ):
                if not dest.endswith("/"):
                    dest = os.path.dirname(dest)

                if dest in existing:
                    continue
                if any([dest in p[0].get('static_files', {}).keys() for p in patches.values()]):
                    continue

                if FileHelper.exists(self.extracted_fs, dest):
                    continue

                result['static_files'][dest] = {
                    "type": "dir",
                    "mode": 0o755,
                }
        return result
