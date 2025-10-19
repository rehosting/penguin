from . import PatchGenerator
from collections import defaultdict
import os
from penguin.helpers.file_helper import FileHelper

class GenerateShellMounts(PatchGenerator):
    """
    Ensure we have /mnt/* directories referenced by shell scripts.
    """

    def __init__(self, extract_dir, existing):
        self.patch_name = "static.shell_script_mounts"
        self.extract_dir = extract_dir
        self.enabled = True
        self.existing = {member.name[1:] for member in existing}

    def generate(self, patches: dict) -> dict:
        result = defaultdict(dict)

        for f in FileHelper.find_shell_scripts(self.extract_dir):
            for dest in list(
                set(FileHelper.find_strings_in_file(f, "^/mnt/[a-zA-Z0-9._/]+$"))
            ):
                if not dest.endswith("/"):
                    dest = os.path.dirname(dest)
                    # We're making the directory in which the file we saw referenced
                    # will be

                # Does this file exist in the filesystem or in any existing patches?
                if dest in self.existing:
                    continue
                if any([dest in p[0].get('static_files', {}).keys() for p in patches.values()]):
                    continue

                # Try resolving the dest (to handle symlinks more correctly than the existing check)
                if FileHelper.exists(self.extract_dir, dest):
                    # Directory already exists - don't clobber!
                    continue

                result['static_files'][dest] = {
                    "type": "dir",
                    "mode": 0o755,
                }
        return result
