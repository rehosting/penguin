import os
import re
from collections import defaultdict
from penguin.static_plugin import ConfigPatcherPlugin

class GenerateMissingFiles(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.patch_name = "static.missing_files"
        self.enabled = True

    def generate(self, patches: dict) -> dict:
        result = defaultdict(dict)

        model = {
            "/bin/sh": {
                "type": "symlink",
                "target": "/igloo/utils/busybox"
            },
            "/etc/TZ": {
                "type": "inline_file",
                "contents": "EST5EDT",
                "mode": 0o755,
            },
            "/var/run/nvramd.pid": {
                "type": "inline_file",
                "contents": "",
                "mode": 0o644,
            },
        }

        for fname, data in model.items():
            if not os.path.isfile(os.path.join(self.extracted_fs, fname[1:])):
                result['static_files'][fname] = data

        hosts = ""
        if os.path.isfile(os.path.join(self.extracted_fs, "etc/hosts")):
            with open(os.path.join(self.extracted_fs, "etc/hosts"), "r") as f:
                hosts = f.read()

        if not re.search(r"^127\.0\.0\.1\s+localhost\s*$", hosts, re.MULTILINE):
            if len(hosts) and not hosts.endswith("\n"):
                hosts += "\n"
            hosts += "127.0.0.1 localhost\n"

            result["static_files"]["/etc/hosts"] = {
                "type": "inline_file",
                "contents": hosts,
                "mode": 0o755,
            }
        return result
