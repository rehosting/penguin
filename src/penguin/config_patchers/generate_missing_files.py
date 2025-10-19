from . import PatchGenerator
from collections import defaultdict
import os
import re

class GenerateMissingFiles(PatchGenerator):
    '''
    Ensure we have /bin/sh, /etc/TZ, /var/run/nvramd.pid, and localhost in /etc/hosts.
    '''
    def __init__(self, extract_dir: str) -> None:
        self.patch_name = "static.missing_files"
        self.enabled = True
        self.extract_dir = extract_dir

    def generate(self, patches: dict) -> dict:
        # Firmadyne/FirmAE mitigation, ensure these 3 files always exist
        # Note including /bin/sh here means we'll add it if it's missing and as a symlink to /igloo/utils/busybox
        # this is similar to how we can shim an (existing) /bin/sh to point to /igloo/utils/busybox but here we
        # only add it if it's missing
        result = defaultdict(dict)

        model = {
            # Ensure /bin/sh exists if not already present
            "/bin/sh": {
                "type": "symlink",
                "target": "/igloo/utils/busybox"
            },

            # Set timezone to EST
            "/etc/TZ": {
                "type": "inline_file",
                "contents": "EST5EDT",
                "mode": 0o755,
            },

            # Needed for Ralink and D-Link
            # See https://github.com/firmadyne/libnvram/blob/e33692277d475d61a03e0772efeef5c829872f34/nvram.c#L189
            "/var/run/nvramd.pid": {
                "type": "inline_file",
                "contents": "",
                "mode": 0o644,
            },
        }

        for fname, data in model.items():
            if not os.path.isfile(os.path.join(self.extract_dir, fname[1:])):
                result['static_files'][fname] = data

        # Ensure we have an entry for localhost in /etc/hosts. So long as we have an /etc/ directory
        hosts = ""
        if os.path.isfile(os.path.join(self.extract_dir, "etc/hosts")):
            with open(os.path.join(self.extract_dir, "etc/hosts"), "r") as f:
                hosts = f.read()

        # if '127.0.0.1 localhost' not in hosts:
        # Regex with whitespace and newlines
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
