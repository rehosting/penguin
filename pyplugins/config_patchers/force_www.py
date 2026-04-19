import os
from penguin.static_plugin import ConfigPatcherPlugin

class ForceWWW(ConfigPatcherPlugin):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.enabled = False
        self.patch_name = 'force_www'

    def generate(self, patches: dict) -> dict | None:
        file2cmd = {
            "./etc/init.d/uhttpd": "/etc/init.d/uhttpd start",
            "./usr/bin/httpd": "/usr/bin/httpd",
            "./usr/sbin/httpd": "/usr/sbin/httpd",
            "./bin/goahead": "/bin/goahead",
            "./bin/alphapd": "/bin/alphapd",
            "./bin/boa": "/bin/boa",
            "./usr/sbin/lighttpd": "/usr/sbin/lighttpd -f /etc/lighttpd/lighttpd.conf",
        }

        www_cmds = []
        www_paths = []

        have_lighttpd_conf = os.path.isfile(os.path.join(self.extracted_fs, "./etc/lighttpd/lighttpd.conf"))

        for file, cmd in file2cmd.items():
            if os.path.isfile(os.path.join(self.extracted_fs, file)):
                if file == "./usr/sbin/lighttpd" and not have_lighttpd_conf:
                    continue
                www_cmds.append(cmd)
                www_paths.append(file)

        if not len(www_cmds):
            return

        cmd_str = """#!/igloo/utils/sh
        /igloo/utils/busybox sleep 120

        while true; do
        """

        for cmd in www_cmds:
            cmd_str += f"""
            if ! (/igloo/utils/busybox ps | /igloo/utils/busybox grep -v grep | /igloo/utils/busybox grep -sqi "{cmd}"); then
                {cmd} &
            fi
        """
        cmd_str += """
            /igloo/utils/busybox sleep 30
            done
        """

        return {
            "core": {
                'force_www': True
            },
            "static_files": {
                "/igloo/utils/www_cmds": {
                    "type": "inline_file",
                    "contents": cmd_str,
                    "mode": 0o755,
                }
            }
        }
