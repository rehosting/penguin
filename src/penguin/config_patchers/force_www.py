from . import PatchGenerator
import os

class ForceWWW(PatchGenerator):
    '''
    This is a hacky FirmAE approach to identify webservers and just start
    them. Unsurprisingly, it increases the rate of web servers starting.
    We'll export this into our static files section so we could later decide
    to try it. We'll enable this by default here.
    '''
    def __init__(self, fs_path: str) -> None:
        self.enabled = False
        self.patch_name = 'force_www'
        self.fs_path = fs_path

    def generate(self, patches: dict) -> dict | None:
        # Map between filename and command
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

        # Do we have lighttpd.conf?
        have_lighttpd_conf = os.path.isfile(os.path.join(self.fs_path, "./etc/lighttpd/lighttpd.conf"))

        for file, cmd in file2cmd.items():
            if os.path.isfile(os.path.join(self.fs_path, file)):
                if file == "./usr/sbin/lighttpd" and not have_lighttpd_conf:
                    # Lighttpd only valid if there's a config file
                    continue
                www_cmds.append(cmd)
                www_paths.append(file)

        if not len(www_cmds):
            return

        # Start of the shell script
        # We want to start each identified webserver in a loop
        cmd_str = """#!/igloo/utils/sh
        /igloo/utils/busybox sleep 120

        while true; do
        """

        # Loop through the commands to add them to the script
        for cmd in www_cmds:
            cmd_str += f"""
            if ! (/igloo/utils/busybox ps | /igloo/utils/busybox grep -v grep | /igloo/utils/busybox grep -sqi "{cmd}"); then
                {cmd} &
            fi
        """
        # Close the loop
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
