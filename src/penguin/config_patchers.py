"""
penguin.config_patchers
=======================

Patch-generation helpers (tar archives, file searches, NVRAM parsing, binary
shims) shared by penguin core and the init plugins in pyplugins/init/ (the
patch-generating classes themselves live there).
"""

import os
import re
import stat
import subprocess
import tarfile

from collections import defaultdict
from pathlib import Path

from penguin import getColoredLogger

logger = getColoredLogger("penguin.config_patchers")

RESOURCES: str = os.path.join(os.path.dirname(os.path.dirname(__file__)), "resources")


class TarHelper:
    '''
    Collection of static method to help find files in a tar archive
    '''
    @staticmethod
    def get_symlink_members(tarfile_path: str) -> dict[str, str]:
        with tarfile.open(tarfile_path, "r") as tar:
            # Trim leading . from path, everything is ./
            return {
                member.name[1:]: member.linkname
                for member in tar.getmembers()
                if member.issym()
            }

    @staticmethod
    def get_all_members(tarfile_path: str):
        with tarfile.open(tarfile_path, "r") as tar:
            # Trim leading . from path, everything is ./
            # return {member.name[1:] for member in tar.getmembers()}
            return tar.getmembers()

    @staticmethod
    def get_other_members(tarfile_path: str):
        # Get things that aren't files nor directories - devices, symlinnks, etc
        with tarfile.open(tarfile_path, "r") as tar:
            # Trim leading . from path, everything is ./
            return {
                member.name[1:]
                for member in tar.getmembers()
                if not member.isfile() and not member.isdir
            }

    @staticmethod
    def get_directory_members(tarfile_path: str) -> set[str]:
        with tarfile.open(tarfile_path, "r") as tar:
            # Trim leading . from path, everything is ./
            results = {member.name[1:] for member in tar.getmembers() if member.isdir()}
        # For each result, recursively add all parent directories
        # e.g., /etc/hosts -> /etc, /
        for r in list(results):
            parts = r.split("/")
            for i in range(len(parts)):
                results.add("/".join(parts[: i + 1]))
        return results

    @staticmethod
    def get_file_members(tarfile_path: str) -> set[str]:
        with tarfile.open(tarfile_path, "r") as tar:
            # Trim leading . from path, everything is ./
            return {member.name[1:] for member in tar.getmembers() if member.isfile()}


class FileHelper:
    @staticmethod
    def find_executables(tmp_dir: str, target_dirs: set[str] | None = None, index=None):
        """Executable files outside /igloo whose path ends with one of
        target_dirs. Pass an InitContext.file_index to avoid re-walking."""
        if not target_dirs:
            target_dirs = {"/"}
        for file_path in FileHelper._iter_executables(tmp_dir, index):
            if any(str(file_path).endswith(d) for d in target_dirs):
                yield file_path

    @staticmethod
    def find_strings_in_file(file_path: str, pattern: str) -> list[str]:
        result = subprocess.run(["strings", file_path], capture_output=True, text=True)
        return [line for line in result.stdout.splitlines() if re.search(pattern, line)]

    @staticmethod
    def find_shell_scripts(tmp_dir: str, index=None):
        """Executable *.sh files outside /igloo. Pass an
        InitContext.file_index to avoid re-walking."""
        for file_path in FileHelper._iter_executables(tmp_dir, index):
            if str(file_path).endswith(".sh"):
                yield file_path

    @staticmethod
    def _iter_executables(tmp_dir: str, index=None):
        if index is not None:
            for e in index.entries:
                # Exclude the '/igloo' path
                if "/igloo" in os.path.dirname(e.path):
                    continue
                if e.is_file and e.executable:
                    yield Path(e.path)
            return
        for root, _, files in os.walk(tmp_dir):
            # Exclude the '/igloo' path
            if "/igloo" in root:
                continue

            for file in files:
                file_path = Path(root) / file
                if file_path.is_file() and os.access(file_path, os.X_OK):
                    yield file_path

    @staticmethod
    def exists(tmp_dir: str, target: str) -> bool:
        """
        Check if the target exists within the extracted filesystem in tmp_dir,
        handling symlinks correctly.

        :param tmp_dir: The root of the extracted filesystem (e.g., /tmp/extracted)
        :type tmp_dir: str
        :param target: The target path to check (e.g., /foo/zoo)
        :type target: str
        :return: True if the target exists within tmp_dir, False otherwise
        :rtype: bool
        """
        assert target.startswith("/")
        assert os.path.exists(tmp_dir)

        # Strip the leading slash from the target to work with relative paths
        target = target[1:]  # Remove leading '/'
        parts = target.split("/")

        # Initialize path traversal from tmp_dir
        current_path = tmp_dir

        for part in parts:
            next_path = os.path.join(current_path, part)

            if os.path.islink(next_path):
                # Resolve symlink
                resolved = os.readlink(next_path)

                # If symlink is absolute, restart from tmp_dir
                if resolved.startswith("/"):
                    current_path = os.path.realpath(os.path.join(tmp_dir, resolved[1:]))
                else:
                    # Resolve relative symlink against the current path
                    current_path = os.path.realpath(os.path.join(current_path, resolved))
            else:
                # Move one level deeper in the path
                current_path = next_path

            # If the resolved path doesn't exist at any point, return False
            if not os.path.exists(current_path):
                return False

        # Final check: Ensure the fully resolved path exists
        return os.path.exists(current_path)


class NvramHelper:
    @staticmethod
    def _get_default_nvram_values() -> dict[str, str]:
        """
        Default nvram values from Firmadyne and FirmAE.

        :return: Dictionary of default NVRAM values.
        :rtype: dict[str, str]
        """
        nvram = {
            "console_loglevel": "7",
            "restore_defaults": "1",
            "sku_name": "",
            "wla_wlanstate": "",
            "lan_if": "br0",
            "lan_ipaddr": "192.168.0.50",
            "lan_bipaddr": "192.168.0.255",
            "lan_netmask": "255.255.255.0",
            "time_zone": "PST8PDT",
            "wan_hwaddr_def": "01:23:45:67:89:ab",
            "wan_ifname": "eth0",
            "lan_ifnames": "eth1 eth2 eth3 eth4",
            "ethConver": "1",
            "lan_proto": "dhcp",
            "wan_ipaddr": "0.0.0.0",
            "wan_netmask": "255.255.255.0",
            "wanif": "eth0",
            "time_zone_x": "0",
            "rip_multicast": "0",
            "bs_trustedip_enable": "0",
            "et0macaddr": "01:23:45:67:89:ab",
            "filter_rule_tbl": "",
            "pppoe2_schedule_config": "127:0:0:23:59",
            "schedule_config": "127:0:0:23:59",
            "access_control_mode": "0",
            "fwpt_df_count": "0",
            "static_if_status": "1",
            "www_relocation": "",
        }

        # Helper function add default entries from firmae
        def _add_firmae_for_entries(config_dict, pattern, value, start, end):
            for index in range(start, end + 1):
                config_dict[pattern % index] = value

        # TODO: do we want a config toggle for these entires seprately from the other defaults?
        _add_firmae_for_entries(
            nvram,
            "usb_info_dev%d",
            "A200396E0402FF83@1@14.4G@U@1@USB_Storage;U:;0;0@",
            0,
            101,
        )
        _add_firmae_for_entries(nvram, "wla_ap_isolate_%d", "", 1, 5)
        _add_firmae_for_entries(nvram, "wlg_ap_isolate_%d", "", 1, 5)
        _add_firmae_for_entries(nvram, "wlg_allow_access_%d", "", 1, 5)
        _add_firmae_for_entries(nvram, "%d:macaddr", "01:23:45:67:89:ab", 0, 3)
        _add_firmae_for_entries(nvram, "lan%d_ifnames", "", 1, 10)

        return nvram

    @staticmethod
    def parse_nvram_file(path: str, f) -> dict:
        """
        Parse a NVRAM file and return key-value pairs.

        :param path: Path to NVRAM file.
        :type path: str
        :param f: File object.
        :return: Dictionary of key-value pairs.
        :rtype: dict
        """
        file_content = f.read()
        key_val_pairs = file_content.split(b"\x00")
        results_null = {}
        results_lines = {}

        # print(f"Parsing potential nvram file {path}")
        # print(f"Found {len(key_val_pairs)} null terminators pairs vs {len(file_content.splitlines())} lines")

        for pair in key_val_pairs[:-1]:  # Exclude the last split as it might be empty
            try:
                key, val = pair.split(b"=", 1)
                # It's safe to set val as a stirng, even when it's an int
                if key.startswith(b"#"):
                    continue
                results_null[key] = val
            except ValueError:
                logger.warning(f"could not process default nvram file {path} for {pair}")
                continue

        # Second pass, if there are a lot of lines, let's try that way
        for line in file_content.split(b"\n"):
            if line.startswith(b"#"):
                continue
            if b"=" not in line:
                continue
            key, val = line.split(b"=", 1)
            results_lines[key] = val

        # Do we have more results in one than the other? Either should have at least 5 for us to have any confidence
        if len(results_null) > 5 and len(results_null) > len(results_lines):
            return results_null
        elif len(results_lines) > 5 and len(results_lines) > len(results_null):
            return results_lines
        else:
            return {}

    @staticmethod
    def nvram_config_analysis(fs_path: str, full_path: bool = True, index=None) -> dict[str, str]:
        # Nvram source 2: standard nvram paths with plaintext data
        # If we have a hit, we combine with any existing values
        # These are notionally sorted - if an earlier path provides a value, we won't clobber
        # but we will consume keys from all paths that we can find and parse
        # If full_path, we check the whole path, otherwise just the basename
        # Pass an InitContext.file_index to avoid re-walking in basename mode
        nvram_paths = [
            "./var/etc/nvram.default",
            "./etc/nvram.default",
            "./etc/nvram.conf",
            "./etc/nvram.deft",
            "./etc/nvram.update",
            "./etc/wlan/nvram_params",
            "./etc/system_nvram_defaults",
            "./image/mnt/nvram_ap.default",
            "./etc_ro/Wireless/RT2860AP/RT2860_default_vlan",
            "./etc_ro/Wireless/RT2860AP/RT2860_default_novlan",
            "./image/mnt/nvram_whp.default",
            "./image/mnt/nvram_rt.default",
            "./image/mnt/nvram_rpt.default",
            "./image/mnt/nvram.default",
        ]
        nvram_basenames = set([os.path.basename(x) for x in nvram_paths])

        path_nvrams = {}
        # XXX: Should we store the source filename somewhere? Maybe
        # move this to a static analysis that spits out more verbose data
        # and then only some turns into a config patch?
        if full_path:
            # Check the exact paths
            for path in nvram_paths:
                abs_path = os.path.join(fs_path, path.lstrip("/"))
                if os.path.exists(abs_path):
                    # Found a default nvram file, parse it
                    with open(abs_path, "rb") as f:
                        result = NvramHelper.parse_nvram_file(path, f)
                        # result is key -> value. We want to store path as well
                        for k, v in result.items():
                            path_nvrams[k.decode()] = v.decode()
        else:
            # Check every file to see if it has a matching basename
            if index is not None:
                candidates = ((e.path, e.name) for e in index.entries)
            else:
                candidates = (
                    (os.path.join(root, file), file)
                    for root, _, files in os.walk(fs_path)
                    for file in files
                )
            for abs_path, file in candidates:
                rel_path = "./" + os.path.relpath(abs_path, fs_path)

                if rel_path in nvram_paths:
                    # Exact match - we already checked this
                    continue

                if any(file == fname for fname in nvram_basenames):
                    # Found a matching basename, parse the file
                    with open(abs_path, "rb") as f:
                        result = NvramHelper.parse_nvram_file(rel_path, f)
                        for k, v in result.items():
                            path_nvrams[k.decode()] = v.decode()

        return path_nvrams


def make_shims(files, shim_targets: dict[str, str]) -> dict:
    """
    Identify binaries in the guest FS that we want to shim and add symlinks to
    go from guest bin -> igloo bin into our config.
    """
    result = defaultdict(dict)
    for fname in files:
        path = fname.path.lstrip('.')  # Trim leading .
        basename = os.path.basename(path)

        if path.startswith("/igloo/utils/"):
            raise ValueError(
                "Unexpected /igloo/utils present in input filesystem archive"
            )

        # It's a guest file/symlink. If it's one of our targets and executable, we want to shim!
        if not (fname.isfile() or fname.issym()) or not fname.mode & (
            stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
        ):
            # Skip if it's not a file or non-executable
            continue

        # Is the current file one we want to shim?
        if basename in shim_targets:
            logger.debug(f"making shim for {basename}, full path: {path}, fname.path: {fname.path}")
            result["static_files"][path] = {
                "type": "shim",
                "target": f"/igloo/utils/{shim_targets[basename]}",
            }
    return result
