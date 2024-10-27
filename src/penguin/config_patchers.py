import os
import re
import stat
import struct
import subprocess
import tarfile

import elftools
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from abc import ABC, abstractmethod
from collections import defaultdict
from pathlib import Path

from penguin import getColoredLogger
from .arch import arch_filter, arch_end
from .defaults import (
    default_init_script,
    default_lib_aliases,
    default_netdevs,
    default_plugins,
    expert_knowledge_pseudofiles,
    default_libinject_string_introspection,
    DEFAULT_KERNEL,
    default_version as DEFAULT_VERSION,
    static_dir as STATIC_DIR
)

logger = getColoredLogger("penguin.config_patchers")

class PatchGenerator(ABC):
    def __init__(self):
        self.enabled = True
        self.patch_name = None

    @abstractmethod
    def generate(self, patches):
        raise NotImplementedError("Subclasses should implement this method")


class TarHelper:
    '''
    Collection of static method to help find files in a tar archive
    '''
    @staticmethod
    def get_symlink_members(tarfile_path):
        with tarfile.open(tarfile_path, "r") as tar:
            # Trim leading . from path, everything is ./
            return {
                member.name[1:]: member.linkname
                for member in tar.getmembers()
                if member.issym()
            }

    @staticmethod
    def get_all_members(tarfile_path):
        with tarfile.open(tarfile_path, "r") as tar:
            # Trim leading . from path, everything is ./
            #return {member.name[1:] for member in tar.getmembers()}
            return tar.getmembers()

    # UNUSED
    @staticmethod
    def get_other_members(tarfile_path):
        # Get things that aren't files nor directories - devices, symlinnks, etc
        with tarfile.open(tarfile_path, "r") as tar:
            # Trim leading . from path, everything is ./
            return {
                member.name[1:]
                for member in tar.getmembers()
                if not member.isfile() and not member.isdir
            }

    # UNUSED
    @staticmethod
    def get_directory_members(tarfile_path):
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

    # UNUSED
    @staticmethod
    def get_file_members(tarfile_path):
        with tarfile.open(tarfile_path, "r") as tar:
            # Trim leading . from path, everything is ./
            return {member.name[1:] for member in tar.getmembers() if member.isfile()}


class FileHelper:
    @staticmethod
    def find_executables(tmp_dir, target_dirs=None):
        if not target_dirs:
            target_dirs = {"/"}
        for root, _, files in os.walk(tmp_dir):
            # Exclude the '/igloo' path
            if "/igloo" in root:
                continue

            for file in files:
                file_path = Path(root) / file
                # Check if the file is executable and in one of the target directories
                if (
                    file_path.is_file()
                    and os.access(file_path, os.X_OK)
                    and any(str(file_path).endswith(d) for d in target_dirs)
                ):
                    yield file_path

    @staticmethod
    def find_strings_in_file(file_path, pattern):
        result = subprocess.run(["strings", file_path], capture_output=True, text=True)
        return [line for line in result.stdout.splitlines() if re.search(pattern, line)]

    @staticmethod
    def find_shell_scripts(tmp_dir):
        for root, _, files in os.walk(tmp_dir):
            # Exclude the '/igloo' path
            if "/igloo" in root:
                continue

            for file in files:
                file_path = Path(root) / file
                # Check if the file is executable and in one of the target directories
                if (
                    file_path.is_file()
                    and os.access(file_path, os.X_OK)
                    and str(file_path).endswith(".sh")
                ):
                    yield file_path

    @staticmethod
    def exists(tmp_dir, target):
        """
        Check if the target exists within the extracted filesystem in tmp_dir,
        handling symlinks correctly.

        :param tmp_dir: The root of the extracted filesystem (e.g., /tmp/extracted)
        :param target: The target path to check (e.g., /foo/zoo)
        :return: True if the target exists within tmp_dir, False otherwise
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
    def _get_default_nvram_values():
        """
        Default nvram values from Firmadyne and FirmAE
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
    def parse_nvram_file(path, f):
        """
        There are a few formats we want to support. binary data like key=value\x00
        and text files with key=value\n
        Returns a dictionary of key-value pairs. Potentially empty.
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
    def nvram_config_analysis(fs_path, full_path=True):
        # Nvram source 2: standard nvram paths with plaintext data
        # If we have a hit, we combine with any existing values
        # These are notionally sorted - if an earlier path provides a value, we won't clobber
        # but we will consume keys from all paths that we can find and parse
        # If full_path, we check the whole path, otherwise just the basename
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
            for root, _, files in os.walk(fs_path):
                for file in files:
                    abs_path = os.path.join(root, file)
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




class BasePatch(PatchGenerator):
    '''
    Generate base config for static_files and default plugins
    '''
    UNKNOWN_INIT = "UNKNOWN_FIX_ME" # Could also use /igloo/utils/exit0.sh?

    def __init__(self, arch_info, inits):
        self.patch_name = "base"
        self.enabled = True

        self.set_arch_info(arch_info)

        if len(inits):
            self.igloo_init = inits[0]
        else:
            self.igloo_init = self.UNKNOWN_INIT
            logger.warning("Failed to find any init programs - config will need manual refinement")


    def set_arch_info(self, arch_identified):
        '''
        Our naming convention for architectures is a bit inconsistent. This function
        handles that by settings self.{arch_name,arch_suffix,dylib_dir}.
        '''

        # TODO: should we allow a config to be generated for an unsupported architecture?
        # For example, what if we're wrong and a user wants to customize this.
        arch, endian = arch_end(arch_identified)
        if arch is None:
            raise NotImplementedError(f"Architecture {arch_identified} not supported ({arch}, {endian})")

        if arch == "aarch64":
            # TODO: We should use a consistent name here. Perhaps aarch64eb?
            self.arch_name = "aarch64"
            self.arch_suffix = ".aarch64"
            self.dylib_dir = os.path.join(STATIC_DIR, "dylibs", "arm64")
            self.kernel_name = f"zImage.arm64"
        elif arch == "intel64":
            self.arch_name = "intel64"
            self.arch_suffix = ".x86_64"
            self.dylib_dir = os.path.join(STATIC_DIR, "dylibs", "x86_64")
            self.kernel_name = f"bzImage.x86_64"
        else:
            self.arch_name = arch + endian
            self.arch_suffix = f".{arch}{endian}"
            self.dylib_dir = os.path.join(STATIC_DIR, "dylibs", arch + endian)
            if arch == "arm":
                self.kernel_name = f"zImage.{arch}{endian}"
            else:
                self.kernel_name = f"vmlinux.{arch}{endian}"

    def get_kernel_path(self):
        return os.path.join(*[STATIC_DIR, "kernels", DEFAULT_KERNEL, self.kernel_name])

    def generate(self, patches):
        resources = os.path.join(os.path.dirname(os.path.dirname(__file__)), "resources")

        result = {
            "core": {
                "arch": self.arch_name,
                "kernel": self.get_kernel_path(),
            },
            "env": {
                "igloo_init": self.igloo_init,
            },
            "pseudofiles": {
                # Ensure guest can't interfere with our 2nd serial console - make it a null device
                "/dev/ttyS1": {
                    "read": {
                        "model": "zero",
                    },
                    "write": {
                        "model": "discard",
                    },
                    "ioctl": {
                        "*": {
                            "model": "return_const",
                            "val": 0,
                        }
                    }
                },
                "/dev/ttyAMA1": {
                    "read": {
                        "model": "zero",
                    },
                    "write": {
                        "model": "discard",
                    },
                    "ioctl": {
                        "*": {
                            "model": "return_const",
                            "val": 0,
                        }
                    }
                }
            },
            "static_files": {
                "/igloo": {
                    "type": "dir",
                    "mode": 0o755,
                },
                "/igloo/init": {
                    "type": "inline_file",
                    "contents": default_init_script,
                    "mode": 0o111,
                },
                "/igloo/utils/sh": {
                    "type": "symlink",
                    "target": "/igloo/utils/busybox",
                },
                "/igloo/utils/sleep": {
                    "type": "symlink",
                    "target": "/igloo/utils/busybox",
                },
                # Add ltrace prototype files. They go in /igloo/ltrace because /igloo is treated as ltrace's /usr/share, and the files are normally in /usr/share/ltrace.
                "/igloo/ltrace/*": {
                    "type": "host_file",
                    "mode": 0o444,
                    "host_path": os.path.join(*[STATIC_DIR, "ltrace", "*"]),
                },

                # Dynamic libraries
                "/igloo/dylibs/*": {
                    "type": "host_file",
                    "mode": 0o755,
                    "host_path": os.path.join(self.dylib_dir, "*"),
                },

                "/igloo/utils": {
                    "type": "dir",
                    "mode": 0o755,
                },

                # Add serial device in pseudofiles
                # XXX: For mips we use major 4, minor 65. For arm we use major 204, minor 65.
                # This is because arm uses ttyAMA (major 204) and mips uses ttyS (major 4).
                "/igloo/serial": {
                    "type": "dev",
                    "devtype": "char",
                    "major": 4 if 'mips' in self.arch_name else 204,
                    "minor": 65,
                    "mode": 0o666,
                }
            },
            "plugins": default_plugins,
        }

        # Always add our utilities into static files. Note that we can't currently use
        # a full directory copy since we're doing some renaming.
        # TODO: Refactor utility paths in container so we can just copy the whole directory
        # for a given architecture.
        for util_dir in ["console", "libnvram", "utils.bin", "utils.source", "vpn"]:
            for f in os.listdir(os.path.join(STATIC_DIR, util_dir)):
                if f.endswith(self.arch_suffix) or f.endswith(".all"):
                    out_name = f.replace(self.arch_suffix, "").replace(".all", "")
                    result["static_files"][f"/igloo/utils/{out_name}"] = {
                        "type": "host_file",
                        "host_path": f"/igloo_static/{util_dir}/{f}",
                        "mode": 0o755,
                    }
        return result

class AutoExplorePatch(PatchGenerator):
    '''
    Auto explore: no root_shell, yes nmap, yes coverage
    '''
    def __init__(self):
        self.patch_name = "auto_explore"
        self.enabled = True

    def generate(self, patches):
        return {
            "core": {
                "root_shell": False,
            },
            "plugins": {
                "nmap": {
                    "enabled": True,
                    "depends_on": "vpn",
                },
                "coverage": {
                    "enabled": True
                }
            }
        }

class NetdevsDefault(PatchGenerator):
    '''
    Add list of default network device names
    '''
    def __init__(self):
        self.enabled = True
        self.patch_name = "netdevs.default"

    def generate(self, patches):
        return { 'netdevs': default_netdevs }

class NetdevsTailored(PatchGenerator):
    '''
    Add list of network device names observed in static analysis
    '''
    def __init__(self, netdevs):
        self.enabled = True
        self.patch_name = "netdevs.dynamic"
        self.netdevs = netdevs

    def generate(self, patches):
        values = set()
        if not self.netdevs:
            return
        for src, devs in self.netdevs.items():
            values.update(devs)
        if len(values):
            return { 'netdevs': sorted(list(values)) }


class PseudofilesExpert(PatchGenerator):
    '''
    Fixed set of pseudofile models from FirmAE
    '''
    def __init__(self):
        self.enabled = True
        self.patch_name = "pseudofiles.expert_knowledge"

    def generate(self, patches):
        return { 'pseudofiles': expert_knowledge_pseudofiles }


class LibInjectSymlinks(PatchGenerator):
    '''
    Detect the ABI of all libc.so files and place a symlink in the same
    directory to lib_inject of the same ABI
    '''
    def __init__(self, filesystem_root_path):
        self.enabled = True
        self.patch_name = 'lib_inject.core'
        self.filesystem_root_path = filesystem_root_path


    def generate(self, patches):
        libc_paths = []
        result = defaultdict(dict)

        # Walk through the filesystem root to find all "libc.so" files
        for root, dirs, files in os.walk(self.filesystem_root_path):
            for filename in files:
                if filename.startswith("libc.so"):
                    libc_paths.append(Path(os.path.join(root, filename)))

        # Iterate over the found libc.so files to generate symlinks based on ABI
        for p in libc_paths:
            with open(p, 'rb') as file:
                try:
                        e = ELFFile(file)
                except ELFError:
                    # Not an ELF. It could be, for example, a GNU ld script.
                    continue

                # Assume `arch_filter` is a function that extracts the ABI from an ELF file.
                abi = arch_filter(e).abi

            # Ensure dest starts with a /
            dest = Path("/") / \
                p.relative_to(self.filesystem_root_path).parent / \
                "lib_inject.so"

            result["static_files"][str(dest)] = {
                "type": "symlink",
                "target": f"/igloo/lib_inject_{abi}.so",
            }

        if len(result.get("static_files", [])):
            # LD_PRELOAD if we set any symlinks
            result["env"] = {"LD_PRELOAD": "lib_inject.so"}

        return result

class LibInjectStringIntrospection(PatchGenerator):
    '''
    Add LibInject aliases for string introspection (e.g., for comparison detection).
    For each method we see in the filesystem that's in our list of shim targets, add the shim
    '''
    def __init__(self, library_info):
        self.enabled = True
        self.patch_name = 'lib_inject.string_introspection'
        self.library_info = library_info

    def generate(self, patches):
        aliases = {}
        for _, exported_syms in self.library_info.get("symbols", {}).items():
            for sym in exported_syms:
                if sym in default_libinject_string_introspection:
                    aliases[sym] = default_libinject_string_introspection[sym]

        return {'lib_inject': {'aliases': aliases}}

class LibInjectTailoredAliases(PatchGenerator):
    '''
    Set default aliases in libinject based on library analysis. If one of the defaults
    is present in a library, we'll add it to the libinject alias list
    '''
    def __init__(self, library_info):
        self.enabled = True
        self.patch_name = 'lib_inject.dynamic_models'
        self.library_info = library_info
        self.unmodeled = set()

    def generate(self, patches):
        aliases = {}


        # Only copy values from our defaults if we see that same symbol exported
        for _, exported_syms in self.library_info.get("symbols", {}).items():
            for sym in exported_syms:
                if sym in default_lib_aliases:
                    aliases[sym] = default_lib_aliases[sym]
                elif "nvram" in sym and sym not in self.unmodeled:
                    self.unmodeled.add(sym)

        if len(self.unmodeled):
            logger.info(f"Detected {len(self.unmodeled)} unmodeled symbols around nvram. You may wish to create libinject models for these:")
            for sym in self.unmodeled:
                logger.info(f"\t{sym}")

        if len(aliases):
            return {'lib_inject': {'aliases': aliases}}

class LibInjectFixedAliases(PatchGenerator):
    '''
    Set all aliases in libinject from our defaults
    '''
    def __init__(self):
        self.enabled = False
        self.patch_name = 'lib_inject.fixed_models'

    def generate(self, patches):
        return {'lib_inject': {'aliases': default_lib_aliases}}

"""
class LibInjectJITAliases(PatchGenerator):
    '''
    For nvram methods that we don't have shims for, try throwing some defaults
    based on symbol names. This is probably going to break things but could be interesting
    '''
    def __init__(self, library_info):
        self.enabled = True
        self.patch_name = 'lib_inject.jit_models'
        self.library_info = library_info
        self.unmodeled = set()

    def generate(self, patches):
        aliases = {}

        # Only copy values from our defaults if we see that same symbol exported
        for _, exported_syms in self.library_info.get("symbols", {}).items():
            for sym in exported_syms:
                if "nvram" in sym and sym not in default_lib_aliases:
                    if "_get" in sym:
                        target = "libinject_nvram_get"
                    elif "_set" in sym:
                        target = "libinject_nvram_get"
                    else:
                        target = "libinject_ret_0"
                    aliases[sym] = target
                    logger.info(f"\tJIT mapping {sym} -> {target}")

        if len(aliases):
            return {'lib_inject': {'aliases': aliases}}
"""

class ForceWWW(PatchGenerator):
    '''
    This is a hacky FirmAE approach to identify webservers and just start
    them. Unsurprisingly, it increases the rate of web servers starting.
    We'll export this into our static files section so we could later decide
    to try it. We'll enable this by default here.
    '''

    def __init__(self, fs_path):
        self.enabled = True
        self.patch_name = 'force_www'
        self.fs_path = fs_path

    def generate(self, patches):
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

class GenerateMissingDirs(PatchGenerator):
    '''
    Examine the fs *archive* to identify missing directories
    We ignore the extracted filesystem because we want to
    ensure symlinks are handled correctly
    '''
    TARGET_DIRECTORIES = [
        "/proc",
        "/etc_ro",
        "/tmp",
        "/var",
        "/run",
        "/sys",
        "/root",
        "/tmp/var",
        "/tmp/media",
        "/tmp/etc",
        "/tmp/var/run",
        "/tmp/home",
        "/tmp/home/root",
        "/tmp/mnt",
        "/tmp/opt",
        "/tmp/www",
        "/var/run",
        "/var/lock",
        "/usr/bin",
        "/usr/sbin",
    ]


    def __init__(self, archive_path, archive_files):
        self.patch_name = "static.missing_dirs"
        self.enabled = True
        self.archive_path = archive_path
        self.archive_files = {member.name[1:] for member in archive_files}

    @staticmethod
    def _resolve_path(d, symlinks, depth=0):
        parts = d.split("/")
        for i in range(len(parts), 1, -1):
            sub_path = "/".join(parts[:i])
            if sub_path in symlinks:
                if depth > 10 or d == symlinks[sub_path]:
                    logger.warning(f"Symlink loop detected for {d}")
                    return d
                return GenerateMissingDirs._resolve_path(
                    d.replace(sub_path, symlinks[sub_path], 1), symlinks, depth=depth+1
                )
        if not d.startswith("/"):
            d = "/" + d

        if d in symlinks:
            # We resolved a symlink to another symlink, need to recurse
            # XXX: What if our resolved path contains a symlink earlier in the path TODO
            if depth > 10 or d == symlinks[d]:
                logger.warning(f"Symlink loop detected for {d}")
                return d
            else:
                # Recurse
                return GenerateMissingDirs._resolve_path(symlinks[d], symlinks, depth=depth+1)

        return d

    def generate(self, patches):
        # XXX: Do we want to operate on archives to ensure symlinks behave as expected?
        symlinks = TarHelper.get_symlink_members(self.archive_path)
        result = defaultdict(dict)

        for d in self.TARGET_DIRECTORIES:
            # It's not already in there, add it as a world-readable directory
            # Handle symlinks. If we have a directory like /tmp/var and /tmp is a symlink to /asdf, we want to make /asdf/var

            resolved_path = self._resolve_path(d, symlinks)
            # Try handling ../s by resolving the path
            if ".." in resolved_path.split("/"):
                resolved_path = os.path.normpath(resolved_path)

            if ".." in resolved_path.split("/"):
                logger.debug("Skipping directory with .. in path: " + resolved_path)
                continue

            while resolved_path.endswith("/"):
                resolved_path = resolved_path[:-1]

            # Check if this directory looks like / - it might be ./ or something else
            if resolved_path == ".":
                continue

            # Guestfs gets mad if there's a /. in the path
            if resolved_path.endswith("/."):
                resolved_path = resolved_path[:-2]

            # Look at each parent directory, is it a symlink?
            for i in range(1, len(resolved_path.split("/"))):
                parent = "/".join(resolved_path.split("/")[:i])
                if parent in symlinks:
                    logger.debug(
                        f"Skipping {resolved_path} because parent {parent} is a symlink"
                    )
                    continue

            while "/./" in resolved_path:
                resolved_path = resolved_path.replace("/./", "/")

            # If this path is in the archive OR any existing patches, skip
            # Note we're ignoring the enabled flag of patches
            if resolved_path in self.archive_files or any([resolved_path in \
                    p[0].get('static_files', {}).keys() for p in patches.values()]):
                continue

            # Add path and parents (as necessary)
            path_parts = resolved_path.split("/")
            for i in range(1, len(path_parts) + 1):
                subdir = "/".join(path_parts[:i])
                if subdir not in self.archive_files:
                    result['static_files'][subdir] = {
                        "type": "dir",
                        "mode": 0o755,
                    }
        return result

class GenerateReferencedDirs(PatchGenerator):
    '''
    FirmAE "Boot mitigation": find path strings in binaries, make their directories
    if they don't already exist.
    '''
    def __init__(self, extract_dir):
        self.patch_name = "static.binary_paths"
        self.enabled = True
        self.extract_dir = extract_dir

    def generate(self, patches):
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

class GenerateShellMounts(PatchGenerator):
    """
    Ensure we have /mnt/* directories referenced by shell scripts
    """
    def __init__(self, extract_dir, existing):
        self.patch_name = "static.shell_script_mounts"
        self.extract_dir = extract_dir
        self.enabled = True
        self.existing = {member.name[1:] for member in existing}

    def generate(self, patches):
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
                if dest in self.existing or any([dest in \
                        p[0].get('static_files', {}).keys() for p in patches.values()]):
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

class GenerateMissingFiles(PatchGenerator):
    '''
    Ensure we have /bin/sh, /etc/TZ, /var/run/libnvram.pid.
    Ensure /etc/hosts has an entry for localhost
    '''
    def __init__(self, extract_dir):
        self.patch_name = "static.missing_files"
        self.enabled = True
        self.extract_dir = extract_dir

    def generate(self, patches):
        # Firmadyne/FirmAE mitigation, ensure these 3 files always exist
        # Note including /bin/sh here means we'll add it if it's missing and as a symlink to /igloo/utils/busybox
        # this is similar to how we can shim an (existing) /bin/sh to point to /igloo/utils/busybox but here we
        # only add it if it's missing
        result = defaultdict(dict)

        model = {
            "/bin/sh": {"type": "symlink",
                        "target": "/igloo/utils/busybox"
            },
            "/etc/TZ": {
                "type": "inline_file",
                "contents": "EST5EDT",
                "mode": 0o755,
            },
            "/var/run/libnvram.pid": {
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

class DeleteFiles(PatchGenerator):
    '''
    Delete some files we don't want
    '''

    def __init__(self, extract_dir):
        self.patch_name = "static.delete_files"
        self.enabled = True
        self.extract_dir = extract_dir

    def generate(self, patches):
        result = defaultdict(dict)
        # Delete some files that we don't want. securetty is general, limits shell access.
        # 'sys_resetbutton' is some FW-specific hack from FirmAE

        # TODO: does securetty matter if our root shell is disabled?
        for f in ["/etc/securetty", "/etc/scripts/sys_resetbutton"]:
            if os.path.isfile(os.path.join(self.extract_dir, f[1:])):
                result["static_files"][f] = {
                    "type": "delete",
                }
        return result

class LinksysHack(PatchGenerator):
    '''
    Linksys specific hack from firmae with pseudofile model
    '''
    def __init__(self, extract_dir):
        self.patch_name = "pseudofiles.linksys"
        self.enabled = True
        self.extract_dir = extract_dir

    def generate(self, patches):
        result = defaultdict(dict)
        # TODO: The following changes from FirmAE should likely be disabled by default
        # as we can't consider this information as part of our search if it's in the initial config
        # Linksys specific hack from firmae
        if all(
            os.path.isfile(os.path.join(self.extract_dir, x[1:]))
            for x in ["/bin/gpio", "/usr/lib/libcm.so", "/usr/lib/libshared.so"]
        ):
            result["pseudofiles"]["/dev/gpio/in"] = {
                "read": {
                    "model": "return_const",
                    "val": 0xFFFFFFFF,
                }
            }

        return result

class KernelModules(PatchGenerator):
    """
    Create a symlink from the guest kernel module path to our kernel's module path (ie.., /lib/modules/1.2.0-custom -> /lib/modules/4.10.0)
    """
    def __init__(self, extract_dir):
        self.patch_name = "static.kernel_modules"
        self.enabled = True
        self.extract_dir = extract_dir

    @staticmethod
    def is_kernel_version(name):
        # Regex to match typical kernel version patterns
        return re.match(r"^\d+\.\d+\.\d+(-[\w\.]+)?$", name) is not None

    def generate(self, patches):
        result = defaultdict(dict)

        # Identify original kernel version and create a symlink to /lib/modules
        kernel_version = None
        potential_kernels = set()

        # Only look at the top-level directories in self.extract_dir / lib / modules
        modules_path = os.path.join(self.extract_dir, "lib/modules")
        if os.path.exists(modules_path):
            for d in os.listdir(modules_path):
                d_path = os.path.join(modules_path, d)
                if os.path.isdir(d_path):
                    potential_kernels.add(d)

        # Filter potential kernels to match the expected version pattern
        potential_kernels = {d for d in potential_kernels if self.is_kernel_version(d)}

        # Determine the kernel version to use
        if len(potential_kernels) == 1:
            kernel_version = potential_kernels.pop()
        elif len(potential_kernels) > 1:
            # Prioritize the version names that match more complex patterns with dashes
            for potential_name in potential_kernels:
                if "." in potential_name and "-" in potential_name:
                    kernel_version = potential_name
                    break
            if not kernel_version:
                # Fallback to a simpler version matching pattern
                for potential_name in potential_kernels:
                    if "." in potential_name:
                        kernel_version = potential_name
                        break

            # Fallback to picking the first one (could improve this further)
            if not kernel_version:
                logger.warning(
                    "Multiple kernel versions look valid (TODO improve selection logic, grabbing first)"
                )
                logger.warning(potential_kernels)
                kernel_version = potential_kernels.pop()

        if kernel_version:
            # We have a kernel version, add it to our config
            result["static_files"][f"/lib/modules/{DEFAULT_KERNEL}.0"] = {
                "type": "symlink",
                "target": f"/lib/modules/{kernel_version}",
            }

        return result

class ShimBinaries:
    '''
    Identify binaries in the guest FS that we want to shim
    and add symlinks to go from guest bin -> igloo bin
    into our config.
    '''
    def __init__(self, files):
        self.files = files

    def make_shims(self, shim_targets):
        result = defaultdict(dict)
        for fname in self.files:
            path = fname.path[1:]  # Trim leading .
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
                result["static_files"][path] = {
                        "type": "shim",
                        "target": f"/igloo/utils/{shim_targets[basename]}",
                }
        return {'static_files': result}

class ShimStopBins(ShimBinaries,PatchGenerator):
    def __init__(self, files):
        super().__init__(files)
        self.patch_name = "static.shims.stop_bins"
        self.enabled = True

    def generate(self, patches):
        result = defaultdict(dict)
        return self.make_shims({
            "reboot": "exit0.sh",
            "halt": "exit0.sh",
        })

class ShimNoModules(ShimBinaries,PatchGenerator):
    def __init__(self, files):
        super().__init__(files)
        self.patch_name = "static.shims.no_modules"
        self.enabled = True

    def generate(self, patches):
        return self.make_shims({
            "insmod": "exit0.sh"
        })

class ShimBusybox(ShimBinaries,PatchGenerator):
    def __init__(self, files):
        super().__init__(files)
        self.patch_name = "static.shims.busybox"
        self.enabled = True

    def generate(self, patches):
        return self.make_shims({
            "ash": "busybox",
            "sh": "busybox",
            "bash": "bash",
        })

class ShimCrypto(ShimBinaries,PatchGenerator):
    def __init__(self, files):
        super().__init__(files)
        self.patch_name = "static.shims.crypto"
        self.enabled = False

    def generate(self, patches):
        resources = os.path.join(os.path.dirname(os.path.dirname(__file__)), "resources")

        result =  self.make_shims({
            "openssl": "openssl",
            "ssh-keygen": "ssh-keygen"
        })

        if not len(result.get("static_files", [])):
            # Nothing to shim, don't add the key copy
            return

        result["static_files"]["/igloo/keys/*"] = {
                "type": "host_file",
                "mode": 0o444,
                "host_path": os.path.join(*[resources, "static_keys", "*"])
        }

        return result

class ShimFwEnv(ShimBinaries,PatchGenerator):
    '''
    Replace fw_printenv/getenv/setenv with hypercall based alternatives
    Work in progress. Needs testing
    '''
    def __init__(self, files):
        raise NotImplementedError("Untested shim type")
        super().__init__(files)
        self.patch_name = "static.shims.fw_env"

    def generate(self, patches):
        return self.make_shims({
            "fw_printenv": "fw_printenv",
            "fw_getenv": "fw_printenv",
            "fw_setenv": "fw_printenv",
        })


class NvramLibraryRecovery(PatchGenerator):
    '''
    During static analysis the LibrarySymbols class collected
    key->value mappings from libraries exporting some common nvram
    defaults symbols ("Nvrams", "router_defaults") - add these to our
    nvram config if we have any.

    TODO: if we find multiple nvram source files here, we should generate multiple patches.
    Then we should consider these during search. For now we just take non-conflicting values
    from largest to smallest source files. More realistic might be to try each file individually.
    '''
    def __init__(self, library_info):
        self.library_info = library_info
        self.patch_name = "nvram.01_library"
        self.enabled = True

    def generate(self, patches):
        sources = self.library_info.get("nvram", {})
        if not len(sources):
            return

        # Sources is source filename -> key -> value
        # First we want to sort sources from most to least keys
        sorted_sources = sorted(sources.items(), key=lambda x: len(x[1]), reverse=True)

        nvram_defaults = {}
        for source, nvram in sorted_sources:
            for key, value in nvram.items():
                if key not in nvram_defaults:
                    nvram_defaults[key] = value

        if len(nvram_defaults):
            return {'nvram': nvram_defaults}

class NvramConfigRecovery(PatchGenerator):
    """
    Search for files that contain nvram keys and values to populate NVRAM defaults
    """
    def __init__(self, extract_dir):
        self.extract_dir = extract_dir
        self.patch_name = "nvram.02_config_paths"
        self.enabled = True

    def generate(self, patches):
        result = NvramHelper.nvram_config_analysis(self.extract_dir, True)
        if len(result):
            return { 'nvram': result }


class NvramConfigRecoveryWild(PatchGenerator):
    """
    Search for files that contain nvram keys and values to populate NVRAM defaults.
    This version relaxes the search to allow for basename matches instead of full path
    matches.
    """
    def __init__(self, extract_dir):
        self.extract_dir = extract_dir
        self.patch_name = "nvram.03_config_paths_basename"
        self.enabled = True

    def generate(self, patches):
        result = NvramHelper.nvram_config_analysis(self.extract_dir, False)
        if len(result):
            return { 'nvram': result }


class NvramDefaults(PatchGenerator):
    """
    Add default nvram values from Firmadyne and FirmAE
    """
    def __init__(self):
        self.patch_name = "nvram.04_defaults"
        self.enabled = True

    def generate(self, patches):
        result = NvramHelper._get_default_nvram_values()
        if len(result):
            return { 'nvram': result }

class NvramFirmAEFileSpecific(PatchGenerator):
    """
    Apply FW-specific nvram patches based on presence of hardcoded strings in files
    from FirmAE
    """
    FIRMAE_TARGETS = {  # filename -> (query, value to set if key is present)
        "./sbin/rc": [("ipv6_6to4_lan_ip", "2002:7f00:0001::")],
        "./lib/libacos_shared.so": [("time_zone_x", "0")],
        "./sbin/acos_service": [("rip_enable", "0")],
        "./usr/sbin/httpd": [
            ("rip_multicast", "0"),
            ("bs_trustedip_enable", "0"),
            ("filter_rule_tbl", ""),
        ],
    }
    def __init__(self, fs_path):
        self.fs_path = fs_path
        self.patch_name = "nvram.05_firmae_file_specific"

    def generate(self, patches):
        result = {}

        # For each key in static_targets, check if the query is in the file
        # TODO: Should we be operating on an archive to better handle symlinks?
        for key, queries in self.FIRMAE_TARGETS.items():
            if not os.path.isfile(os.path.join(self.fs_path, key[1:])):
                continue

            try:
                with open(os.path.join(self.fs_path, key[1:]), "rb") as f:
                    for query, _ in queries:
                        # Check if query is in file
                        if query.encode() in f.read():
                            result[key] = query
            except Exception as e:
                # Not sure what kind of errors we could encounter here, missing files? perms?
                logger.error(f"Failed to read {key} for nvram key check: {e}")

        if len(result):
            return { 'nvram': result }

class PseudofilesTailored(PatchGenerator):
    '''
    For all missing pseudofiles we saw referenced during static analysis,
    try adding them with a default model
    '''

    def __init__(self, pseudofiles):
        self.patch_name = "pseudofiles.dynamic"
        self.pseudofiles = pseudofiles
        self.enabled = True

    def generate(self, patches):
        results = {}
        mtd_count = 0

        for section, file_names in self.pseudofiles.items():
            for file_name in file_names:
                if section == 'dev' and file_name.startswith("/dev/mtd"):
                    # TODO: do we want to make placeholders for MTD or not?
                    continue

                if file_name.endswith("/"):
                    # We don't want to treat a directory as a pseudofile, instead we'll
                    # add a placehodler into the directory. This ensures the directory is created
                    # XXX: hyperfs doesn't allow userspace to create files in these directories yet
                    # https://github.com/rehosting/hyperfs/issues/20
                    file_name += ".placeholder"
                results[file_name] = {
                    'read': {
                        "model": "zero",
                    },
                    'write': {
                        "model": "discard",
                    }
                }

                if section == "dev":
                    # /dev files get a default IOCTL model
                    results[file_name]['ioctl'] = {
                        '*': { "model": "return_const", "val": 0 }
                    }

                    if file_name.startswith("/dev/mtd"):
                        # MTD devices get a name (shows up in /proc/mtd)
                        # Note 'uboot' probably isn't right, but we need something
                        results[file_name]['name'] = f"uboot.{mtd_count}"
                        mtd_count += 1

        if len(results):
            return {'pseudofiles': results}
