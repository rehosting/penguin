import csv
import os
import re
import stat
import struct
import subprocess
import tarfile
import tempfile
from copy import deepcopy
from pathlib import Path

import elftools
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile

from penguin import getColoredLogger

from .arch import arch_filter
from .common import yaml

IGLOO_KERNEL_VERSION = "4.10.0"

"""
Given a config with a filesystem .tar, analyze
the filesystem and populate metadata fields
    - potential_init: list of potential init scripts
    - potential_dev: list of potential device files
    - potential_env: dict of potential environment variables (keys = None or list of values)
    - potential_proc: list of potential /proc/ files
"""

logger = getColoredLogger("penguin.static")


def _find_in_fs(target_regex, tar_path, only_files=True):
    """
    Given a regex pattern to match against, search the filesystem
    and track matches + counts.
    Returns a dict of {match: {count: int, files: [str]}
    """
    results = {}

    boring_vars = ["TERM"]

    # Open tar archive
    with tarfile.open(tar_path, "r") as tar:
        # Iterate through each file in the tar archive
        for member in tar.getmembers():
            # Skip our files
            if member.path.startswith("./igloo"):
                continue

            # Skip directories and non-regular files
            if only_files and not member.isfile():
                continue

            # Open file
            f = tar.extractfile(member)
            if f is None:
                continue

            # Read content and convert to string
            content = f.read().decode("utf-8", "replace")

            # Apply regex pattern
            matches = target_regex.findall(content)
            for match in matches:
                if match in boring_vars:
                    continue

                if match not in results:
                    results[match] = {"count": 0, "files": []}
                results[match]["count"] += 1
                results[match]["files"].append(member.name)
    return results


def _get_devfiles_in_fs(tar_path):
    """
    Get a list of all device files in the filesystem
    """
    results = set()

    # Open tar archive
    with tarfile.open(tar_path, "r") as tar:
        # Iterate through each file in the tar archive
        for member in tar.getmembers():
            if not member.path.startswith("./dev/"):
                continue
            results.add(member.path[1:])
    return results


def get_directories_from_tar(tarfile_path):
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


def get_files_from_tar(tarfile_path):
    with tarfile.open(tarfile_path, "r") as tar:
        # Trim leading . from path, everything is ./
        return {member.name[1:] for member in tar.getmembers() if member.isfile()}


def get_other_from_tar(tarfile_path):
    # Get things that aren't files nor directories - devices, symlinnks, etc
    with tarfile.open(tarfile_path, "r") as tar:
        # Trim leading . from path, everything is ./
        return {
            member.name[1:]
            for member in tar.getmembers()
            if not member.isfile() and not member.isdir
        }


def get_all_from_tar(tarfile_path):
    with tarfile.open(tarfile_path, "r") as tar:
        # Trim leading . from path, everything is ./
        return {member.name[1:] for member in tar.getmembers()}


def get_symlinks_from_tar(tarfile_path):
    with tarfile.open(tarfile_path, "r") as tar:
        # Trim leading . from path, everything is ./
        return {
            member.name[1:]: member.linkname
            for member in tar.getmembers()
            if member.issym()
        }


def find_strings_in_file(file_path, pattern):
    result = subprocess.run(["strings", file_path], capture_output=True, text=True)
    # return [line for line in result.stdout.splitlines() if pattern in line]
    # Pattern is a regex
    return [line for line in result.stdout.splitlines() if re.search(pattern, line)]


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


def pre_shim(proj_dir, config, settings):
    """
    General static analysis for configuration updates. Make directories we think are missing, add standard files.
    """
    fs_path = os.path.join(proj_dir, config["core"]["fs"])  # tar archive

    # Add /firmadyne/ttyS1 for console - we could pick a different major/minor number later to ensure the guest
    # can't stomp on us. Or we could patch console to use a different path (i.e., something sane in /dev)

    # XXX: For mips we use major 4, minor 65. For arm we use major 204, minor 65.
    # This is because arm uses ttyAMA (major 204) and mips uses ttyS (major 4).
    # so calling it ttyS1 is a bit of a misnomer, but we don't want to go patch the console
    # binary to use a different path.
    config["static_files"]["/igloo/serial"] = {
        "type": "dev",
        "devtype": "char",
        "major": 4 if "mips" in config["core"]["arch"] else 204,
        "minor": 65,
        "mode": 0o666,
    }

    # XXX: We don't want this - if we add it it will rm -rf igloo directory to create it, which is bad
    # config['static_files']['igloo'] = {
    #    'type': 'dir',
    #    'mode': 0o755,
    # }

    # Directories we want to make sure exist in the FS. This list is based on firmadyne and firmae. Added /dev explicitly because we need
    # it for devtmpfs (e.g., devtmpfs could try mounting before /igloo/init runs and makes the directory)
    if settings.get("default_directories", {"enabled": True}).get("enabled", True):
        # Unless configured otherwise, we want to add these directories
        directories = [
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
    else:
        directories = []

    # If user wants to add other directories, include them.
    if settings.get("default_directories", {}).get("user_directories"):
        directories.extend(settings["default_directories"]["user_directories"])

    existing = get_all_from_tar(fs_path)
    symlinks = get_symlinks_from_tar(fs_path)

    def resolve_path(d, symlinks, depth=0):
        parts = d.split("/")
        for i in range(len(parts), 1, -1):
            sub_path = "/".join(parts[:i])
            if sub_path in symlinks:
                return resolve_path(
                    d.replace(sub_path, symlinks[sub_path], 1), symlinks
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
                return resolve_path(symlinks[d], symlinks, depth=depth + 1)

        return d

    for d in directories:
        # It's not already in there, add it as a world-readable directory
        # Handle symlinks. If we have a directory like /tmp/var and /tmp is a symlink to /asdf, we want to make /asdf/var

        resolved_path = resolve_path(d, symlinks)
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

        if resolved_path in existing or resolved_path in config["static_files"]:
            continue

        while "/./" in resolved_path:
            resolved_path = resolved_path.replace("/./", "/")

        path_parts = resolved_path.split("/")
        for i in range(1, len(path_parts) + 1):
            subdir = "/".join(path_parts[:i])
            if subdir not in existing:
                config["static_files"][subdir] = {
                    "type": "dir",
                    "mode": 0o755,
                }

    # Temporary directory for tar file extraction
    with tempfile.TemporaryDirectory() as tmp_dir:
        with tarfile.open(fs_path, "r") as tar:
            for member in tar.getmembers():
                # Don't actually create devices- we don't always have permission to create these!
                if member.isdev():
                    # Make a placeholder file (so we know it exists)
                    open(os.path.join(tmp_dir, member.name), "w").close()
                else:
                    try:
                        tar.extract(member, tmp_dir)
                    except PermissionError:
                        # XXX We can't look at this file. Whelp. Don't die
                        continue

        # Disable adding directories that are referenced in binaries if applicable.
        if settings.get("add_binary_directories"):
            # FIRMAE_BOOT mitigation: find path strings in binaries, make their directories if they don't already exist
            for f in find_executables(
                tmp_dir, {"/bin", "/sbin", "/usr/bin", "/usr/sbin"}
            ):
                # For things that look like binaries, find unique strings that look like paths
                for dest in list(
                    set(find_strings_in_file(f, "^(/var|/etc|/tmp)(.+)([^\\/]+)$"))
                ):
                    if any([x in dest for x in ["%s", "%c", "%d", "/tmp/services"]]):
                        # Ignore these paths, printf format strings aren't real directories to create
                        # Not sure what /tmp/services is or where we got that from?
                        continue

                    config["static_files"][dest] = {"type": "dir", "mode": 0o755}

        # CUSTOM mitigation: Try adding referenced mount points
        if settings.get("add_mnt_paths"):
            for f in find_shell_scripts(tmp_dir):
                for dest in list(
                    set(find_strings_in_file(f, "^/mnt/[a-zA-Z0-9._/]+$"))
                ):
                    if dest in existing:
                        continue
                    config["static_files"][dest] = {"type": "dir", "mode": 0o755}

        for fname in settings.get("always_add", []):
            # Three special files we can add - /etc/TZ, /bin/sh, and /var/run/libnvram.pid.
            # Note including /bin/sh here means we'll add it if it's missing and as a symlink to /igloo/utils/busybox
            # this is similar to how we can shim an (existing) /bin/sh to point to /igloo/utils/busybox but here we
            # only add it if it's missing
            model = {
                "/etc/TZ": {
                    "type": "inline_file",
                    "contents": "EST5EDT",
                    "mode": 0o755,
                },
                "/bin/sh": {"type": "symlink", "target": "/igloo/utils/busybox"},
                "/var/run/libnvram.pid": {
                    "type": "inline_file",
                    "contents": "",
                    "mode": 0o644,
                },
            }

            if not os.path.isfile(os.path.join(tmp_dir, fname[1:])):
                # File is missing - add it
                config["static_files"][fname] = model[fname]

        # Ensure we have an entry for localhost in /etc/hosts. So long as we have an /etc/ directory
        if settings.get("localhost_in_hosts"):
            hosts = ""
            if os.path.isdir(tmp_dir + "/etc"):
                if os.path.isfile(tmp_dir + "/etc/hosts"):
                    with open(tmp_dir + "/etc/hosts", "r") as f:
                        hosts = f.read()

            # if '127.0.0.1 localhost' not in hosts:
            # Regex with whitespace and newlines
            if not re.search(r"^127\.0\.0\.1\s+localhost\s*$", hosts, re.MULTILINE):
                if len(hosts) and not hosts.endswith("\n"):
                    hosts += "\n"
                hosts += "127.0.0.1 localhost\n"
                config["static_files"]["/etc/hosts"] = {
                    "type": "inline_file",
                    "contents": hosts,
                    "mode": 0o755,
                }

        # Delete some files that we don't want. securetty is general, limits shell access. Sys_resetbutton is some FW-specific hack?
        # TODO: in manual mode, delete securetty, in automated mode leave it.
        for f in settings.get("always_delete", []):
            if os.path.isfile(tmp_dir + f):
                config["static_files"][f] = {
                    "type": "delete",
                }

        # TODO: The following changes from FirmAE should likely be disabled by default
        # as we can't consider this information as part of our search if it's in the initial config
        # Linksys specific hack from firmae
        if settings.get("add_default_linksys_devices"):
            if all(
                os.path.isfile(tmp_dir + x)
                for x in ["/bin/gpio", "/usr/lib/libcm.so", "/usr/lib/libshared.so"]
            ):
                config["pseudofiles"]["/dev/gpio/in"] = {
                    "read": {
                        "model": "return_const",
                        "value": 0xFFFFFFFF,
                    }
                }


def find_symbol_address(elffile, symbol_name):
    try:
        symbol_tables = [
            s
            for s in elffile.iter_sections()
            if isinstance(s, elftools.elf.sections.SymbolTableSection)
        ]
    except elftools.common.exceptions.ELFParseError:
        return None, None

    for section in symbol_tables:
        if symbol := section.get_symbol_by_name(symbol_name):
            symbol = symbol[0]
            return (
                symbol["st_value"],
                symbol["st_shndx"],
            )  # Return symbol address and section index
    return None, None


def get_string_from_address(elffile, address, is_64=False, is_eb=False):
    for section in elffile.iter_sections():
        start_addr = section["sh_addr"]
        end_addr = start_addr + section.data_size
        if start_addr <= address < end_addr:
            offset_within_section = address - start_addr
            data = section.data()[offset_within_section:]
            str_end = data.find(b"\x00")
            if str_end != -1:
                try:
                    return data[:str_end].decode("utf-8")
                except UnicodeDecodeError:
                    # print(f"Failed to decode string: {data[:str_end]}")
                    pass
    return None


def analyze_library(elf_path, config):
    """
    Examine a single library. Is there anything we care about in here?

    1) look for exported tables: router_defaults and Nvrams to place in default nvram config
    2) report all exported function names
    """

    archend = config["core"]["arch"]
    is_eb = "eb" in archend
    is_64 = "64" in archend

    symbols = {}  # Symbol name -> relative(?) address
    nvram_data = {}  # key -> value (may be empty string)

    def _is_elf(filename):
        try:
            with open(filename, "rb") as f:
                magic = f.read(4)
            return magic == b"\x7fELF"
        except IOError:
            return False

    with open(elf_path, "rb") as f:
        try:
            elffile = ELFFile(f)
        except elftools.common.exceptions.ELFError:
            # elftools failed to parse our file. If it's actually an ELF, warn
            if _is_elf(elf_path):
                logger.warning(
                    f"Failed to parse {elf_path} as an ELF file when analyzing libraries"
                )
            return nvram_data, symbols

        try:
            match = ".dynsym" in [s.name for s in elffile.iter_sections()]
        except elftools.common.exceptions.ELFParseError:
            logger.warning(
                f"Failed to find .dynsym section in {elf_path} when analyzing libraries"
            )
            match = False

        if match:
            dynsym = elffile.get_section_by_name(".dynsym")
            for symbol in dynsym.iter_symbols():

                # Filter for exported functions??
                if symbol["st_info"]["bind"] == "STB_GLOBAL":
                    symbols[symbol.name] = symbol["st_value"]

        # Check for nvram keys
        for nvram_key in ["Nvrams", "router_defaults"]:
            address, section_index = find_symbol_address(elffile, nvram_key)
            if address is None:
                continue

            if section_index == "SHN_UNDEF":
                # This is a common case for shared libraries, it means
                # the symbol is defined in another library?
                continue

            try:
                section = elffile.get_section(section_index)
            except TypeError:
                logger.warning(
                    f"Failed to get section {section_index} for symbol {nvram_key} in {elf_path} when analyzing libraries"
                )
                continue
            data = section.data()
            start_addr = section["sh_addr"]
            offset = address - start_addr

            pointer_size = 8 if is_64 else 4
            unpack_format = f"{'>' if is_eb else '<'}{'Q' if is_64 else 'I'}"

            # We expect key_ptr, value_ptr, NULL, ...
            # note that we could have key_ptr, NULL, NULL
            # end when we get a NULL key

            fail_count = 0
            while offset + (pointer_size * 3) < len(data):
                ptrs = [
                    struct.unpack(
                        unpack_format,
                        data[
                            offset + i * pointer_size: offset + (i + 1) * pointer_size
                        ],
                    )[0]
                    for i in range(3)
                ]
                if ptrs[0] != 0:
                    key = get_string_from_address(elffile, ptrs[0], is_64, is_eb)
                    val = get_string_from_address(elffile, ptrs[1], is_64, is_eb)

                    if (
                        key
                        and not any([x in key for x in ' /\t\n\r<>"'])
                        and not key[0].isnumeric()
                    ):
                        fail_count = 0
                        if key not in nvram_data:
                            nvram_data[key] = val
                    else:
                        fail_count += 1
                else:
                    # Should we break here?
                    # For now let's just keep going (be sure to keep offset increment below)
                    # so we're more likely to find additional keys - might get false positives though
                    pass

                if fail_count > 5:
                    # Probably just outside of the table?
                    break

                offset += pointer_size * 3

    return nvram_data, symbols


def library_analysis(proj_dir, config, outdir):
    """
    Examine all the libraries (.so, .so.* files) in the filesystem. Use pyelftools to parse
    and analyze symbols
    """

    symbols = {}
    nvram = {}

    # Temporary directory for tar file extraction
    with tempfile.TemporaryDirectory() as tmp_dir:
        with tarfile.open(os.path.join(proj_dir, config["core"]["fs"]), "r") as tar:
            # tar.extractall(tmp_dir)
            # Only extract *.so or .so.* files:
            for member in tar.getmembers():
                if member.name.endswith(".so") or ".so." in member.name:
                    tar.extract(member, tmp_dir)

        # Now let's examine each extracted library
        for root, _, files in os.walk(tmp_dir):
            for file in files:
                file_path = Path(root) / file
                if file_path.is_file():
                    try:
                        found_nvram, found_syms = analyze_library(file_path, config)
                    except Exception as e:
                        logger.error(
                            f"Unhandled exception in analyze_library for {file_path}: {e}"
                        )
                        continue
                    tmpless_path = str(file_path).replace(tmp_dir, "")
                    for symname, offset in found_syms.items():
                        symbols[(tmpless_path, symname)] = offset
                    for key, value in found_nvram.items():
                        nvram[(tmpless_path, key)] = value

    # Let's use the csv format for now
    with open(os.path.join(outdir, "library_symbols.csv"), "w") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "symbol", "offset"])
        for (path, symname), offset in symbols.items():
            writer.writerow([path, symname, offset])

    with open(os.path.join(outdir, "nvram.csv"), "w") as f:
        writer = csv.writer(f)
        writer.writerow(["source", "path", "key", "value"])
        for (path, key), value in nvram.items():
            if key is not None and len(key):
                writer.writerow(
                    ["libraries", path, key, value if value is not None else ""]
                )


def _kernel_version_to_int(potential_name):
    try:
        # Seems like a kernel version! Let's compare to existing value.
        # Treat major version as an 10 000x, minor as 100x, patch as 1x
        # e.g., 4.4.0 -> 40 40 0
        comps = [int(x) for x in potential_name.split(".")]
    except ValueError:
        return None
    return comps[0] * 10000 + comps[1] * 100 + comps[2]


def shim_configs(proj_dir, config, settings):
    """
    Identify binaries in the guest FS that we want to shim
    and add symlinks to go from guest bin -> igloo bin
    into our config.
    """
    fs_path = os.path.join(proj_dir, config["core"]["fs"])  # tar archive

    # XXX: For now we'll only shim executables - if we later want to shim other things we need to
    # Update some of the later checks

    # shim_targets maps guest_bin -> path in /igloo/utils/ that we'll symlink to.
    # we'll back up the original binary to /igloo/utils/<guest_bin>.orig
    shim_targets = {
        # 'fw_printenv': 'fw_printenv', # NYI
        # 'fw_getenv': 'fw_printenv',
        # 'fw_setenv': 'fw_printenv',
        # XXX: We should re-enable these later when they work better
        # For now we could consider trying them in automated analyses, but openssl
        # shim breaks guests sometimes
        # OpenSSL is disabled by default
        # Bash/Ash is enabled by default
        "reboot": "exit0.sh",
        "halt": "exit0.sh",
        "insmod": "exit0.sh",
        "modprobe": "exit0.sh",
        "mount": "exit0.sh",
        "umount": "exit0.sh",
        "ash": "busybox",
        "sh": "busybox",
        "bash": "bash",
    }

    # Loop through settings and pop shim targets that are set to False
    default_targets = settings.get("shim_targets", {}).get("default_targets", {})
    for target in list(default_targets.keys()):
        if not default_targets[target]:
            shim_targets.pop(target, None)

        # Add user defined targets to the shim dictionary
        user_targets = settings.get("shim_targets", {}).get("user_targets")
        for target, command in user_targets.items():
            shim_targets[target] = command

    with tarfile.open(fs_path) as fs:
        for fname in fs.getmembers():  # getmembers for full path
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

            if basename in shim_targets:
                config["static_files"][path] = {
                    "type": "shim",
                    "target": f"/igloo/utils/{shim_targets[basename]}",
                }

    # Identify original kernel version and shim /lib/modules/4.10.0 to it's /lib/modules path
    kernel_version = None
    potential_kernels = set()
    with tarfile.open(fs_path) as fs:
        for member in fs.getmembers():
            if member.path.startswith("./lib/modules/") and member.isdir():
                # is this directly in under lib/modules?
                if not os.path.dirname(member.path) == "./lib/modules":
                    continue
                potential_kernels.add(os.path.basename(member.path))

    # Do any of these kernel strings look like a version
    # If we only have one, let's say it's definitely right
    if len(potential_kernels) == 1:
        kernel_version = potential_kernels.pop()
    elif len(potential_kernels) > 1:
        # Yikes, how can we tell which is the right one?
        # One simple heuristic for now - look for dots and dashes?
        # Future could be to look for .ko files in dir
        for potential_name in potential_kernels:
            if "." in potential_name and "-" in potential_name:
                kernel_version = potential_name
                break
        if not kernel_version:
            # Try again, ignoring dashes
            for potential_name in potential_kernels:
                if "." in potential_name:
                    kernel_version = potential_name
                    break

            # Fallback to picking the first one (TODO, could check for numbers at least)
            if not kernel_version:
                logger.warning(
                    "multiple kernel versions look valid (TODO improve selection logic, grabbing first)"
                )
                logger.warning(potential_kernels)
                kernel_version = potential_kernels.pop()

    if kernel_version:
        # We have a kernel version, add it to our config
        config["static_files"][f"/lib/modules/{IGLOO_KERNEL_VERSION}"] = {
            "type": "symlink",
            "target": f"/lib/modules/{kernel_version}",
        }


def _is_init_script(tarinfo, fs):
    if tarinfo.name.startswith("./igloo"):
        return False

    # Check if it is a file (and not a directory)
    if tarinfo.isreg() or tarinfo.issym():
        name = os.path.basename(tarinfo.name)
        # Add more specific conditions to match the init script names. Exclude standard linux script names that aren't init scripts
        if any([x in name for x in ["init", "start"]]) and not any(
            [x in name for x in ["inittab", "telinit", "initd"]]
        ):

            # If start is in the name, we want something with a clear "start" not "restart" or "startup".
            # Consider _ - and . as word boundaries and check
            if "start" in name:
                if not re.search(r"[\W_\-\.]start[\W_\-\.]", name):
                    return False

            # If it's a symlink, make sure the link target exists
            if tarinfo.issym():
                link_target = tarinfo.name

                sym_loop_ctr = 0
                subpath = ""
                while subpath != link_target:
                    components = link_target.split(os.sep)
                    for component in components:
                        if component:
                            subpath = os.path.join(subpath, component)

                        try:
                            filename = fs.getmember(subpath)
                        except KeyError:
                            logger.warning(
                                f"Potential init '{tarinfo.name}' is a symlink to '{link_target}' which does not exist in the filesystem'"
                            )
                            return False

                        if filename.issym():
                            newlink = filename.linkname

                            if newlink.startswith("/"):
                                link_target = os.path.normpath(
                                    newlink + link_target[len(subpath):]
                                )
                            else:
                                link_target = os.path.normpath(
                                    os.path.dirname(subpath)
                                    + "/"
                                    + newlink
                                    + link_target[len(subpath):]
                                )

                            if not link_target.startswith("./"):
                                if link_target.startswith("/"):
                                    link_target = "." + os.path.normpath(link_target)
                                else:
                                    link_target = "./" + os.path.normpath(link_target)
                            subpath = ""
                            break

                    sym_loop_ctr += 1
                    if sym_loop_ctr == 100:
                        logger.warning(
                            f"Potential init '{tarinfo.name}' is a symlink loop'"
                        )
                        return False

            # If we have init in the name, make sure it's not named .init (e.g., rc.d startup names)
            if "init" in name and name.endswith(".init"):
                return False

            if tarinfo.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                return True
            # TODO: we could prioritize those on standard paths:
            # if tarinfo.name.startswith(('./sbin/', './etc/init.d/', './etc/rc.d/')):
        elif "rcS" in name:
            if tarinfo.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                return True

    return False


def add_init_meta(proj_dir, base_config, output_dir):
    # Examine the filesystem and find any binaries that might be an init binary
    fs_path = os.path.join(proj_dir, base_config["core"]["fs"])  # tar archive
    inits = []

    try:
        with tarfile.open(fs_path) as fs:
            # Use generator expression for more efficient filtering
            inits = [
                member.name[1:].strip()
                for member in fs.getmembers()
                if _is_init_script(member, fs)
            ]
    except FileNotFoundError:
        logger.error(f"Target filesystem {fs_path} was not found.")
        raise
    except tarfile.TarError:
        logger.error(f"Target filesystem {fs_path} is not a valid tar.gz archive.")
        raise

    # Sort inits by length shortest to longest
    inits.sort(key=lambda x: len(x))

    # Next examine init.txt in the output_dir - these are particularly interesting
    # because they're the ones we saw in kernel args
    kernel_inits = []
    try:
        with open(output_dir + "/init.txt", "r") as f:
            kernel_inits = [x.strip() for x in f.readlines()]
        # Now remove the inits file, we're done with it
        os.remove(output_dir + "/init.txt")
    except FileNotFoundError:
        # No init.txt - it's okay, we don't really depend on it
        pass

    if len(kernel_inits):
        # Anything in both lists should go to the top. This filters out junk (e.g.,
        # values identified in kernel_inits that aren't in fs) while prioritizing
        # static analysis.
        common_inits = [x for x in kernel_inits if x in inits]
        only_fs_inits = [x for x in inits if x not in common_inits]

        # Sort both sets by length shortest to longest
        common_inits.sort(key=lambda x: len(x))
        only_fs_inits.sort(key=lambda x: len(x))

        # Then combine with common_inits before only_fs_inits
        inits = common_inits + only_fs_inits

    # If anything is longer than 32 characters, it's probably not an init script, warn and drop it
    for i in list(inits):
        if len(i) > 32:
            logger.debug(f"{i} is too long to be an init script, dropping")
            inits.remove(i)

    # Final pass, go through archive and make sure all inits are executable
    # We could only drop entries from only_fs_inits
    with tarfile.open(fs_path) as fs:
        for i in list(inits):
            member = fs.getmember("." + i)
            if not member.mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                inits.remove(i)

    base_config["meta"]["potential_init"] = inits


def add_dev_proc_meta(proj_dir, base_config, output_dir):
    pattern = re.compile(r"\/dev\/([A-Za-z0-9_/]+)", re.MULTILINE)

    tar_path = os.path.join(
        proj_dir, base_config["core"]["fs"]
    )  # Should all be the same
    potential_devfiles = ["/dev/" + x for x in _find_in_fs(pattern, tar_path).keys()]

    # Drop anything already in the FS or in our list of known device files
    # this list comes from igloo's utils/devtable.txt
    igloo_added_devices = [
        "/dev/mem",
        "/dev/kmem",
        "/dev/null",
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",
        "/dev/armem",
        "/dev/tt",
        "/dev/console",
        "/dev/ptmx",
        "/dev/tty0",
        "/dev/ttyS",
        "/dev/adsl0",
        "/dev/ppp",
        "/dev/hidraw0",
        "/dev/mtd",
        "/dev/mtd/0",
        "/dev/mtd/1",
        "/dev/mtd/2",
        "/dev/mtd/3",
        "/dev/mtd/4",
        "/dev/mtd/5",
        "/dev/mtd/6",
        "/dev/mtd/7",
        "/dev/mtd/8",
        "/dev/mtd/9",
        "/dev/mtd/10",
        "/dev/mtd",
        "/dev/mtdr",
        "/dev/tts/0",
        "/dev/tts/1",
        "/dev/tts/2",
        "/dev/tts/3",
        "/dev/mtdblock/0",
        "/dev/mtdblock/1",
        "/dev/mtdblock/2",
        "/dev/mtdblock/3",
        "/dev/mtdblock/4",
        "/dev/mtdblock/5",
        "/dev/mtdblock/6",
        "/dev/mtdblock/7",
        "/dev/mtdblock/8",
        "/dev/mtdblock/9",
        "/dev/mtdblock/10",
    ] + [
        "/dev/mtdblock",
        "/dev/tts",
        "/dev/mtd",
    ]  # Directories created by IGLOO as part of adding subfiles. Can't make as files now

    for k in list(_get_devfiles_in_fs(tar_path)) + igloo_added_devices:
        if k in potential_devfiles:
            potential_devfiles.remove(k)

    # Drop any directories
    directories_to_remove = set()

    # Populate set with directories that have subpaths
    for k in potential_devfiles:
        parent_path_parts = k.split("/")[:-1]
        for i in range(len(parent_path_parts)):
            parent_path = "/".join(parent_path_parts[: i + 1])
            if parent_path in potential_devfiles:
                directories_to_remove.add(parent_path)

    # Create the filtered list
    filtered_devfiles = [
        k for k in potential_devfiles if k not in directories_to_remove
    ]

    pattern = re.compile(r"\/proc\/([A-Za-z0-9_/]+)", re.MULTILINE)
    proc_files = ["/proc/" + x for x in _find_in_fs(pattern, tar_path).keys()]
    # Drop any that we expect to already have. TODO

    # Add all these to our meta field
    potential_files = filtered_devfiles + proc_files

    with open(output_dir + "/pseudofiles.yaml", "w") as f:
        yaml.dump(potential_files, f)

    base_config["meta"]["potential_files"] = potential_files


def add_env_meta(proj_dir, base_config, output_dir):
    # We want to search the filesystem for shell scripts accessing /proc/cmdline
    # and try to guess at what environment variables we might want to set
    # based on that. Store in meta ['potential_env'] field - we'll set them later
    tar_path = os.path.join(
        proj_dir, base_config["core"]["fs"]
    )  # Should all have the same FS
    pattern = re.compile(r"\/proc\/cmdline.*?([A-Za-z0-9_]+)=", re.MULTILINE)
    potential_keys = _find_in_fs(pattern, tar_path).keys()

    # Three magic values for igloo_task_size
    task_options = [0xBF000000, 0x7F000000, 0x3F000000]

    # We should have called add_init_meta before this, so we should have
    # a list of potential init scripts in meta['potential_init']
    potential_env = {
        "igloo_task_size": task_options,
        "igloo_init": base_config["meta"]["potential_init"],
    }

    # Drop any keys from potential_keys if the key is in boring_vars
    boring_vars = ["TERM"]
    for k in boring_vars:
        if k in potential_keys:
            potential_keys.remove(k)

    # Add all these to our meta field
    # if 'potential_env' not in base_config['meta']:
    #    base_config['meta']['potential_env'] = {}

    # We've been finding keys, not values they'd get set to
    # We could update our static analysis to search for those too if we'd like
    for k in potential_keys:
        known_vals = None
        pattern = re.compile(k + r"=([A-Za-z0-9_]+)", re.MULTILINE)
        potential_vals = _find_in_fs(pattern, tar_path).keys()

        if len(potential_vals):
            known_vals = list(potential_vals)

        # base_config['meta']['potential_env'][k] = known_vals
        potential_env[k] = known_vals

    base_config["meta"]["potential_env"] = potential_env
    # We're going to sort this as done by firmadyne/firmae - prioritize these:
    target_inits = ["/preinit", "/init", "/rcS"]
    init_list = deepcopy(potential_env["igloo_init"])
    sorted_env = []
    for target in target_inits:
        for hit in [x for x in init_list if target in x]:
            sorted_env.append(hit)
            init_list.remove(hit)

    # Now append any remaining inits
    sorted_env += init_list
    base_config["meta"]["potential_env"]["igloo_init"] = sorted_env

    with open(output_dir + "/env.yaml", "w") as f:
        yaml.dump(potential_env, f)

    # We moved potential_init into potential_env
    if "potential_init" in base_config["meta"]:
        del base_config["meta"]["potential_init"]

    # We need to pick an init binary, or we'll kernel panic! Let's grab the first
    if len(base_config["meta"]["potential_env"]["igloo_init"]):
        base_config["env"]["igloo_init"] = base_config["meta"]["potential_env"][
            "igloo_init"
        ][0]
    else:
        base_config["env"]["igloo_init"] = "TODO_MANUALLY_SET_ME"
        logger.warning(
            "no init binaries identified. Manually set one in config['env']['igloo_init']"
        )

    return base_config


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


def default_nvram_values(settings):
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

    if not settings.get("default_nvram_values", {"enabled": True}).get("enabled"):
        # Default values are diabled, clear
        nvram = {}

    if settings.get("default_nvram_values", {}).get("user_nvram_values"):
        nvram.update(settings.get("default_nvram_values").get("user_nvram_values"))

    return nvram


def add_nvram_meta(proj_dir, config, output_dir, settings):
    fs_path = os.path.join(proj_dir, config["core"]["fs"])
    nvram_sources = {}  # source -> count

    # Open our output dir's library.csv and parse (from library_analysis)
    if os.path.isfile(output_dir + "/nvram.csv"):
        # Nvram source 1: library exported tables
        with open(output_dir + "/nvram.csv", "r") as f:
            nvram_sources["libraries"] = 0
            reader = csv.DictReader(f)
            for row in reader:
                nvram_sources["libraries"] += 1
    else:
        # Create with header, we'll append later
        with open(output_dir + "/nvram.csv", "w") as f:
            writer = csv.writer(f)
            writer.writerow(["source", "path", "key", "value"])

    # Nvram source 2: standard nvram paths with plaintext data
    # If we have a hit, we combine with any existing values
    # These are notionally sorted - if an earlier path provides a value, we won't clobber
    # but we will consume keys from all paths that we can find and parse
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

    # Configure the paths used when searching for device-specific NVRAM values
    if settings and not settings["nvram_config"]["default_paths"]:
        nvram_paths = []
    if settings and settings["nvram_config"]["user_paths"]:
        nvram_paths.extend(settings["nvram_config"]["user_paths"])

    path_nvrams = {}
    with tarfile.open(fs_path, "r") as tar:
        for path in nvram_paths:
            if path in tar.getnames():
                # Found a default nvram file, parse it
                f = tar.extractfile(path)
                if f is not None:
                    result = parse_nvram_file(path, f)
                    # result is key-> value. We want to store path as well
                    for k, v in result.items():
                        path_nvrams[(path[1:], k.decode())] = v.decode()

    if len(path_nvrams):
        nvram_sources["full_config_paths"] = len(path_nvrams)
        with open(output_dir + "/nvram.csv", "a") as f:
            writer = csv.writer(f)
            for (path, k), v in path_nvrams.items():
                writer.writerow(["full_config_paths", path, k, v])

    wild_nvrams = {}
    # Still haven't found anything. Try widening the search to include these files as basenames, not full paths
    nvram_filenames = set([os.path.basename(x) for x in nvram_paths])
    # Do any of these files exist in the filesystem?
    # If so we'll parse nvram keys from them and update config['nvram']
    with tarfile.open(fs_path, "r") as tar:
        # Check again, just for filenames, without the path
        for member in tar.getmembers():
            if member.path in nvram_paths:
                # Exact match - we already checked this
                continue
            if any(member.name.endswith("/" + fname) for fname in nvram_filenames):
                if f := tar.extractfile(member.name):
                    result = parse_nvram_file(path, f)
                    for k, v in result.items():
                        wild_nvrams[(member.path[1:], k.decode())] = v.decode()

    if len(wild_nvrams):
        with open(output_dir + "/nvram.csv", "a") as f:
            writer = csv.writer(f)
            nvram_sources["basename_config_file"] = len(wild_nvrams)
            for (path, k), v in wild_nvrams.items():
                writer.writerow(["basename_config_file", path, k, v])

    # Time to add default values
    default_nvram = default_nvram_values(settings)

    with open(output_dir + "/nvram.csv", "a") as f:
        writer = csv.writer(f)
        nvram_sources["defaults"] = len(default_nvram)
        for k, v in default_nvram.items():
            writer.writerow(["defaults", "", k, v])

    # FirmAE provides a list of hardcoded files to check for nvram keys, and default values
    # to add if they're present. Here we add this into our config.
    static_targets = {  # filename -> (query, value to set if key is present)
        "./sbin/rc": [("ipv6_6to4_lan_ip", "2002:7f00:0001::")],
        "./lib/libacos_shared.so": [("time_zone_x", "0")],
        "./sbin/acos_service": [("rip_enable", "0")],
        "./usr/sbin/httpd": [
            ("rip_multicast", "0"),
            ("bs_trustedip_enable", "0"),
            ("filter_rule_tbl", ""),
        ],
    }

    nvram_sources["firmae_file_specific"] = 0
    with tarfile.open(fs_path, "r") as tar:
        # For each key in static_targets, check if the query is in the file
        for key, queries in static_targets.items():
            if key not in tar.getnames():
                continue

            try:
                f = tar.extractfile(key)
            except KeyError:
                # File not found - yes, we just checked.
                # but if it's a symlink to a file that doesn't exist, we'll get a KeyError
                continue
            if f is None:
                continue

            for query, _ in queries:
                # Check if query is in file
                if query.encode() in f.read():
                    if key not in config["nvram"]:
                        nvram_sources["firmae_file_specific"] += 1

    # Now we need to select which values we'll put in our config. Here's an algorithm:
    # We'd prefer libraries, full_config_paths, basename_config_file, defaults.
    # We'll always add firmae_file_specific, so long as those values aren't already in the config
    # We have a minimum of 10 values for us to select from a source
    for src in ["libraries", "full_config_paths", "basename_config_file", "defaults"]:
        with open(output_dir + "/nvram.csv", "r") as f:
            nvram_data = csv.DictReader(f)
            if nvram_sources.get(src, 0) > 10:
                # Now select data from nvram_data that matches this src
                # print(f"Found {nvram_sources[src]} nvram entries from {src} - selecting")
                for row in nvram_data:
                    if row["source"] == src:
                        # Preserve original value, unless it was empty
                        take_val = True
                        if (
                            row["key"] in config["nvram"]
                            and config["nvram"][row["key"]] != row["value"]
                        ):
                            take_val = (
                                len(config["nvram"].get(row["key"], "").strip()) == 0
                            )  # If old value was empty, take the new one
                            logger.debug(
                                f"NVRAM {row['key']} is {config['nvram'][row['key']]} but {row['source']} suggests {row['value']} instead. "
                                + ("Taking new value" if take_val else "Ignoring")
                            )

                        # If key is non-printable, ignore it
                        if not row["key"].isprintable():
                            take_val = False

                        if take_val:
                            config["nvram"][row["key"]] = row["value"]

            # if len(config['nvram']) > 10:
            #    # Don't mix our sources - just take what we got
            #    break

    # Re-open so we're at the start of the file?
    with open(output_dir + "/nvram.csv", "r") as f:
        nvram_data = csv.DictReader(f)
        # Now add firmae_file_specific values if they're not already in the config
        for row in nvram_data:
            if row["source"] == "firmae_file_specific":
                if row["key"] not in config["nvram"]:
                    config["nvram"][row["key"]] = row["value"]

    # Make sure everything is string
    for k, v in config["nvram"].items():
        if not isinstance(k, str):
            raise ValueError(
                f"Expected string value for nvram key, got {k} of type {type(k)}"
            )

        if not len(k):
            raise ValueError(f"Empty nvram key {k} => {v}")

        if not isinstance(v, str):
            raise ValueError(
                f"Expected string key for nvram[{k}], got {v} of type {type(v)}"
            )

    # Now report results. How many nvram values from which sources?
    logger.info(
        f"Selected {len(config['nvram'])} default NVRAM entries from: "
        + ", ".join(
            [f"{source} ({count})" for source, count in nvram_sources.items() if count]
        )
    )


def add_firmae_hacks(proj_dir, config, output_dir, settings):
    # This is a hacky FirmAE approach to identify webservers and just start
    # them. Unsurprisingly, it increases the rate of web servers starting.
    # We'll export this into our static files section so we could later decide
    # to try it. We'll enable this by default here.

    fs_path = os.path.join(proj_dir, config["core"]["fs"])  # tar archive
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

    # Allow users to customize mapping from webserver binary to command
    if settings and not settings["webserver_mapping"]["defaults"]:
        file2cmd = {}
    if settings and settings["webserver_mapping"]["user_mapping"]:
        file2cmd.update(settings["webserver_mapping"]["user_mapping"])

    www_cmds = []
    www_paths = []

    with tarfile.open(fs_path, "r") as tar:
        have_lighttpd_conf = "./etc/lighttpd/lighttpd.conf" in tar.getnames()

        for file, cmd in file2cmd.items():
            if file in tar.getnames():
                if file == "./usr/sbin/lighttpd" and not have_lighttpd_conf:
                    continue
                www_cmds.append(cmd)
                www_paths.append(file)

    if len(www_cmds):
        # We want to start each identified webserver in a loop

        # Start of the shell script
        cmd_str = """#!/igloo/utils/sh
        /igloo/utils/busybox sleep 120

        while true; do
        """

        # Loop through the commands to add them to the script
        # XXX we need to preload our libnvram here. If we ever mess with that we should also change it here
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

        config["static_files"]["/igloo/utils/www_cmds"] = {
            "type": "inline_file",
            "contents": cmd_str,
            "mode": 0o755,
        }

        if settings:
            config["core"]["force_www"] = settings["set_core_force_www"]


def add_lib_inject_symlinks(proj_dir, conf):
    """
    Detect the ABI of all libc.so files and place a symlink in the same
    directory to lib_inject of the same ABI
    """

    tf = tarfile.open(proj_dir / conf["core"]["fs"])
    libc_paths = [
        m.name
        for m in tf.getmembers()
        if os.path.basename(m.name).startswith("libc.so")
    ]
    for p in libc_paths:
        try:
            e = ELFFile(tf.extractfile(p))
        except ELFError:
            # Not an ELF. It could be for example a GNU ld script.
            continue
        abi = arch_filter(e).abi
        resolved_path = str(Path("/", os.path.dirname(p), "lib_inject.so"))
        conf["static_files"][resolved_path] = dict(
            type="symlink",
            target=f"/igloo/lib_inject_{abi}.so",
        )


def extend_config_with_static(proj_dir, base_config, outdir, settings):

    if "meta" not in base_config:
        base_config["meta"] = {}

    pre_shim(proj_dir, base_config, settings)

    # Search the filesystem for filenames that we want to shim with igloo-utils
    # We shim them all, every time
    shim_configs(proj_dir, base_config, settings)

    # Next we want to identify potential device files and environment variables
    # These are stored in our metadata: [meta][potential_dev] and [meta][potential_env]
    # and they write to base/{env,files,init}.yaml
    add_init_meta(proj_dir, base_config, outdir)
    add_env_meta(proj_dir, base_config, outdir)
    add_dev_proc_meta(proj_dir, base_config, outdir)

    # Analyze *.so, *.so.* to learn about library functions
    # and exported nvram values
    library_analysis(proj_dir, base_config, outdir)
    add_nvram_meta(proj_dir, base_config, outdir, settings)  # Sets more nvram values

    if settings and settings["enable_firmae_hack"]:
        add_firmae_hacks(proj_dir, base_config, outdir, settings)
    add_lib_inject_symlinks(proj_dir, base_config)

    # TODO: Additional static analysis of shell scripts to find more environment variables?
    # We could do some LLM-based shell script analysis

    return base_config


def main():
    from os.path import dirname
    from sys import argv

    if len(argv) != 3:
        print("Usage: python3 penguin_static.py <config> [outdir]")
        exit(1)

    # We'll dump the static analysis outputs into outdir/{env,files}.yaml
    # We don't use the returned object with the meta fields when called directly
    inconf = yaml.load(open(argv[1]), Loader=yaml.FullLoader)
    outdir = argv[2] if len(argv) > 2 else dirname(argv[1])
    proj_dir = dirname(argv[1])
    extend_config_with_static(proj_dir, inconf, outdir)


if __name__ == "__main__":
    main()
