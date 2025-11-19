"""
penguin.static_analyses
=======================

Static analysis utilities for the Penguin emulation environment.

This module provides classes and helpers for analyzing extracted filesystems.
"""

import os
import re
import stat
import struct
from subprocess import check_output, CalledProcessError, STDOUT, PIPE, SubprocessError

from abc import ABC
from elftools.common.exceptions import ELFError, ELFParseError
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from collections import Counter
from pathlib import Path
from penguin import getColoredLogger
from penguin.utils import get_available_kernel_versions
from penguin.defaults import DEFAULT_KERNEL
import tempfile
import subprocess

from .arch import arch_filter, arch_end
logger = getColoredLogger("penguin.static_analyses")


class FileSystemHelper:
    @staticmethod
    def find_regex(
        target_regex: re.Pattern,
        extract_root: str,
        ignore: list | tuple | None = None
    ) -> dict:
        """
        Search the filesystem for matches to a regex pattern using ripgrep.

        :param target_regex: Compiled regex pattern to match.
        :param extract_root: Root directory to search.
        :param ignore: Optional list/tuple of matches to ignore.
        :return: Dict of {match: {"count": int, "files": [str]}}
        """
        results = {}
        if not ignore:
            ignore = tuple()
        elif isinstance(ignore, list):
            ignore = tuple(ignore)

        pattern_str = target_regex.pattern
        extract_path_str = str(extract_root)

        try:
            # Get list of files containing matches
            file_list_output = check_output(
                f"rg --files-with-matches -a '{pattern_str}' '{extract_path_str}'",
                stderr=PIPE,
                shell=True,
            )

            # Process each file with Python's regex to extract actual matches
            if file_list_output:
                for filepath in file_list_output.decode().splitlines():
                    if not os.path.isfile(filepath) or os.path.islink(filepath):
                        continue

                    # open the file and read the content
                    try:
                        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                    except Exception as e:
                        logger.warning(f"failed to read file {filepath}: {e}")
                        continue
                    # apply regex pattern to find matches
                    matches = target_regex.findall(content)
                    for match in matches:
                        if match in ignore:
                            continue
                        if match not in results:
                            results[match] = {"count": 0, "files": set()}
                        results[match]["count"] += 1
                        results[match]["files"].add(filepath)
        except (SubprocessError, FileNotFoundError) as e:
            if e.returncode == 1:
                return {}
            else:
                logger.warning(f"Failed to run ripgrep: {e} - falling back to pure Python regex")
                return FileSystemHelper._find_regex_python(target_regex, extract_root, ignore)

        return results

    @staticmethod
    def _find_regex_python(
        target_regex: re.Pattern,
        extract_root: str,
        ignore: list | None = None
    ) -> dict:
        """
        Fallback implementation using Python's built-in regex.

        :param target_regex: Compiled regex pattern to match.
        :param extract_root: Root directory to search.
        :param ignore: Optional list of matches to ignore.
        :return: Dict of {match: {"count": int, "files": [str]}}
        """
        results = {}
        if not ignore:
            ignore = []

        # iterate through each file in the extracted root directory
        for root, dirs, files in os.walk(extract_root):
            for filename in files:
                filepath = os.path.join(root, filename)

                # skip our files in the "./igloo" path
                if filepath.startswith(os.path.join(extract_root, "igloo")):
                    continue

                # skip non-regular files if `only_files` is true
                if not os.path.isfile(filepath) or os.path.islink(filepath):
                    continue

                # open the file and read the content
                try:
                    with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read()
                except Exception as e:
                    logger.warning(f"failed to read file {filepath}: {e}")
                    continue

                # apply regex pattern to find matches
                matches = target_regex.findall(content)
                for match in matches:
                    if match in ignore:
                        continue
                    if match not in results:
                        results[match] = {"count": 0, "files": set()}
                    results[match]["count"] += 1
                    results[match]["files"].add(filepath)

        return results


class StaticAnalysis(ABC):
    """
    Abstract base class for static analyses.
    """
    def __init__(self) -> None:
        """
        Initialize the static analysis.
        """
        pass

    def run(self, extract_dir: str, prior_results: dict) -> None:
        """
        Run the static analysis.

        :param extract_dir: Directory containing extracted filesystem.
        :param prior_results: Results from previous analyses.
        """
        pass


class ArchId(StaticAnalysis):
    """
    Identify the most common architecture in the extracted filesystem.
    """
    def run(self, extracted_fs: str, prior_results: dict) -> str:
        '''
        Count architectures to identify most common.

        If both 32 and 64 bit binaries from the most common architecture are present,
        prefer 64-bit. Raise an error if architecture cannot be determined or is unsupported.

        :param extracted_fs: Path to extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Most common architecture string.
        :raises ValueError: If unable to determine architecture.
        '''

        arch_counts = {32: Counter(), 64: Counter(), "unknown": 0}
        for root, _, files in os.walk(extracted_fs):
            for file_name in files:
                path = os.path.join(root, file_name)

                if (
                    os.path.isfile(path)
                    and not os.path.islink(path)
                    and self._binary_filter(extracted_fs, path)
                ):
                    logger.debug(f"Checking architecture in {path}")
                    with open(path, "rb") as f:
                        if f.read(4) != b"\x7fELF":
                            continue
                        f.seek(0)
                        try:
                            ef = ELFFile(f)
                        except ELFError as e:
                            logger.warning(f"Failed to parse ELF file {path}: {e}. Ignoring")
                            continue
                        info = arch_filter(ef)
                    if info.bits is None or info.arch is None:
                        arch_counts["unknown"] += 1
                    else:
                        arch_counts[info.bits][info.arch] += 1

        # If there is at least one intel and non-intel arch,
        # filter out all the intel ones.
        # Some firmwares include x86_64 binaries left-over from the build process that aren't run in the guest.
        intel_archs = ("intel", "intel64")
        archs_list = list(arch_counts[32].keys()) + list(arch_counts[64].keys())
        if any(arch in intel_archs for arch in archs_list) and any(
            arch not in intel_archs for arch in archs_list
        ):
            del arch_counts[32]["intel"]
            del arch_counts[64]["intel64"]

        # Now select the most common architecture.
        # First try the most common 64-bit architecture.
        # Then try the most common 32-bit one.
        best_64 = arch_counts[64].most_common(1)
        best_32 = arch_counts[32].most_common(1)
        if len(best_64) != 0:
            best = best_64[0][0]
            best_count = best_64[0][1]
        elif len(best_32) != 0:
            best = best_32[0][0]
            best_count = best_32[0][1]
        else:
            raise ValueError("Failed to determine architecture of filesystem")

        # If unknown is the most common, we'll raise an error
        if arch_counts["unknown"] > best_count:
            # Dump debug info - which arches have what counts?
            for arch, count in arch_counts[32].items():
                logger.info(f"32-bit arch {arch} has {count} files")

            for arch, count in arch_counts[64].items():
                logger.info(f"64-bit arch {arch} has {count} files")

            # Finally, report unknown count
            logger.info(f"Unknown architecture count: {arch_counts['unknown']}")
            raise ValueError("Failed to determine architecture of filesystem")

        logger.debug(f"Identified architecture: {best}")
        return best

    @staticmethod
    def _binary_filter(fsbase: str, name: str) -> bool:
        """
        Filter for binary files of interest.

        :param fsbase: Base directory.
        :param name: File path.
        :return: True if file is a relevant binary.
        """
        base_directories = ["sbin", "bin", "usr/sbin", "usr/bin"]
        for base in base_directories:
            if name.startswith(os.path.join(fsbase, base)):
                return True
        # Shared libraries, kernel modules, or busybox
        return name.endswith((".so", ".ko")) or \
            ".so." in name or \
            name.endswith("busybox")


class InitFinder(StaticAnalysis):
    '''
    Find potential init scripts and binaries in an extracted filesystem.
    '''
    def run(self, filesystem_root_path: str, prior_results: dict) -> list[str]:
        '''
        Search the filesystem for binaries that might be init scripts.

        :param filesystem_root_path: Root path of extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Sorted list of init script paths.
        '''
        inits = []

        # Walk through the filesystem root and find potential init scripts.
        for root, dirs, files in os.walk(filesystem_root_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                if self._is_init_script(filepath, filesystem_root_path):
                    inits.append("/" + os.path.relpath(filepath, filesystem_root_path))

        # Sort inits by length, shortest to longest.
        inits.sort(key=lambda x: len(x))

        # Deprecated: kernel_inits. Filesystem extraction could try analyzing kernel binary
        # to find init argument built into the kernel. We do not currently do this or have a
        # way to pass this information through
        '''
        # Examine `init.txt` in the output directory, if it exists.
        kernel_inits = []
        try:
            with open(os.path.join(output_dir, "init.txt"), "r") as f:
                kernel_inits = [x.strip() for x in f.readlines()]
            os.remove(os.path.join(output_dir, "init.txt"))
        except FileNotFoundError:
            # No `init.txt`, it's okay.
            pass

        if kernel_inits:
            # Combine `kernel_inits` with `inits`, prioritizing `kernel_inits`.
            common_inits = [x for x in kernel_inits if x in inits]
            only_fs_inits = [x for x in inits if x not in common_inits]
            common_inits.sort(key=lambda x: len(x))
            only_fs_inits.sort(key=lambda x: len(x))
            inits = common_inits + only_fs_inits
        '''

        # Now rank our init options, using the same ranking as Firmadyne/Firmae where
        # a few specific inits are prioritized, then fallback to others

        target_inits = ["preinit", "init", "rcS"]
        # If any of these are in our init list, move them to the front
        # but maintain this order (i.e., preinit goes before /init so loop backwards)
        for potential in target_inits[::-1]:
            try:
                idx = [x.split("/")[-1] for x in inits].index(potential)
            except ValueError:
                # No match
                continue
            # Move to front
            match = inits.pop(idx)
            inits.insert(0, match)

        # Remove entries longer than 32 characters.
        inits = [i for i in inits if len(i) <= 32]

        # Final pass to ensure all inits are executable.
        # Trim the first / in the path to ensure it's relative to our extract dir
        inits = [
            i for i in inits
            if os.stat(os.path.join(filesystem_root_path, i[:1])).st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        ]

        return inits

    @staticmethod
    def _is_init_script(filepath: str, fsroot: str) -> bool:
        '''
        Determine if a file is a potential init script.

        :param filepath: Path to file.
        :param fsroot: Filesystem root.
        :return: True if file is a potential init script.
        '''
        if filepath.startswith("./igloo"):
            return False

        if not os.path.isfile(filepath) and not os.path.islink(filepath):
            return False

        name = os.path.basename(filepath)
        if any([x in name for x in ["init", "start"]]) and not any(
            [x in name for x in ["inittab", "telinit", "initd"]]
        ):
            # If 'start' is in the name, ensure it's not part of "restart" or "startup".
            if "start" in name and not re.search(r"[\W_\-\.]start[\W_\-\.]", name):
                return False

            # Handle symlinks: make sure the link target exists.
            if os.path.islink(filepath):
                link_target = os.readlink(filepath)
                if os.path.isabs(link_target):
                    result = os.path.join(fsroot, "./"+link_target)
                else:
                    result = os.path.join(os.path.dirname(filepath), link_target)
                if not os.path.exists(result):
                    logger.warning(
                        f"Potential init '{filepath}' is a symlink to '{link_target}' which does not exist in the filesystem"
                    )
                    return False

            # If 'init' is in the name, ensure it's not named `.init`.
            if "init" in name and name.endswith(".init"):
                return False

            # Check if the file is executable.
            if os.path.isfile(filepath) and os.stat(filepath).st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                return True

        elif "rcS" in name:
            if os.path.isfile(filepath) and os.stat(filepath).st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
                return True

        return False


class KernelVersionFinder(StaticAnalysis):
    """
    Find and select the best kernel version from extracted filesystem.
    """
    @staticmethod
    def is_kernel_version(name: str) -> bool:
        """
        Check if a string matches a kernel version pattern.

        :param name: Version string.
        :return: True if matches kernel version pattern.
        """
        return re.match(r"^\d+\.\d+\.\d+(-[\w\.]+)?$", name) is not None

    @staticmethod
    def select_best_kernel(kernel_versions: set[str]) -> str:
        """
        Select the most recent kernel version and match to available kernels.

        :param kernel_versions: Iterable of kernel version strings.
        :return: Best matching kernel version string.
        """
        if not kernel_versions:
            return DEFAULT_KERNEL

        # Parse kernel versions into tuples for comparison
        def parse_version(ver):
            base = ver.split("-", 1)[0]
            return tuple(int(t) for t in base.split(".") if t.isdigit())

        # Sort kernel_versions by parsed version, descending
        sorted_versions = sorted(kernel_versions, key=parse_version, reverse=True)
        most_recent = sorted_versions[0]

        # Now use the logic from the previous select_best_kernel
        base_version = most_recent.split("-", 1)[0]
        guest_tokens = base_version.split(".")
        guest_version = tuple(int(t) for t in guest_tokens if t.isdigit())
        guest_major = guest_version[0] if guest_version else None

        available_versions = get_available_kernel_versions()

        major_matches = [v for v in available_versions if v[0] == guest_major]

        def version_distance(v):
            maxlen = max(len(v), len(guest_version))
            v_pad = v + (0,) * (maxlen - len(v))
            g_pad = guest_version + (0,) * (maxlen - len(guest_version))
            return sum(abs(a - b) for a, b in zip(v_pad, g_pad))

        if major_matches:
            best = min(major_matches, key=version_distance)
        else:
            best = min(available_versions, key=version_distance)

        best_str = ".".join(str(x) for x in best)
        return best_str

    def run(self, extract_dir: str, prior_results: dict) -> dict[str, list[str] | str]:
        """
        Run kernel version analysis.

        :param extract_dir: Directory containing extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Dict with potential and selected kernel versions.
        """
        potential_kernels = set()

        # Only look at the top-level directories in self.extract_dir / lib / modules
        modules_path = os.path.join(extract_dir, "lib/modules")
        if os.path.exists(modules_path):
            for d in os.listdir(modules_path):
                d_path = os.path.join(modules_path, d)
                if os.path.isdir(d_path):
                    potential_kernels.add(d)

        # Filter potential kernels to match the expected version pattern
        potential_kernels = {d for d in potential_kernels if self.is_kernel_version(d)}
        selected_kernel = self.select_best_kernel(potential_kernels)
        return {
            "potential_kernels": sorted(potential_kernels),
            "selected_kernel": selected_kernel,
        }


class EnvFinder(StaticAnalysis):
    """
    Identify potential environment variables and their values in the filesystem.
    """
    BORING_VARS: list[str] = ["TERM"]

    def run(self, extract_dir: str, prior_results: dict) -> dict[str, list | None]:
        """
        Find environment variables and their possible values.

        DEPRECATED: This analysis is removed from default set and will likely be removed in the future

        :param extract_dir: Directory containing extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Dict of environment variable names to possible values.
        """

        # To start, we know there's `igloo_task_size` (a knob we created to configure), and
        # igloo_init (another knob we created) to specify the init program. We'll find
        # values for both
        # Three magic values for igloo_task_size
        task_options = [0xBF000000, 0x7F000000, 0x3F000000]

        potential_env = {
            "igloo_task_size": task_options,
            "igloo_init": prior_results['InitFinder']
        }

        # Now search the filesystem for shell scripts accessing /proc/cmdline
        pattern = re.compile(r"\/proc\/cmdline.*?([A-Za-z0-9_]+)=", re.MULTILINE)
        potential_keys = FileSystemHelper.find_regex(pattern, extract_dir, ignore=self.BORING_VARS).keys()

        # For each key, try pulling out potential values from the filesystem
        for k in potential_keys:
            known_vals = None
            pattern = re.compile(k + r"=([A-Za-z0-9_]+)", re.MULTILINE)
            potential_vals = FileSystemHelper.find_regex(pattern, extract_dir,
                                                         ignore=self.BORING_VARS).keys()

            if len(potential_vals):
                known_vals = list(potential_vals)

            potential_env[k] = known_vals

        return potential_env


class PseudofileFinder(StaticAnalysis):
    """
    Find device and proc pseudofiles in the extracted filesystem.
    """
    IGLOO_ADDED_DEVICES: list[str] = [
        "autofs", "btrfs-control", "cfs0", "cfs1", "cfs2", "cfs3",
        "cfs4", "console", "cpu_dma_latency", "full", "fuse", "input", "kmsg",
        "loop-control", "loop0", "loop1", "loop2", "loop3", "loop4",
        "loop5", "loop6", "loop7", "mem", "memory_bandwidth", "mice", "net",
        "network_latency", "network_throughput", "null", "port", "ppp",
        "psaux", "ptmx", "pts", "ptyp0", "ptyp1", "ptyp2", "ptyp3", "ptyp4",
        "ptyp5", "ptyp6", "ptyp7", "ptyp8", "ptyp9", "ptypa", "ptypb",
        "ptypc", "ptypd", "ptype", "ptypf", "ram", "ram0", "ram1", "ram10",
        "ram11", "ram12", "ram13", "ram14", "ram15", "ram2", "ram3",
        "ram4", "ram5", "ram6", "ram7", "ram8", "ram9", "random", "root",
        "tty", "tty0", "tty1", "tty10", "tty11", "tty12", "tty13",
        "tty14", "tty15", "tty16", "tty17", "tty18", "tty19", "tty2",
        "tty20", "tty21", "tty22", "tty23", "tty24", "tty25", "tty26",
        "tty27", "tty28", "tty29", "tty3", "tty30", "tty31", "tty32",
        "tty33", "tty34", "tty35", "tty36", "tty37", "tty38", "tty39",
        "tty4", "tty40", "tty41", "tty42", "tty43", "tty44", "tty45",
        "tty46", "tty47", "tty48", "tty49", "tty5", "tty50", "tty51",
        "tty52", "tty53", "tty54", "tty55", "tty56", "tty57", "tty58",
        "tty59", "tty6", "tty60", "tty61", "tty62", "tty63", "tty7",
        "tty8", "tty9",
        "ttyS0", "ttyS1", "ttyS2", "ttyS3",
        "ttyp0",
        "ttyp1", "ttyp2", "ttyp3", "ttyp4", "ttyp5", "ttyp6", "ttyp7",
        "ttyp8", "ttyp9", "ttypa", "ttypb", "ttypc", "ttypd", "ttype",
        "ttypf", "tun", "urandom", "vcs", "vcs1", "vcsa", "vcsa1", "vda",
        "vga_arbiter", "vsock", "zero",
        "root", "pts",  # Added in init
        "ttyAMA0", "ttyAMA1",  # ARM
        "stdin", "stdout", "stderr",  # Symlinks to /proc/self/fd/X
    ]

    IGLOO_PROCFS: list[str] = [
        "buddyinfo",
        "cgroups",
        "cmdline",
        "config.gz",
        "consoles",
        "cpuinfo",
        "crypto",
        "devices",
        "diskstats",
        "execdomains",
        "fb",
        "filesystems",
        "interrupts",
        "iomem",
        "ioports",
        "kallsyms",
        "key-users",
        "keys",
        "kmsg",
        "kpagecount",
        "kpageflags",
        "loadavg",
        "locks",
        "meminfo",
        "misc",
        "modules",
        "mounts",
        "mtd",  # We might shadow this later intentionally, but not by default
        "net",
        "pagetypeinfo",
        "partitions",
        "penguin_net",  # This is custom and unique but we shouldn't ever shadow it
        "sched_debug",
        "slabinfo",
        "softirqs",
        "stat",
        "swaps",
        "sysrq-trigger",
        "thread-self",
        "timer_list",
        "uptime",
        "version",
        "vmallocinfo",
        "vmstat",
        "zoneinfo",

        # Directories
        "bus",
        "bus/pci",
        "bus/pci/00",
        "bus/pci/00/00.0",
        "bus/pci/00/0a.0",
        "bus/pci/00/0a.1 ",
        "bus/pci/00/0a.2 ",
        "bus/pci/00/0a.3 ",
        "bus/pci/00/0b.0 ",
        "bus/pci/00/12.0 ",
        "bus/pci/00/13.0 ",
        "bus/pci/00/14.0 ",
        "bus/pci/devices ",
        "bus/input",
        "bus/input/devices",
        "bus/input/handlers",

        "cpu",
        "cpu/alignment",

        "driver",
        "driver/rtc",

        "fs",
        "fs/afs",
        "fs/afs/cells",
        "fs/afs/rootcell",
        "fs/ext4",
        "fs/f2fs",
        "fs/jbd2",
        "fs/nfsd",
        "fs/lockd",
        "fs/lockd/nlm_end_grace",
        "fs/nfsfs",
        "fs/nfsfs/servers",
        "fs/nfsfs/volumes",

        # Sys is special, loaded dynamically


        # sysvipc, driver (empty), scsi, tty, sys (big), irq (numbers), bus, fs
        "sysvipc/shm",
        "sysvipc/sem",
        "sysvipc/msg",

        "scsi/device_info",
        "scsi/scsi",

        "tty/drivers",
        "tty/ldisc",
        "tty/driver",
        "tty/driver/serial",
        "tty/ldisc",
    ]

    # Directories that we want to just ignore entirely - don't create any entries
    # within these directories. IRQs and device-tree are related to the emulated CPU
    # self and PID are related to the process itself and dynamically created
    PROC_IGNORE: list[str] = ["irq", "self", "PID", "device-tree", "net", "vmcore"]

    def __init__(self) -> None:
        """
        Initialize PseudofileFinder and load additional procfs entries.
        """
        # Load ../resources/proc_sys.txt, add each line to IGLOO_PROCFS
        resources = os.path.join(os.path.dirname(os.path.dirname(__file__)), "resources")
        with open(os.path.join(resources, "proc_sys.txt"), "r") as f:
            for line in f.readlines():
                self.IGLOO_PROCFS.append(line.strip())

    def _filter_files(
        self,
        extract_dir: str,
        pattern: re.Pattern,
        ignore_list: list[str],
        remove_list: list[str]
    ) -> list[str]:
        """
        Filter files in a directory based on regex, ignore, and remove lists.

        :param extract_dir: Directory to search.
        :param pattern: Regex pattern to match.
        :param ignore_list: List of prefixes to ignore.
        :param remove_list: List of absolute matches to remove.
        :return: Filtered list of file paths.
        """
        # Find all files matching the pattern
        found_files = list(FileSystemHelper.find_regex(pattern, extract_dir).keys())

        # Apply ignore filters: these are paths we'll ignore entirely
        # filtered_files = [
        #    f for f in found_files if not any(f == ignored or f.startswith(ignored +"/") for ignored in ignore_list)
        # ]
        filtered_files = []
        for x in found_files:
            for f in ignore_list:
                if x == f or x.startswith(f + "/"):
                    # print(f"Ignoring {x}")
                    break
            else:
                filtered_files.append(x)

        # Remove items from remove_list (like IGLOO_ADDED_DEVICES or IGLOO_PROCFS)
        # filtered_files = [f for f in filtered_files if \
        #                  f not in remove_list]
        for f in remove_list:
            if f in filtered_files:
                # print(f"Removing {f}")
                filtered_files.remove(f)

        # Remove directories that have subpaths
        directories_to_remove = {
            "/".join(k.split("/")[:i + 1])  # get parent directories
            for k in filtered_files
            for i in range(len(k.split("/")[:-1]))  # only consider parent parts
        }

        return [k for k in filtered_files if k not in directories_to_remove]

    def run(self, extract_dir: str, prior_results: dict) -> dict[str, list[str]]:
        """
        Run pseudofile analysis.

        :param extract_dir: Directory containing extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Dict with lists of device and proc files.
        """
        # Regex patterns for dev and proc files
        dev_pattern = re.compile(r"/dev/([a-zA-Z0-9_/]+)", re.MULTILINE)
        proc_pattern = re.compile(r"/proc/([a-zA-Z0-9_/]+)", re.MULTILINE)

        # Filter device files
        dev_files = self._filter_files(
            extract_dir, dev_pattern, [], self.IGLOO_ADDED_DEVICES
        )

        # Filter proc files, applying PROC_IGNORE and IGLOO_PROCFS
        proc_files = self._filter_files(
            extract_dir, proc_pattern, self.PROC_IGNORE, self.IGLOO_PROCFS
        )

        # Return dev and proc files in the appropriate format
        return {
            "dev": [f"/dev/{x}" for x in dev_files],
            "proc": [f"/proc/{x}" for x in proc_files],
        }

    @staticmethod
    def _get_devfiles_in_fs(extracted_dir: str) -> list[str]:
        """
        Get all device files in extracted_dir/dev.

        :param extracted_dir: Directory containing extracted filesystem.
        :return: List of device file paths.
        """
        dev_dir = os.path.join(extracted_dir, "dev")
        results = []

        if os.path.exists(dev_dir):
            for root, _, files in os.walk(dev_dir):
                for f in files:
                    relative_path = os.path.join("/dev", os.path.relpath(os.path.join(root, f), dev_dir))
                    results.append(relative_path)

        return results


class InterfaceFinder(StaticAnalysis):
    """
    Identify network interfaces in the filesystem.
    """
    def run(self, extract_dir: str, prior_results: dict) -> dict[str, list[str]] | None:
        """
        Find network interfaces using sysfs and command references.

        :param extract_dir: Directory containing extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Dict of interfaces found via sysfs and commands.
        """
        # Find all network interfaces in the filesystem
        pattern = re.compile(r"/sys/class/net/([a-zA-Z0-9_]+)", re.MULTILINE)
        sys_net_ifaces = FileSystemHelper.find_regex(pattern, extract_dir).keys()

        # Filter out the default network interfaces
        sys_net_ifaces = [i for i in sys_net_ifaces if not i.startswith("veth") and not i.startswith("br")
                          and not i == "lo"]

        # Now search for references to standard network commands: ifconfig, ip, brctl
        # We'll use these to identify interfaces
        interfaces = set()

        # Look for patterns that match network interface names in the context of commands
        interface_regex = r"([a-zA-Z0-9][a-zA-Z0-9_-]{2,15})"

        ifconfig_matches = re.compile(rf"ifconfig\s+{interface_regex}")
        ip_link_matches = re.compile(rf"ip\s+(?:addr|link|route|add|set|show)\s+{interface_regex}")
        ifup_down_matches = re.compile(rf"if(?:up|down)\s+{interface_regex}")
        ethtool_matches = re.compile(rf"ethtool\s+{interface_regex}")
        route_matches = re.compile(rf"route\s+(?:add|del)\s+{interface_regex}")
        iwconfig_matches = re.compile(rf"iwconfig\s+{interface_regex}")
        netstat_matches = re.compile(rf"netstat\s+-r\s+{interface_regex}")
        ss_matches = re.compile(rf"ss\s+-i\s+{interface_regex}")

        # Aggregate all patterns
        patterns = [
            ifconfig_matches, ip_link_matches, ifup_down_matches, ethtool_matches,
            route_matches, iwconfig_matches, netstat_matches, ss_matches
        ]

        for p in patterns:
            interfaces.update(FileSystemHelper.find_regex(p, extract_dir).keys())

        bad_prefixes = ["veth", "br"]
        bad_vals = ["lo", "set", "add", "del", "route", "show", "addr", "link", "up", "down",
                    "flush", "help", "default"]

        # Filter out the default network interfaces
        interfaces = [iface for iface in interfaces if
                      not any([x in iface for x in bad_vals]) and
                      not any([iface.startswith(x) for x in bad_prefixes]) and
                      not iface.isnumeric()]

        result = {}
        if len(sys_net_ifaces):
            result["sysfs"] = list(sys_net_ifaces)

        if len(interfaces):
            result["commands"] = list(interfaces)

        if len(result):
            return result


class ClusterCollector(StaticAnalysis):
    '''
    Collect summary statistics for the filesystem to help identify clusters.
    '''
    def run(self, extract_dir: str, prior_results: dict) -> dict[str, list[str]]:
        """
        Collect basename and hash of every executable file.

        :param extract_dir: Directory containing extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Dict with lists of files, executables, and hashes.
        """
        # Collect the basename + hash of every executable file in the system
        all_files = set()
        executables = set()
        executable_hashes = set()

        for root, _, files in os.walk(extract_dir):
            for f in files:
                file_path = os.path.join(root, f)

                if os.path.isfile(file_path):
                    all_files.add(os.path.basename(f))

                if os.path.isfile(file_path) and os.access(file_path, os.X_OK):
                    executables.add(os.path.basename(f))

                    hash_value = self.compute_file_hash(file_path)
                    if hash_value:
                        executable_hashes.add(hash_value)

        return {
            'files': list(all_files),
            'executables': list(executables),
            'executable_hashes': list(executable_hashes)
        }

    @staticmethod
    def compute_file_hash(file_path: str) -> str | None:
        """
        Compute SHA256 hash of a file.

        :param file_path: Path to file.
        :return: Hex digest string or None on failure.
        """
        try:
            # Use the system's sha256sum binary for better performance
            output = check_output(["sha256sum", file_path], stderr=STDOUT)
            # sha256sum output format: '<hash>  <file_path>'
            return output.decode('utf-8').split()[0]
        except (CalledProcessError, FileNotFoundError, IOError) as e:
            logger.debug(f"Failed to hash file {file_path}: {e}")
            return None


class LibrarySymbols(StaticAnalysis):
    """
    Examine libraries in the filesystem for NVRAM keys and exported symbols.

    Uses pyelftools to find definitions for NVRAM_KEYS variables and tracks exported function names.
    """
    NVRAM_KEYS: list[str] = ["Nvrams", "router_defaults"]

    def run(self, extract_dir: str, prior_results: dict) -> dict[str, dict]:
        """
        Analyze libraries for NVRAM keys and symbols.

        :param extract_dir: Directory containing extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Dict with nvram values and symbol paths.
        """
        self.extract_dir = extract_dir
        self.archend = arch_end(prior_results['ArchId'])

        if any([x is None for x in self.archend]):
            self.enabled = False
            print(f"Warning: Unknown architecture/endianness: {self.archend}. Cannot run NVRAM recovery Static Analysis")
            return

        symbols = {}
        nvram = {}
        sym_paths = {}  # path -> symbol names

        # Now let's examine each extracted library
        for root, _, files in os.walk(self.extract_dir):
            for file in files:
                file_path = Path(root) / file
                if file_path.is_file() and \
                        (str(file_path).endswith(".so") or ".so." in str(file_path)):
                    try:
                        found_nvram, found_syms = self._analyze_library(file_path,
                                                                        self.archend)
                    except Exception as e:
                        logger.error(
                            f"Unhandled exception in _analyze_library for {file_path}: {e}"
                        )
                        continue
                    tmpless_path = str(file_path).replace(str(self.extract_dir), "")
                    sym_paths[tmpless_path] = found_syms
                    for symname, offset in found_syms.items():
                        symbols[(tmpless_path, symname)] = offset
                    for key, value in found_nvram.items():
                        nvram_key = key.rsplit(":", 1)[-1]  # Handle case of value coming from ar
                        nvram[(tmpless_path, nvram_key)] = value

        # Raw data will be library path -> key -> value
        nvram_values = {}
        for (path, key), value in nvram.items():
            if path not in nvram_values:
                nvram_values[path] = {}
            if key is not None and len(key) and value is not None:
                nvram_values[path][key] = value

        # nvram is key of filepath -> nvram key -> nvram value
        # We should 1) generate patches for each possible non-conflicting source
        return {'nvram': nvram_values,
                'symbols': sym_paths}

    @staticmethod
    def _find_symbol_address(
        elffile: ELFFile,
        symbol_name: str
    ) -> tuple[int | None, int | str | None]:
        """
        Find the address and section index of a symbol in an ELF file.

        :param elffile: ELFFile object.
        :param symbol_name: Name of the symbol.
        :return: Tuple of (address, section_index) or (None, None).
        """
        try:
            symbol_tables = [
                s
                for s in elffile.iter_sections()
                if isinstance(s, SymbolTableSection)
            ]
        except ELFParseError:
            return None, None

        for section in symbol_tables:
            if symbol := section.get_symbol_by_name(symbol_name):
                symbol = symbol[0]
                return (
                    symbol["st_value"],
                    symbol["st_shndx"],
                )  # Return symbol address and section index
        return None, None

    @staticmethod
    def _get_string_from_address(
        elffile: ELFFile,
        address: int,
        is_64: bool = False,
        is_eb: bool = False
    ) -> str | None:
        """
        Get a string from a given address in an ELF file.

        :param elffile: ELFFile object.
        :param address: Address to read string from.
        :param is_64: True if 64-bit ELF.
        :param is_eb: True if big-endian.
        :return: Decoded string or None.
        """
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

    @staticmethod
    def _is_elf(filename: str) -> bool:
        """
        Check if a file is an ELF binary.

        :param filename: Path to file.
        :return: True if ELF, False otherwise.
        """
        try:
            with open(filename, "rb") as f:
                magic = f.read(4)
            return magic == b"\x7fELF"
        except IOError:
            return False

    @staticmethod
    def get_nvram_info(
        elf_path: str,
        archend: str
    ) -> dict[str, str | None]:
        """
        Extract NVRAM key-value pairs from an ELF file.

        :param elf_path: Path to ELF file.
        :param archend: Architecture/endianness info.
        :return: Dict of NVRAM key-value pairs.
        """
        nvram_data = {}
        is_eb = "eb" in archend
        is_64 = "64" in archend
        with open(elf_path, "rb") as f:
            try:
                elffile = ELFFile(f)
            except ELFError:
                # elftools failed to parse our file. If it's actually an ELF, warn
                if LibrarySymbols._is_elf(elf_path):
                    logger.warning(
                        f"Failed to parse {elf_path} as an ELF file when analyzing libraries"
                    )
                return nvram_data

            # Check for nvram keys
            for nvram_key in LibrarySymbols.NVRAM_KEYS:
                address, section_index = LibrarySymbols._find_symbol_address(elffile, nvram_key)
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
                        key = LibrarySymbols._get_string_from_address(elffile, ptrs[0], is_64, is_eb)
                        val = LibrarySymbols._get_string_from_address(elffile, ptrs[1], is_64, is_eb)

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
            return nvram_data

    @staticmethod
    def _analyze_library(
        elf_path: str,
        archend: str
    ) -> tuple[dict, dict]:
        """
        Analyze a single library for exported tables and function names.

        :param elf_path: Path to library file.
        :param archend: Architecture/endianness info.
        :return: Tuple of (nvram_data, symbols).
        """

        symbols = {}  # Symbol name -> relative(?) address
        nvram_data = {}  # key -> value (may be empty string)

        # Check if the file is an ar archive
        try:
            with open(elf_path, 'rb') as f:
                archive = f.read(8) == b"!<arch>\n"

            if archive:
                with tempfile.TemporaryDirectory() as temp_dir:
                    subprocess.run(["ar", "x", elf_path], cwd=temp_dir, check=True)
                    for obj_file in os.listdir(temp_dir):
                        obj_path = os.path.join(temp_dir, obj_file)
                        found_nvram, found_syms = LibrarySymbols._analyze_library(obj_path, archend)
                        archive_key = f"{os.path.basename(elf_path)}:{obj_file}"
                        symbols.update({f"{archive_key}:{k}": v for k, v in found_syms.items()})
                        nvram_data.update({f"{archive_key}:{k}": v for k, v in found_nvram.items()})
                return nvram_data, symbols
        except CalledProcessError as e:
            logger.error(f"Error processing archive {elf_path}: {e.output.decode('utf-8', errors='ignore')}")

        # Handle ELF files
        try:
            if nm_out := check_output(["nm", "-D", "--defined-only", elf_path],
                                      stderr=STDOUT):
                for line in nm_out.decode("utf8", errors="ignore").split("\n"):
                    if line:
                        parts = line.split()
                        if len(parts) == 3:
                            addr, _, name = parts
                            if '@' in name:
                                name = name.split("@")[0]
                            addr = int(addr, 16)
                            if addr != 0:
                                symbols[name] = addr
                        elif line.strip().endswith("no symbols"):
                            continue
                        else:
                            logger.warning(f"Unexpected nm output format: {line}")
        except CalledProcessError as e:
            if LibrarySymbols._is_elf(elf_path):
                logger.error(f"Error running nm on {elf_path}: {e.output.decode('utf-8', errors='ignore')}")
            return nvram_data, symbols

        if any(sym in symbols for sym in LibrarySymbols.NVRAM_KEYS):
            nvram_data = LibrarySymbols.get_nvram_info(elf_path, archend)

        return nvram_data, symbols
