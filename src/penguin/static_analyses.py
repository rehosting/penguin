import os
import re
import stat
import struct
import subprocess
import tarfile

import elftools
from abc import ABC
from elftools.common.exceptions import ELFError
from elftools.elf.elffile import ELFFile
from collections import Counter, defaultdict
from pathlib import Path
from penguin import getColoredLogger

from .arch import arch_filter
from .defaults import (
    default_init_script,
    default_lib_aliases,
    default_netdevs,
    default_plugins,
    default_pseudofiles,
    DEFAULT_KERNEL,
    default_version as DEFAULT_VERSION,
    static_dir as STATIC_DIR
)

logger = getColoredLogger("penguin.static_analyses")

class FileSystemHelper:
    @staticmethod
    def find_regex(target_regex, extract_root, ignore=None, only_files=True):
        """
        Given a regex pattern to match against, search the filesystem
        and track matches + counts.
        Returns a dict of {match: {count: int, files: [str]}
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
                if only_files and not os.path.isfile(filepath):
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
                        results[match] = {"count": 0, "files": []}
                    results[match]["count"] += 1
                    results[match]["files"].append(filepath)

        return results


class StaticAnalysis(ABC):
    def __init__(self):
        pass
    
    def run(self, extract_dir, prior_results):
        pass

class ArchId(StaticAnalysis):
    def run(self, extracted_fs, prior_results):
        '''
        Count architectures to identify most common.
        If we have both 32 and 64 bit binaries from the most common architecture
        we'll take 64-bit even if 32 is more common -> likely 64-bit with backwards compatibility
        '''

        arch_counts = {32: Counter(), 64: Counter()}
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
                        ef = ELFFile(f)
                        info = arch_filter(ef)
                    assert info.bits is not None
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
        elif len(best_32) != 0:
            best = best_32[0][0]
        else:
            raise ValueError(f"Failed to determine architecture of filesystem")

        logger.debug(f"Identified architecture: {best}")
        return best

    @staticmethod
    def _binary_filter(fsbase, name):
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
    Given an extracted filesystem, find potential init scripts and binaries
    '''
    def run(self, filesystem_root_path, prior_results):
        '''
        Search the filesystem, find any binaries that might be inits. Return
        a sorted list.
        '''
        inits = []

        # Walk through the filesystem root and find potential init scripts.
        for root, dirs, files in os.walk(filesystem_root_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                if self._is_init_script(filepath):
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
    def _is_init_script(filepath):
        '''
        Determine if a file is a potential init script.
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
                if not os.path.exists(os.path.join(os.path.dirname(filepath), link_target)):
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


class EnvFinder(StaticAnalysis):
    BORING_VARS = ["TERM"]

    def run(self, extract_dir, prior_results):
        """
        Identify potential environment variables and values we find them compared to
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
    IGLOO_ADDED_DEVICES = [ "autofs", "btrfs-control", "cfs0", "cfs1", "cfs2","cfs3",
                            "cfs4", "console", "cpu_dma_latency", "full", "fuse", "kmsg",
                            "loop-control", "loop0", "loop1", "loop2", "loop3", "loop4",
                            "loop5", "loop6", "loop7", "mem", "memory_bandwidth", 
                            "network_latency", "network_throughput", "null", "port", "ppp", 
                            "psaux", "ptmx", "ptyp0", "ptyp1", "ptyp2", "ptyp3", "ptyp4", 
                            "ptyp5", "ptyp6", "ptyp7", "ptyp8", "ptyp9", "ptypa", "ptypb", 
                            "ptypc", "ptypd", "ptype", "ptypf", "ram0", "ram1", "ram10", 
                            "ram11", "ram12", "ram13", "ram14", "ram15", "ram2", "ram3", 
                            "ram4", "ram5", "ram6", "ram7", "ram8", "ram9", "random", 
                            "tty", "tty0", "tty1", "tty10", "tty11", "tty12", "tty13", 
                            "tty14", "tty15", "tty16", "tty17", "tty18", "tty19", "tty2", 
                            "tty20", "tty21", "tty22", "tty23", "tty24", "tty25", "tty26", 
                            "tty27", "tty28", "tty29", "tty3", "tty30", "tty31", "tty32", 
                            "tty33", "tty34", "tty35", "tty36", "tty37", "tty38", "tty39", 
                            "tty4", "tty40", "tty41", "tty42", "tty43", "tty44", "tty45", 
                            "tty46", "tty47", "tty48", "tty49", "tty5", "tty50", "tty51", 
                            "tty52", "tty53", "tty54", "tty55", "tty56", "tty57", "tty58", 
                            "tty59", "tty6", "tty60", "tty61", "tty62", "tty63", "tty7", 
                            "tty8", "tty9", "ttys0", "ttys1", "ttys2", "ttys3", "ttyp0", 
                            "ttyp1", "ttyp2", "ttyp3", "ttyp4", "ttyp5", "ttyp6", "ttyp7", 
                            "ttyp8", "ttyp9", "ttypa", "ttypb", "ttypc", "ttypd", "ttype", 
                            "ttypf", "urandom", "vcs", "vcs1", "vcsa", "vcsa1", "vda", 
                            "vsock", "zero", "vga_arbiter"]

    def run(self, extract_dir, prior_results):
        pattern = re.compile(r"\/dev\/([a-zA-Z0-9_/]+)", re.MULTILINE)

        matches = FileSystemHelper.find_regex(pattern, extract_dir).keys()
        potential_devfiles = [f"/dev/{m}" for m in matches]

        # list of devices from igloo kernel's /dev with no pseudofiles


        for k in self._get_devfiles_in_fs(extract_dir) + \
                        ["/dev/{x}" for x in self.IGLOO_ADDED_DEVICES]:
            if k in potential_devfiles:
                potential_devfiles.remove(k)

        # drop any directories
        directories_to_remove = set()

        # populate set with directories that have subpaths
        for k in potential_devfiles:
            parent_path_parts = k.split("/")[:-1]
            for i in range(len(parent_path_parts)):
                parent_path = "/".join(parent_path_parts[: i + 1])
                if parent_path in potential_devfiles:
                    directories_to_remove.add(parent_path)

        # create the filtered list
        filtered_devfiles = [
            k for k in potential_devfiles if k not in directories_to_remove
        ]

        pattern = re.compile(r"\/proc\/([a-za-z0-9_/]+)", re.MULTILINE)
        proc_files = ["/proc/" + x for x in FileSystemHelper.find_regex(pattern, extract_dir).keys()]
        # TODO: drop any proc files we expect to have in our kernel?

        potential_files = filtered_devfiles + proc_files

        assert(isinstance(potential_files, list))

        return potential_files

    @staticmethod
    def _get_devfiles_in_fs(extracted_dir):
        """
        Get a list of all device files in extracted_dir/dev.
        Note that fw2tar might not actually package up devices (depends on version)
        so this could often be empty.
        """
        dev_dir = os.path.join(extracted_dir, "dev")
        results = []

        if os.path.exists(dev_dir):
            for root, _, files in os.walk(dev_dir):
                for f in files:
                    relative_path = os.path.join("/dev", os.path.relpath(os.path.join(root, f), dev_dir))
                    results.append(relative_path)

        return results
