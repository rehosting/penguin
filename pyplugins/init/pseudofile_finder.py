"""
Find device and proc pseudofiles referenced by the extracted filesystem.
"""

import os
import re

from penguin.config_patchers import RESOURCES
from penguin.init_plugin import InitPlugin, cached_analysis
from penguin.static_analyses import FileSystemHelper


class PseudofileFinder(InitPlugin):
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
        "fd", "root", "pts", "shm",  # Added in init
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

        # Sys is special, loaded dynamically. Do not model /proc/sys itself as
        # a procfs file; sysctl entries below it are handled separately.
        "sys",


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

    @staticmethod
    def _known_procfs() -> list[str]:
        """IGLOO_PROCFS plus the sysctl entries from resources/proc_sys.txt."""
        # Load penguin's resources/proc_sys.txt, add each line to a copy of IGLOO_PROCFS
        procfs = list(PseudofileFinder.IGLOO_PROCFS)
        with open(os.path.join(RESOURCES, "proc_sys.txt"), "r") as f:
            for line in f.readlines():
                procfs.append(line.strip())
        return procfs

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
        found_files = sorted({
            f.rstrip("/")
            for f in FileSystemHelper.find_regex(pattern, extract_dir).keys()
        })

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

    @cached_analysis
    def pseudofiles(self) -> dict[str, list[str]]:
        """
        Run pseudofile analysis.

        :return: Dict with lists of device and proc files.
        """
        extract_dir = str(self.ctx.extracted_fs)

        # Regex patterns for dev and proc files
        dev_pattern = re.compile(r"/dev/([a-zA-Z0-9_/]+)", re.MULTILINE)
        proc_pattern = re.compile(r"/proc/([a-zA-Z0-9_/]+)", re.MULTILINE)

        # Filter device files
        dev_files = self._filter_files(
            extract_dir, dev_pattern, [], self.IGLOO_ADDED_DEVICES
        )

        # Filter proc files, applying PROC_IGNORE and known procfs entries
        proc_files = self._filter_files(
            extract_dir, proc_pattern, self.PROC_IGNORE, self._known_procfs()
        )

        # Return dev and proc files in the appropriate format
        return {
            "dev": [f"/dev/{x}" for x in dev_files],
            "proc": [f"/proc/{x}" for x in proc_files],
        }

    def static_result(self) -> dict[str, list[str]]:
        return self.pseudofiles

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
