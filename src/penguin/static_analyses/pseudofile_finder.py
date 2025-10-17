import os
import re
from penguin import getColoredLogger
from .base import StaticAnalysis
from ..static_analyses import FileSystemHelper

logger = getColoredLogger("penguin.static_analyses")

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
        # ...existing code for directories...
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

    PROC_IGNORE: list[str] = ["irq", "self", "PID", "device-tree", "net", "vmcore"]

    def __init__(self) -> None:
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
        found_files = list(FileSystemHelper.find_regex(pattern, extract_dir).keys())
        filtered_files = []
        for x in found_files:
            first_component = x.split("/", 1)[0]
            if first_component.isdigit():
                continue
            for f in ignore_list:
                if x == f or x.startswith(f + "/"):
                    break
            else:
                filtered_files.append(x)
        for f in remove_list:
            if f in filtered_files:
                filtered_files.remove(f)
        directories_to_remove = {
            "/".join(k.split("/")[:i + 1])
            for k in filtered_files
            for i in range(len(k.split("/")[:-1]))
        }
        return [k for k in filtered_files if k not in directories_to_remove]

    def run(self, extract_dir: str, prior_results: dict) -> dict[str, list[str]]:
        # allow . - _ + : @ = , and slashes inside the tail; stop at whitespace, quotes, ) , ; or end
        PATH_TAIL = r"[A-Za-z0-9._:+=@,\-\/]+?"
        BOUND    = r"(?=[\s\"'`),;]|$)"

        dev_pattern  = re.compile(rf"/dev/({PATH_TAIL}){BOUND}")
        proc_pattern = re.compile(rf"/proc/({PATH_TAIL}){BOUND}")

        dev_files = self._filter_files(
            extract_dir, dev_pattern, [], self.IGLOO_ADDED_DEVICES
        )
        proc_files = self._filter_files(
            extract_dir, proc_pattern, self.PROC_IGNORE, self.IGLOO_PROCFS
        )
        return {
            "dev": [f"/dev/{x}" for x in dev_files],
            "proc": [f"/proc/{x}" for x in proc_files],
        }

    @staticmethod
    def _get_devfiles_in_fs(extracted_dir: str) -> list[str]:
        dev_dir = os.path.join(extracted_dir, "dev")
        results = []
        if os.path.exists(dev_dir):
            for root, _, files in os.walk(dev_dir):
                for f in files:
                    relative_path = os.path.join("/dev", os.path.relpath(os.path.join(root, f), dev_dir))
                    results.append(relative_path)
        return results
