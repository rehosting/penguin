import os
import re
from penguin import getColoredLogger
from penguin.defaults import RESOURCES
from .base import StaticAnalysis
from ..static_analyses import FileSystemHelper

logger = getColoredLogger("penguin.static_analyses")


class PseudofileFinder(StaticAnalysis):
    """
    Find device and proc pseudofiles in the extracted filesystem.

    Key points:
    - Regex-based families for "added" /dev and standard /proc (keeps legacy lists for back-compat).
    - Proper de-duplication and normalization.
    - Boundary-safe path parsing (no trailing punctuation, no token gluing).
    - Template/wildcard path suppression (e.g., /dev/%s, /proc/<pid>).
    - Stemming for common /proc glued tokens at top level (e.g., 'vmstatread' -> 'vmstat').
    - Drops clearly templated /proc/sys entries like trailing underscores (e.g., tcp_).
    - Special-cases suspicious doc paths (e.g., nostromo tarballs, null:/dev/null).
    """

    # --- Legacy literal lists (kept for drop-in compatibility) ----------------
    IGLOO_ADDED_DEVICES: list[str] = [
        "autofs", "btrfs-control", "cfs0", "cfs1", "cfs2", "cfs3", "cfs4",
        "console", "cpu_dma_latency", "full", "fuse", "input", "kmsg",
        "loop-control", "loop0", "loop1", "loop2", "loop3", "loop4",
        "loop5", "loop6", "loop7", "mem", "memory_bandwidth", "mice", "net",
        "network_latency", "network_throughput", "null", "port", "ppp",
        "psaux", "ptmx", "pts", "ptyp0", "ptyp1", "ptyp2", "ptyp3", "ptyp4",
        "ptyp5", "ptyp6", "ptyp7", "ptyp8", "ptyp9", "ptypa", "ptypb",
        "ptypc", "ptypd", "ptype", "ptypf", "ram", "ram0", "ram1", "ram10",
        "ram11", "ram12", "ram13", "ram14", "ram15", "ram2", "ram3", "ram4",
        "ram5", "ram6", "ram7", "ram8", "ram9", "random", "root",
        "tty", "tty0", "tty1", "tty10", "tty11", "tty12", "tty13", "tty14",
        "tty15", "tty16", "tty17", "tty18", "tty19", "tty2", "tty20",
        "tty21", "tty22", "tty23", "tty24", "tty25", "tty26", "tty27",
        "tty28", "tty29", "tty3", "tty30", "tty31", "tty32", "tty33",
        "tty34", "tty35", "tty36", "tty37", "tty38", "tty39", "tty4",
        "tty40", "tty41", "tty42", "tty43", "tty44", "tty45", "tty46",
        "tty47", "tty48", "tty49", "tty5", "tty50", "tty51", "tty52",
        "tty53", "tty54", "tty55", "tty56", "tty57", "tty58", "tty59",
        "tty6", "tty60", "tty61", "tty62", "tty63", "tty7", "tty8", "tty9",
        "ttyS0", "ttyS1", "ttyS2", "ttyS3", "ttyp0", "ttyp1", "ttyp2",
        "ttyp3", "ttyp4", "ttyp5", "ttyp6", "ttyp7", "ttyp8", "ttyp9",
        "ttypa", "ttypb", "ttypc", "ttypd", "ttype", "ttypf", "tun",
        "urandom", "vcs", "vcs1", "vcsa", "vcsa1", "vda", "vga_arbiter",
        "vsock", "zero",
        "root", "pts",  # Added in init
        "ttyAMA0", "ttyAMA1",  # ARM
        "stdin", "stdout", "stderr",  # Symlinks to /proc/self/fd/X
    ]

    IGLOO_PROCFS: list[str] = [
        # flat files
        "buddyinfo", "cgroups", "cmdline", "config.gz", "consoles", "cpuinfo",
        "crypto", "devices", "diskstats", "execdomains", "fb", "filesystems",
        "interrupts", "iomem", "ioports", "kallsyms", "key-users", "keys",
        "kmsg", "kpagecount", "kpageflags", "loadavg", "locks", "meminfo",
        "misc", "modules", "mounts", "mtd", "net", "pagetypeinfo",
        "partitions", "penguin_net", "sched_debug", "slabinfo", "softirqs",
        "stat", "swaps", "sysrq-trigger", "thread-self", "timer_list",
        "uptime", "version", "vmallocinfo", "vmstat", "zoneinfo",
        # directories
        "bus", "bus/pci", "bus/input", "bus/input/devices", "bus/input/handlers",
        "cpu", "cpu/alignment",
        "driver", "driver/rtc",
        "fs", "fs/afs", "fs/afs/cells", "fs/afs/rootcell",
        "fs/ext4", "fs/f2fs", "fs/jbd2", "fs/nfsd",
        "fs/lockd", "fs/lockd/nlm_end_grace",
        "fs/nfsfs", "fs/nfsfs/servers", "fs/nfsfs/volumes",
        "sysvipc/shm", "sysvipc/sem", "sysvipc/msg",
        "scsi/device_info", "scsi/scsi",
        "tty/drivers", "tty/ldisc", "tty/driver", "tty/driver/serial",
        # extra normals seen in baselines
        "bus/usb", "ide",
        "tty/ldiscs",           # present in some baselines
        "lvm", "lvm/VGs",       # LVM proc tree variants
        "evms", "evms/volumes", # EVMS variants
    ]

    # High-level "ignore these top-level /proc dirs entirely"
    PROC_IGNORE: list[str] = ["irq", "self", "thread-self", "task", "PID", "device-tree", "net", "vmcore"]

    # --- Regex families (new) -------------------------------------------------
    # Families of "we add these" or "Linux provides these" that should be ignored for /dev.
    IGLOO_ADDED_DEVICE_PATTERNS: list[str] = [
        r"^(autofs|btrfs-control|cpu_dma_latency|fuse|hwrng|kmsg|mem|port|psaux|ptmx|random|urandom|full|null|zero|console|vsock|vga_arbiter|loop-control)$",
        r"^vhost-(net|vsock)$",
        r"^ram\d+$",
        r"^loop\d+$",
        r"^tty\d+$",
        r"^ttyS\d+$",
        r"^ttyAMA\d+$",
        r"^ttyp[a-f0-9]+$",
        r"^ptyp[a-f0-9]+$",
        r"^(stdin|stdout|stderr)$",
        # Common directories we shouldn't treat as device files
        r"^(pts|net|shm|fs|proc|sys|dev|tmp|var|run)$",
    ]

    # Exact /dev roots to drop (leave real numbered/leaf forms alone).
    # NOTE: intentionally NOT dropping "dsa" per request.
    DEV_EXACT_DROP: set[str] = {
        "mtd",       # keep mtd\d+
        "usbmon",    # keep usbmon\d+
        "poll",      # docs artifact
        "pty",       # family root
        "fd",        # proc-style fd dir
        "loop",      # family root
        "block",     # dir root
        "ptyXX",     # docs placeholder
    }

    # Whole /proc families that the kernel normally provides (and we should suppress as "known")
    IGLOO_PROCFS_PATTERNS: list[str] = [
        r"^bus(/.*)?$", r"^cpu(/.*)?$", r"^driver(/.*)?$", r"^fs(/.*)?$",
        r"^sysvipc(/.*)?$", r"^scsi(/.*)?$", r"^tty(/.*)?$", r"^ide(/.*)?$",
        r"^lvm(/.*)?$", r"^evms(/.*)?$", r"^bus/usb(/.*)?$",
        # Drop bare '/proc/sys/net/ipv' without the version suffix (common glue FP)
        r"^sys/net/ipv(?![46](/|$)).*$",
        # Any PIDs anywhere
        r"^\d+(/|$)",
    ]

    # Exact /proc entries to drop (stale/rare or known false-positives)
    PROC_EXACT_DROP: set[str] = {
        "sys/kernel/rtsig-max",  # reported spurious in earlier samples
    }

    # Template characters that indicate placeholders
    TEMPLATE_CHARS = set("%$*?[]{}<>")

    def __init__(self) -> None:
        # Load detailed /proc/sys matrix (kept as-is: fine-grained)
        with open(os.path.join(RESOURCES, "proc_sys.txt"), "r") as f:
            for line in f:
                val = line.strip()
                if val:
                    self.IGLOO_PROCFS.append(val)

        # Deduplicate and sanitize
        self.IGLOO_PROCFS = self._normalize_list(self.IGLOO_PROCFS)
        self.IGLOO_ADDED_DEVICES = self._normalize_list(self.IGLOO_ADDED_DEVICES)

        # Precompute for stemming glued tokens at /proc's top level
        self._proc_top_basenames = {x for x in self.IGLOO_PROCFS if "/" not in x}

    @staticmethod
    def _normalize_list(items: list[str]) -> list[str]:
        seen = set()
        out = []
        for i in items:
            s = i.strip()
            if not s or s in seen:
                continue
            seen.add(s)
            out.append(s)
        return out

    @staticmethod
    def _is_template_path(path_tail: str) -> bool:
        if any(ch in path_tail for ch in PseudofileFinder.TEMPLATE_CHARS):
            return True
        if "%s" in path_tail or "%d" in path_tail or "${" in path_tail or "$(" in path_tail:
            return True
        if "<" in path_tail and ">" in path_tail:
            return True
        return False

    @staticmethod
    def _clean_tail(t: str) -> str:
        # strip quotes/brackets and trailing punctuation
        t = t.strip().strip('`"\'')
        t = t.rstrip('.,:)]}>')
        # collapse duplicate slashes, remove ./, strip trailing /
        t = t.replace("//", "/")
        if t.startswith("./"):
            t = t[2:]
        return t.rstrip("/")

    @staticmethod
    def _matches_any(patterns: list[str], text: str) -> bool:
        return any(re.match(p, text) for p in patterns)

    @staticmethod
    def _maybe_stem_glued(token: str, basenames: set[str]) -> str:
        """
        If 'token' looks like a known /proc top-level basename with a glued
        alpha suffix (e.g., 'vmstatread'), return just the basename.
        """
        if "/" in token or not basenames:
            return token
        for base in basenames:
            if token.startswith(base) and token != base:
                suffix = token[len(base):]
                if suffix.isalpha():
                    return base
        return token

    def _filter_files(
        self,
        extract_dir: str,
        pattern: re.Pattern,
        ignore_list: list[str],
        remove_list: list[str],
        ignore_patterns: list[str] | None = None,
        remove_patterns: list[str] | None = None,
        stem_basenames: set[str] | None = None,
        is_dev: bool = False,
    ) -> list[str]:
        """
        Generic file matcher + filter:
        - normalizes matches
        - drops templated/globbed/placeholder paths
        - supports literal and regex-based ignores/removals
        - removes parent dirs that have subpaths
        - proc-only: drops trailing-underscore "template" entries (e.g., tcp_)
        """
        scoped_find = getattr(FileSystemHelper, "find_regex_scoped", FileSystemHelper.find_regex)
        try:
            hits = scoped_find(
                pattern, extract_dir,
                globs_include=(),
                globs_exclude=("**/proc/**", "**/sys/**", "**/dev/**")
            )
        except TypeError:
            hits = FileSystemHelper.find_regex(pattern, extract_dir)

        ignore_patterns = ignore_patterns or []
        remove_patterns = remove_patterns or []

        # Normalize and optionally stem (only for /proc top-level glue FPs)
        found = []
        for k in hits.keys():
            if not k:
                continue
            kt = self._clean_tail(k)
            if stem_basenames:
                kt = self._maybe_stem_glued(kt, stem_basenames)
            if kt:
                found.append(kt)

        results = set()
        for x in found:
            if not x:
                continue

            # obvious templates/placeholders
            if self._is_template_path(x):
                continue

            # Top-level ignore by literal (e.g., 'irq', 'self', etc.)
            first = x.split("/", 1)[0]
            if first.isdigit() or first in ignore_list:
                continue

            # Regex ignores that apply to full path or just the first segment
            if self._matches_any(ignore_patterns, x) or self._matches_any(ignore_patterns, first):
                continue

            # Literal removals (exact matches against remove_list)
            if x in remove_list:
                continue

            # Regex-based removals (families)
            if self._matches_any(remove_patterns, x) or self._matches_any(remove_patterns, first):
                continue

            # Extra dev-specific sanitization
            if is_dev:
                # Drop exact roots we consider non-leaf families or doc artifacts
                if x in self.DEV_EXACT_DROP or first in self.DEV_EXACT_DROP:
                    continue
                # Canonical doc/path artifacts
                lx = x.lower()
                if lx.startswith("null:/dev/null"):
                    continue
                # Known tarball/docs path that sometimes shows up in package metadata
                if re.search(r"nostromo.*\.tar(\.gz)?$", x, flags=re.IGNORECASE):
                    continue
            else:
                # /proc-specific cleanup
                # trailing-underscore "template" entries (e.g., tcp_)
                if x.endswith("_"):
                    continue
                # occasional exact drops (legacy or FPs)
                if x in self.PROC_EXACT_DROP or first in self.PROC_EXACT_DROP:
                    continue

            results.add(x)

        # Remove directories that have subpaths
        dirs = {"/".join(p.split("/")[:i + 1]) for p in results for i in range(len(p.split("/")[:-1]))}
        leafs = results - dirs

        return sorted(leafs)

    def run(self, extract_dir: str, prior_results: dict) -> dict[str, list[str]]:
        # Allowed characters and boundaries for a path tail
        # (Stop before a non-path char or end; avoid trailing ':' or '.')
        ALLOWED = r"A-Za-z0-9._:+=@,\-\/"
        TAIL    = rf"([{ALLOWED}]+?)"
        BOUND   = rf"(?:(?=[^{ALLOWED}])|$)"

        dev_pattern  = re.compile(rf"/dev/{TAIL}(?<![:.]){BOUND}")
        proc_pattern = re.compile(rf"/proc/{TAIL}(?<![:.]){BOUND}")

        # DEV: ignore nothing at top-level (literal) but remove known families by regex + legacy list
        dev_files = self._filter_files(
            extract_dir,
            dev_pattern,
            ignore_list=[],  # no top-level literal ignores for /dev
            remove_list=self.IGLOO_ADDED_DEVICES,            # legacy literals supported
            ignore_patterns=[],                              # none for /dev top-level
            remove_patterns=self.IGLOO_ADDED_DEVICE_PATTERNS,
            stem_basenames=None,                             # stemming is only for /proc glued tokens
            is_dev=True,
        )

        # PROC: ignore common top-level dirs entirely + remove standard families & legacy literals
        proc_files = self._filter_files(
            extract_dir,
            proc_pattern,
            ignore_list=self.PROC_IGNORE,
            remove_list=self.IGLOO_PROCFS,
            ignore_patterns=[r"^\d+(/|$)"],  # PIDs anywhere
            remove_patterns=self.IGLOO_PROCFS_PATTERNS,
            stem_basenames=self._proc_top_basenames,
            is_dev=False,
        )

        # Final de-dup and sort (defensive)
        dev_out = sorted(set(dev_files))
        proc_out = sorted(set(proc_files))

        return {
            "dev":  [f"/dev/{x}"  for x in dev_out],
            "proc": [f"/proc/{x}" for x in proc_out],
        }

    @staticmethod
    def _get_devfiles_in_fs(extracted_dir: str) -> list[str]:
        dev_dir = os.path.join(extracted_dir, "dev")
        results = []
        if os.path.exists(dev_dir):
            for root, _, files in os.walk(dev_dir):
                for f in files:
                    rel = os.path.relpath(os.path.join(root, f), dev_dir)
                    results.append(os.path.join("/dev", rel))
        return results
