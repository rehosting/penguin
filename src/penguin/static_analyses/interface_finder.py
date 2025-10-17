import re
from penguin import getColoredLogger
from .base import StaticAnalysis
from ..static_analyses import FileSystemHelper

logger = getColoredLogger("penguin.static_analyses")

class InterfaceFinder(StaticAnalysis):
    """
    Identify network interfaces in the filesystem.
    """
    def run(self, extract_dir: str, prior_results: dict) -> dict[str, list[str]] | None:
        """
        Find network interfaces from:
          - explicit /sys/class/net references (as before),
          - command usages (ifconfig/ip/ifup/wpa_supplicant/etc.),
          - distro/networkd/NM/udev configuration files (new: "configs" key).

        Return: dict[str, list[str]] | None  (backwards compatible)
        Keys:
          - "sysfs":    as before, filtered to exclude lo, veth*, br*
          - "commands": as before (but more accurate grammar), filtered identically
          - "configs":  new, unfiltered (lets you see bridges/veth/tunnels defined in config)
        """
        # ---------- helpers ----------
        # Accept VLANs (eth0.100) and peer-suffixed (veth0@if5); kernel default is 15 chars.
        IFACE = r"([A-Za-z0-9._:@-]{1,15})"

        def clean(name: str) -> str:
            # strip peer suffixes like veth0@if5 -> veth0
            return name.split('@', 1)[0]

        # keep old deny behavior for sysfs/commands
        bad_prefixes = ("veth", "br")
        bad_vals = set(["lo","set","add","del","route","show","addr","link","up","down","flush","help","default"])

        def filt_cmd_or_sysfs(names: set[str]) -> list[str]:
            out = []
            for n in names:
                if not n or n.isnumeric():
                    continue
                if any(n.startswith(p) for p in bad_prefixes):
                    continue
                if n in bad_vals:
                    continue
                out.append(n)
            return sorted(set(out))
        
        include_globs = (
            "**/*.sh","**/*.conf","**/*.rules","**/*.service",
            "**/*.network","**/*.netdev","**/*.link",
            "**/ifcfg-*","**/*.nmconnection",
            "**/init.d/*","**/rc*.d/*","**/default/*","**/systemd/network/*",
        )
        exclude_globs = ("**/*.so","**/*.ko*","**/*.bin","**/*.o","**/*.pyc","**/proc/**","**/sys/**","**/dev/**")

        # ---------- 1) sysfs string references (legacy behavior, but interface charset expanded) ----------
        sysfs_pat = re.compile(r"/sys/class/net/" + IFACE, re.MULTILINE)
        sysfs_hits = FileSystemHelper.find_regex_scoped(sysfs_pat, extract_dir, globs_include=include_globs, globs_exclude=exclude_globs)
        sysfs_raw = {clean(k) for k in sysfs_hits.keys()}
        sysfs = filt_cmd_or_sysfs(sysfs_raw)

        # ---------- 2) command-aware patterns (precise grammars) ----------
        patterns_cmd = {
            # classic tools:
            "ifconfig":        re.compile(rf"\bifconfig\s+{IFACE}\b"),
            "iwconfig":        re.compile(rf"\biwconfig\s+{IFACE}\b"),
            "ethtool":         re.compile(rf"\bethtool\s+{IFACE}\b"),
            "ifupdown":        re.compile(rf"\b(?:ifup|ifdown)\s+{IFACE}\b"),

            # ip(8) common forms:
            "ip-dev":          re.compile(rf"\bip\b[^\n;#]*?\b(?:dev|name)\s+{IFACE}\b"),
            "ip-link-add":     re.compile(rf"\bip\s+link\s+add\b[^\n;#]*?\b(?:name\s+)?{IFACE}\b"),
            "ip-tuntap":       re.compile(rf"\bip\s+tuntap\s+add\b[^\n;#]*?\bdev\s+{IFACE}\b"),

            # dhcp/wifi/pcap:
            "wpa":             re.compile(rf"\bwpa_supplicant\b[^\n;#]*?\b-(?:i|interface)\s+{IFACE}\b"),
            "udhcpc":          re.compile(rf"\budhcpc\b[^\n;#]*?\b-(?:i|I)\s+{IFACE}\b"),
            "dhclient-flag":   re.compile(rf"\bdhclient\b[^\n;#]*?\b-(?:i|I|--interface)\s+{IFACE}\b"),
            # dhclient sometimes takes bare IFACE at end; keep a conservative pattern:
            "dhclient-bare":   re.compile(rf"\bdhclient\b(?![^\n;#]*\b-(?:i|I|--interface)\b)[^\n;#]*\b{IFACE}\b"),
            "tcpdump":         re.compile(rf"\btcpdump\b[^\n;#]*?\b-(?:i|I)\s+{IFACE}\b"),
        }

        cmd_candidates: set[str] = set()
        for pat in patterns_cmd.values():
            found = FileSystemHelper.find_regex_scoped(pat, extract_dir, globs_include=include_globs, globs_exclude=exclude_globs)
            for m in found.keys():
                cmd_candidates.add(clean(m))
        commands = filt_cmd_or_sysfs(cmd_candidates)

        # ---------- 3) configuration sources (new) ----------
        # These are high-confidence and we DO NOT drop br*/veth* here.
        patterns_cfg = {
            # Debian ifupdown
            "debian-interfaces": re.compile(r"(?m)^\s*(?:auto|allow-hotplug|iface)\s+([A-Za-z0-9._:@-]{1,15})\b"),
            # RHEL/SUSE style
            "ifcfg":             re.compile(r"(?m)^\s*DEVICE\s*=\s*([A-Za-z0-9._:@-]{1,15})\s*$"),
            # systemd-networkd
            "systemd-networkd":  re.compile(r"(?m)^\s*Name\s*=\s*([A-Za-z0-9._:@-]{1,15})\s*$"),
            # NetworkManager
            "nmconnection":      re.compile(r"(?m)^\s*interface-name\s*=\s*([A-Za-z0-9._:@-]{1,15})\s*$"),
            # udev rules assigning stable names to net devices
            "udev-rules":        re.compile(r'(?m)\bSUBSYSTEM\s*==\s*"net".*?\bNAME\s*=\s*"([A-Za-z0-9._:@-]{1,15})"'),
        }

        cfg_candidates: set[str] = set()
        for pat in patterns_cfg.values():
            found = FileSystemHelper.find_regex_scoped(pat, extract_dir, globs_include=include_globs, globs_exclude=exclude_globs)
            for m in found.keys():
                cfg_candidates.add(clean(m))
        # For configs we only remove obviously bad tokens; keep br*/veth* visible
        configs = sorted({n for n in cfg_candidates if n and not n.isnumeric() and n not in bad_vals})

        # ---------- assemble result (backwards compatible) ----------
        result: dict[str, list[str]] = {}
        if sysfs:
            result["sysfs"] = sysfs
        if commands:
            result["commands"] = commands
        if configs:
            result["configs"] = configs

        return result or None
