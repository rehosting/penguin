import re
from penguin import getColoredLogger
from .base import StaticAnalysis
from penguin.helpers.filesystem_helper import FileSystemHelper  # changed import

logger = getColoredLogger("penguin.static_analyses")

class InterfaceFinder(StaticAnalysis):
    """
    Identify network interfaces in the filesystem.
    """

    def run(self, extract_dir: str, prior_results: dict) -> dict[str, list[str]] | None:
        # Accept VLANs (eth0.100) and peer suffixes (veth0@if5). Kernel default is 15 bytes.
        IFACE = r"([A-Za-z0-9._:@-]{1,15})"

        def clean(name: str) -> str:
            # strip peer suffixes like veth0@if5 -> veth0
            return name.split('@', 1)[0]

        # Words we NEVER treat as interface names (case-insensitive).
        RESERVED = {
            "lo","set","add","del","route","show","addr","link","up","down","flush","help","default",
            # Your FPs & typical help lexemes:
            "specify","bonding_masters","command","endpoints","failed","for","get","implies",
            "inet","inet6","list","must","net","option","options","parms","remove","replace","restore",
            "results","save","subnet","summary","table","together","address","netmask","broadcast",
            "pointopoint","mtu","hardware","ether","arp","allmulti","promisc","txqueuelen","dynamic",
            "dstaddr","media","tunnel","loop","slip","cslip","slip6","cslip6","adaptive","ash","ax25",
            "netrom","rose","ppp","hdlc","lapb","arcnet","dlci","frad","sit","fddi","hippi","irda","ec",
            "x25","eui64","unix","darpa","internet","ipx","ddp","appletalk","econet","ccitt","usage",
            "devname","version","drivers","flags","types","families"
        }

        # Strong shape test for command-based candidates.
        STRICT_SHAPE = re.compile(r"""(?xi)
            (?:eth\d+|en[psox]\w+|eno\d+|ens\d+|ib\d+)        # ethernet/udev
            |(?:wlan\d+|wl\w+|wwan\d+)                        # wifi/cellular
            |(?:veth[\w-]+)                                   # veth
            |(?:br\d+|br-[a-z0-9-]+)                          # bridges
            |(?:tun\d+|tap\d+|wg\d+)                          # tunnels/WireGuard
            |(?:ppp\d+)                                       # PPP
            |(?:can\d+|vcan\d+)                               # CAN
            |(?:vxlan\d+|gre\d+|gretap\d+|erspan\d+)          # overlay/tunnel
            |(?:ip6tnl\d+|sit\d+)                             # ipip/6to4
            |(?:macvlan\d+|macvtap\d+)                        # macvlan
            |(?:bond\d+|team\d+)                              # bonding/team
            |(?:ifb\d+|dummy\d+)                              # shaping/dummy
            |(?:usb\d+)                                       # usbnet style
            |(?:[a-z]{2,6}[\w.-]*\d)                          # generic: letters + ... + digit
            |(?:eth\d+\.\d+)                                  # VLAN subif
        """)

        def likely_iface_from_command(tok: str) -> bool:
            t = tok.lower()
            if t in RESERVED:
                return False
            return bool(STRICT_SHAPE.fullmatch(tok))

        # Prefer scoped finder if available; otherwise use the legacy finder.
        scoped_find = getattr(FileSystemHelper, "find_regex_scoped", FileSystemHelper.find_regex)

        # We DO NOT exclude blobs; only skip pseudo trees.
        include_globs = ()  # search everything
        exclude_globs = ("**/proc/**","**/sys/**","**/dev/**")

        # ---------- 1) sysfs references (legacy behavior), now accepting '.' and '@' ----------
        sysfs_pat = re.compile(r"/sys/class/net/" + IFACE, re.MULTILINE)
        sysfs_hits = scoped_find(sysfs_pat, extract_dir, globs_include=include_globs, globs_exclude=exclude_globs)
        sysfs_raw = {clean(k) for k in sysfs_hits.keys()}
        sysfs = sorted({
            n for n in sysfs_raw
            if n and not n.isnumeric()
            and not n.startswith("veth")
            and not n.startswith("br")
            and n.lower() != "lo"
        })

        # ---------- 2) command-aware grammars (BusyBox + iproute2) ----------

        # Guard against help/usage lines by avoiding 'Usage:' anchored lines.
        NOT_USAGE = r"(?mi)^(?!\s*(?:usage|help)\b)"

        # BusyBox/inet-tools:
        pat_ifconfig = re.compile(rf"{NOT_USAGE}\s*ifconfig\b[^\n#;]*?\s+{IFACE}\b")
        pat_iwconfig = re.compile(rf"{NOT_USAGE}\s*iwconfig\b[^\n#;]*?\s+{IFACE}\b")
        pat_ethtool  = re.compile(rf"{NOT_USAGE}\s*ethtool\b[^\n#;]*?\s+{IFACE}\b")  # ethtool ... DEVNAME

        # ip(8) common forms (BusyBox subset supported too):
        pat_ip_dev   = re.compile(rf"\bip\b[^\n;#]*?\b(?:dev|name)\s+{IFACE}\b")
        pat_ip_add   = re.compile(rf"\bip\s+link\s+add\b[^\n;#]*?\b(?:name\s+)?{IFACE}\b")
        pat_ip_set   = re.compile(rf"\bip\s+link\s+(?:set|show|delete)\b[^\n;#]*?\s+{IFACE}\b")
        pat_ip_tap   = re.compile(rf"\bip\s+tuntap\s+add\b[^\n;#]*?\bdev\s+{IFACE}\b")

        # BusyBox udhcpc / ISC dhclient (support -iIFACE, -i IFACE, --interface=IFACE)
        opt_iface    = rf"(?:-(?:i|I)(?:\s*|=)?{IFACE}|--interface(?:\s*|=){IFACE})"
        pat_udhcpc   = re.compile(rf"\budhcpc\b[^\n;#]*?\b{opt_iface}")
        pat_dhclient = re.compile(rf"\bdhclient\b[^\n;#]*?\b{opt_iface}")
        # Conservative support for bare 'dhclient IFACE' (real-world scripts); shape filter prevents 'interface' placeholder.
        pat_dhclient_bare = re.compile(rf"(?mi)^(?!\s*(?:usage|help)\b)\s*dhclient\b(?![^\n#;]*\b-(?:i|I|--interface)\b)[^\n#;]*\b{IFACE}\b")

        # tcpdump -i IFACE / -iIFACE
        pat_tcpdump  = re.compile(rf"\btcpdump\b[^\n;#]*?\b-(?:i|I)(?:\s*|=)?{IFACE}\b")

        # route (BusyBox/net-tools): require 'dev IFACE' to avoid grabbing 'route add default'
        pat_route    = re.compile(rf"\broute\b[^\n;#]*?\b(?:add|del)\b[^\n;#]*?\bdev\s+{IFACE}\b", re.IGNORECASE)

        # iw (modern wireless): 'iw dev IFACE ...'
        pat_iw_dev   = re.compile(rf"\biw\b[^\n;#]*?\bdev\s+{IFACE}\b")

        # tc (traffic control): 'tc qdisc|filter|class ... dev IFACE'
        pat_tc_dev   = re.compile(rf"\btc\b[^\n;#]*?\b(?:qdisc|filter|class)\b[^\n;#]*?\bdev\s+{IFACE}\b")

        # brctl (BusyBox/bridge-utils): 'brctl addif BR IFACE' → capture the member IFACE (second device)
        # We capture ANY interface-shaped token after 'addif' (or 'delif').
        pat_brctl_if = re.compile(rf"\bbrctl\b[^\n;#]*?\b(?:addif|delif)\b[^\n;#]*?\b{IFACE}\b[^\n;#]*?\b{IFACE}\b")

        # iptables (optional signal): '-i IFACE' or '-o IFACE'
        pat_iptables = re.compile(rf"\biptables\b[^\n;#]*?\b-(?:i|o)\s+{IFACE}\b")

        patterns_cmd = [
            pat_ifconfig, pat_iwconfig, pat_ethtool,
            pat_ip_dev, pat_ip_add, pat_ip_set, pat_ip_tap,
            pat_udhcpc, pat_dhclient, pat_dhclient_bare, pat_tcpdump,
            pat_route, pat_iw_dev, pat_tc_dev, pat_brctl_if,
            pat_iptables,
        ]

        cmd_candidates: set[str] = set()
        for pat in patterns_cmd:
            found = scoped_find(pat, extract_dir, globs_include=include_globs, globs_exclude=exclude_globs)
            for m in found.keys():
                # Special-case brctl: two interface-like tokens appear; ripgrep/Python will give us both captures across matches.
                name = clean(m)
                if likely_iface_from_command(name):
                    cmd_candidates.add(name)

        # Legacy filters for "commands" (keep bridges/veth hidden here to preserve your current behavior).
        commands = sorted({
            n for n in cmd_candidates
            if n and not n.isnumeric()
            and n.lower() not in RESERVED
            and not n.startswith("veth")
            and not n.startswith("br")
            and n.lower() != "lo"
        })

        # ---------- 3) configs (high confidence, incl. BusyBox/OpenWrt UCI) ----------
        # Debian ifupdown
        pat_ifaces_debian = re.compile(r"(?m)^\s*(?:auto|allow-hotplug|iface)\s+([A-Za-z0-9._:@-]{1,15})\b")
        # RHEL/SUSE ifcfg
        pat_ifcfg         = re.compile(r"(?m)^\s*DEVICE\s*=\s*([A-Za-z0-9._:@-]{1,15})\s*$")
        # systemd-networkd: Name= in *.netdev or *.link; Match.Name= often appears in *.network
        pat_netdev_name   = re.compile(r"(?m)^\s*Name\s*=\s*([A-Za-z0-9._:@-]{1,15})\s*$")
        pat_match_name    = re.compile(r"(?m)^\s*Match\.\s*Name\s*=\s*([A-Za-z0-9._:@-]{1,15})\s*$")
        # NetworkManager
        pat_nmconn        = re.compile(r"(?m)^\s*interface-name\s*=\s*([A-Za-z0-9._:@-]{1,15})\s*$")
        # udev net rules
        pat_udev_rules    = re.compile(r'(?m)\bSUBSYSTEM\s*==\s*"net".*?\bNAME\s*=\s*"([A-Za-z0-9._:@-]{1,15})"')
        # OpenWrt / UCI (BusyBox environments):
        # option ifname/device/ports 'eth0.1'   OR   list ports 'eth0'
        pat_uci_option    = re.compile(r"(?m)^\s*option\s+(?:ifname|device|ports)\s+['\"]([A-Za-z0-9._:@-]{1,15})['\"]\s*$")
        pat_uci_list      = re.compile(r"(?m)^\s*list\s+(?:ports|device)\s+['\"]([A-Za-z0-9._:@-]{1,15})['\"]\s*$")
        # also capture bridge device names: option name 'br-lan'
        pat_uci_devname   = re.compile(r"(?m)^\s*option\s+name\s+['\"]([A-Za-z0-9._:@-]{1,15})['\"]\s*$")

        patterns_cfg = [
            pat_ifaces_debian, pat_ifcfg, pat_netdev_name, pat_match_name,
            pat_nmconn, pat_udev_rules, pat_uci_option, pat_uci_list, pat_uci_devname
        ]

        cfg_candidates: set[str] = set()
        for pat in patterns_cfg:
            found = scoped_find(pat, extract_dir, globs_include=include_globs, globs_exclude=exclude_globs)
            for m in found.keys():
                name = clean(m)
                if name and not name.isnumeric() and name.lower() not in RESERVED:
                    cfg_candidates.add(name)

        configs = sorted(cfg_candidates)

        # ---------- assemble ----------
        result: dict[str, list[str]] = {}
        if sysfs:
            result["sysfs"] = sysfs
        if commands:
            result["commands"] = commands
        if configs:
            result["configs"] = configs

        return result or None
