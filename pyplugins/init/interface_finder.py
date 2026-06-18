"""
Identify network interfaces referenced in the filesystem.
"""

import re

from penguin.init_plugin import InitPlugin, cached_analysis
from penguin.static_analyses import FileSystemHelper


class InterfaceFinder(InitPlugin):
    """
    Identify network interfaces in the filesystem.
    """

    # Linux interface names are capped at IFNAMSIZ-1 chars; anything longer is a
    # glued/runaway scrape, not a real device name.
    IFNAMSIZ: int = 15

    # The command-argument scrape captures the token after `ifconfig`/`ip link`
    # etc. in any string, so help/usage text yields unbounded English garbage
    # ("Specify", "command", "together", "bonding_masters", "afstats", ...). A
    # denylist can't enumerate English; instead allowlist by interface-name
    # shape. Real names start with a letter and contain a digit (eth0, vlan1,
    # enp0s25, and underscore-segmented driver names like rmnet_mhi0,
    # pcie_mhi0, sipa_dummy0); English words don't contain digits.
    NETDEV_SHAPE = re.compile(r"^[a-z][a-z0-9_.\-]*\d[a-z0-9_.\-]*$")

    # OpenWrt-style named bridges/vlans (br-lan, br-wan, bond-mgmt) have no
    # trailing number, so allow a known-prefix + hyphenated name explicitly.
    NETDEV_NAMED = re.compile(r"^(?:br|bond|lan|wan)-[a-z0-9_]+$")

    # Genuinely standalone interface names with no digit (not NIC prefixes like
    # eth/wlan/br, whose numbered forms already match the shape rule).
    NETDEV_BARE: set[str] = {
        "lo", "et", "lan", "wan", "ppp", "pppoe", "l2tp", "vpn", "dsl",
        "lte", "wwan", "sta", "mesh",
    }

    # Network words that *do* match the shape rule (trailing digit) but are not
    # interfaces.
    NETDEV_DENY: set[str] = {"inet", "inet6", "ipv4", "ipv6", "ipv4cfg", "ipv6cfg"}

    def _keep_iface(self, iface: str) -> bool:
        """Whether a scraped token is a plausible real interface name."""
        iface = str(iface)
        if not iface or len(iface) > self.IFNAMSIZ:
            return False
        if iface.isnumeric() or iface in self.NETDEV_DENY:
            return False
        # Container/virtual scaffolding is dynamic, never a firmware interface.
        if iface.startswith(("veth", "docker", "virbr")):
            return False
        if iface in self.NETDEV_BARE:
            return True
        return bool(self.NETDEV_SHAPE.match(iface) or self.NETDEV_NAMED.match(iface))

    @cached_analysis
    def interfaces(self) -> dict[str, list[str]] | None:
        """
        Find network interfaces using sysfs and command references.

        :return: Dict of interfaces found via sysfs and commands.
        """
        extract_dir = str(self.ctx.extracted_fs)

        # Find all network interfaces in the filesystem
        pattern = re.compile(r"/sys/class/net/([a-zA-Z0-9_]+)", re.MULTILINE)
        sys_net_ifaces = FileSystemHelper.find_regex(pattern, extract_dir).keys()

        # Filter out scaffolding/placeholder/glued names
        sys_net_ifaces = [i for i in sys_net_ifaces if self._keep_iface(i)]

        # Now search for references to standard network commands: ifconfig, ip, brctl
        # We'll use these to identify interfaces
        interfaces = set()

        # Look for patterns that match network interface names in the context of commands
        interface_regex = r"([a-zA-Z0-9][a-zA-Z0-9_-]{2,15})"

        ifconfig_matches = re.compile(rf"ifconfig\s+{interface_regex}")
        # iproute2: `ip [opts] OBJECT [COMMAND] [dev] <name>`. Match the OBJECT
        # and optional COMMAND so the capture lands on the interface name, not
        # the sub-command keyword (old pattern captured 'set' in `ip link set eth0`).
        ip_link_matches = re.compile(
            rf"ip\s+(?:-\S+\s+)*(?:addr|address|link|route|neigh|rule)\s+"
            rf"(?:add|del|delete|set|show|list|flush|change|replace)?\s*(?:dev\s+)?{interface_regex}"
        )
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

        # Drop command keywords, placeholders, and glued/oversized captures.
        interfaces = [iface for iface in interfaces if self._keep_iface(iface)]

        result = {}
        if len(sys_net_ifaces):
            result["sysfs"] = list(sys_net_ifaces)

        if len(interfaces):
            result["commands"] = list(interfaces)

        if len(result):
            return result

    def static_result(self) -> dict[str, list[str]] | None:
        return self.interfaces
