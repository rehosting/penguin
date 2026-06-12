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

    def static_result(self) -> dict[str, list[str]] | None:
        return self.interfaces
