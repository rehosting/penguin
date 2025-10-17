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
        Find network interfaces using sysfs and command references.

        :param extract_dir: Directory containing extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Dict of interfaces found via sysfs and commands.
        """
        pattern = re.compile(r"/sys/class/net/([a-zA-Z0-9_]+)", re.MULTILINE)
        sys_net_ifaces = FileSystemHelper.find_regex(pattern, extract_dir).keys()

        sys_net_ifaces = [i for i in sys_net_ifaces if not i.startswith("veth") and not i.startswith("br")
                          and not i == "lo"]

        interfaces = set()

        interface_regex = r"([a-zA-Z0-9][a-zA-Z0-9_-]{2,15})"

        ifconfig_matches = re.compile(rf"ifconfig\s+{interface_regex}")
        ip_link_matches = re.compile(rf"ip\s+(?:addr|link|route|add|set|show)\s+{interface_regex}")
        ifup_down_matches = re.compile(rf"if(?:up|down)\s+{interface_regex}")
        ethtool_matches = re.compile(rf"ethtool\s+{interface_regex}")
        route_matches = re.compile(rf"route\s+(?:add|del)\s+{interface_regex}")
        iwconfig_matches = re.compile(rf"iwconfig\s+{interface_regex}")
        netstat_matches = re.compile(rf"netstat\s+-r\s+{interface_regex}")
        ss_matches = re.compile(rf"ss\s+-i\s+{interface_regex}")

        patterns = [
            ifconfig_matches, ip_link_matches, ifup_down_matches, ethtool_matches,
            route_matches, iwconfig_matches, netstat_matches, ss_matches
        ]

        for p in patterns:
            interfaces.update(FileSystemHelper.find_regex(p, extract_dir).keys())

        bad_prefixes = ["veth", "br"]
        bad_vals = ["lo", "set", "add", "del", "route", "show", "addr", "link", "up", "down",
                    "flush", "help", "default"]

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
