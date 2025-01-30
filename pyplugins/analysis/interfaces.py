import logging
from copy import deepcopy
from os.path import join as pjoin
from typing import List
import re

from pandare2 import PyPlugin

from penguin import getColoredLogger, yaml
from penguin import plugins
from penguin.analyses import PenguinAnalysis
from penguin.graphs import Configuration, Failure, Mitigation

iface_log = "iface.log"
ioctl_log = "iface_ioctl.log"

# Regex pattern for a valid Linux interface name
intf_pattern = r'^[a-zA-Z][a-zA-Z0-9._/-]{0,15}$'
ENODEV = 19

ignored_interfaces = ["lo"]


class Interfaces(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.conf = self.get_arg("conf")
        self.logger = getColoredLogger("plugins.interfaces")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        open(f"{self.outdir}/{iface_log}", "w").close()
        open(f"{self.outdir}/{ioctl_log}", "w").close()

        self.added_ifaces = self.conf.get("netdevs", [])

        self.missing_ifaces = set()
        self.failed_ioctls = set()

        self.panda.ppp("syscalls2", "on_sys_ioctl_return")(self.after_ioctl)
        plugins.subscribe(plugins.Health, "igloo_exec", self.iface_on_exec)

    def handle_interface(self, iface):
        if iface is None or not len(iface):
            return

        if iface in self.added_ifaces or iface in self.missing_ifaces \
                or iface in ignored_interfaces:
            return

        if not re.match(intf_pattern, iface):
            self.logger.debug(f"Invalid interface name {iface}")
            return

        self.missing_ifaces.add(iface)
        with open(f"{self.outdir}/{iface_log}", "a") as f:
            f.write(f"{iface}\n")
        self.logger.debug(f"Detected new missing interface {iface}")

    def failing_ioctl(self, ioctl, iface, rv):
        if iface and not re.match(intf_pattern, iface):
            self.logger.debug(f"Invalid interface name {iface}")
            iface = None

        if (ioctl, iface) in self.failed_ioctls:
            return

        self.failed_ioctls.add((ioctl, iface))
        self.logger.debug(
            f"Detected new failing ioctl {hex(ioctl)} for {iface or '[?]'}")

        with open(f"{self.outdir}/{ioctl_log}", "a") as f:
            f.write(f"{hex(ioctl)},{iface or '[?]'},{rv}\n")

    def get_iface_from_ioctl(self, cpu, arg):
        try:
            return self.panda.read_str(cpu, arg, max_length=16)
        except ValueError:
            return None

    def after_ioctl(self, cpu, pc, fd, request, arg):
        if 0x8000 < request < 0x9000:
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            iface = self.get_iface_from_ioctl(cpu, arg)

            # try to catch missing interfaces
            if rv == -ENODEV:
                self.handle_interface(iface)

            if rv < 0:
                # try to catch failing ioctls
                self.failing_ioctl(request, iface, rv)

    def iface_on_exec(self, cpu, fname, argv):
        # note argv[0] is the binary name, similar to fname
        if argv is None or len(argv) == 0:
            return

        if fname.startswith("/igloo/utils"):
            # This is us adding interfaces in /igloo_init
            return

        iface = None
        if fname.endswith("/ip") or argv[0] == "ip":
            # (ip .* dev \K[a-zA-Z0-9.]+(?=))'
            for idx, arg in enumerate(argv):
                if not arg:
                    continue
                if "dev" in arg and idx < len(argv) - 1:
                    iface = argv[idx + 1]

        if fname.endswith("/ifconfig") or argv[0] == "ifconfig":
            # device is the first argument
            if len(argv) > 1:
                iface = argv[1]
        self.handle_interface(iface)


class InterfaceAnalysis(PenguinAnalysis):
    ANALYSIS_TYPE = "interfaces"
    VERSION = "1.0.0"

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger("iface")
        self.logger.setLevel(logging.DEBUG)

    def parse_failures(self, output_dir) -> List[Failure]:
        # Read the iface.log file and create a list of failures

        with open(pjoin(output_dir, "core_config.yaml")) as f:
            self.config = yaml.safe_load(f)

        # Read existing interfaces from config's netdevs list

        # Return a list of all interfaces identified - in the mitigation stage
        # we'll filter to drop existing/default ones (this reduces duplication)
        ifaces = []
        with open(f"{output_dir}/{iface_log}", "r") as f:
            for iface in f.readlines():
                iface = iface.strip()
                ifaces.append(iface)

        # Delete anything from ifaces that's in already in self.config['netdevs']
        ifaces = [
            iface for iface in ifaces if iface not in self.config.get("netdevs", [])
        ]

        # One failure for each iface
        return [
            Failure(
                f"net_ifaces_{name}",
                self.ANALYSIS_TYPE,
                {"ifaces": [name]},
                patch_name=f"iface_{name}",
            )
            for name in ifaces
        ]

    def get_potential_mitigations(self, config, failure: Failure) -> List[Mitigation]:
        # Create a mitiation with every iface in the list, so long as at least one isn't already in the config
        ifaces = failure.info["ifaces"]  # Should just be one now
        if not any([iface not in config.get("netdevs", []) for iface in ifaces]):
            return []  # Already present
        iface = ifaces[0]

        # Create a mitigation with all the ifaces
        return [
            Mitigation(f"iface_{iface}", self.ANALYSIS_TYPE, {"ifaces": [iface]},
                       patch={"netdevs": [iface]}, failure_name=failure.friendly_name)
        ]

    def implement_mitigation(
        self, config: Configuration, failure: Failure, mitigation: Mitigation
    ) -> List[Configuration]:
        ifaces = failure.info["ifaces"]
        if all(iface in config.info.get("netdevs", []) for iface in ifaces):
            print(f"Warning: Interface {ifaces} already exists, refusing to add")
            return []

        new_config = deepcopy(config.info)
        new_config["netdevs"] = config.info.get("netdevs", []) + ifaces
        return [Configuration(f"iface_{len(ifaces)}", new_config)]
