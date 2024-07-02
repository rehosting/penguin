import logging
from copy import deepcopy
from os.path import join as pjoin
from typing import List

from pandare import PyPlugin

from penguin import getColoredLogger, yaml
from penguin.analyses import PenguinAnalysis
from penguin.graphs import Configuration, Failure, Mitigation

# XXX this needs some testing

iface_log = "iface.log"
ioctl_log = "iface_ioctl.log"


class Interfaces(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.conf = self.get_arg("conf")
        self.ppp.Health.ppp_reg_cb("igloo_exec", self.iface_on_exec)
        self.logger = getColoredLogger("plugins.interfaces")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        open(f"{self.outdir}/{iface_log}", "w").close()
        open(f"{self.outdir}/{ioctl_log}", "w").close()
        self.added_ifaces = self.conf.get("netdevs", [])

        self.seen_ifaces = set()
        self.seen_ioctls = (
            set()
        )  # Only failing network ioctls between 0x8000 and 0x9000
        conf = self.get_arg("conf")

        net_ioctl_block = conf.get("net_ioctl_block", None)

        if not net_ioctl_block:
            return

        @panda.ppp("syscalls2", "on_sys_ioctl_return")
        def after_ioctl(cpu, pc, fd, request, arg):
            # This seems to never happen, even though we'll see errors about SIOCSIFHWADDR
            # if ifconfig tries to interact with a misisng device. It's trying to issue that ioctl
            # but fails to get a handle to the device - an ioctl is never actually issued!
            if 0x8000 < request < 0x9000:
                rv = panda.arch.get_retval(cpu, convention="syscall")
                if rv < 0:
                    if request not in self.seen_ioctls:
                        self.seen_icotls.add(request)
                        with open(f"{self.outdir}/{ioctl_log}", "a") as f:
                            f.write(f"{request}\n")
                        self.logger.debug(
                            f"Failed net ioctl {request} with return {rv}"
                        )

                    if rv in net_ioctl_block:
                        panda.arch.set_retval(cpu, 0, convention="syscall")

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

        if iface is None:
            return

        if iface in self.added_ifaces:
            return

        # First character must be alphabetical
        if not iface[0].isalpha():
            return

        # Is this a valid interface name? It can be alphanumeric and contain dots and dashes
        if not iface.replace(".", "").replace("-", "").isalnum():
            return

        if iface in self.seen_ifaces or iface in ["lo"]:
            return

        self.seen_ifaces.add(iface)
        with open(f"{self.outdir}/{iface_log}", "a") as f:
            f.write(f"{iface}\n")
        self.logger.debug(f"Detected new interface reference {iface}")


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

        # Single failure with all ifaces
        return [
            Failure(
                f"net_ifaces_{len(ifaces)}",
                self.ANALYSIS_TYPE,
                {"ifaces": sorted(ifaces)},
            )
        ]

    def get_potential_mitigations(self, config, failure: Failure) -> List[Mitigation]:
        # Create a mitiation with every iface in the list, so long as at least one isn't already in the config
        ifaces = failure.info["ifaces"]
        if not any([iface not in config.get("netdevs", []) for iface in ifaces]):
            return []  # Already present

        # Create a mitigation with all the ifaces
        return [
            Mitigation(f"iface_{len(ifaces)}", self.ANALYSIS_TYPE, {"ifaces": ifaces})
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
