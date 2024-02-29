import logging

from copy import deepcopy
from os.path import join as pjoin
from typing import List

from pandare import PyPlugin
from penguin import PenguinAnalysis, yaml
from penguin.graphs import Failure, Mitigation, Configuration
from penguin.defaults import default_netdevs

# XXX this needs some testing

# Loopback isn't in our default list but we don't want to add it as a fake device
DEFAULT_IFACES =  default_netdevs + ["lo"]

iface_log = "iface.log"

class Interfaces(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.ppp.Health.ppp_reg_cb('igloo_exec', self.on_exec)
        open(f'{self.outdir}/{iface_log}', 'w').close()
        self.seen_ifaces = set()

    def on_exec(self, cpu, fname, argv):
        # note argv[0] is the binary name, similar to fname

        if argv is None or not len(argv):
            if argv is None:
                print("INTERFACE BUG", self, cpu, fname, argv)
            return

        if fname.startswith("/igloo/utils"):
            # This is us adding interfaces in /igloo_init
            return

        iface = None
        if fname.endswith('/ip') or argv[0] == 'ip':
            # (ip .* dev \K[a-zA-Z0-9.]+(?=))'
            if any('dev' in arg for arg in argv):
                for idx, arg in enumerate(argv):
                    if 'dev' in arg and idx < len(argv)-1:
                        iface = argv[idx+1]

        if fname.endswith('/ifconfig') or argv[0] == 'ifconfig':
            # device is the first argument
            if len(argv) > 1:
                iface = argv[1]

        if iface is None:
            return

        if iface in DEFAULT_IFACES:
            return

        # First character must be alphabetical
        if not iface[0].isalpha():
            return

        # Is this a valid interface name? It can be alphanumeric and contain dots and dashes
        if not iface.replace('.', '').replace('-', '').isalnum():
            return

        if iface in self.seen_ifaces:
            return

        self.seen_ifaces.add(iface)
        with open(f'{self.outdir}/{iface_log}', 'a') as f:
            f.write(f'{iface}\n')


class InterfaceAnalysis(PenguinAnalysis):
    ANALYSIS_TYPE="interfaces"
    VERSION="1.0.0"

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger("iface")
        self.logger.setLevel(logging.DEBUG)

    def parse_failures(self, output_dir) -> List[Failure]:
        # Read the iface.log file and create a list of failures

        with open(pjoin(output_dir, 'core_config.yaml')) as f:
            self.config = yaml.safe_load(f)

        # Read existing interfaces from config's netdevs list
        netdevs = set(self.config.get('netdevs', []))

        fails = []
        with open(f'{output_dir}/{iface_log}', 'r') as f:
            for iface in f.readlines():
                iface = iface.strip()
                if iface in netdevs:
                    continue
                fails.append(Failure(f"net_{iface}", self.ANALYSIS_TYPE, {"iface": iface}))
        return fails
    
    def get_potential_mitigations(self, config, failure : Failure) -> List[Mitigation]:
        iface = failure.info['iface']
        if iface not in config.get('netdevs', []):
            return [Mitigation(f"add_{iface}", self.ANALYSIS_TYPE, {"iface": iface})]


    def implement_mitigation(self, config : Configuration, failure : Failure, mitigation : Mitigation) -> List[Configuration]:
        iface = failure.info['iface']
        if iface in config.info.get('netdevs', []):
            print(f"Warning: Interface {iface} already exists, refusing toa dd")
            return []

        new_config = deepcopy(config.info)
        new_config['netdevs'] = config.info.get('netdevs', []) + [iface]
        return [Configuration(f"iface_{iface}", new_config)]