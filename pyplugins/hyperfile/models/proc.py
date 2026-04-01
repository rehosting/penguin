from hyperfile.models.read import ReadConstBuf
from hyperfile.models.base import ProcFile
from wrappers.ptregs_wrap import PtRegsWrapper

class PenguinNet(ReadConstBuf, ProcFile):
    PATH = "/proc/penguin_net"  # No /proc prefix
    def __init__(self, config):
        netdev_val = "\n".join(config["netdevs"])+"\n"
        self.config = config
        super().__init__(buffer=netdev_val)

