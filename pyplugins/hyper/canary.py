import os
from pandare import PyPlugin
from penguin import getColoredLogger, plugins


class Canary(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")

        self.logger = getColoredLogger("plugins.canary")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
        plugins.SendHypercall.subscribe("canary", self.cmd_canary)

    def cmd_canary(self, status):
        path = os.path.join(self.outdir, "canary.txt")
        self.logger.debug(f"Received canary status {status}")
        if int(status) == 0:
            with open(path, "w") as f:
                f.write("1")
        return 0, ""
