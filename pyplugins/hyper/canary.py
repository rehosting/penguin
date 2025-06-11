import os
from penguin import plugins, Plugin


class Canary(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")

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
