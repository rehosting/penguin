import csv
import os
from pandare import PyPlugin
from penguin import getColoredLogger, plugins


class BashCommand(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.bash_command")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        # Bash
        outdir = self.get_arg("outdir")
        path = os.path.join(outdir, "bash_cov.csv")
        self.bash_cov_csv = open(path, "w")
        csv.writer(self.bash_cov_csv).writerow(["filename", "lineno", "pid", "command"])
        self.bash_cov_csv.flush()
        plugins.SendHypercall.subscribe("bash_command", self.cmd_bash_command)

    def cmd_bash_command(self, cmd, path, lineno, pid):
        csv.writer(self.bash_cov_csv).writerow([path, lineno, pid, cmd])
        self.bash_cov_csv.flush()
        self.logger.debug(f"bash_command {path}:{lineno} {pid}: {cmd}")
        return 0, ""
