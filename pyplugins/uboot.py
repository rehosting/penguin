import os
from pandare import PyPlugin
from penguin import getColoredLogger, plugins

UBOOT_LOG = "uboot.log"

class UBoot(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        open(os.path.join(self.outdir, UBOOT_LOG), "w").close()
        self.uboot_log = set()

        self.logger = getColoredLogger("plugins.uboot")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        # U-Boot
        self.uboot_env = self.get_arg("conf").get("uboot_env", dict())
        plugins.SendHypercall.subscribe("fw_setenv", self.cmd_fw_setenv)
        plugins.SendHypercall.subscribe("fw_getenv", self.cmd_fw_getenv)
        plugins.SendHypercall.subscribe("fw_printenv", self.cmd_fw_printenv)

    def cmd_fw_setenv(self, var, val):
        if var not in self.uboot_log:
            self.uboot_log.add(var)
            with open(os.path.join(self.outdir, UBOOT_LOG), "a") as f:
                f.write(f"{var}={val}\n")
        self.uboot_env[var] = val
        self.logger.debug(f"fw_setenv {var}={val}")
        return 0, ""

    def cmd_fw_getenv(self, var):
        try:
            return 0, self.uboot_env[var]
        except KeyError:
            if var not in self.uboot_log:
                self.uboot_log.add(var)
                with open(os.path.join(self.outdir, UBOOT_LOG), "a") as f:
                    f.write(var + "\n")
            self.logger.debug(f"fw_getenv {var}")
            return 1, ""

    def cmd_fw_printenv(self, arg):
        raise NotImplementedError("fw_printenv shim unimplemented")