from pandare import PyPlugin

from penguin import getColoredLogger, plugins

log = "nvram.csv"

# access: 0 = miss get, 1 = hit get, 2 = set, 3 = clear


class Nvram2(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.panda = panda
        self.logger = getColoredLogger("plugins.nvram2")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
        # Even at debug level, logging every nvram get/clear can be very verbose.
        # As such, we only debug log nvram sets

        plugins.subscribe(plugins.Events,'igloo_nvram_get_hit', self.on_nvram_get_hit)
        plugins.subscribe(plugins.Events,'igloo_nvram_get_miss', self.on_nvram_get_miss)
        plugins.subscribe(plugins.Events,'igloo_nvram_set', self.on_nvram_set)
        plugins.subscribe(plugins.Events,'igloo_nvram_clear', self.on_nvram_clear)

        with open(f"{self.outdir}/{log}", "w") as f:
            f.write("key,access,value\n")

    def on_nvram_get_hit(self, cpu, key):
        self.on_nvram_get(cpu, key, True)

    def on_nvram_get_miss(self, cpu, key):
        self.on_nvram_get(cpu, key, False)

    def on_nvram_get(self, cpu, key, hit):
        if "/" not in key:
            return
        key = key.split("/")[-1]  # It's the full /igloo/libnvram_tmpfs/keyname path

        status = "hit" if hit else "miss"
        with open(f"{self.outdir}/{log}", "a") as f:
            f.write(f"{key},{status},\n")
        self.panda.arch.set_arg(cpu, 1, 0)
        # self.logger.debug(f"nvram get {key} {status}")

    def on_nvram_set(self, cpu, key, newval):
        if "/" not in key:
            return
        key = key.split("/")[-1]  # It's the full /igloo/libnvram_tmpfs/keyname path
        with open(f"{self.outdir}/{log}", "a") as f:
            f.write(f"{key},set,{newval}\n")
        self.panda.arch.set_arg(cpu, 1, 0)
        self.logger.debug(f"nvram set {key} {newval}")

    def on_nvram_clear(self, cpu, key):
        if "/" not in key:
            return
        key = key.split("/")[-1]  # It's the full /igloo/libnvram_tmpfs/keyname path
        with open(f"{self.outdir}/{log}", "a") as f:
            f.write(f"{key},clear,\n")
        self.panda.arch.set_arg(cpu, 1, 0)
        # self.logger.debug(f"nvram clear {key}")
