from pandare import PyPlugin

log = "nvram.csv"

class Nvram2(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.panda = panda
        self.ppp.Core.ppp_reg_cb('igloo_nvram_get', self.on_nvram_get)
        with open(f'{self.outdir}/{log}', "w") as f:
            f.write("key,hit\n")


    def on_nvram_get(self, cpu, key, hit):
        if '/' not in key:
            return
        key = key.split("/")[-1] # It's the full /igloo/libnvram_tmpfs/keyname path

        with open(f'{self.outdir}/{log}', 'a') as f:
            f.write(f'{key},{1 if hit else 0}')
        self.panda.arch.set_arg(cpu, 1, 0)