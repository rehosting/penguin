# Hypercall based coverage tracking
import copy
from pandare import PyPlugin

class Coverage(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")

        # TODO: create and load coverage plugin, then pass outdir to coverage
        panda.load_plugin("track_proc_hc")
        panda.load_plugin("proc_map")
        panda.load_plugin("pandata_cov")