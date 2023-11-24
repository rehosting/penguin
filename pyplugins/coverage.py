# Hypercall based coverage tracking
import copy
from pandare import PyPlugin

class Coverage(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        panda.load_plugin("track_proc_hc")
        panda.load_plugin("proc_map", {"outfile": self.outdir + "/coverage_tree.csv"})
        panda.load_plugin("pandata_cov", {"outfile": self.outdir + "/coverage.csv"})