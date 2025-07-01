# Hypercall based coverage tracking
from pandare2 import PyPlugin


class Coverage(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        config = self.get_arg("conf")
        self.panda = panda
        if config["core"].get("early_monitoring", False):
            self.start_coverage()
        else:
            self.panda.subscribe("igloo_init_done", self.start_coverage)

    def start_coverage(self, *args, **kwargs):
        self.panda.load_plugin("track_proc_hc")
        self.panda.load_plugin("proc_map", {"outfile": self.outdir + "/coverage_tree.csv"})
        self.panda.load_plugin("pandata_cov", {"outfile": self.outdir + "/coverage.csv"})

        # Must enable this in kernel boot args, otherwise kernel won't hypercall with memory layout info
        self.get_arg("conf")["env"]["igloo_log_cov"] = "1"
