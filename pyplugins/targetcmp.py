from pandare import PyPlugin

class TargetCmp(PyPlugin):
    def __init__(self, panda):
        outdir = self.get_arg("outdir")
        panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
        panda.load_plugin("targetcmp", args={"outdir": outdir, "target_str": "DYNVAL"})