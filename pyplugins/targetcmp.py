from pandare import PyPlugin
import yaml
from os.path import dirname

class TargetCmp(PyPlugin):
    def __init__(self, panda):
        outdir = self.get_arg("outdir")

        with open(dirname(self.outdir) + "/config.yaml", "r") as f:
            self.current_config = yaml.safe_load(f)

        if 'DYNVAL' in self.current_config['base']['append']:
            # Config specifies DYNVAL, so we'll dynamically analyze
            panda.load_plugin("callstack_instr", args={"stack_type": "asid"})
            panda.load_plugin("targetcmp", args={"outdir": outdir, "target_str": "DYNVAL"})