from pandare import PyPlugin
import os
try:
    from penguin import PenguinAnalysis, yaml
except ImportError:
    # We can still run as a PyPlugin, but we can't do post-run analysis
    import yaml
    PenguinAnalysis = object

class Core(PyPlugin):
    '''
    Simple sanity check. Create .ran in outdir if and only if
    we don't see a kernel error in console.log and no python error
    in qemu_stderr.txt (XXX: can we detect python errors from here?)
    '''
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")

    def uninit(self):
        # Create .ran
        open(os.path.join(self.outdir, ".ran"), "w").close()

class CoreAnalysis(PenguinAnalysis):
    ANALYSIS_TYPE = "core"
    def parse_failures(self, output_dir):
        '''
        We don't really parse failures mitigations, we just make sure there's no python
        errors during our analysis
        '''
        # First: sanity checks. Do we see any errors in console.log? If so abort
        with open(os.path.join(output_dir, "console.log"), "rb") as f:
            for line in f:
                if b"BUG" in line:
                    print(f"KERNEL BUG: {repr(line)}")
                    raise RuntimeError(f"Found BUG in {output_dir}/console.log")

        with open(os.path.join(output_dir, "qemu_stderr.txt")) as f:
            for line in f.readlines():
                if "Traceback " in line:
                    raise RuntimeError(f"Python analysis crashed in {output_dir}")
        return {}

    def get_potential_mitigations(self, config, path_ioctl, info):
        return []

    def implement_mitigation(self, config, failure, mitigation):
        raise NotImplementedError("Core doesn't do mitigations")