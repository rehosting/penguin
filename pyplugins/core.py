from pandare import PyPlugin
import os

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

def propose_mitigations(config, result_dir, quiet=False):
    '''
    We don't really propose mitigations, we just make sure there's no python
    errors during our analysis
    '''
    # First: sanity checks. Do we see any errors in console.log? If so abort
    with open(os.path.join(result_dir, "console.log"), "rb") as f:
        for line in f:
            if b"BUG" in line:
                print(f"KERNEL BUG: {repr(line)}")
                raise RuntimeError(f"Found BUG in {result_dir}/console.log")

    with open(os.path.join(result_dir, "qemu_stderr.txt")) as f:
        for line in f.readlines():
            if "Traceback " in line:
                raise RuntimeError(f"Python analysis crashed in {result_dir}")
    return []