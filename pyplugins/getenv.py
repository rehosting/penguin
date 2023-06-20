from pandare import PyPlugin

class GetEnv(PyPlugin):
    '''
    Use library hooking to record all programs that call getenv
    and the variable name they are looking for.
    '''
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.panda = panda
        self.got_args = [] # (progname, varname) tuples

        @panda.hook_symbol("libc-", "getenv")
        def hook_getenv(cpu, tb, h):
            # Get the procname
            procname = panda.get_process_name(cpu)

            # Get the argument
            arg = panda.arch.get_arg(cpu, 0)
            try:
                s = panda.read_str(cpu, arg)
            except ValueError:
                s = None

            if s is None and procname is None:
                return

            self.got_args.append((procname, s))

    def uninit(self):
        with open(self.outdir + "/getenv.csv", "w") as f:
            f.write("progname,varname\n")
            for progname, varname in self.got_args:
                f.write(f"{progname},{varname}\n")