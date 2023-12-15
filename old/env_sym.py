from pandare import PyPlugin

from sys import path
from os.path import dirname
# Add this directory to python path so we can import symex
path.append(dirname(__file__))

from symex import PathExpEnv

'''
This script is an analysis pass that tries to identify what values kernel variables might be set to.
Unlike ioctl solving this is A) tricky and B) not used to solve things on demand - just to record
what values might be set to (i.e., after the hypothesis phase)
'''

def var_interesting(var):
    for prefix in ["LC_", "LD_", "XDG_", "QT_", "GTK_", "GDK_", "GIO_", "PERL"]:
        if var.startswith(prefix):
            return False
        
    # Other unimportant variables we've seen before (expand as needed)
    if var in   'BLKID_FILE \
                CONSOLE \
                HOME \
                HZ \
                KRB5CCNAME \
                LANG \
                LANGUAGE \
                LOCALDOMAIN \
                LOCPATH \
                MKE2FS_CONFIG \
                MKE2FS_DEVICE_SECTSIZE \
                MKE2FS_SYNC \
                NLDBG \
                PATH \
                POSIXLY_CORRECT \
                PROC_NET_PSCHED \
                PROC_ROOT \
                RES_OPTIONS \
                SHELL \
                SNMPCONFPATH \
                SNMPDLMODPATH \
                SNMP_PERSISTENT_DIR \
                SNMP_PERSISTENT_FILE \
                TICKS_PER_USEC \
                TMPDIR \
                TZ'.split():
        return False

    # Otherwise it IS interesting
    return True

class EnvSym(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.seen = set()
        
        self.do_symex = False
        if self.do_symex:
            self.symex = PathExpEnv(self.outdir)

        # Getenv
        @panda.hook_symbol("libc-", "getenv")
        def hook_getenv(cpu, tb, h):
            try:
                varname = panda.read_str(cpu, panda.arch.get_arg(cpu, 0))
            except ValueError:
                print("Failed to read env var name")
                return
            
            if not var_interesting(varname):
                return
            
            #if varname in self.seen:
            #    print("Skipping subsequent getenv of", varname)
            #    return

            if varname in ["LOOPER_VERBOSE"]:
                #print("DEBUG skipping getenv on", varname)
                return

            if varname not in ["arch"]:
                #print("DEBUG2 skipping getenv on", varname)
                return
            
            retaddr = panda.arch.get_return_address(cpu)

            @panda.hook(retaddr)
            def hook_getenv_ret(cpu, tb, h):
                h.enabled = False
                val_ptr = panda.arch.get_retval(cpu)
                val_len = 0
                try:
                    s = panda.read_str(cpu, val_ptr)
                    val_len = len(s)
                except ValueError:
                    pass

                if panda.arch.get_retval(cpu) == 0:
                    # getenv returned NULL. Two choices
                    # 1) run a symex from here with a symbolic buffer returned
                    # 2) Write this down and on a subsequent run set to a magic string and look for comparisons
                    print(f"GetEnv for {varname} => {s} ({val_len})")
                    if self.do_symex:
                        self.symex.do_symex(panda, varname, val_ptr, val_len)
                    self.seen.add(varname)

        '''
        @panda.ppp("syscalls2", "on_sys_open_enter")
        def hook_open(cpu, tb, h, path, flags, mode):
            try:
                fname = panda.read_str(cpu, path).decode()
            except ValueError:
                return
            if fname == "/proc/cmdline":
                print("PROC CMDLINE READ TODO")
        '''

    def uninit(self):
        # Tell angrypanda to save results
        if self.do_symex:
            self.symex.save_results()
        else:
            # Save the list of seen variables in self.outdir/env_vars.txt
            with open(f"{self.outdir}/env_vars.txt", "w") as f:
                for var in sorted(self.seen):
                    f.write(f"{var}\n")


if __name__ == "__main__":
    import sys, pandare
    if len(sys.argv) < 2:
        raise RuntimeError(f"USAGE {sys.argv[0]} [outdir]")
    
    panda = pandare.Panda(generic="x86_64")
    panda.pyplugins.load(EnvSym, {"outdir": sys.argv[1]})

    @panda.queue_blocking
    def driver():
        panda.revert_sync("root")
        print(panda.run_serial_cmd("python3 -c 'print(1)'"))
        panda.end_analysis()
    panda.run()
