# Hypercall based coverage tracking
import copy
from pandare import PyPlugin

class Coverage(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.in_vma_loop = False
        self.pending_proc = {}
        self.ppp_cb_boilerplate('on_hc_proc_change')
        self.ppp_cb_boilerplate('on_hc_proc_exec')
        self.ppp_cb_boilerplate('on_hc_proc_vma_update')

        self.vmas = []
        self.current_proc = None
        self.total_coverage = {} # procname: set of (modname, offset) tuples

        @panda.cb_start_block_exec
        def cov_sbe(cpu, tb):
            if self.current_proc is None or self.current_proc['ignore'] or self.current_proc['name'] == "vpn":
                return
            pc = tb.pc
            if name_mod_off := self.addr_to_mod_offset(pc):
                name, mod, off = name_mod_off
                #print(f"{name}: {mod}+{off}")
                if name not in self.total_coverage:
                    self.total_coverage[name] = set()
                self.total_coverage[name].add((mod, off))

        @panda.cb_guest_hypercall
        def on_hypercall(cpu):
            # Stride is... arm. Arg 0 (r0) is the hypercall number, r1 is arg
            num = panda.arch.get_arg(cpu, 0)
            arg = panda.arch.get_arg(cpu, 1)
                
            if num == 590:
                try:
                    self.pending_proc['name' ] = panda.read_str(cpu, arg)
                except ValueError:
                    self.pending_proc['name'] = "[error]"
            elif num == 591:
                self.pending_proc['pid'] = arg
            elif num == 592:
                self.pending_proc['ppid'] = arg
            elif num == 593:
                self.pending_proc['create_time'] = arg
            elif num == 594:
                self.pending_proc['ignore'] = arg != 0

                self.current_proc = copy.deepcopy(self.pending_proc)
                self.pending_proc = {}
                self.do_ppp('on_hc_proc_change', self.pending_proc)

            # Execve of new program (which is within an existing process)
            elif num in [595, 596]:
                # 595: kernel-task, 596: user-task
                is_user = num == 596
                try:
                    name = panda.read_str(cpu, arg)
                except ValueError:
                    name = "[error]"

                self.pending_proc['name'] = name

                self.do_ppp('on_hc_proc_exec', self.pending_proc)

            # VMA loop - build up a loop of VMAs
            elif num == 5910:
                # arg == 1: start, arg=2: finished one, arg=3: finished all
                if arg == 1 and not self.in_vma_loop:
                    # Starting
                    self.in_vma_loop = True
                    self.vmas = []
                    self.pending_vma = {}
                    # XXX we should run a on_hc_proc_vma_update callback with an empty list so clients
                    # don't see stale data mid-update
                    self.do_ppp('on_hc_proc_vma_update', self.vmas)

                elif arg == 2 and self.in_vma_loop:
                    # Finished a VMA. Move pending into our list, reset pending
                    if 'filename' not in self.pending_vma:
                        self.pending_vma['filename'] = "[?]"
                    self.vmas.append(self.pending_vma)
                    self.pending_vma = {}

                elif arg == 3 and self.in_vma_loop:
                    # Finished with all VMAs
                    self.in_vma_loop = False
                    #del self.pending_vma
                    self.do_ppp('on_hc_proc_vma_update', self.vmas)
                else:
                    print("ERROR: vma_loop_toggle with unexpected in_vma_loop", arg, self.in_vma_loop)

            elif num == 5911:
                if self.in_vma_loop:
                    self.pending_vma['vma_start'] = arg

            elif num == 5912:
                if self.in_vma_loop:
                    self.pending_vma['vma_end'] = arg

            elif num == 5913:
                if self.in_vma_loop:
                    # VMA has a name, read it out
                    try:
                        name = panda.read_str(cpu, arg)
                    except ValueError:
                        name = "[error]"
                    self.pending_vma['filename'] = name
            elif num == 5914:
                if self.in_vma_loop:
                    # VMA is special: We support three types: heap, stack, and ???
                    self.pending_vma['type'] = "[heap]" if arg == 1 else "[stack]" if arg == 2 else "[???]"
            else:
                return False # We didn't process the hypercall

            # We did process the hypercall
            return True


    def do_ppp(self, name, *args):
        #print("coverage runs PPP", name, args)
        pass

    def addr_to_mod_offset(self, addr):
        # Walk through VMAs, find the one that contains this address
        # returns (proc_name, module_name, offset)
        for vma in self.vmas:
            if addr >= vma['vma_start'] and addr < vma['vma_end']:
                return (self.current_proc['name'], vma['filename'] if 'filename' else None, addr - vma['vma_start'])
        return None
    
    def uninit(self):
        # Write out coverage data
        with open(self.outdir + "/coverage.log", "w") as f:
            for proc, cov in self.total_coverage.items():
                for mod, off in cov:
                    f.write(f"{proc}: {mod}+{off}\n")