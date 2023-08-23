import angr
import elftools
import logging
from sys import stderr

import angr
import claripy
import cle
import pandare
import capstone
import logging
from angr_targets import PandaConcreteTarget

import os
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"]="python"

from pandare import PyPlugin

# Generally log at WARNING, but keep angr_targets.panda at DEBUG
logging.getLogger().setLevel('WARNING')
logging.getLogger('angr').setLevel('WARNING')
logging.getLogger("angr_targets.panda").setLevel('DEBUG')

class IoctlSimProcedure(angr.SimProcedure):
    def run(self, fd, request, argp):
        # Return an unconstrained symbolic value
        return claripy.BVS('ioctl_ret', panda.bits)

class SleepSimProcedure(angr.SimProcedure):
    def run(self, fd, request, argp):
        return None

class PathExpIoctl(PyPlugin):
    '''
    PyPANDA plugin to examine return values from each IOCTL
    if we ever see an ICOTL in target_ioctls that returns an error,
    we run a symex with angr. We copy concrete PANDA state into
    angr as needed.
    '''
    def __init__(self, panda):
        self.panda = panda
        self.ptr_size = int(panda.bits/8)
        self.log_file = open(os.path.join(self.get_arg("outdir"), "symex.log"), "w")
        self.target_ioctls = [0x40046401] # XXX TESTING - stride

        # On each ioctl return
        @panda.ppp("syscalls2", "on_sys_ioctl_return")
        def pei_post_ioctl(cpu, pc, fd, no, argp):
            rval = panda.arch.get_retval(cpu, convention='syscall')

            #if no not in self.target_ioctls or rval >= 0:
            if rval >= 0:
                # Not one we're tracking or no error
                return
            
            if rval != -25:
                # Not -25 (ENOTTY)? We don't care
                return

            self.log(f"Considering symex for ioctl {no:x} as it returns {rval}")
            name = self.panda.get_file_name(cpu, fd).decode()

            if name.startswith("/dev/") or name.startswith("/proc"):
                self.log(f"Running symex for {no:x} on {name}")
                self.do_symex(cpu, pc, fd, name, no, argp)

    def log(self, msg):
        logging.log(logging.INFO, msg)
        self.log_file.write(str(msg) + "\n")

    def do_symex(self, cpu, pc, fd, dev_name, no, argp):
        # Where are we returning to? That's where we'll start symex
        ioctl_ret_addr = self.panda.arch.get_return_address(cpu)
        self.log(f"IOCTL {no:x} will return to {ioctl_ret_addr:#x}")


        callmap = {} # callstack -> module + offset
        target_binary = None
        target_base = None

        # We'll read the current module that PC is at (libc?) in addition
        # to the return address
        cur_pc = self.panda.arch.get_pc(cpu)
        cur_pc_data = None
        cur_pc_base = None

        self.log("Create target...")
        panda_target = PandaConcreteTarget(self.panda)
        lib_opts = {} # libname {'base_addr': x}
        force_load_libs = []

        # Find target binary, and track library mappings
        maps = self.panda.get_mappings(cpu)
        for m in maps:
            if m.file == self.panda.ffi.NULL:
                continue # Ignore non-file backed mappings

            fname = self.panda.ffi.string(m.file).decode()
            self.log(f"Mapping from {m.base:x} to {m.base + m.size:x}: {fname}")

            if ioctl_ret_addr >= m.base and ioctl_ret_addr < m.base + m.size:
                self.log("\tMapping contains return address for symex")
                target_base = m.base
                target_binary = fname
                continue # Don't set this up twice, we'll set it up as our main binary when creating the angr project

            if cur_pc >= m.base and cur_pc < m.base + m.size:
                self.log("\tMapping contains current PC")

            if not os.path.isfile("/share/strideroot/" + fname):
                self.log(f"Warning, could not find {fname} in extracted rootfs")
                continue

            # Copy file from /share/strideroot to /share/stridelibs
            os.makedirs("/share/stridelibs/", exist_ok=True)
            # Copy the library into the stridelibs directory so angr can find it
            os.system(f"cp /share/strideroot/{fname} /share/stridelibs/{os.path.basename(fname)}")

            # Add basename to lib_opts
            libname = os.path.basename(fname)

            # TODO: is offset going to work? Should we only do for zero offset?
            #lib_opts[libname] = {'base_addr': m.base, 'offset': m.offset}
            if m.offset == 0:
                lib_opts[libname] = {'base_addr': m.base}
                force_load_libs.append(libname)
            else:
                self.log(f"\tWarning, ignoring non-zero offset for {libname}")


            '''
            if m.size > 0:
                binary = cle.Loader("/share/strideroot/" + fname,
                                    main_opts={'base_addr': m.base})

                # Map the loaded binary into the project's memory
                for obj in binary.all_objects:
                    for seg in obj.segments:
                        start_addr = seg.min_addr
                        data = obj.memory.load(seg.min_addr, seg.memsize)
                        proj.loader.memory.add_backer(start_addr, data)
                        self.log(f"Writing {seg.memsize} bytes to {start_addr:#x} from {fname}")
            '''

        self.log("Create project...")

        proj = angr.Project("/share/strideroot/" + target_binary,
                            concrete_target=panda_target,
                            use_sim_procedures=True,
                            main_opts={'base_addr': target_base},
                            lib_opts=lib_opts,
                            force_load_libs=force_load_libs,
                            ld_path="/share/stridelibs/",
                            auto_load_libs=False)
        

        self.log(f"Loaded {target_binary} into angr")
        state = proj.factory.entry_state(addr=cur_pc)
        state.options.add(angr.options.SYMBION_SYNC_CLE)
        state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
        proj.hook_symbol('ioctl', IoctlSimProcedure()) # Any subsequent calls to ioctl will also return symbolic
        proj.hook_symbol('sleep', SleepSimProcedure()) # Any subsequent calls to ioctl will also return symbolic
        #proj.hook(14d00) # SLEEP
        self.run_symex(proj, state)


    def uninit(self):
        self.log_file.close()

    def run_symex(self, proj, state):
        # Get concrete state from panda
        self.log("Running symex. Start by syncing concrete state from PANDA")
        state.concrete.sync()

        # And also set the return value of the concretely-issued ioctl to be symbolic
        retval = claripy.BVS('ioctl_ret', self.panda.bits)
        if self.panda.arch_name == 'x86_64':
            state.regs.rax = retval
        elif self.panda.arch_name == 'i386':
            state.regs.eax = retval
        elif self.panda.arch_name == 'arm':
            state.regs.r0 = retval
        elif self.panda.arch_name == 'mips':
            state.regs.v0 = retval

        '''
        class SyscallHandler(angr.SimProcedure):
            def run(self, syscall_num):
                self.log("Skipping syscall", self.state.solver.eval(syscall_num))
                if not hasattr(self.state.globals, 'syscalls'):
                    self.state.globals['syscalls'] = []
                self.state.globals['syscalls'].append(syscall_num)
                return 0  # Return value for the syscall


        # MIPS HACK - hook syscall handler?
        proj.hook(0x40253c, SyscallHandler())
        '''

        # Run our symbolic execution
        simgr = proj.factory.simgr(state)

        # Explore until program terminates
        #simgr.explore()

        # Debug: explore short
        #simgr.run(n=80)

        def step_callback(simgr):
            if simgr.active:
                for state in simgr.active:
                    self.log(f"Executing block at address: {state.addr:#x}")
                    #proj.factory.block(state.addr).vex.pp()
                    

        # Debug run 80 BBs, and log
        simgr.run(n=80, step_func=step_callback)

        def _report(i, s, name=None):
            # Find a concrete value that meets the constraints
            model = s.solver.eval(retval)
            model_s = self.panda.from_unsigned_guest(model)
            # Get stdout
            stdout = s.posix.dumps(1)

            #self.log(f"State {(name + ' ') if name else '' + i}: ioctl return of {model} reaches output {repr(stdout.decode('utf-8'))}")
            self.log(f"State {i} {(' ' + name) if name else ''}: ioctl return of {model} (signed {model_s}")
            s.solver.simplify()
            for constraint in s.solver.constraints:
                self.log("\t"+str(constraint))

        self.log(simgr)

        try:
            self.log(simgr.errored[0])
        except Exception:
            pass

        for i, s in enumerate(simgr.active):
            _report(i, s, 'active')

        # Print details of each distinct state, constraints, and stdout
        for i, s in enumerate(simgr.deadended):
            _report(i, s, 'deadended')

if __name__ == '__main__':
    from pandare import Panda
    panda = Panda(generic="x86_64")
    panda.load_plugin("osi")
    panda.pyplugins.load(PathExpIoctl)


    @panda.queue_blocking
    def run():
        panda.revert_sync("root")
        print(panda.run_serial_cmd("hdparm /dev/random"))
        panda.end_analysis()


    @panda.ppp("syscalls2", "on_sys_ioctl_enter")
    def pre_ioctl(cpu, pc, fd, no, argp):
        print(f"ENTER ioctl {no:#x} on {fd} at {pc:#x}")

    @panda.ppp("syscalls2", "on_sys_ioctl_return")
    def post_ioctl(cpu, pc, fd, no, argp):
        rv = panda.arch.get_retval(cpu, convention='syscall')
        print(f"EXIT ioctl {no:#x} on {fd} at {pc:#x} returns {rv}")

    panda.run()
