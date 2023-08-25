import angr
import elftools
import logging
from sys import stderr

import logging
# Generally log at WARNING, but keep angr_targets.panda at DEBUG
logging.getLogger().setLevel('WARNING')
logging.getLogger('angr').setLevel('WARNING')
logging.getLogger("angr_targets.panda").setLevel('WARNING')

import angr
import claripy
import cle
import pandare
import capstone
from angr_targets import PandaConcreteTarget

import os
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"]="python"

from pandare import PyPlugin


EXTRACTED_FS = "/share/tikroot"
SCRATCH = "/share/tmp/"

class IoctlSimProcedure(angr.SimProcedure):
    def __init__(self, panda, *args, **kwargs):
        self.panda = panda
        super().__init__(*args, **kwargs)

    def run(self, fd, request, argp):
        # Return an unconstrained symbolic value
        return claripy.BVS('additional_ioctl_ret', self.panda.bits)

class PathExpIoctl(PyPlugin):
    '''
    PyPANDA plugin to examine return values from each IOCTL
    if we ever see an ICOTL in target_ioctls that returns an error,
    we run a symex with angr. We copy concrete PANDA state into
    angr as needed.
    '''
    def __init__(self, panda):
        self.panda = panda
        self.log_file = open(os.path.join(self.get_arg("outdir"), "symex.log"), "w")
        self.results = {} # {fname: {ioctl: {'ok': [constraint_set1, constraint_set2, ...], 'error': [constraint_set1, constraint_set2, ...]}}}

    def log(self, msg):
        logging.log(logging.INFO, msg)
        # If file is closed, we can't write to it
        if not self.log_file.closed:
            self.log_file.write(str(msg) + "\n")
            self.log_file.flush()

    def uninit(self):
        self.log_file.close()

    def get_map_info(self, cpu, ioctl_ret_addr):
        '''
        Enumerate memory mappings to find the target binary and libraries.
        Ensure libraries exist in scratch directory
        '''
        # Find target binary, and track library mappings
        target_binary = None
        target_base = None
        lib_opts = {}
        force_load_libs = []

        maps = self.panda.get_mappings(cpu)
        for m in maps:
            if m.file == self.panda.ffi.NULL:
                continue # Ignore non-file backed mappings

            fname = self.panda.ffi.string(m.file).decode()
            #self.log(f"Mapping from {m.base:x} to {m.base + m.size:x}: {fname}")

            if ioctl_ret_addr >= m.base and ioctl_ret_addr < m.base + m.size:
                #self.log("\tMapping contains return address for symex")
                target_base = m.base
                target_binary = fname

            if not os.path.isfile(EXTRACTED_FS + fname):
                self.log(f"Warning, could not find {fname} in extracted rootfs")
                continue

            # Copy the library into the stridelibs directory so angr can find it
            os.system(f"cp {EXTRACTED_FS}/{fname} {SCRATCH}/{os.path.basename(fname)}")

            # Add basename to lib_opts
            libname = os.path.basename(fname)

            # I think we'll always have 0 offset for code vs non-zero for data.
            # For each 0-offset mapping, we'll add it to the lib_opts so angr
            # can read it
            if m.offset == 0:
                lib_opts[libname] = {'base_addr': m.base}
                force_load_libs.append(libname)
        return target_binary, target_base, lib_opts, force_load_libs

    def make_symbolic_retval(self, state):
        # And also set the return value of the concretely-issued ioctl to be symbolic
        retval = claripy.BVS('target_ioctl_ret', self.panda.bits, explicit_name=True)
        if self.panda.arch_name == 'x86_64':
            state.regs.rax = retval
        elif self.panda.arch_name == 'i386':
            state.regs.eax = retval
        elif self.panda.arch_name == 'arm':
            state.regs.r0 = retval
        elif self.panda.arch_name == 'mips':
            state.regs.v0 = retval
        return retval, state
    
    def setup_project(self, cpu):
        if os.path.isdir(SCRATCH):
            os.system(f"rm -rf {SCRATCH}")
        os.makedirs(SCRATCH)

        ioctl_ret_addr = self.panda.arch.get_return_address(cpu)
        (target_binary, target_base, lib_opts, force_load_libs) = self.get_map_info(cpu, ioctl_ret_addr)
        panda_target = PandaConcreteTarget(self.panda)

        proj = angr.Project(EXTRACTED_FS + target_binary,
                            concrete_target=panda_target,
                            use_sim_procedures=True,
                            main_opts={'base_addr': target_base},
                            lib_opts=lib_opts,
                            force_load_libs=force_load_libs,
                            ld_path=SCRATCH,
                            auto_load_libs=False)
        
        state = proj.factory.entry_state(addr=self.panda.arch.get_pc(cpu))
        state.options.add(angr.options.SYMBION_SYNC_CLE)
        state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
        proj.hook_symbol('ioctl', IoctlSimProcedure(self.panda)) # Any subsequent calls to ioctl will also return symbolic
        return proj, state

    @PyPlugin.ppp_export
    def do_symex(self, cpu, name, no, argp):
        self.log(f"\nioctl {no:x} on {name}")

        # Setup our results dict
        if name not in self.results:
            self.results[name] = {}
        if no not in self.results[name]:
            self.results[name][no] = {'ok': [], 'error': []}
        proj, state = self.setup_project(cpu)

        # Get concrete state from panda and replace retval with symbolic val
        state.concrete.sync()
        (retval, state) = self.make_symbolic_retval(state)

        # Run symex for 50 BBs
        simgr = proj.factory.simgr(state)
        simgr.run(n=50)

        # Given a state, pull out all constraints that reference a given variable and drop others
        def extract_constraints(state, var_name):
            constraints = []
            for constraint in state.solver.constraints:
                if var_name in str(constraint):
                    constraints.append(constraint)
            return constraints

        # Now examine our results - we care about the error and active stashes
        these_results = []
        for i, s in enumerate(simgr.active):
            s.solver.simplify()
            these_results.append(extract_constraints(s, 'target_ioctl_ret'))
        self.results[name][no]['ok'].append(these_results)

        # Now add errors
        #these_errors = []
        #for i, s in enumerate(simgr.errored):
        #    these_errors.append(s.solver.constraints)
        #self.results[name][no]['error'].append(these_errors)

        print(f"RESULTS FOR {name} {no:x}")
        for prior_constrs in self.results[name][no]['ok']:
            print(prior_constrs)

        # Now return some results!
        rvs = set()
        # If we have a single set of results, just solve and return
        if len(self.results[name][no]['ok']) == 1:
            for i, s in enumerate(simgr.active):
                rvs.add(s.solver.min(retval))

        else:
            import itertools
            def synthesize_constraints(constraint_lists):
                # Flatten and deduplicate the constraints
                flattened_constraints = [constraint for symex in constraint_lists for path in symex for constraint in path]
                unique_constraints_dict = {str(c): c for c in flattened_constraints}
                unique_constraints = list(unique_constraints_dict.values())

                # Initialize the final constraints
                final_constraints = []

                state = proj.factory.blank_state()
                solver = state.solver

                # Create all unique pairs from the unique constraints
                for constraint_A, constraint_B in itertools.combinations(unique_constraints, 2):
                    # Test various combinations - if any are satisfiable, add them to the final constraints
                    if solver.satisfiable([constraint_A & constraint_B]):
                        final_constraints.append([constraint_A & constraint_B])
                    if solver.satisfiable([constraint_A & ~constraint_B]):
                        final_constraints.append([constraint_A & ~constraint_B])
                    if solver.satisfiable([~constraint_A & constraint_B]):
                        final_constraints.append([~constraint_A & constraint_B])
                    if solver.satisfiable([~constraint_A & ~constraint_B]):
                        final_constraints.append([~constraint_A & ~constraint_B])

                return final_constraints

            constrs = synthesize_constraints(self.results[name][no]['ok'])

            # Now we've got a list of constraints that are satisfiable, enumerate
            # all possible solutions
            for c in constrs:
                self.log(f"CONSTR: {c}")
                rvs.add(state.solver.min(retval, extra_constraints=c))

        result = list(rvs)
        for rv in result:
            self.log(f"\t{rv} ({rv:#x})")
        return result