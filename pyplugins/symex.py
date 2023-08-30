import angr
import elftools
import logging
from sys import stderr
import pickle
import itertools

import time
import logging

#logging.getLogger().setLevel('DEBUG')
logging.getLogger().setLevel('WARNING')
logging.getLogger('angr').setLevel('WARNING')
logging.getLogger("angr_targets.panda").setLevel('WARNING')

import angr
import claripy
import cle
import capstone
from angr_targets import PandaConcreteTarget

import os
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"]="python"


EXTRACTED_FS = "/share/tikroot"
SCRATCH = "/share/tmp/"

class IoctlSimProcedure(angr.SimProcedure):
    def __init__(self, panda, *args, **kwargs):
        self.panda = panda
        super().__init__(*args, **kwargs)

    def run(self, fd, request, argp):
        # Return an unconstrained symbolic value
        return claripy.BVS('additional_ioctl_ret', self.panda.bits)

class PathExpIoctl():
    '''
    Plugin to symbolically execute IOCTLs and track constraints that lead to distinct paths
    '''
    def __init__(self, out_dir, read_only = False):
        self.log_file = open(os.path.join(out_dir, "symex.log"), "w" if not read_only else "r")
        self.read_only = read_only
        self.result_path = os.path.join(out_dir, "symex.pkl")
        self.results = {} # {fname: {ioctl: {'ok': [constraint_set1, constraint_set2, ...], 'error': [constraint_set1, constraint_set2, ...]}}}

    def angr_block(self, state):
        """
        Debug callback - Print before block before we execute it
        """
        # Use angr's pp method on the current block
        state.block().pp()

    def log(self, msg):
        logging.log(logging.INFO, msg)
        # If file is closed, we can't write to it
        if not self.log_file.closed and not self.read_only:
            self.log_file.write(str(msg) + "\n")
            self.log_file.flush()

    def get_map_info(self, panda, cpu, ioctl_ret_addr):
        '''
        Enumerate memory mappings to find the target binary and libraries.
        Ensure libraries exist in scratch directory
        '''
        # Find target binary, and track library mappings
        target_binary = None
        target_base = None
        lib_opts = {}
        force_load_libs = []

        maps = panda.get_mappings(cpu)
        for m in maps:
            if m.file == panda.ffi.NULL:
                continue # Ignore non-file backed mappings

            fname = panda.ffi.string(m.file).decode()
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

    def make_symbolic_retval(self, state, panda):
        # And also set the return value of the concretely-issued ioctl to be symbolic
        nbits = panda.bits
        retval = claripy.BVS('target_ioctl_ret', nbits, explicit_name=True)
        if panda.arch_name == 'x86_64':
            state.regs.rax = retval
        elif panda.arch_name == 'i386':
            state.regs.eax = retval
        elif panda.arch_name == 'arm':
            state.regs.r0 = retval
        elif panda.arch_name == 'mips':
            state.regs.v0 = retval
        return retval, state

    def make_symbolic_buffer(self, state, panda, size):
        # And also set the return value of the concretely-issued ioctl to be symbolic
        retbuf = claripy.BVS('target_ioctl_buffer', size, explicit_name=True)
        if panda.arch_name == 'x86_64':
            state.regs.rdx = retbuf
        elif panda.arch_name == 'i386':
            state.regs.edx = retbuf
        elif panda.arch_name == 'arm':
            state.regs.r2 = retbuf
        elif panda.arch_name == 'mips':
            state.regs.a2 = retbuf

        return retbuf, state
    
    def setup_project(self, panda):
        if os.path.isdir(SCRATCH):
            os.system(f"rm -rf {SCRATCH}")
        os.makedirs(SCRATCH)

        cpu = panda.get_cpu() 
        ioctl_ret_addr = panda.arch.get_return_address(cpu)
        (target_binary, target_base, lib_opts, force_load_libs) = self.get_map_info(panda, cpu, ioctl_ret_addr)
        panda_target = PandaConcreteTarget(panda)

        proj = angr.Project(EXTRACTED_FS + target_binary,
                            concrete_target=panda_target,
                            use_sim_procedures=True,
                            main_opts={'base_addr': target_base},
                            lib_opts=lib_opts,
                            force_load_libs=force_load_libs,
                            ld_path=SCRATCH,
                            auto_load_libs=False)
        
        state = proj.factory.entry_state(addr=panda.arch.get_pc(cpu))
        state.options.add(angr.options.SYMBION_SYNC_CLE)
        state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
        proj.hook_symbol('ioctl', IoctlSimProcedure(panda)) # Any subsequent calls to ioctl will also return symbolic
        return proj, state

    def do_symex(self, panda, name, no, argp):
        self.log(f"\nioctl {no:x} on {name}")

        # Setup our results dict
        if name not in self.results:
            self.results[name] = {}
        if no not in self.results[name]:
            self.results[name][no] = {'ok': [], 'error': []}
        proj, state = self.setup_project(panda)

        # Get concrete state from panda and replace retval with symbolic val
        state.concrete.sync()
        self.log(f"State is {state}")

        decoded = self.decode_ioctl(no)
        buf_size = 0
        if decoded['Direction'] in ['IOR', 'IOWR']:
            # Userspace is planning to READ from the buffer - we should make this buffer
            # symbolic. Yikes.
            buf_size = decoded['Argument Size']


        #state.inspect.b('statement', action=self.angr_block, when=angr.BP_BEFORE)

        (retval, state) = self.make_symbolic_retval(state, panda)
        
        buffer = None
        if buf_size:
            (buffer, state) = self.make_symbolic_buffer(state, panda, buf_size)

        # Run symex for 50 BBs. Timeout at 1 minute
        simgr = proj.factory.simgr(state)
        # Run for 50 basic blocks or until 60s timeout? Not positive we can have both
        #simgr.use_technique(angr.exploration_techniques.Timeout(60))
        simgr.run(n=50)

        self.log(f"Simgr has {len(simgr.active)} active states, {len(simgr.deadended)} deadended states, and {len(simgr.errored)} errored states")

        # For each errored state, log
        for i, s in enumerate(simgr.errored):
            self.log(f"Errored state #{i}: {s.error}")

        # Now log deadended states
        for i, s in enumerate(simgr.deadended):
            self.log(f"Deadended state #{i}: {s}")

        # Now examine our results and collect relative constraints
        # TODO: is there a way to get constraints from the error stash (i.e., what should we avoid?)
        concrete_rvs = set() # Concrete return values
        these_results = [] # List of lists of constraints with retval
        for i, s in enumerate(simgr.active + simgr.deadended):
            s.solver.simplify()
            concrete_rvs.add(s.solver.min(retval))

            rel_constraints = []
            for constraint in s.solver.constraints:
                if 'target_ioctl_ret' in str(constraint) or 'target_ioctl_buffer' in str(constraint):
                    rel_constraints.append(constraint)
            these_results.append(rel_constraints)

        self.results[name][no]['ok'].append(these_results)

        result = list(concrete_rvs)
        self.log("Results:")
        for rv in result:
            self.log(f"\t{rv} ({rv:#x})")
        return result

    def save_results(self):
        '''
        Dump results to a pickle file at symex.pkl
        '''
        self.log("\n----\nSaving results:")
        for fname, details in self.results.items():
            self.log(f"\t{fname}")
            for ioctl, results in details.items():
                self.log(f"\t\tIOCTL {ioctl:#x}")
                self.log(f"\t\t\t{results['ok']}")

        with open(self.result_path, 'wb') as f:
            f.write(pickle.dumps(self.results, -1))

    def _load_results(self):
        with open(self.result_path, 'rb') as f:
            self.results = pickle.loads(f.read())

    def get_known_values(self):
        '''
        Return details of all filenames and IOCTLs we've analyzed
        in the format {fname: [ioctl1, ioctl2]}
        '''
        if not len(self.results):
            self._load_results()
        return {fname: list(self.results[fname].keys()) for fname in self.results}


    def synthesize_constraints(self, solver, constraint_lists):
        # Flatten and deduplicate the constraints
        flattened_constraints = [constraint for symex in constraint_lists for path in symex for constraint in path]
        unique_constraints_dict = {str(c): c for c in flattened_constraints}
        unique_constraints = list(unique_constraints_dict.values())

        # Initialize the final constraints
        final_constraints = []

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

    def find_distinct_paths(self, path, no, nbits):
        if not len(self.results):
            self._load_results()

        if path not in self.results or no not in self.results[path]:
            raise ValueError(f"No results for {path} {no}")

        # Just need a solver, doesn't matter what project's backed by?
        proj = angr.Project('/bin/true')
        state = proj.factory.blank_state()
        solver = state.solver

        # With explicit_name=True, we can just reconstruct the symbolic variable(?)
        retval = claripy.BVS('target_ioctl_ret', nbits, explicit_name=True)

        constrs = []
        if len(self.results[path][no]['ok']) == 0:
            return []

        elif len(self.results[path][no]['ok']) == 1:
            # No need to combine pairs - we did a single run so 
            # data contains [[constraints1_part1, constraints1_part2], [...]]
            for c in self.results[path][no]['ok'][0]:
                constrs.append(state.solver.And(*c))

        else:
            # We have multiple runs for this fname and ioctl.
            # Let's combine the constraints between runs
            combined_constraints = set() # String reprs
            # Iterate through all pairs of runs
            for run1, run2 in itertools.combinations(self.results[path][no]['ok'], 2):
                # Iterate through all pairs of states within the selected runs
                for c1 in run1:
                    for c2 in run2:
                        # Combine constraints within each state using AND
                        constraints1 = state.solver.And(*c1)
                        constraints2 = state.solver.And(*c2)
                        
                        # Combine the constraints of the two states using AND
                        new_constraints = state.solver.And(constraints1, constraints2)
                        
                        # Check if the new constraints are satisfiable
                        if state.solver.satisfiable(extra_constraints=[new_constraints]):
                            # Convert the constraints to a string for comparison
                            constraint_str = str(new_constraints)
                            if constraint_str not in combined_constraints:
                                combined_constraints.add(constraint_str)
                                constrs.append(new_constraints)

        rvs = set()
        for c in constrs:
            rvs.add(solver.min(retval, extra_constraints=[c]))

        rvs = list(rvs)
        def custom_sort_key(num):
            # Return a tuple that will guide the sort operation.
            # Positive (small to big), negative (big to small), then 0
            # We pick 0 last because it's our default before we specify something
            if num == 0:
                return (3, 0)
            elif num >= 2**(nbits-1): # If highest bit is set, it's negative
                return (2, num - 2**nbits) # Gets us the negative value
            else: # Else it's positive
                return (1, num) # Gets us the positive value

        return sorted(rvs, key=custom_sort_key)

    @staticmethod
    def decode_ioctl(ioctl_number):
        direction_enum = ["IO", "IOW", "IOR", "IOWR"]
        direction = (ioctl_number >> 30) & 0x03
        arg_size = (ioctl_number >> 16) & 0x3FFF
        cmd_num = (ioctl_number >> 8) & 0xFF
        type_num = ioctl_number & 0xFF

        return {
            "Direction": direction_enum[direction],
            "Argument Size": arg_size,
            "Command Number": cmd_num,
            "Type Number": type_num
        }

    def hypothesize_models(self):
        models = {} # {"/dev/device": {ioctl: [likeliest value, 2nd likliest value...]}
        try:
            known_values = self.get_known_values()
        except FileNotFoundError:
            return {}

        for fname, nums in known_values.items():
            models[fname] = {}

            for n in nums:
                paths = self.find_distinct_paths(fname, n, 32)

                if not len(paths):
                    print("\tWarning: no paths found - return 0")
                    paths = [0]

                models[fname][n] = paths
        return models


if __name__ == '__main__':
    symex = PathExpIoctl('/home/andrew/git/igloo/output/debug_mtik/runs/children/2/output0/', read_only=True)

    for fname, nums in symex.get_known_values().items():
        print("\nDevice: ", fname)

        for n in nums:
            print(f"Ioctl {n:#x}:")
            paths = symex.find_distinct_paths(fname, n, 32)
            for p in paths:
                print(f"\t{p:#x}")

            if not len(paths):
                print("\tWarning: no paths found")