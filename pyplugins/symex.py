import itertools
import logging
import os
import pickle
import tarfile
import tempfile

import angr
import claripy
from angr_targets import PandaConcreteTarget # pylint: disable=import-error

# Silence a bunch of angr logging
logging.getLogger().setLevel('WARNING')
logging.getLogger('angr').setLevel('WARNING')
logging.getLogger("angr_targets.panda").setLevel('WARNING')
logging.getLogger("cle.loader").setLevel('ERROR')
logging.getLogger("cle.backends.externs").setLevel('ERROR')
logging.getLogger("angr.simos.linux").setLevel('ERROR')

# Does this actually help? Need happy protobufs instead of sad panda protobufs
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"]= "python"

# DEBUG callback for logging each BB when doing symex
DBG_LAST_BB = None
def angr_block(state):
    """
    Debug callback - Print before block before we execute it
    """
    # Use angr's pp method on the current block

    global DBG_LAST_BB
    if DBG_LAST_BB != state.block().addr:
        state.block().pp()
        DBG_LAST_BB = state.block().addr

class IoctlSimProcedure(angr.SimProcedure):
    '''
    SimProcedure to return a unconstrained symbolic value for an IOCTL
    '''
    def __init__(self, panda, *args, **kwargs):
        self.panda = panda
        super().__init__(*args, **kwargs)

    def run(self, *_):
        # Return an unconstrained symbolic value
        return claripy.BVS('additional_ioctl_ret', self.panda.bits)

class PathExpIoctl:
    '''
    Plugin to symbolically execute IOCTLs and track constraints that lead to distinct paths
    '''
    def __init__(self, out_dir, fs_archive, read_only = False):
        # Set up log and results paths in out_dir
        self.logger = logging.getLogger(__name__)
        if read_only and not os.path.isfile(os.path.join(out_dir, "symex.pkl")):
            self.has_data_or_writing = False # either we have results, or we're writing results
        else:
            self.has_data_or_writing = True
        # Store fs_archive
        self.fs_archive = fs_archive
        self.read_only = read_only

        # Initialize remaining state
        self.results = {} # {fname: {ioctl: {'ok': [constraint_set1, constraint_set2, ...],
                          # 'error': [constraint_set1, constraint_set2, ...]}}}
        self.result_path = os.path.join(out_dir, "symex.pkl")

        if self.has_data_or_writing:
            self.log_file = open(os.path.join(out_dir, "symex.log"), "w" if not read_only else "r",
                                encoding='utf-8')

    def uninit(self):
        if self.has_data_or_writing and not self.log_file.closed:
            self.log_file.close()

    def do_symex(self, panda, cpu, targ_addr, name, num):
        '''
        Main entrypoint after initial state is set. Given current concrete PANDA state
        at an IOCTL return, run symex in order identify distinct reachable paths
        '''
        self.log(f"do_symex for ioctl {num:x} on {name}")

        # We're hooking at syscall return. This is often libc's ioctl function or another
        # library, not a part of the main binary. But it seems to work anyway! (previously
        # we were getting the "return address" which was just coincidentally working)
        # Targ_addr tells us this address

        # Initialize project and state using panda's concrete state and the target address
        proj, state = self.setup_project_state(panda, targ_addr)

        # Hook ioctl to return symbolic values - not sure if it's necessary
        proj.hook_symbol('ioctl', IoctlSimProcedure(panda))

        # DEBUG: Trace all blocks
        #state.inspect.b('statement', action=angr_block, when=angr.BP_BEFORE)

        # Write symbolic return value into the state
        sym_retval = claripy.BVS('target_ioctl_ret', panda.bits, explicit_name=True)
        state = self.set_retval(state, panda, sym_retval, convention='syscall')

        # Write symbolic argument buffer into state if the IOCTL number indicates
        # that userspace will be reading from it.
        decoded = self.decode_ioctl(num)
        if decoded['Direction'] in ['IOR', 'IOWR']:
            # Userspace is planning to READ from the buffer - we should make this buffer
            # symbolic. Yikes. TODO: we could take the return address here as sym_arg
            # and pass through to collapse_results
            self.make_symbolic_buffer(state, panda, decoded['Argument Size'])

        # Create our simulation manager and run it.
        # TODO: which strategy is best for us? Is there a way to use a timeout + limit on BBs?
        simgr = proj.factory.simgr(state)
        #simgr.use_technique(angr.exploration_techniques.Timeout(60)) # Timeout at 60s
        simgr.run(n=50) # 50 BBs

        # Report simgr state to log
        self.log_simgr(simgr)

        # Update our results dictionary and return
        return self.collapse_results(simgr, name, num, sym_retval)

    def collapse_results(self, simgr, name, num, sym_retval):
        '''
        Examine the results from a simulation, collect constraints,
        and return a list of concrete return values

        TODO: We coiuld take in sym_arg as well and analyze

        TODO: If there's an error stash would we want to pull values out of it to try
              avoiding? Or are these just bugs in our code?
        '''

        # Setup our results dict
        if name not in self.results:
            self.results[name] = {}
        if num not in self.results[name]:
            self.results[name][num] = {'ok': [], 'error': []}

        concrete_rvs = set() # Concrete return values
        these_results = [] # List of lists of constraints with retval
        for s in simgr.active + simgr.deadended:
            # Add the concrete return value to our results set
            s.solver.simplify()
            concrete_rvs.add(s.solver.min(sym_retval))
            # XXX: For now we ignore sym_arg, but we could track that too

            rel_constraints = []
            for constraint in s.solver.constraints:
                if 'target_ioctl_ret' in str(constraint) or \
                        'target_ioctl_buffer' in str(constraint):
                    rel_constraints.append(constraint)
            these_results.append(rel_constraints)

        self.results[name][num]['ok'].append(these_results)

        result = list(concrete_rvs)
        self.log("Results:")
        for rv in result:
            self.log(f"\t{rv} ({rv:#x})")

        return result

    @staticmethod
    def set_retval(state, panda, retval, convention='default'):
        '''
        Map panda arch name to angr retval register name
        Syscall and regular convention seem to be the same...
        '''
        reg_map = {
            'default':
                {
                    'x86_64': 'rax',
                    'i386': 'eax',
                    'arm': 'r0',
                    'mips': 'v0'
                }
            }
        reg_map['default']['mipsel'] = reg_map['default']['mips']
        reg_map['syscall'] = reg_map['default']
        # Now set the angr state.regs.<reg> to retval
        setattr(state.regs, reg_map[convention][panda.arch_name], retval)
        return state

    @staticmethod
    def make_symbolic_buffer(state, panda, size):
        '''
        Set the return value of the concretely-issued ioctl to be symbolic
        '''
        retbuf = claripy.BVS('target_ioctl_buffer', size, explicit_name=True)
        if panda.arch_name == 'x86_64':
            state.regs.rdx = retbuf
        elif panda.arch_name == 'i386':
            state.regs.edx = retbuf
        elif panda.arch_name == 'arm':
            state.regs.r2 = retbuf
        elif panda.arch_name == 'mips':
            state.regs.a2 = retbuf

        return retbuf


    def log_simgr(self, simgr):
        self.log(f"Simgr has {len(simgr.active)} active states, {len(simgr.deadended)} " \
                 f"deadended states, and {len(simgr.errored)} errored states")
        # For each errored state, log
        for idx, state in enumerate(simgr.errored):
            self.log(f"Errored state #{idx}: {state.error}")
        # Now log deadended states
        for idx, state in enumerate(simgr.deadended):
            self.log(f"Deadended state #{idx}: {state}")

    def log(self, msg):
        self.logger.log(logging.INFO, msg)
        # If file is closed, we can't write to it
        if not self.log_file.closed and not self.read_only:
            self.log_file.write(str(msg) + "\n")
            self.log_file.flush()

    def create_proj(self, panda, targ_addr, scratch):
        '''
        Initialize PANDA target, then enumerate memory mappings to find
        in-memory executables. Pull these out of self.fs_tar.

        1. Enumerate memory mappings to find the target binary and libraries.
        2. Extract the target binary and loaded libraries from the FS and
           store in our scratch directory
        3. Create a PandaConcreteTarget
        4. Create an angr project
        '''

        panda_target = PandaConcreteTarget(panda)
        target_binary, target_base = None, None
        target_files = set()
        lib_opts = {}

        # Make a directory in scratch
        os.mkdir(os.path.join(scratch, "lib"))

        # Look through our mappings. Track all unique filenames
        # and identify the binary that was loaded at targ_addr
        for mapping in panda_target.get_mappings():
            target_files.add(mapping.name)

            if mapping.offset == 0 and ".so" in mapping.name:
                # Library loaded at base address so we want to load it.
                # I think this is a hack - what we really want is to load the executable sections
                # with the right offsets. But angr doesn't support offsets?
                # Fortunately the executable sections seem to end up at offset 0 and it just works
                lib_opts[os.path.basename(mapping.name)] = {'base_addr': mapping.start_address,
                                                        #'offset': mapping.offset
                                                     }

            if targ_addr >= mapping.start_address < mapping.end_address:
                # This mapping contains the target address - we'll configure this binary as our
                # main object
                target_binary, target_base = os.path.basename(mapping.name), mapping.start_address

        if not target_binary:
            # We must find a target!
            raise ValueError(f"Failed to find anything in memory at {targ_addr:x}")

        # Now copy each of the files we care about into our scratch directory
        with open(self.fs_archive, 'rb') as f:
            with tarfile.open(fileobj=f) as tar:
                for member in tar.getmembers():
                    # Extract our target files into scratch
                    fname = member.name[1:]
                    if fname not in target_files:
                        continue
                    if member.islnk():
                        continue

                    # Extract into scratch dir and preserve paths
                    #tar.extract(member, scratch)

                    # Extract into ./scratch/ and discard original path
                    file_content = tar.extractfile(member).read()
                    final_path = os.path.basename(fname)
                    output_file_path = os.path.join(*[scratch, final_path])
                    with open(output_file_path, 'wb') as out_file:
                        out_file.write(file_content)

                    # Remove from pending_files
                    target_files.remove(fname)

        # Create an angr project referencing the binary on disk
        # and the libraries on disk. All in scratch!
        self.log(f"Creating project with binary {target_binary} at {target_base:x}")
        self.log(f"Initial PC is {targ_addr:x}")

        load_options = {
            'auto_load_libs': False,
            'except_missing_libs': True,
            'ld_path': scratch,
            'lib_opts': lib_opts,
            'force_load_libs': list(lib_opts.keys()),
            'main_opts': {'base_addr': target_base},
        }

        proj = angr.Project(os.path.join(scratch, target_binary),
                            concrete_target=panda_target,
                            use_sim_procedures=False,
                            load_options=load_options
                            )
        return proj

    def setup_project_state(self, panda, targ_addr):
        '''
        Given a concrete PANDA state and a target address
        create a new angr project and state, and synchronize
        with PANDA concrete state.
        '''
        with tempfile.TemporaryDirectory(prefix="penguin_") as tmpdir:
            proj = self.create_proj(panda, targ_addr, tmpdir)

        # Now create state, synchronize it, and do some sanity checks

        # Create a state at the target address
        state = proj.factory.entry_state(addr=targ_addr)

        state.options.add(angr.options.SYMBION_SYNC_CLE)
        state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

        # Now pull in the concrete state from PANDA
        state.concrete.sync()

        return proj, state

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
        if os.path.isfile(self.result_path):
            with open(self.result_path, 'rb') as f:
                self.results = pickle.loads(f.read())

    def get_known_values(self):
        '''
        Return details of all filenames and IOCTLs we've analyzed
        in the format {fname: [ioctl1, ioctl2]}
        '''
        if len(self.results) == 0:
            self._load_results()
        return {fname: list(self.results[fname].keys()) for fname in self.results}


    '''
    @staticmethod
    def synthesize_constraints(self, solver, constraint_lists):
        # Flatten and deduplicate the constraints
        flattened_constraints = [constraint for symex in constraint_lists \
                                 for path in symex for constraint in path]
        unique_constraints_dict = {str(c): c for c in flattened_constraints}
        unique_constraints = list(unique_constraints_dict.values())

        # Initialize the final constraints
        final_constraints = []

        # Create all unique pairs from the unique constraints
        for constr1, constr2 in itertools.combinations(unique_constraints, 2):
            # Test various combinations - if any are satisfiable, add them to the final constraints
            if solver.satisfiable([constr1 & constr2]):
                final_constraints.append([constr1 & constr2])
            if solver.satisfiable([constr1 & ~constr2]):
                final_constraints.append([constr1 & ~constr2])
            if solver.satisfiable([~constr1 & constr2]):
                final_constraints.append([~constr1 & constr2])
            if solver.satisfiable([~constr1 & ~constr2]):
                final_constraints.append([~constr1 & ~constr2])

        return final_constraints
    '''

    def find_distinct_paths(self, path, num, nbits):
        if len(self.results) == 0:
            self._load_results()

        if path not in self.results or num not in self.results[path]:
            raise ValueError(f"No results for {path} {num}")

        # Just need a solver, doesn't matter what project's backed by?
        proj = angr.Project('/bin/true')
        state = proj.factory.blank_state()

        # With explicit_name=True, we can just reconstruct the symbolic variable(?)
        retval = claripy.BVS('target_ioctl_ret', nbits, explicit_name=True)

        constrs = []
        if len(self.results[path][num]['ok']) == 0:
            return []

        if len(self.results[path][num]['ok']) == 1:
            # No need to combine pairs - we did a single run so
            # data contains [[constraints1_part1, constraints1_part2], [...]]
            for constr in self.results[path][num]['ok'][0]:
                constrs.append(state.solver.And(*constr))

        else:
            # We have multiple runs for this fname and ioctl.
            # Let's combine the constraints between runs
            combined_constraints = set() # String reprs
            # Iterate through all pairs of runs
            for run1, run2 in itertools.combinations(self.results[path][num]['ok'], 2):
                # Iterate through all pairs of states within the selected runs
                for constr1, constr2 in itertools.product(run1, run2):
                    # Combine constraints within each state using AND
                    constraints1 = state.solver.And(*constr1)
                    constraints2 = state.solver.And(*constr2)

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
        for constr in constrs:
            rvs.add(state.solver.min(retval, extra_constraints=[constr]))

        rvs = list(rvs)
        def custom_sort_key(num):
            # Return a tuple that will guide the sort operation.
            # Positive (small to big), negative (big to small), then 0
            # We pick 0 last because it's our default before we specify something
            if num == 0:
                return (3, 0)

            if num >= 2**(nbits-1): # If highest bit is set, it's negative
                return (2, num - 2**nbits) # Gets us the negative value

            # Else it's positive
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

    def hypothesize_models(self, target=None, cmd=None, verbose=True):
        '''
        Given some results, hypothesize models for each device and ioctl.
        Not sure if we really need this
        '''
        models = {} # {"/dev/device": {ioctl: [likeliest value, 2nd likliest value...]}
        try:
            known_values = self.get_known_values()
        except FileNotFoundError:
            # We found no results, and we're not loading from disk. This is probably a bad design
            self.log("No results")
            return {}

        for fname, nums in known_values.items():
            if target is not None and fname != target:
                continue

            models[fname] = {}
            for num in nums:
                if cmd is not None and cmd != num:
                    continue
                paths = self.find_distinct_paths(fname, num, 32)

                if not paths or len(paths) == 0:
                    print("\tWarning: no paths found - return 0")
                    paths = [0]

                if verbose:
                    self.log(f"{fname}, {num} = {paths}")
                models[fname][num] = paths
        return models

if __name__ == '__main__':
    from sys import argv
    symex = PathExpIoctl(argv[1], None, read_only=True)
    models = symex.hypothesize_models()
    for fname, details in models.items():
        print(f"{fname}:")
        for ioctl, values in details.items():
            print(f"\t{ioctl:#x}: {values}")