import angr
import elftools
import logging
from sys import stderr
import pickle
import itertools
import tempfile

import time
import logging

#logging.getLogger().setLevel('DEBUG')
#logging.getLogger().setLevel('INFO')
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

EXTRACTED_FS = "/share/tmproot" # XXX TODO, parameterize this - is it actually even used?

from angr.concretization_strategies import SimConcretizationStrategy

from angr.concretization_strategies.logging import SimConcretizationStrategyLogging

class MyStrat(SimConcretizationStrategy):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
    def _concretize(self, memory, addr, **kwargs):
        # Debug print before default concretization
        print(f"[DEBUG] About to concretize addr: {addr}")
        
        # Invoke default concretization logic
        values = super()._eval(memory, addr, n, **kwargs)
        
        # Debug print after default concretization
        print(f"[DEBUG] Concretized to values: {values}")
        
        return values

def get_map_info(logger, panda, cpu, targ_addr, scratch):
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
        #logger(f"Mapping from {m.base:x} to {m.base + m.size:x}: {fname}")

        if targ_addr >= m.base and targ_addr < m.base + m.size:
            logger(f"Mapping {fname} from {m.base:x} to {m.base + m.size:x} contains target address {targ_addr:x}")
            target_base = m.base
            target_binary = fname

        if not os.path.isfile(EXTRACTED_FS + fname):
            logger(f"Warning, could not find {fname} in extracted rootfs")
            continue

        if not ".so" in fname:
            #logger(f"Warning, skipping non shared library {fname}")
            continue

        # Copy the library into the stridelibs directory so angr can find it
        os.system(f"cp {EXTRACTED_FS}/{fname} {scratch}/{os.path.basename(fname)}")

        # Add basename to lib_opts
        libname = os.path.basename(fname)

        # I think we'll always have 0 offset for code vs non-zero for data.
        # For each 0-offset mapping, we'll add it to the lib_opts so angr
        # can read it
        if m.offset == 0:
            lib_opts[libname] = {'base_addr': m.base}
            force_load_libs.append(libname)
    return target_binary, target_base, lib_opts, force_load_libs

def setup_project(panda, targ_addr, logger):
    scratch = tempfile.mkdtemp(prefix="penguin_")

    cpu = panda.get_cpu() 
    (target_binary, target_base, lib_opts, force_load_libs) = get_map_info(logger, panda, cpu, targ_addr, scratch)
    panda_target = PandaConcreteTarget(panda)

    print("Target binary:", target_binary)

    if target_binary is None:
        raise RuntimeError("Could not find target binary in mappings")

    proj = angr.Project(EXTRACTED_FS + target_binary,
                        concrete_target=panda_target,
                        use_sim_procedures=True,
                        main_opts={'base_addr': target_base},
                        lib_opts=lib_opts,
                        force_load_libs=force_load_libs,
                        ld_path=scratch,
                        auto_load_libs=False)
    
    state = proj.factory.entry_state(addr=panda.arch.get_pc(cpu))
    state.options.add(angr.options.SYMBION_SYNC_CLE)
    state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

    # If PANDA memory read fails, fill with symbolic (Angr patch not yet upstreamed)
    #state.options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
    #state.options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
    #proj.concretization_strategies['MEMORY'] = MyStrat()

    #state.memory.write_strategies = list(map(lambda s: SimConcretizationStrategyLogging(s, False), state.memory.write_strategies))


    state.options.remove(angr.options.ALL_FILES_EXIST)
    # TODO: we want to add the files we're adding - need to parse file config
    state.fs.insert('/dev/flash', angr.SimFile('devflash', content=''))
    state.fs.insert('/dev/rb', angr.SimFile('devrb', content=''))

    # XXX should we rm scratch now? Or return it?
    return proj, state

def set_retval(state, panda, retval, convention='default'):
    # Map panda arch name to angr retval register name
    # Syscall and regular convention seem to be the same...
    reg_map = {
        'syscall': {
                'x86_64': 'rax',
                'i386': 'eax',
                'arm': 'r0',
                'mips': 'v0'
            },
        'default':
            {
                'x86_64': 'rax',
                'i386': 'eax',
                'arm': 'r0',
                'mips': 'v0'
            }
        }

    # Now set the angr state.regs.<reg> to retval
    setattr(state.regs, reg_map[convention][panda.arch_name], retval)
    #if panda.arch_name == 'x86_64':
    #    state.regs.rax = retval
    #elif panda.arch_name == 'i386':
    #    state.regs.eax = retval
    #elif panda.arch_name == 'arm':
    #    state.regs.r0 = retval
    #elif panda.arch_name == 'mips':
    #    state.regs.v0 = retval
    return state

def get_concise_representation(state, sym_var, start_idx=0, BUF_SIZE=32):
    concise_string = ""
    
    for i in range(start_idx, BUF_SIZE):
        byte = sym_var.get_byte(i)
        
        # Check satisfiability with an extra constraint added for the current byte
        is_constrained = state.solver.satisfiable(extra_constraints=(byte == byte,))
        print(f"Byte {i} constrained={is_constrained}")
        
        if is_constrained:
            # The byte is constrained, fetch its value
            byte_values = state.solver.eval_upto(byte, 1, cast_to=bytes)
            if not len(byte_values):
                print("WARNING: couldn't find any byte values for constrained byte")
                concise_string += "?"
            else:
                print(byte_values)
                concise_string += byte_values[0].decode("ascii")
        else:
            # Check if all subsequent bytes are also unconstrained
            # In the process, we'l solve for the rest of the string
            # so we're done looping
            if remaining_string := get_concise_representation(state, sym_var, i + 1, BUF_SIZE):
                concise_string += remaining_string
            break
                
    return concise_string

def find_shortest_strings(state, sym_var, buf_size, idx=0, prefix=None):
    """
    Recursively find the shortest strings that satisfy the constraints.
    """
    if idx >= buf_size:
        return [prefix]

    byte = sym_var.get_byte(idx)
    possible_bytes = state.solver.eval_upto(byte, 256)

    # Check if the byte is constrained or unconstrained
    if len(possible_bytes) == 256:
        return [prefix]  # Unconstrained, return the prefix as is

    results = []
    for b in possible_bytes:
        new_prefix = (prefix + chr(b)) if prefix else chr(b)

        # Only add the constraint and recurse if there is more than one possibility
        if len(possible_bytes) > 1:
            new_state = state.copy()
            new_state.add_constraints(byte == b)
        else:
            new_state = state  # Reuse the state if it won't be modified

        # Recursively find shortest strings for this path
        for s in find_shortest_strings(new_state, sym_var, buf_size, idx + 1,  new_prefix):
            if s and not s.startswith(new_prefix):
                results.append(s)

    return results

last_bb = None

def angr_block(state):
    """
    Debug callback - Print before block before we execute it
    """
    # Use angr's pp method on the current block

    global last_bb
    if last_bb != state.block().addr:
        state.block().pp()
        last_bb = state.block().addr

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


    def log(self, msg):
        logging.log(logging.INFO, msg)
        # If file is closed, we can't write to it
        if not self.log_file.closed and not self.read_only:
            self.log_file.write(str(msg) + "\n")
            self.log_file.flush()


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
    
    def do_symex(self, panda, name, no, argp):
        self.log(f"\nioctl {no:x} on {name}")

        # Setup our results dict
        if name not in self.results:
            self.results[name] = {}
        if no not in self.results[name]:
            self.results[name][no] = {'ok': [], 'error': []}

        # XXX if we're hooking at return, is this an extra level of return?
        ioctl_ret_addr = panda.arch.get_return_address(panda.get_cpu())
        #targ_addr = panda.arch.get_pc(panda.get_cpu()) # Maybe we want this??
        proj, state = setup_project(panda, ioctl_ret_addr, self.log)

        proj.hook_symbol('ioctl', IoctlSimProcedure(panda)) # Any subsequent calls to ioctl will also return symbolic

        # Get concrete state from panda and replace retval with symbolic val
        state.concrete.sync()
        #self.log(f"State is {state}")

        decoded = self.decode_ioctl(no)
        buf_size = 0
        if decoded['Direction'] in ['IOR', 'IOWR']:
            # Userspace is planning to READ from the buffer - we should make this buffer
            # symbolic. Yikes.
            buf_size = decoded['Argument Size']


        #state.inspect.b('statement', action=angr_block, when=angr.BP_BEFORE)

        retval = claripy.BVS('target_ioctl_ret', panda.bits, explicit_name=True)
        state = set_retval(state, panda, retval, convention='syscall')
        
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
            # We found no results, and we're not loading from disk. This is probably a bad design
            self.log("No results")
            return {}

        for fname, nums in known_values.items():
            models[fname] = {}

            for n in nums:
                paths = self.find_distinct_paths(fname, n, 32)

                if not len(paths):
                    print("\tWarning: no paths found - return 0")
                    paths = [0]

                self.log(f"{fname}, {n} = {paths}")
                models[fname][n] = paths
        return models

class PathExpEnv():
    '''
    Plugin to symbolically model returns from getenv to try finding string values
    that are checked for

    XXX unused???
    '''
    def __init__(self, out_dir, read_only = False):
        self.log_file = open(os.path.join(out_dir, "env_symex.log"), "w" if not read_only else "r")
        self.read_only = read_only
        self.result_path = os.path.join(out_dir, "env_symex.pkl")
        self.results = {} # {env_var: [value1, value2, ...]}

    def log(self, msg):
        logging.log(logging.INFO, msg)
        # If file is closed, we can't write to it
        if not self.log_file.closed and not self.read_only:
            self.log_file.write(str(msg) + "\n")
            self.log_file.flush()

    def do_symex(self, panda, varname, outbuf, outbuf_size):
        if varname not in self.results:
            self.results[varname] = []

        pc = panda.arch.get_pc(panda.get_cpu())
        proj, state = setup_project(panda, pc, self.log)
        state.inspect.b('statement', action=angr_block, when=angr.BP_BEFORE)

        # Get concrete state from panda and replace retval with symbolic val
        state.concrete.sync()
        #self.log(f"State is {state}")

        # Now we create our symbolic string - let's stick to 32 bytes for now
        BUF_SIZE = outbuf_size
        sym_buffer = claripy.BVS("sym_buf", 8 * BUF_SIZE)
        for i in range(BUF_SIZE -1 ):
            # Constrain each byte to be printable
            byte = sym_buffer.get_byte(i)
            #state.solver.add(
            #    state.solver.Or(
            #        state.solver.And(byte >= 0x20, byte <= 0x7E), # ASCII
            #        byte == 0) # Or NULL
            #)
            # Each byte can be a-zA-Z0-9_ or null
            state.solver.add(
                state.solver.Or(
                    #state.solver.And(byte >= 0x30, byte <= 0x39), # 0-9
                    #state.solver.And(byte >= 0x41, byte <= 0x5A), # A-Z
                    state.solver.And(byte >= 0x61, byte <= 0x7A), # a-z
                    #byte == ord('_'), # _
                    byte == 0)) # Or NULL

        or_list = [sym_buffer.get_byte(i) == 0 for i in range(BUF_SIZE)]
        null_constraint = claripy.Or(*or_list)
        state.solver.add(null_constraint)

        # Additional constraints for null-termination
        for i in range(BUF_SIZE - 1):
            is_null = sym_buffer.get_byte(i) == 0
            next_byte = sym_buffer.get_byte(i + 1)
            
            additional_constraint = claripy.If(is_null, next_byte == 0, next_byte == next_byte)
            
            state.solver.add(additional_constraint)

        # Allocate heap space and write the buffer to it
        #buffer_address = state.heap.allocate(BUF_SIZE)

        # Set return value (from getenv call) to point to our buffer on the heap
        #set_retval(state, panda, buffer_address)

        # XXX change the output buffer returned by getenv to be symbolic
        buffer_address = outbuf
        state.memory.store(buffer_address, sym_buffer)

        simgr = proj.factory.simgr(state)

        # Run until we get multiple states - use timeout
        #simgr.use_technique(angr.exploration_techniques.Timeout(240))
        simgr.run(until=lambda lpg: len(lpg.active) > 1)
        #simgr.run(n=500)

        # Then another 100 BBs to get the states to be more interesting
        simgr.run(n=100, until=lambda lpg: len(lpg.errored) > 1)

        # Let's explore up to a specific address for testing
        #simgr.explore(find=[0x10600,], avoid=[0x10790,]) # Will this work?

        '''
        for cnt in range(100):
            simgr.step()

            for i, s in enumerate(simgr.active):
                # solve for the buffer
                result_bytes = s.solver.eval_upto(sym_buffer, 1, cast_to=bytes)
                assert(len(result_bytes) == 1)
                result = result_bytes[0].decode('ascii')
                if '\x00' in result:
                    # Trim to first null
                    result = result[:result.index('\x00')]
                print(f"Step {cnt} state {i}: {result}")

            for s in simgr.errored:
                print(f"Step {cnt} errored state: {s.error}")
        '''

        self.log(f"\nResults for {varname}")
        self.log(f"Simgr has {len(simgr.active)} active states, {len(simgr.deadended)} deadended states, and {len(simgr.errored)} errored states")

        # For each errored state, log
        for i, s in enumerate(simgr.errored):
            self.log(f"Errored state #{i}: {s.error}")

        if len(simgr.errored):
            simgr.errored[0].debug()

        # Now log deadended states
        for i, s in enumerate(simgr.deadended):
            self.log(f"Deadended state #{i}: {s}")

        for s in simgr.active + simgr.found:
            self.log(f"ACTIVE: {s}")

            buffer = s.memory.load(buffer_address, 4)
            # Solve for the buffer
            result_bytes = s.solver.eval_upto(buffer, 10, cast_to=bytes)
            for r in result_bytes:
                result = result_bytes.decode('ascii', 'replace') # ?'s when can't decode
                self.log(f"\t{result}")

        '''
        # To keep track of unique constraints/fingerprints
        seen_constraints = set()

        # Loop over the states
        printed = set()
        for i, s in enumerate(simgr.active + simgr.deadended):

            rel_constraints = set()
            for constraint in s.solver.constraints:
                if 'sym_buf' in str(constraint):
                    rel_constraints.add(constraint)

            # Calculate a fingerprint for the relevant constraints
            state_fingerprint = hash(str(rel_constraints))
            if state_fingerprint in seen_constraints:
                print("yay, skip")
                continue
            seen_constraints.add(state_fingerprint)

            if rel_constraints not in self.results[varname]:
                self.results[varname].append(rel_constraints)
                self.log(f"Storing {rel_constraints}")

                result_bytes = s.solver.eval_upto(sym_buffer, 1, cast_to=bytes)

                # Now check if the string 'arm' could be in the result
                s2 = s.copy()
                s2.add_constraints(sym_buffer.get_byte(0) == ord('a'))
                s2.add_constraints(sym_buffer.get_byte(1) == ord('r'))
                s2.add_constraints(sym_buffer.get_byte(2) == ord('m'))
                s2.add_constraints(sym_buffer.get_byte(3) == 0)

                if s2.solver.satisfiable():
                    self.log("\tarm VALID")
                else:
                    self.log("\tarm invalid :(")



                if (len(result_bytes) == 1):
                    result = result_bytes[0].decode('ascii')
                    if '\x00' in result:
                        # Trim to first null
                        result = result[:result.index('\x00')]
                    if result not in printed:
                        printed.add(result)
                        self.log(f"\t{result}")

            # This is just for debugging - actually solve now instead of recording constraints
            #for cur_len in range(1, BUF_SIZE):
            #    # Create new state and constrain it to be NULL-terminated of cur_len
            #    s2 = s.copy()
            #    s2.add_constraints(sym_buffer.get_byte(cur_len) == 0)
            #    for i in range(0, cur_len):
            #        s2.add_constraints(sym_buffer.get_byte(i) != 0)

            #    if s2.solver.satisfiable():
            #        result_bytes = s2.solver.eval_upto(sym_buffer, 1, cast_to=bytes)
            #        assert(len(result_bytes) == 1)
            #        result = result_bytes[0].decode('ascii')[:cur_len]
            #        if result not in self.printed[varname]:
            #            self.log(f"Found result: {result}")
            #            # And print constraints
            #            self.log(f"\tConstraints: {rel_constraints}")
            #            self.printed[varname].append(result)
            #        break # Once we find a short result, we're good
            #else:
            #    print("WARNING: found no solutions")
        '''

    def save_results(self):
        '''
        Dump results to a pickle file at env_symex.pkl
        '''
        self.log("\n----\nSaving results:")
        for varname, details in self.results.items():
            self.log(f"{varname}")
            for results in details:
                self.log(f"\t\t{results}")

        with open(self.result_path, 'wb') as f:
            f.write(pickle.dumps(self.results, -1))

    def _load_results(self):
        with open(self.result_path, 'rb') as f:
            self.results = pickle.loads(f.read())



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