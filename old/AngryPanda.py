#Largely based on:
#https://github.com/AndrewFasano/angrypanda/blob/master/run.py
import angr
from io import BytesIO
from angr.engines.vex.lifter import VEX_IRSB_MAX_SIZE
import elftools
import re
class AngryPanda:
    def __init__(self, panda, cpu):
        self.panda = panda
        self.cpu = cpu
        self.wordsize = int(panda.bits/8)
        self.buffer_addr = None
        self.max_block_len = VEX_IRSB_MAX_SIZE
        #TODO: endianness

    def mem_jit(self,state):
        '''
        Immediately before angr reads new data from memory, set a concrete
        value from PANDA
        '''
        try:
          addr = state.inspect.mem_read_address
          if not isinstance(addr,int):
            assert(addr.concrete), "Symbolic address is being read"
            assert(addr.op == 'BVV'), f"Unknown address op type: {addr.op}"
            addr_c = addr.args[0] # Concrete value of address
          else:
            addr_c = addr

          read_len = state.inspect.mem_read_length
          try:
              concrete_byte_val = self.panda.virtual_memory_read(self.cpu, addr_c, read_len)
          except ValueError:
              print(f"mem_jit failed to read {read_len} bytes from {addr_c:#x}")
              return
          assert(read_len <= self.wordsize), f"Unsupported read of multiple words, read_len: {read_len}"

          state.memory.store(addr_c, concrete_byte_val)
        except AssertionError as e:
          return

    def should_mem_jit(self,state):
        '''
        Concretize address - if it's not in our memory map, then we need to mem_jit
        '''
        l = state.inspect.mem_read_length
        addr = state.inspect.mem_read_address
        addr_c = state.solver.eval(addr)

        angr_mem = state.memory.concrete_load(addr_c, l)

        return len(angr_mem)==0

    def call_jit(self, state):
        '''
        Just before angr does a call into not yet-JIT-ed memory, load 0x100 bytes there
        using our code_jit logic
        '''
        addr = state.inspect.function_address
        state.inspect.mem_read_address = state.solver.eval(addr)
        state.inspect.mem_read_length = 0x100
        self.code_jit(state)

    def should_call_jit(self, state):
        '''
        Before angr enters a call instruction, check if there's an instruction (one word?) of data there
        '''
        addr = state.inspect.function_address
        addr_c = state.solver.eval(addr)
        angr_mem = state.memory.concrete_load(addr_c, self.wordsize)
        return len(angr_mem)==0



    def code_jit(self, state):
        '''
        Immediately before angr parses a new block of code, set a concrete value from PANDA
        '''
        addr = state.inspect.mem_read_address #XXX: This returns an int not an object like normal
        max_read_length = state.inspect.mem_read_length
        concrete_byte_val = self.panda.virtual_memory_read(self.cpu, addr, max_read_length)

        state.memory.store(addr, concrete_byte_val)

    def should_code_jit(self, state):
        '''
        Given an address and the (maximum) size of the code there,
        return true if any data in that range is missing from angr's memory
        '''
        base_addr = state.inspect.mem_read_address
        if not base_addr:
            return False
        max_length = state.inspect.mem_read_length
        #logger.debug(f"Evaluate need to JIT store any code from 0x{base_addr:x} to 0x{base_addr+max_length:x}")
        for addr in range(base_addr, base_addr+max_length):
            if addr not in state.memory:
                #logger.debug(f"Need memory at 0x{addr:x}")
                return True

        return False

    def exit_jit(self, state):
        '''
        Bring the memory that is our next target from PANDA into angr
        '''
        #If this is not concrete we have bigger problems, so just got for it
        addr = state.solver.eval(state.inspect.exit_target)
        try:
            #We are fetching the block, so we have no information on the size needed
            #print(f"exit_jit: pulling in {self.max_block_len} bytes from {addr:#x}")
            data = self.panda.virtual_memory_read(self.cpu, addr, self.max_block_len)
        except ValueError:
            print(f"exit_jit: failed to read {self.max_block_len} bytes from {addr:#x}")
            return

        state.memory.store(addr, data)

    def should_exit_jit(self, state):
        '''
        On block exit, check to see if our target is in memory (e.g., indirect jump)
        '''
        target_c = state.solver.eval(state.inspect.exit_target)
        #print(f"should_exit_jit: target {state.inspect.exit_target} resolves to {target_c:#x}")

        for addr in range(target_c, target_c+self.max_block_len):
            if addr not in state.memory:
                return True
        return False

    def should_irsb_jit(self, state):
        '''
        Check to see if our target is in memory (e.g., indirect jump)
        '''
        target_c = state.solver.eval(state.inspect.address)
        #print(f"should_irsb_jit: target {state.inspect.address} resolves to {target_c:#x}")


        for addr in range(target_c, target_c+self.max_block_len):
            if addr not in state.memory:
                #print(f"should_irsb_jit: failed to read from {target_c:#x}")
                break
                #return True
        return False

    #synchronizes panda registers with angr state
    def sync_state(self, sim_state, enable_jit=False, sync_mem=False):
        for reg in self.panda.arch.registers.keys():
            regval = self.panda.arch.get_reg(self.cpu, reg)
            setattr(sim_state.regs, reg.lower(), regval)

        if sync_mem:
            self.sync_process_memory(sim_state)

        if enable_jit:
            sim_state.inspect.b('mem_read', condition=self.should_mem_jit,
                                action=self.mem_jit, when=angr.BP_BEFORE)

            sim_state.inspect.b('call', condition=self.should_call_jit,
                                action=self.call_jit, when=angr.BP_BEFORE)

            sim_state.inspect.b('vex_lift', condition=self.should_code_jit,
                                action=self.code_jit, when=angr.BP_BEFORE)

            sim_state.inspect.b('exit', condition=self.should_exit_jit,
                                action=self.exit_jit, when=angr.BP_BEFORE)

            sim_state.inspect.b('irsb', condition=self.should_irsb_jit,
                                action=self.exit_jit, when=angr.BP_BEFORE)

    def proj_from_current_process(self, sym_pc):
        barray=bytes()
        mappings = self.panda.get_mappings(self.cpu)

        #Load the mapping that contains the address we wish to start symex at
        for mapping in mappings:
            if mapping.base <= sym_pc and (sym_pc <= (mapping.base + mapping.size)):
                base = mapping.base
                size = mapping.size
                name = self.panda.ffi.string(mapping.name).decode('utf8', 'ignore')
                break

        print(f"Loading {name} from {base:#x} into angr")
        barray=bytes()
        for addr in range(base, base+size, 0x1000):
            try:
                obj=self.panda.virtual_memory_read(self.cpu, addr, 0x1000)
                barray += obj
            except ValueError:
                print(f"Stopped loading at {addr:#x}")
                break

        proj = angr.Project(BytesIO(barray),
                            main_opts={
                                'backend': 'blob',
                                'arch': self.panda.arch_name,
                                'entry_point': sym_pc,
                                'base_addr': base
                                },
                            )
        return proj

    def get_lib_opts(self):
        """
        Builds a dict of library loaded base addresses to get as close a match
        as we can to CLE when creating an angr Project

        i.e., can pass the returned dict to lib_opts= in angr.Project()
        """
        lib_opts=dict()
        skip_name_re=re.compile(r'^\[.*\]$')
        #Skip duplicates, kept as a separate list so we don't pull the main executable's header multiple times
        visited=set()
        for m in self.panda.get_mappings(self.cpu):
            if m.name == self.panda.ffi.NULL:
                continue
            name = self.panda.ffi.string(m.name).decode('utf8', 'ignore')
            if name in lib_opts or skip_name_re.match(name):
                continue
            #We'll assume first occurence is base address of that object
            #Next, we'll load up the ELF header and see if it's a library
            try:
                elfbytes=self.panda.virtual_memory_read(self.cpu, m.base, 0x40)
            except ValueError:
                print(f"Couldn't read ELF header from {m.base:#x} of {name}")
                continue
            try:
                header = elftools.elf.elffile.ELFFile(BytesIO(elfbytes)).header
                if header.e_type == 'ET_DYN':
                    lib_opts[name] = {'base_addr':m.base}
            except elftools.common.exceptions.ELFError:
                #Probably not an ELF
                continue
        return lib_opts

    def sync_process_memory(self, state):
        """
        In the abscense of a better memory model, we'll use COSI to identify
        all writeable sections of process memory and bring those over one page
        at a time. Assumption being that r/x pages are already loaded
        """
        VM_WRITE=0x2 #no contant
        cosi_proc=self.panda.cosi.current_process()
        for cosi_map in cosi_proc.mappings():
            if cosi_map.inner.vma.vm_flags & VM_WRITE:
                if cosi_map.get_name() == "[stack]":
                    #Stack grows down
                    addr = cosi_map.base+cosi_map.size
                    incr = -0x1000
                else:
                    addr = cosi_map.base
                    incr = 0x1000
                bytes_read=0
                try:
                    while bytes_read<cosi_map.size:
                        panda_bytes = self.panda.virtual_memory_read(self.cpu, addr, 0x1000)
                        state.memory.store(addr, panda_bytes)
                        bytes_read+=0x1000
                        addr += incr
                except Exception as e:
                    print(e)
                    print(f"Skipped {cosi_map.get_name()} at {addr:#x} after reading {bytes_read} bytes")
