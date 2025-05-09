from pandare2 import PyPlugin
from penguin import getColoredLogger
import struct
from collections.abc import Iterator
import functools

# CHUNK_SIZE = 4096 - 8*3
CHUNK_SIZE = 1000
HYPER_REGISTER_MEM_REGION = 0xbebebebe

HYPER_OP_NONE = 0
HYPER_OP_READ = 1
HYPER_OP_WRITE = 2
HYPER_OP_READ_FD_NAME = 3
HYPER_OP_READ_PROCARGS = 4
HYPER_OP_READ_SOCKET_INFO = 5
HYPER_OP_READ_STR = 6
HYPER_OP_READ_FILE = 7
HYPER_OP_READ_PROCENV = 8
HYPER_OP_READ_PROCPID = 9
HYPER_OP_DUMP = 10
HYPER_OP_MAX = 11

HYPER_RESP_NONE = 0xf0000000
HYPER_RESP_READ_OK = 0xf0000001
HYPER_RESP_READ_FAIL = 0xf0000002
HYPER_RESP_READ_PARTIAL = 0xf0000003
HYPER_RESP_WRITE_OK = 0xf0000004
HYPER_RESP_WRITE_FAIL = 0xf0000005
HYPER_RESP_READ_NUM = 0xf0000006
HYPER_RESP_MAX = 0xf0000007

class Hypermem(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.hypermem")
        # if self.get_arg_bool("verbose"):
            # self.logger.setLevel("DEBUG")
        self.panda = panda
        self.panda.hypercall(HYPER_REGISTER_MEM_REGION)(
            self._register_cpu_memregion)
        self.cpu_memregion_structs = {}
        # Set endianness format character for struct operations
        self.endian_format = '<' if panda.endianness == 'little' else '>'
        self.id_reg = 1
    
    '''
    Our memregion is the first available memregion OR the one that is owned by us

    This can return none
    '''
    def _find_free_memregion(self, cpu, id_reg, claimed_slot):
        cpu_memregion_struct = self.cpu_memregion_structs[cpu]
        memregion_head = self.panda.virtual_memory_read(cpu, cpu_memregion_struct, 8*3)
        count, memregions_requested, call_num = struct.unpack("<QQQ", memregion_head)

        if claimed_slot:
            # still need to check the slot
            next_region = self.panda.virtual_memory_read(cpu, cpu_memregion_struct+(8*3)+ (16*claimed_slot), 16)
            owner_id, mem_region = struct.unpack("<QQ", next_region)
            if owner_id in [0, id_reg]:
                return call_num, claimed_slot, mem_region

        for i in range(count):
            next_region = self.panda.virtual_memory_read(cpu, cpu_memregion_struct+(8*3)+ (16*i), 16)
            owner_id, mem_region = struct.unpack("<QQ", next_region)
            if owner_id in [0, id_reg]:
                return call_num, i, mem_region
        breakpoint()
        # we didn't find one. request an additional memregion
        memregions = struct.pack("<Q", memregions_requested+1)
        self.panda.virtual_memory_write(cpu, cpu_memregion_struct+8, memregions)
    
    def _claim_memregion(self, cpu, slot, id_reg):
        cpu_memregion_struct = self.cpu_memregion_structs[cpu]
        id_ = struct.pack("<Q", id_reg)
        self.panda.virtual_memory_write(cpu, cpu_memregion_struct+(8*3)+(slot*16), id_)

    def _release_memregion(self, cpu, slot):
        self._claim_memregion(cpu, slot, 0)

    def _read_memregion_state(self, cpu, cpu_memregion):
        mem = self.panda.virtual_memory_read(cpu, cpu_memregion, 8*3)
        op, addr, size = struct.unpack("<QQQ", mem)
        self.logger.debug(
            f"Reading memregion state: op={op}, addr={addr:#x}, size={size}")
        return op, addr, size, 

    def _read_memregion_data(self, cpu, cpu_memregion, size):
        if size > CHUNK_SIZE:
            self.logger.error(f"Size {size} exceeds chunk size {CHUNK_SIZE}")
            size = CHUNK_SIZE
        try:
            mem = self.panda.virtual_memory_read(cpu, cpu_memregion+(8*3), size)
            return mem
        except ValueError as e:
            self.logger.error(f"Failed to read memory: {e}")

    def _write_memregion_state(self, cpu, cpu_memregion, op, addr, size):
        if size > CHUNK_SIZE:
            self.logger.error(f"Size {size} exceeds chunk size {CHUNK_SIZE}")
            size = CHUNK_SIZE
        if size < 0:
            self.logger.error(f"Size {size} is negative")
            size = 0
        if addr < 0:
            self.logger.debug(f"Address {addr} is negative. Converting to unsigned")
            mask = 0xFFFFFFFFFFFFFFFF if self.panda.bits == 64 else 0xFFFFFFFF
            addr = addr & mask
        
        self.logger.debug(
            f"Writing memregion state:  op={op}, addr={addr:#x}, size={size}")

        mem = struct.pack("<QQQ", op, addr, size)
        try:
            self.panda.virtual_memory_write(cpu, cpu_memregion, mem)
        except ValueError as e:
            self.logger.error(f"Failed to write memregion state: {e}")

    def _write_memregion_data(self, cpu, data):
        cpu_memregion = self.cpu_memregions[cpu]
        try:
            self.panda.virtual_memory_write(cpu, cpu_memregion+(8*3), data)
        except ValueError as e:
            self.logger.error(f"Failed to write memregion data: {e}")

    def _handle_input_state(self, cpu, cpu_memregion):
        in_op = None
        op, addr, size = self._read_memregion_state(cpu, cpu_memregion)
        if op == HYPER_OP_NONE:
            pass
        elif op & HYPER_RESP_NONE == 0:
            self.logger.error(f"Invalid operation OP in return {op:#x}")
        elif op < HYPER_RESP_NONE or op > HYPER_RESP_MAX:
            self.logger.error(f"Invalid operation: {op:#x}")
        elif op == HYPER_RESP_READ_OK:
            self.logger.debug(f"Read OK: {addr:#x} {size}")
            data = self._read_memregion_data(cpu, cpu_memregion, size)
            in_op = (op, data)
        elif op == HYPER_RESP_READ_FAIL:
            self.logger.debug("Failed to read memory")
            pass
        elif op == HYPER_RESP_READ_PARTIAL:
            self.logger.debug(f"Read OK: {addr:#x} {size}")
            data = self._read_memregion_data(cpu, cpu_memregion, size)
            in_op = (op, data)
        elif op == HYPER_RESP_WRITE_OK:
            pass
        elif op == HYPER_RESP_WRITE_FAIL:
            self.logger.debug("Failed to write memory")
            pass
        elif op == HYPER_RESP_READ_NUM:
            in_op = (op, size)
        elif op == HYPER_RESP_NONE:
            pass
        else:
            self.logger.error(f"Unknown operation: {op:#x}")
        return in_op

    def _handle_output_cmd(self, cpu, cpu_memregion, cmd):
        match cmd:
            case ("read", addr, size):
                self._write_memregion_state(cpu, cpu_memregion, HYPER_OP_READ, addr, size)
            case ("read_str", addr):
                self._write_memregion_state(cpu, cpu_memregion, HYPER_OP_READ_STR, addr, 0)
            case ("read_fd_name", fd):
                self._write_memregion_state(cpu, cpu_memregion, HYPER_OP_READ_FD_NAME, fd, 0)
            case ("read_proc_args"):
                self._write_memregion_state(cpu, cpu_memregion, HYPER_OP_READ_PROCARGS, 0, 0)
            case ("read_proc_env"):
                self._write_memregion_state(cpu, cpu_memregion, HYPER_OP_READ_PROCENV, 0, 0)
            case ("read_proc_pid"):
                self._write_memregion_state(cpu, cpu_memregion, HYPER_OP_READ_PROCPID, 0, 0)
            case ("write", addr, data):
                self._write_memregion_state(
                    cpu, cpu_memregion, HYPER_OP_WRITE, addr, len(data))
                self._write_memregion_data(cpu, data)
            case None:
                return False
            case _:
                self.logger.error(f"Unknown command: {cmd}")
                return False
        return True

    def wrap(self, f):
        id_reg = self.id_reg
        self.id_reg += 1
        cpu_iterators = {} 
        cpu_iterator_start = {}
        claimed_slot = {}
        @functools.wraps(f)
        def wrapper(self_, *args, **kwargs):
            cpu = self.panda.get_cpu()
            fn_return = None
            nonlocal cpu_iterators, claimed_slot, cpu_iterator_start

            new_iterator = False
            if cpu not in cpu_iterators or cpu_iterators[cpu] is None:
                self.logger.debug(f"Creating new iterator for CPU {(cpu,f)}")
                # Revert to calling the original function f with self_
                fn_ret = f(self_, *args, **kwargs)

                if not isinstance(fn_ret, Iterator):
                    self.logger.error(f"Function {f.__name__} did not return an iterator.\
                                      You need at least one yield statement in the function.")
                    return fn_ret
                
                cpu_iterators[cpu] = fn_ret
                new_iterator = True
            memregion_result = self._find_free_memregion(cpu, id_reg, claimed_slot.get(cpu, None)) 
            if memregion_result is None:
                self.logger.info(f"Bypassing this call in {f.__name__} because we don't have a memregion")
                return
            call_num, slot, cpu_memregion = memregion_result
            self.logger.debug(f"Claiming memregion {cpu_memregion:#x} for {f.__name__} on CPU {cpu} @ {call_num} with slot {slot}")
            if new_iterator:
                cpu_iterator_start[cpu] = call_num
            if cpu_iterator_start[cpu] and cpu_iterator_start[cpu] != call_num:
                breakpoint()
                print("active iterator is not the same as the one we started with")
            
            in_op = self._handle_input_state(cpu, cpu_memregion)
            self._release_memregion(cpu, slot)
            
            try:
                if not in_op:
                    cmd = next(cpu_iterators[cpu])
                elif in_op[0] == HYPER_RESP_READ_OK:
                    cmd = cpu_iterators[cpu].send(in_op[1])
                elif in_op[0] == HYPER_RESP_READ_NUM:
                    cmd = cpu_iterators[cpu].send(in_op[1])
                elif in_op[0] == HYPER_RESP_READ_PARTIAL:
                    cmd = cpu_iterators[cpu].send(in_op[1])
                else:
                    cpu_iterators[cpu] = None
                    raise Exception(f"Invalid state cmd is {in_op}")
            except StopIteration as e:
                self.logger.debug(f"StopIteration in {f.__name__} for CPU {cpu} @ {call_num}")
                cpu_iterators[cpu] = None
                # The function has completed, and we need to return the value
                fn_return = e.value
                cpu_iterator_start[cpu] = None
                self._write_memregion_state(cpu, cpu_memregion, HYPER_OP_NONE, 0, 0)
                self._release_memregion(cpu, slot)
                claimed_slot[cpu] = None
                cmd = None
            

            if new_iterator and cmd is None:
                # this is basically a no-op. Our functionality wasn't used
                return fn_return
            
            try:
                active_claim = self._handle_output_cmd(cpu, cpu_memregion, cmd)
            except ValueError as e:
                self.logger.error(f"Failed to write memory {e}")
            
            if active_claim:
                self._claim_memregion(cpu, slot, id_reg)
                claimed_slot[cpu] = slot
            else:
                # possibly unnecessary
                self._release_memregion(cpu, slot)
                claimed_slot[cpu] = None
            
            return fn_return
        return wrapper

    def _register_cpu_memregion(self, cpu):
        self.cpu_memregion_structs[cpu] = self.panda.arch.get_arg(
            cpu, 1, convention="syscall")

    def write_bytes(self, addr, data):
        self.logger.debug(
            f"write_bytes called: addr={addr}, data_len={len(data)}")
        for i in range((len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE):
            offset = i * CHUNK_SIZE
            chunk_addr = addr + offset
            chunk_data = data[offset:offset + CHUNK_SIZE]
            self.logger.debug(
                f"Writing chunk: chunk_addr={chunk_addr}, chunk_len={len(chunk_data)}")
            yield ("write", chunk_addr, chunk_data)
        self.logger.debug(f"Total bytes written: {len(data)}")
        return len(data)

    def read_bytes(self, addr, size):
        self.logger.debug(f"read_bytes called: addr={addr}, size={size}")
        data = b""
        for i in range((size + CHUNK_SIZE - 1) // CHUNK_SIZE):
            offset = i * CHUNK_SIZE
            chunk_addr = addr + offset
            chunk_size = min(CHUNK_SIZE, size - offset)
            self.logger.debug(
                f"Reading chunk: chunk_addr={chunk_addr}, chunk_size={chunk_size}")
            chunk = yield ("read", chunk_addr, chunk_size)
            if not chunk:
                self.logger.debug(
                    f"Failed to read memory at addr={chunk_addr}, size={chunk_size}")
                chunk = b"\x00" * chunk_size
            elif len(chunk) != chunk_size:
                self.logger.debug(
                    f"Partial read at addr={chunk_addr}, expected {chunk_size} bytes, got {len(chunk)}")
                # If the read was partial, fill the rest with zeros
                chunk = chunk.ljust(chunk_size, b"\x00")
            self.logger.debug(
                f"Received response from queue: {chunk} chunk_len={len(chunk)}")
            data += chunk
        data = data[:size]
        self.logger.debug(f"Total bytes read: {len(data)}")
        return data

    def read_str(self, addr):
        if addr != 0:
            self.logger.debug(f"read_str called: addr={addr:#x}")
            # if addr == 0xbeffff2d:
            #     import debugpy
            #     debugpy.listen(("0.0.0.0", 5678))
            #     debugpy.wait_for_client()
            #     breakpoint()
            chunk = yield ("read_str", addr)
            if chunk:
                self.logger.debug(f"Received response from queue: {chunk}")
                return chunk.decode('latin-1', errors='replace')
        return ""

    def read_int(self, addr):
        self.logger.debug(f"read_int called: addr={addr}")
        data = yield from self.read_bytes(addr, 4)
        if len(data) != 4:
            self.logger.error(
                f"Failed to read int at addr={addr}, data_len={len(data)}")
            return None
        value = struct.unpack(f"{self.endian_format}I", data)[0]
        self.logger.debug(f"Integer read successfully: value={value}")
        return value

    def read_long(self, addr):
        self.logger.debug(f"read_long called: addr={addr}")
        data = yield from self.read_bytes(addr, 8)
        if len(data) != 8:
            self.logger.error(
                f"Failed to read long at addr={addr}, data_len={len(data)}")
            return None
        value = struct.unpack(f"{self.endian_format}Q", data)[0]
        self.logger.debug(f"Long read successfully: value={value}")
        return value

    def read_ptr(self, addr):
        if self.panda.bits == 32:
            ptr = yield from self.read_int(addr)
        elif self.panda.bits == 64:
            ptr = yield from self.read_long(addr)
        else:
            raise Exception("read_ptr: Could not determine bits")
        return ptr

    def write_int(self, addr, value):
        self.logger.debug(f"write_int called: addr={addr}, value={value}")
        # Pack the integer according to system endianness
        data = struct.pack(f"{self.endian_format}I", value)
        bytes_written = yield from self.write_bytes(addr, data)
        self.logger.debug(f"Integer written successfully: {value}")
        return bytes_written

    def write_long(self, addr, value):
        self.logger.debug(f"write_long called: addr={addr}, value={value}")
        # Pack the long according to system endianness
        data = struct.pack(f"{self.endian_format}Q", value)
        bytes_written = yield from self.write_bytes(addr, data)
        self.logger.debug(f"Long written successfully: {value}")
        return bytes_written

    def write_ptr(self, addr, value):
        if self.panda.bits == 32:
            yield from self.write_int(addr, value)
        elif self.panda.bits == 64:
            yield from self.write_long(addr, value)
        else:
            raise Exception("read_ptr: Could not determine bits")

    def write_str(self, addr, string, null_terminate=True):
        self.logger.debug(
            f"write_str called: addr={addr}, string_len={len(string)}")
        # Convert string to bytes
        if isinstance(string, str):
            data = string.encode('latin-1')
        else:
            data = string

        # Add null terminator if requested
        if null_terminate:
            data = data + b'\0'

        bytes_written = yield from self.write_bytes(addr, data)
        self.logger.debug(f"String written successfully: {len(data)} bytes")
        return bytes_written

    def get_fd_name(self, fd):
        self.logger.debug(f"read_fd_name called: fd={fd}")
        fd_name = yield ("read_fd_name", fd)
        if fd_name:
            self.logger.debug(
                f"File descriptor name read successfully: {fd_name}")
            return fd_name.decode('latin-1', errors='replace')
    
    def read_socket_info(self, fd):
        self.logger.debug(f"read_socket_info called: fd={fd}")
        socket_info = yield ("read_socket_info", fd)
        if socket_info:
            self.logger.debug(f"Socket info read successfully: {socket_info}")
            return socket_info.decode('latin-1', errors='replace')

    def get_proc_args(self):
        self.logger.debug("read_process_args called")
        proc_args = yield ("read_proc_args")
        if proc_args:
            args = [i.decode("latin-1") for i in proc_args.split(b"\0") if i]
            self.logger.debug(
                f"Proc args read successfully: {args}")
            return args
        return []
    
    def get_proc_name(self):
        self.logger.debug("get_process_name called")
        proc_name = yield ("read_proc_name")
        if proc_name:
            self.logger.debug(f"Proc name read successfully: {proc_name}")
            return proc_name.decode("latin-1").split(" ")[0]
        return ""

    def get_proc_env(self):
        self.logger.debug("get_process_env called")
        proc_env = yield ("read_proc_env")
        if proc_env:
            args = [i.decode("latin-1").split("=")
                    for i in proc_env.split(b"\0") if i]
            env = {k: v for k, v in args}
            self.logger.debug(f"Proc env read successfully: {env}")
            return env
        return {}

    def get_proc_pid(self):
        self.logger.info("read_process_pid called")
        pid = yield ("read_proc_pid")
        if pid:
            self.logger.info(f"Process PID read successfully: {pid}")
            return pid
        return None
    
    def read_ptrlist(self, addr, length):
        ptrs = []
        ptrsize = int(self.panda.bits/8)
        for start in range(length):
            ptr = yield from self.read_ptr(addr + (start * ptrsize))
            if ptr == 0:
                break
            ptrs.append(ptr)
        return ptrs
    
    def read_char_ptrlist(self, addr, length):
        ptrlist = yield from self.read_ptrlist(addr, length)
        vals = []
        for start in range(len(ptrlist)):
            strs = yield from self.read_str(ptrlist[start])
            vals.append(strs)
        return vals

    def nop(self):
        return
