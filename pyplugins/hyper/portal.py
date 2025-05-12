from pandare2 import PyPlugin
from penguin import getColoredLogger
import struct
from collections.abc import Iterator
import functools
from hyper.consts import *
from analysis.portal_wrappers import Wrapper, MappingWrapper, MappingsWrapper


class Portal(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.portal")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
        self.panda = panda
        self.panda.hypercall(IGLOO_HYPER_REGISTER_MEM_REGION)(
            self._register_cpu_memregion)
        self.cpu_memregion_structs = {}
        # Set endianness format character for struct operations
        self.endian_format = '<' if panda.endianness == 'little' else '>'
        self.id_reg = 1

    def _get_struct_at(self, cpu, addr, type_):
        buf = self.panda.virtual_memory_read(cpu, addr, ffi.sizeof(type_))
        return ffi.from_buffer(f"{type_} *", buf)

    '''
    Our memregion is the first available memregion OR the one that is owned by us

    This can return none
    '''

    def _find_free_memregion(self, cpu, id_reg, claimed_slot):
        cpu_memregion_struct = self.cpu_memregion_structs[cpu]
        cmrh = self._get_struct_at(
            cpu, cpu_memregion_struct, "struct cpu_mem_region_hdr")
        if claimed_slot:
            # still need to check the slot
            addr = cpu_memregion_struct + \
                ffi.sizeof(cmrh[0]) + (claimed_slot *
                                       ffi.sizeof("struct cpu_mem_region"))
            region = self._get_struct_at(cpu, addr, "struct cpu_mem_region")
            if region.owner_id in [0, id_reg]:
                return cmrh.call_num, claimed_slot, region.mem_region

        for i in range(cmrh.count):
            addr = cpu_memregion_struct + \
                ffi.sizeof(cmrh[0]) + (i*ffi.sizeof("struct cpu_mem_region"))
            region = self._get_struct_at(cpu, addr, "struct cpu_mem_region")
            if region.owner_id in [0, id_reg]:
                return cmrh.call_num, i, region.mem_region
        breakpoint()

    def _claim_memregion(self, cpu, slot, id_reg):
        cpu_memregion_struct = self.cpu_memregion_structs[cpu]
        id_ = struct.pack("<Q", id_reg)
        addr = cpu_memregion_struct + \
            ffi.sizeof("struct cpu_mem_region_hdr") + \
            (slot*ffi.sizeof("struct cpu_mem_region"))
        self.panda.virtual_memory_write(cpu, addr, id_)

    def _release_memregion(self, cpu, slot):
        self._claim_memregion(cpu, slot, 0)

    def _read_memregion_state(self, cpu, cpu_memregion):
        memr = self._get_struct_at(cpu, cpu_memregion, "region_header")
        self.logger.debug(
            f"Reading memregion state: op={memr.op}, addr={memr.addr:#x}, size={memr.size}")
        return memr.op, memr.addr, memr.size

    def _read_memregion_data(self, cpu, cpu_memregion, size):
        if size > self.regions_size:
            self.logger.error(
                f"Size {size} exceeds chunk size {self.regions_size}")
            size = self.regions_size
        try:
            mem = self.panda.virtual_memory_read(
                cpu, cpu_memregion+ffi.sizeof("region_header"), size)
            return mem
        except ValueError as e:
            self.logger.error(f"Failed to read memory: {e}")

    def _write_memregion_state(self, cpu, cpu_memregion, op, addr, size, pid=None):
        if size > self.regions_size:
            self.logger.error(
                f"Size {size} exceeds chunk size {self.regions_size}")
            size = self.regions_size
        if size < 0:
            self.logger.error(f"Size {size} is negative")
            size = 0
        if addr < 0:
            self.logger.debug(
                f"Address {addr} is negative. Converting to unsigned")
            mask = 0xFFFFFFFFFFFFFFFF if self.panda.bits == 64 else 0xFFFFFFFF
            addr = addr & mask

        self.logger.debug(
            f"Writing memregion state:  op={op}, addr={addr:#x}, size={size}")

        pid = pid or CURRENT_PID_NUM

        mem = struct.pack("<QQQQ", op, addr, size, pid)
        try:
            self.panda.virtual_memory_write(cpu, cpu_memregion, mem)
        except ValueError as e:
            self.logger.error(f"Failed to write memregion state: {e}")

    def _write_memregion_data(self, cpu, cpu_memregion, data):
        if len(data) > self.regions_size:
            self.logger.error(
                f"Data length {len(data)} exceeds chunk size {self.regions_size}")
            data = data[:self.regions_size]
        try:
            self.panda.virtual_memory_write(
                cpu, cpu_memregion+ffi.sizeof("region_header"), data)
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
            case ("read", addr, size, pid):
                self._write_memregion_state(
                    cpu, cpu_memregion, HYPER_OP_READ, addr, size, pid)
            case ("read_str", addr, pid):
                self._write_memregion_state(
                    cpu, cpu_memregion, HYPER_OP_READ_STR, addr, 0, pid)
            case ("read_fd_name", fd, pid):
                self._write_memregion_state(
                    cpu, cpu_memregion, HYPER_OP_READ_FD_NAME, fd, 0, pid)
            case ("read_proc_args", pid):
                self._write_memregion_state(
                    cpu, cpu_memregion, HYPER_OP_READ_PROCARGS, 0, 0, pid)
            case ("read_proc_env", pid):
                self._write_memregion_state(
                    cpu, cpu_memregion, HYPER_OP_READ_PROCENV, 0, 0, pid)
            case ("read_file_offset", fname, offset, size):
                self._write_memregion_state(
                    cpu, cpu_memregion, HYPER_OP_READ_FILE, offset, size)
                self._write_memregion_data(cpu, cpu_memregion, fname)
            case ("write_file", fname, offset, data):
                self._write_memregion_state(
                    cpu, cpu_memregion, HYPER_OP_WRITE_FILE, offset, len(data))
                self._write_memregion_data(cpu, cpu_memregion, fname + data)
            case ("get_proc", pid):
                self._write_memregion_state(
                    cpu, cpu_memregion, HYPER_OP_OSI_PROC, 0, 0, pid)
            case ("get_proc_mappings", pid, skip):
                self._write_memregion_state(
                    cpu, cpu_memregion, HYPER_OP_OSI_MAPPINGS, skip, 0, pid)
            case ("exec", wait, data):
                self._write_memregion_state(
                    cpu, cpu_memregion, HYPER_OP_EXEC, wait, len(data))
                self._write_memregion_data(cpu, cpu_memregion, data)
            case ("write", addr, data, pid):
                self._write_memregion_state(
                    cpu, cpu_memregion, HYPER_OP_WRITE, addr, len(data), pid)
                self._write_memregion_data(cpu, cpu_memregion, data)
            case None:
                return False
            case _:
                breakpoint()
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
        def wrapper(*args, **kwargs):
            cpu = self.panda.get_cpu()
            fn_return = None
            # nonlocal cpu_iterators, claimed_slot, cpu_iterator_start

            new_iterator = False
            if cpu not in cpu_iterators or cpu_iterators[cpu] is None:
                self.logger.debug(f"Creating new iterator for CPU {(cpu,f)}")
                # Revert to calling the original function f with self_
                fn_ret = f(*args, **kwargs)

                if not isinstance(fn_ret, Iterator):
                    self.logger.error(f"Function {f.__name__} did not return an iterator.\
                                      You need at least one yield statement in the function.")
                    return fn_ret

                cpu_iterators[cpu] = fn_ret
                new_iterator = True
            memregion_result = self._find_free_memregion(
                cpu, id_reg, claimed_slot.get(cpu, None))
            if memregion_result is None:
                self.logger.info(
                    f"Bypassing this call in {f.__name__} because we don't have a memregion")
                return
            call_num, slot, cpu_memregion = memregion_result
            self.logger.debug(
                f"Claiming memregion {cpu_memregion:#x} for {f.__name__} on CPU {cpu} @ {call_num} with slot {slot}")
            if new_iterator:
                cpu_iterator_start[cpu] = call_num
            if cpu_iterator_start[cpu] and cpu_iterator_start[cpu] != call_num:
                self.logger.error(
                    f"CPU {cpu} iterator start {cpu_iterator_start[cpu]} != call_num {call_num}; We must have missed a call!")

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
                self.logger.debug(
                    f"StopIteration in {f.__name__} for CPU {cpu} @ {call_num}")
                cpu_iterators[cpu] = None
                # The function has completed, and we need to return the value
                fn_return = e.value
                cpu_iterator_start[cpu] = None
                self._write_memregion_state(
                    cpu, cpu_memregion, HYPER_OP_NONE, 0, 0)
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
        self.regions_size = self.panda.arch.get_arg(
            cpu, 2, convention="syscall")

    def write_bytes(self, addr, data, pid=None):
        self.logger.debug(
            f"write_bytes called: addr={addr}, data_len={len(data)}")
        for i in range((len(data) + self.regions_size - 1) // self.regions_size):
            offset = i * self.regions_size
            chunk_addr = addr + offset
            chunk_data = data[offset:offset + self.regions_size]
            self.logger.debug(
                f"Writing chunk: chunk_addr={chunk_addr}, chunk_len={len(chunk_data)}")
            yield ("write", chunk_addr, chunk_data, pid)
        self.logger.debug(f"Total bytes written: {len(data)}")
        return len(data)

    def read_bytes(self, addr, size, pid=None):
        self.logger.debug(f"read_bytes called: addr={addr}, size={size}")
        data = b""
        for i in range((size + self.regions_size - 1) // self.regions_size):
            offset = i * self.regions_size
            chunk_addr = addr + offset
            chunk_size = min(self.regions_size, size - offset)
            self.logger.debug(
                f"Reading chunk: chunk_addr={chunk_addr}, chunk_size={chunk_size}")
            chunk = yield ("read", chunk_addr, chunk_size, pid)
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

    def read_str(self, addr, pid=None):
        if addr != 0:
            self.logger.debug(f"read_str called: addr={addr:#x}")
            chunk = yield ("read_str", addr, pid)
            if chunk:
                self.logger.debug(f"Received response from queue: {chunk}")
                return chunk.decode('latin-1', errors='replace')
        return ""

    def read_int(self, addr, pid=None):
        self.logger.debug(f"read_int called: addr={addr}")
        data = yield from self.read_bytes(addr, 4, pid)
        if len(data) != 4:
            self.logger.error(
                f"Failed to read int at addr={addr}, data_len={len(data)}")
            return None
        value = struct.unpack(f"{self.endian_format}I", data)[0]
        self.logger.debug(f"Integer read successfully: value={value}")
        return value

    def read_long(self, addr, pid=None):
        self.logger.debug(f"read_long called: addr={addr}")
        data = yield from self.read_bytes(addr, 8, pid)
        if len(data) != 8:
            self.logger.error(
                f"Failed to read long at addr={addr}, data_len={len(data)}")
            return None
        value = struct.unpack(f"{self.endian_format}Q", data)[0]
        self.logger.debug(f"Long read successfully: value={value}")
        return value

    def read_ptr(self, addr, pid=None):
        if self.panda.bits == 32:
            ptr = yield from self.read_int(addr, pid)
        elif self.panda.bits == 64:
            ptr = yield from self.read_long(addr, pid)
        else:
            raise Exception("read_ptr: Could not determine bits")
        return ptr

    def write_int(self, addr, value, pid=None):
        self.logger.debug(f"write_int called: addr={addr}, value={value}")
        # Pack the integer according to system endianness
        data = struct.pack(f"{self.endian_format}I", value)
        bytes_written = yield from self.write_bytes(addr, data, pid)
        self.logger.debug(f"Integer written successfully: {value}")
        return bytes_written

    def write_long(self, addr, value, pid=None):
        self.logger.debug(f"write_long called: addr={addr}, value={value}")
        # Pack the long according to system endianness
        data = struct.pack(f"{self.endian_format}Q", value)
        bytes_written = yield from self.write_bytes(addr, data, pid)
        self.logger.debug(f"Long written successfully: {value}")
        return bytes_written

    def write_ptr(self, addr, value, pid=None):
        if self.panda.bits == 32:
            yield from self.write_int(addr, value, pid)
        elif self.panda.bits == 64:
            yield from self.write_long(addr, value, pid)
        else:
            raise Exception("read_ptr: Could not determine bits")

    def write_str(self, addr, string, null_terminate=True, pid=None):
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

        bytes_written = yield from self.write_bytes(addr, data, pid)
        self.logger.debug(f"String written successfully: {len(data)} bytes")
        return bytes_written

    def get_fd_name(self, fd, pid=None):
        self.logger.debug(f"read_fd_name called: fd={fd}")
        fd_name = yield ("read_fd_name", fd, pid)
        if fd_name:
            self.logger.debug(
                f"File descriptor name read successfully: {fd_name}")
            return fd_name.decode('latin-1', errors='replace')

    def read_socket_info(self, fd, pid=None):
        self.logger.debug(f"read_socket_info called: fd={fd}")
        socket_info = yield ("read_socket_info", fd, pid)
        if socket_info:
            self.logger.debug(f"Socket info read successfully: {socket_info}")
            return socket_info.decode('latin-1', errors='replace')

    def get_proc_args(self, pid=None):
        self.logger.debug("read_process_args called")
        proc_args = yield ("read_proc_args", pid)
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

    def get_proc_env(self, pid=None):
        self.logger.debug("get_process_env called")
        proc_env = yield ("read_proc_env", pid)
        if proc_env:
            args = [i.decode("latin-1").split("=")
                    for i in proc_env.split(b"\0") if i]
            env = {k: v for k, v in args}
            self.logger.debug(f"Proc env read successfully: {env}")
            return env
        return {}

    def read_ptrlist(self, addr, length, pid=None):
        ptrs = []
        ptrsize = int(self.panda.bits/8)
        for start in range(length):
            ptr = yield from self.read_ptr(addr + (start * ptrsize), pid)
            if ptr == 0:
                break
            ptrs.append(ptr)
        return ptrs

    def read_char_ptrlist(self, addr, length, pid=None):
        ptrlist = yield from self.read_ptrlist(addr, length, pid)
        vals = []
        for start in range(len(ptrlist)):
            strs = yield from self.read_str(ptrlist[start], pid)
            vals.append(strs)
        return vals

    def read_file(self, fname, size=None, offset=0):
        """
        Read a file from a specified offset with optional size limit.
        If size is not specified, reads the entire file from the given offset.

        Args:
            fname: Path to the file
            size: Optional size limit. If None, reads entire file
            offset: Optional offset in bytes where to start reading (default: 0)

        Returns:
            The file data as bytes
        """
        fname_bytes = fname.encode('latin-1')[:255] + b'\0'

        # Handle the case where we want to read a specific amount
        if size is not None:
            # If size is small enough, do a single read
            if size <= self.regions_size - 1:
                data = yield ("read_file_offset", fname_bytes, offset, size)
                return data

            # For larger sizes, read in chunks
            all_data = b""
            current_offset = offset
            bytes_remaining = size

            while bytes_remaining > 0:
                chunk_size = min(self.regions_size - 1, bytes_remaining)
                self.logger.debug(
                    f"Reading file chunk: {fname}, offset={current_offset}, size={chunk_size}")

                chunk = yield ("read_file_offset", fname_bytes, current_offset, chunk_size)

                if not chunk:
                    self.logger.debug(
                        f"No data returned at offset {current_offset}, stopping read")
                    break

                all_data += chunk
                current_offset += len(chunk)
                bytes_remaining -= len(chunk)

                # If we got less data than requested, we've reached EOF
                if len(chunk) < chunk_size:
                    self.logger.debug(
                        f"Reached EOF at offset {current_offset} (requested {chunk_size}, got {len(chunk)})")
                    break

            return all_data

        # If size is not specified, read the entire file in chunks
        all_data = b""
        current_offset = offset
        chunk_size = self.regions_size - 1

        while True:
            self.logger.debug(
                f"Reading file chunk: {fname}, offset={current_offset}, size={chunk_size}")

            chunk = yield ("read_file_offset", fname_bytes, current_offset, chunk_size)

            if not chunk:
                self.logger.debug(
                    f"No data returned at offset {current_offset}, stopping read")
                break

            all_data += chunk
            current_offset += len(chunk)

            # If we got less data than requested, we've reached EOF
            if len(chunk) < chunk_size:
                self.logger.debug(
                    f"Reached EOF at offset {current_offset} (requested {chunk_size}, got {len(chunk)})")
                break

        return all_data

    def write_file(self, fname, data, offset=0):
        """
        Write data to a file at a specified offset.
        Similar to read_file, this method handles chunking for large data automatically.

        Args:
            fname: Path to the file
            data: Bytes or string data to write to the file
            offset: Optional offset in bytes where to start writing (default: 0)

        Returns:
            Number of bytes written
        """
        # Convert string data to bytes if necessary
        if isinstance(data, str):
            data = data.encode('latin-1')

        fname_bytes = fname.encode('latin-1')[:255] + b'\0'

        # Calculate the maximum data size that can fit in one region
        max_data_size = self.regions_size - len(fname_bytes)

        # If data is small enough, do a single write
        if len(data) <= max_data_size:
            self.logger.debug(
                f"Writing {len(data)} bytes to file {fname} at offset {offset}")
            bytes_written = yield ("write_file", fname_bytes, offset, data)
            return bytes_written

        # For larger files, write in chunks
        total_bytes = 0
        current_offset = offset
        current_pos = 0

        while current_pos < len(data):
            # Calculate maximum chunk size to fit in memory region, considering filename length
            max_chunk = max_data_size - 16  # Add safety margin
            chunk_size = min(max_chunk, len(data) - current_pos)

            self.logger.debug(
                f"Writing file chunk: {fname}, offset={current_offset}, size={chunk_size}")
            chunk = data[current_pos:current_pos + chunk_size]

            bytes_written = yield ("write_file", fname_bytes, current_offset, chunk)

            if not bytes_written:
                self.logger.error(
                    f"Failed to write chunk at offset {current_offset}")
                break

            total_bytes += bytes_written
            current_offset += bytes_written
            current_pos += chunk_size

            # If we couldn't write the full chunk, stop
            if bytes_written < chunk_size:
                self.logger.debug(
                    f"Partial write: wrote {bytes_written} of {chunk_size} bytes")
                break

        self.logger.debug(f"Total bytes written to file: {total_bytes}")
        return total_bytes

    def exec_program(self, exe_path=None, argv=None, envp=None, wait=False):
        """
        Execute a program using the kernel's call_usermodehelper function.

        Args:
            exe_path: Path to executable
            argv: List of arguments (including program name as first arg)
            envp: Dictionary of environment variables
            wait: Whether to wait for program to complete

        Returns:
            Return code from execution
        """

        if not exe_path:
            exe_path = argv[0]

        self.logger.debug(
            f"exec_program called: exe_path={exe_path}, wait={wait}")

        # Prepare the data buffer using a list of bytes objects
        data_parts = []

        # Add executable path (null-terminated)
        data_parts.append(exe_path.encode('latin-1') + b'\0')

        # Add argv (null-separated, double-null terminated)
        if argv:
            for arg in argv:
                data_parts.append(arg.encode('latin-1') + b'\0')
        data_parts.append(b'\0')  # Double null termination

        # Add environment variables (null-separated, double-null terminated)
        if envp:
            for key, value in envp.items():
                env_string = f"{key}={value}"
                data_parts.append(env_string.encode('latin-1') + b'\0')
        data_parts.append(b'\0')  # Double null termination

        data_parts.append(b'\0')  # Just null termination

        # Convert the list to a single bytes object
        data = b''.join(data_parts)

        # Call the kernel with the prepared data
        # The wait mode is passed in header.addr field
        result = yield ("exec", wait, data)

        self.logger.debug(f"exec_program result: {result}")
        return result

    def get_proc(self, pid=None):
        proc_bytes = yield ("get_proc", pid)
        if proc_bytes:
            pb = ffi.from_buffer("struct osi_proc *", proc_bytes)
            wrap = Wrapper(pb)
            wrap.name = proc_bytes[pb.name_offset:].decode("latin-1")
            return wrap

    def get_proc_mappings(self, pid=None):
        skip = 0
        self.logger.debug(
            f"get_proc_mappings called for pid={pid}, skip={skip}")

        all_mappings = []
        current_skip = skip
        total_count = 0

        while True:
            # Send skip count in addr field, as per portal.c implementation
            self.logger.debug(f"Fetching mappings with skip={current_skip}")
            mappings_bytes = yield ("get_proc_mappings", pid, current_skip)

            if not mappings_bytes:
                self.logger.debug("No mapping data received")
                if not all_mappings:  # If this was our first request
                    return [], 0
                break

            # First 8 bytes: count of mappings in this response
            count = struct.unpack(
                f"{self.endian_format}Q", mappings_bytes[:8])[0]
            # Next 8 bytes: total count of VMAs in process
            total_count = struct.unpack(
                f"{self.endian_format}Q", mappings_bytes[8:16])[0]

            self.logger.debug(
                f"Received {count} mappings out of {total_count}")

            # Skip the header (two 64-bit counts)
            offset = 16
            mappings = []
            t = "struct osi_module"
            t_size = ffi.sizeof(t)

            # Each mapping entry
            for i in range(count):
                # Ensure we have enough data
                if offset + t_size > len(mappings_bytes):
                    self.logger.error(
                        f"Buffer too short for mapping {i}: offset {offset}, len {len(mappings_bytes)}")
                    break

                try:
                    # Create wrapper object for the mapping
                    b = ffi.from_buffer(
                        f"{t} *", mappings_bytes[offset:offset+t_size])
                    mapping = MappingWrapper(b)
                    # Extract name using name_offset
                    if mapping.name_offset and mapping.name_offset < len(mappings_bytes):
                        # Find null terminator
                        end = mappings_bytes.find(b'\0', mapping.name_offset)
                        if end != -1:
                            name = mappings_bytes[mapping.name_offset:end].decode(
                                'latin-1', errors='replace')
                            mapping.name = name
                        else:
                            mapping.name = "[unknown]"
                    else:
                        mapping.name = "[unknown]"

                    mappings.append(mapping)
                    offset += t_size  # 7 uint64 values
                except Exception as e:
                    self.logger.error(f"Error unpacking mapping {i}: {e}")
                    break

            all_mappings.extend(mappings)

            # If we received less mappings than requested or already have all mappings, we're done
            if len(mappings) == 0 or len(all_mappings) >= total_count:
                break

            # Update skip for next request
            current_skip += len(mappings)
        ret_mappings = MappingsWrapper(all_mappings)

        self.logger.debug(f"Retrieved a total of {len(all_mappings)} mappings")
        return ret_mappings
