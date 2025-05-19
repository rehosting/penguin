from pandare2 import PyPlugin
from penguin import getColoredLogger
import struct
from collections.abc import Iterator
import functools
from hyper.consts import *
from wrappers.generic import Wrapper
from wrappers.portal_wrap import MappingWrapper, MappingsWrapper
import time

CURRENT_PID_NUM = 0xffffffff

kffi = plugins.kffi


class Portal(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.portal")
        # if self.get_arg_bool("verbose"):
        #     self.logger.setLevel("DEBUG")
        self.panda = panda
        self.cpu_memregion_structs = {}
        # Set endianness format character for struct operations
        self.endian_format = '<' if panda.endianness == 'little' else '>'
        self.portal_interrupt = None
        self.try_panda = True if self.panda.arch != "riscv64" else False

        # Generic interrupts mechanism
        self._interrupt_handlers = {}  # plugin_name -> handler_function
        self._pending_interrupts = set()  # Set of plugin names with pending work
        self.panda.hypercall(IGLOO_HYPER_REGISTER_MEM_REGION)(
            self._register_cpu_memregion)
        self.panda.hypercall(IGLOO_HYPER_ENABLE_PORTAL_INTERRUPT)(
            self._register_portal_interrupt)
        # Don't wrap _portal_interrupt - it's not a generator function
        self.panda.hypercall(IGLOO_HYPER_PORTAL_INTERRUPT)(
            self.wrap(self._portal_interrupt))

    def _register_portal_interrupt(self, cpu):
        self.portal_interrupt = self.panda.arch.get_arg(
            cpu, 1, convention="syscall")
        assert self.panda.arch.get_arg(
            cpu, 2, convention="syscall") == 0

    def _portal_interrupt(self, cpu):
        """Handle portal interrupts - process pending items from registered plugins"""
        # Process one item from each plugin that has pending interrupts
        interrupts = self._pending_interrupts.copy()
        self._pending_interrupts.clear()
        for plugin_name in list(interrupts):
            if plugin_name in self._interrupt_handlers:
                handler_fn = self._interrupt_handlers[plugin_name]
                self.logger.debug(f"Processing interrupt for {plugin_name}")
                # Call handler function without any arguments
                # Plugin is responsible for tracking its own pending work
                yield from handler_fn()

    def register_interrupt_handler(self, plugin_name, handler_fn):
        """
        Register a plugin to handle portal interrupts.

        Args:
            plugin_name (str): Name of the plugin
            handler_fn (callable): Function to handle interrupts for this plugin
                                  Must be a generator function that can be used with yield from
        """
        self.logger.debug(f"Registering interrupt handler for {plugin_name}")
        # The handler function should be a wrapped generator
        self._interrupt_handlers[plugin_name] = handler_fn
        if plugin_name in self._pending_interrupts:
            self.logger.debug(
                f"Plugin {plugin_name} already had pending interrupts")

    def queue_interrupt(self, plugin_name):
        """
        Queue an interrupt for a plugin.

        Args:
            plugin_name (str): Name of the plugin

        Returns:
            bool: True if queued successfully, False otherwise
        """
        if plugin_name not in self._interrupt_handlers:
            self.logger.error(
                f"No interrupt handler registered for {plugin_name}")
            return False

        # Add plugin to pending set
        self._pending_interrupts.add(plugin_name)

        # Trigger an interrupt to process the item
        self._portal_set_interrupt()
        return True

    def _cleanup_all_interrupts(self):
        """Clean up all registered interrupt handlers and pending interrupts"""
        self._interrupt_handlers = {}
        self._pending_interrupts = set()

    def _portal_set_interrupt_value(self, value):
        if self.portal_interrupt:
            buf = struct.pack(f"{self.endian_format}Q", value)
            self.panda.virtual_memory_write(
                self.panda.get_cpu(), self.portal_interrupt, buf)

    def _portal_set_interrupt(self):
        self._portal_set_interrupt_value(1)

    def _portal_clear_interrupt(self):
        self._portal_set_interrupt_value(0)

    '''
    Our memregion is the first available memregion OR the one that is owned by us

    This can return none
    '''

    def _read_memregion_state(self, cpu):
        cpu_memregion = self.cpu_memregion_structs[cpu]
        memr = kffi.read_type_panda(cpu, cpu_memregion, "region_header")
        self.logger.debug(
            f"Reading memregion state: op={memr.op}, addr={memr.addr:#x}, size={memr.size}")
        return memr.op, memr.addr, memr.size

    def _read_memregion_data(self, cpu, size):
        cpu_memregion = self.cpu_memregion_structs[cpu]
        if size > self.regions_size:
            self.logger.error(
                f"Size {size} exceeds chunk size {self.regions_size}")
            size = self.regions_size
        try:
            mem = self.panda.virtual_memory_read(
                cpu, cpu_memregion+kffi.sizeof("region_header"), size)
            return mem
        except ValueError as e:
            self.logger.error(f"Failed to read memory: {e}")

    def _write_memregion_state(self, cpu, op, addr, size, pid=None):
        cpu_memregion = self.cpu_memregion_structs[cpu]
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

        # mem = struct.pack("<QQQQ", op, addr, size, pid)
        mem = kffi.new("region_header")
        mem.op = op
        mem.addr = addr
        mem.size = size
        mem.pid = pid

        try:
            self.panda.virtual_memory_write(cpu, cpu_memregion, mem.to_bytes())
        except ValueError as e:
            self.logger.error(f"Failed to write memregion state: {e}")

    def _write_memregion_data(self, cpu, data):
        cpu_memregion = self.cpu_memregion_structs[cpu]
        if len(data) > self.regions_size:
            self.logger.error(
                f"Data length {len(data)} exceeds chunk size {self.regions_size}")
            data = data[:self.regions_size]
        try:
            self.panda.virtual_memory_write(
                cpu, cpu_memregion+kffi.sizeof("region_header"), data)
        except ValueError as e:
            self.logger.error(f"Failed to write memregion data: {e}")

    def _handle_input_state(self, cpu):
        in_op = None
        op, addr, size = self._read_memregion_state(cpu)
        if op == HYPER_OP_NONE:
            pass
        elif op & HYPER_RESP_NONE == 0:
            self.logger.error(f"Invalid operation OP in return {op:#x}")
        elif op < HYPER_RESP_NONE or op > HYPER_RESP_MAX:
            self.logger.error(f"Invalid operation: {op:#x}")
        elif op == HYPER_RESP_READ_OK:
            self.logger.debug(f"Read OK: {addr:#x} {size}")
            data = self._read_memregion_data(cpu, size)
            in_op = (op, data)
        elif op == HYPER_RESP_READ_FAIL:
            self.logger.debug("Failed to read memory")
        elif op == HYPER_RESP_READ_PARTIAL:
            self.logger.debug(f"Read OK: {addr:#x} {size}")
            data = self._read_memregion_data(cpu, size)
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

    def _handle_output_cmd(self, cpu, cmd):
        match cmd:
            case("read", addr, size, pid):
                self._write_memregion_state(
                    cpu, HYPER_OP_READ, addr, size, pid)
            case("read_str", addr, pid):
                self._write_memregion_state(
                    cpu, HYPER_OP_READ_STR, addr, 0, pid)
            case("read_proc_args", pid):
                self._write_memregion_state(
                    cpu, HYPER_OP_READ_PROCARGS, 0, 0, pid)
            case("read_proc_env", pid):
                self._write_memregion_state(
                    cpu, HYPER_OP_READ_PROCENV, 0, 0, pid)
            case("read_file_offset", fname, offset, size):
                self._write_memregion_state(
                    cpu, HYPER_OP_READ_FILE, offset, size)
                self._write_memregion_data(cpu, fname)
            case("write_file", fname, offset, data):
                self._write_memregion_state(
                    cpu, HYPER_OP_WRITE_FILE, offset, len(data))
                self._write_memregion_data(cpu, fname + data)
            case("get_osi_proc_handles"):
                self._write_memregion_state(
                    cpu, HYPER_OP_OSI_PROC_HANDLES, 0, 0)
            case("get_fds", start_fd, pid):
                self._write_memregion_state(
                    cpu, HYPER_OP_READ_FDS, start_fd, 0, pid)
            case("get_proc", pid):
                self._write_memregion_state(
                    cpu, HYPER_OP_OSI_PROC, 0, 0, pid)
            case("get_proc_mappings", pid, skip):
                self._write_memregion_state(
                    cpu, HYPER_OP_OSI_MAPPINGS, skip, 0, pid)
            case("exec", wait, data):
                self._write_memregion_state(
                    cpu, HYPER_OP_EXEC, wait, len(data))
                self._write_memregion_data(cpu, data)
            case("write", addr, data, pid):
                self._write_memregion_state(
                    cpu, HYPER_OP_WRITE, addr, len(data), pid)
                self._write_memregion_data(cpu, data)
            case("ffi_exec", ffi_data):
                self._write_memregion_state(
                    cpu, HYPER_OP_FFI_EXEC, 0, len(ffi_data))
                self._write_memregion_data(cpu, ffi_data)
            case("uprobe_reg", addr, data):
                self._write_memregion_state(
                    cpu, HYPER_OP_REGISTER_UPROBE, addr, len(data))
                self._write_memregion_data(cpu, data)
            case("uprobe_unreg", id_):
                self._write_memregion_state(
                    cpu, HYPER_OP_UNREGISTER_UPROBE, id_, 0)
            case("syscall_reg", data):
                self._write_memregion_state(
                    cpu, HYPER_OP_REGISTER_SYSCALL_HOOK, 0, len(data))
                self._write_memregion_data(cpu, data)
            case("syscall_unreg", id_):
                self._write_memregion_state(
                    cpu, HYPER_OP_UNREGISTER_SYSCALL_HOOK, id_, 0)
            case("dump", mode, signal):
                # mode in lowest 8 bits, signal in next 8 bits
                dump_addr = ((signal & 0xFF) << 8) | (mode & 0xFF)
                self._write_memregion_state(
                    cpu, HYPER_OP_DUMP, dump_addr, 0)
            case None:
                return False
            case _:
                breakpoint()
                self.logger.error(f"Unknown command: {cmd}")
                return False
        return True

    def wrap(self, f):
        cpu_iterators = {}
        cpu_iterator_start = {}
        claimed_slot = {}
        iteration_time = {}

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            cpu = self.panda.get_cpu()
            fn_return = None
            # nonlocal cpu_iterators, claimed_slot, cpu_iterator_start

            if cpu not in self.cpu_memregion_structs:
                self.logger.error("CPU not registered")
                return

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
                iteration_time[cpu] = time.time()
                new_iterator = True

            in_op = self._handle_input_state(cpu)

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
                cpu_iterators[cpu] = None
                # The function has completed, and we need to return the value
                fn_return = e.value
                cpu_iterator_start[cpu] = None
                self._write_memregion_state(
                    cpu, HYPER_OP_NONE, 0, 0)
                claimed_slot[cpu] = None
                cmd = None

            if new_iterator and cmd is None:
                # this is basically a no-op. Our functionality wasn't used
                return fn_return

            self._handle_output_cmd(cpu, cmd)

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
        cpu = None
        for i in range((len(data) + self.regions_size - 1) // self.regions_size):
            offset = i * self.regions_size
            chunk_addr = addr + offset
            chunk_data = data[offset:offset + self.regions_size]
            self.logger.debug(
                f"Writing chunk: chunk_addr={chunk_addr}, chunk_len={len(chunk_data)}")
            success = False
            if self.try_panda:
                if cpu is None:
                    cpu = self.panda.get_cpu()
                try:
                    self.panda.virtual_memory_write(
                        cpu, chunk_addr, chunk_data)
                    success = True
                except ValueError:
                    pass
            if not success:
                yield ("write", chunk_addr, chunk_data, pid)
        self.logger.debug(f"Total bytes written: {len(data)}")
        return len(data)

    def read_bytes(self, addr, size, pid=None):
        self.logger.debug(f"read_bytes called: addr={addr}, size={size}")
        data = b""
        cpu = None
        for i in range((size + self.regions_size - 1) // self.regions_size):
            offset = i * self.regions_size
            chunk_addr = addr + offset
            chunk_size = min(self.regions_size, size - offset)
            self.logger.debug(
                f"Reading chunk: chunk_addr={chunk_addr}, chunk_size={chunk_size}")
            chunk = None
            if self.try_panda:
                if cpu is None:
                    cpu = self.panda.get_cpu()
                try:
                    chunk = self.panda.virtual_memory_read(
                        cpu, chunk_addr, chunk_size)
                except ValueError:
                    pass
            if not chunk:
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
            if self.try_panda:
                try:
                    chunk = self.panda.read_str(self.panda.get_cpu(), addr)
                    return chunk
                except ValueError:
                    pass
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
        """
        Get the filename for a specific file descriptor.

        This uses the more efficient get_fds function that can return information
        for a specific file descriptor instead of sending a separate hypercall.

        Args:
            fd: File descriptor number
            pid: Process ID, or None for current process

        Returns:
            The file descriptor name as a string
        """
        self.logger.debug(f"get_fd_name called: fd={fd}")

        # Try using the get_fds functionality first (more efficient)
        # Only request the single FD we need
        fds = yield from self.get_fds(pid=pid, start_fd=fd, count=1)
        if fds and len(fds) > 0 and fds[0].fd == fd:
            fd_name = fds[0].name
            self.logger.debug(
                f"File descriptor name read successfully: {fd_name}")
            return fd_name

    def get_args(self, pid=None):
        self.logger.debug("read_process_args called")
        proc_args = yield ("read_proc_args", pid)

        if not proc_args:
            return []

        # From examining the handle_op_read_procargs function in portal_osi.c:
        # - The kernel reads the process args area (mm->arg_start to mm->arg_end)
        # - In Linux, arguments are already null-terminated in memory
        # - The kernel converts nulls to spaces (except the final one)
        # - This creates a space-separated string, similar to /proc/pid/cmdline

        # First, strip any trailing null bytes at the end of the buffer
        proc_args = proc_args.rstrip(b'\0')

        # Split by spaces which is how the kernel formats the arguments
        # The kernel function converts nulls to spaces except for the last one
        args = proc_args.decode('latin-1', errors='replace').split()

        # Remove any binary garbage that might be present (common issue with syscalls)
        clean_args = []
        for arg in args:
            # Remove trailing null characters from each argument
            arg = arg.rstrip('\0')

            # Simple heuristic: if most chars are printable, it's probably a valid arg
            if sum(c.isprintable() for c in arg) > len(arg) * 0.8:
                clean_args.append(arg)

        self.logger.debug(f"Proc args read successfully: {clean_args}")
        return clean_args

    def get_proc_name(self, pid=None):
        self.logger.debug("get_process_name called")
        proc_name = yield from self.get_args(pid)
        if proc_name:
            return proc_name[0]
        return "[???]"

    def get_env(self, pid=None):
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
            pb = kffi.from_buffer("osi_proc", proc_bytes)
            wrap = Wrapper(pb)
            wrap.name = proc_bytes[pb.name_offset:].decode("latin-1")
            return wrap

    def get_mappings(self, pid=None):
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

            orh_struct = kffi.from_buffer("osi_result_header", mappings_bytes)
            count = orh_struct.result_count
            total_count = orh_struct.total_count

            # Get the actual size of data returned from the kernel
            total_size = len(mappings_bytes)

            self.logger.debug(
                f"Received {count} mappings out of {total_count}, buffer size: {total_size}")

            # Skip the header (two 64-bit counts)
            offset = 16
            mappings = []
            t_size = kffi.sizeof("osi_module")

            # Verify expected module array size against buffer size
            expected_end = offset + (count * t_size)
            if expected_end > total_size:
                self.logger.warning(
                    f"Buffer too small for all mappings: need {expected_end}, got {total_size}. Adjusting count.")
                # Adjust count to fit available buffer
                adjusted_count = (total_size - offset) // t_size
                if adjusted_count < count:
                    count = adjusted_count
                    self.logger.warning(f"Adjusted mapping count to {count}")

            # Each mapping entry
            for i in range(count):
                # Ensure we have enough data
                if offset + t_size > total_size:
                    self.logger.error(
                        f"Buffer too short for mapping {i}: offset {offset}, len {total_size}")
                    break

                try:
                    # Create wrapper object for the mapping
                    b = kffi.from_buffer(
                        "osi_module", mappings_bytes, instance_offset_in_buffer=offset)
                    mapping = MappingWrapper(b)

                    # Check if name_offset is within bounds, and if the offset makes sense
                    if mapping.name_offset and mapping.name_offset < total_size:
                        try:
                            # Find null terminator - safely handle potential out-of-bounds access
                            end = mappings_bytes.find(
                                b'\0', mapping.name_offset)
                            if end != -1 and end < total_size:
                                name = mappings_bytes[mapping.name_offset:end].decode(
                                    'latin-1', errors='replace')
                                mapping.name = name
                            else:
                                # If no null terminator found or out of bounds, use a limited slice
                                max_name_len = total_size - mapping.name_offset
                                if max_name_len > 0:
                                    name = mappings_bytes[mapping.name_offset:mapping.name_offset+max_name_len].decode(
                                        'latin-1', errors='replace')
                                    mapping.name = name
                                else:
                                    mapping.name = "[unknown]"
                        except Exception as e:
                            self.logger.warning(
                                f"Error decoding name for mapping {i}: {e}")
                            mapping.name = "[invalid name]"
                    else:
                        mapping.name = "[unknown]"

                    mappings.append(mapping)
                    offset += t_size  # Size of struct osi_module
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

    def get_proc_handles(self):
        """
        Retrieve a list of process handles from the kernel.

        Returns:
            A list of process handle objects with properties:
                pid: Process ID
                taskd: Task descriptor address
                start_time: Process creation time
        """
        self.logger.debug("get_proc_handles called")

        # Fetch proc handles from the kernel
        proc_handles_bytes = yield ("get_osi_proc_handles")

        if not proc_handles_bytes:
            self.logger.debug("No process handles data received")
            return []

        # Get the actual size of data returned from the kernel
        total_size = len(proc_handles_bytes)

        # Ensure we have enough data for the header
        if total_size < 16:
            self.logger.error(
                f"Buffer too small for header: {total_size} bytes")
            return []

        # Extract header information
        orh_struct = kffi.from_buffer("osi_result_header", proc_handles_bytes)
        count = orh_struct.result_count
        total_count = orh_struct.total_count

        self.logger.debug(
            f"Received {count} process handles out of {total_count}")

        # Validate count values
        if count > 10000:
            self.logger.warning(
                f"Unreasonably large handle count: {count}, capping at 1000")
            count = 1000

        # Skip the header
        offset = kffi.sizeof("osi_result_header")
        handles = []
        handle_type = "osi_proc_handle"
        handle_size = kffi.sizeof(handle_type)

        # Calculate how many handles can actually fit in the buffer
        max_possible_count = (total_size - offset) // handle_size
        safe_count = min(count, max_possible_count)

        if safe_count < count:
            self.logger.warning(
                f"Buffer can only fit {safe_count} handles out of reported {count}")
            count = safe_count

        # Process each handle
        for i in range(count):
            if offset + handle_size > total_size:
                self.logger.error(
                    f"Buffer too short for handle {i}: offset {offset}, len {total_size}")
                break

            try:
                # Create wrapper object for the handle
                handle = kffi.from_buffer(
                    "osi_proc_handle", proc_handles_bytes, instance_offset_in_buffer=offset)
                handle_wrapper = Wrapper(handle)
                handles.append(handle_wrapper)
                offset += handle_size
            except Exception as e:
                self.logger.error(f"Error unpacking handle {i}: {e}")
                break

        self.logger.debug(f"Retrieved {len(handles)} process handles")
        return handles

    def get_fds(self, pid=None, start_fd=0, count=None):
        """
        Retrieve file descriptors for a process.

        Args:
            pid: Process ID, or None for current process
            start_fd: FD number to start listing from (for pagination), defaults to 0
            count: Maximum number of file descriptors to return (None for all)

        Returns:
            List of file descriptor objects with fd and name properties
        """
        # Ensure start_fd is an integer
        if start_fd is None:
            start_fd = 0

        self.logger.debug(
            f"get_fds called: start_fd={start_fd}, pid={pid}, count={count}")
        fds = []
        current_fd = start_fd
        while True:
            fds_bytes = yield ("get_fds", current_fd, pid)

            if not fds_bytes:
                self.logger.debug("No file descriptors data received")
                # Return empty list only if we haven't fetched any FDs yet
                if not fds:
                    return []
                break

            # Get the actual size of data returned from the kernel
            total_size = len(fds_bytes)

            # Ensure we have enough data for the header
            if total_size < 16:
                self.logger.error(
                    f"Buffer too small for header: {total_size} bytes")
                return []

            # Make sure we're using the correct header structure format
            orh_struct = kffi.from_buffer("osi_result_header", fds_bytes)
            # In the kernel, these are LE64 values, need to access correctly
            batch_count = orh_struct.result_count
            total_count = orh_struct.total_count

            self.logger.debug(
                f"Raw header values: result_count={batch_count}, total_count={total_count}")

            self.logger.debug(
                f"Received {batch_count} file descriptors out of {total_count}")

            # Break if there are no FDs in this batch to avoid infinite loop
            if batch_count == 0:
                self.logger.debug(
                    "No file descriptors in this batch, breaking loop")
                break

            # Skip the header
            offset = kffi.sizeof("osi_result_header")
            fd_size = kffi.sizeof("osi_fd_entry")

            # Process each FD entry
            for i in range(batch_count):
                if offset + fd_size > total_size:
                    self.logger.error(
                        f"Buffer too short for FD {i}: offset {offset}, len {total_size}")
                    break

                try:
                    # Create wrapper object for the FD
                    fd_entry = kffi.from_buffer(
                        "osi_fd_entry", fds_bytes, instance_offset_in_buffer=offset)
                    fd_wrapper = Wrapper(fd_entry)

                    # Extract the path name using name_offset
                    if fd_entry.name_offset and fd_entry.name_offset < total_size:
                        try:
                            # Find null terminator
                            end = fds_bytes.find(b'\0', fd_entry.name_offset)
                            if end != -1 and end < total_size:
                                name = fds_bytes[fd_entry.name_offset:end].decode(
                                    'latin-1', errors='replace')
                                fd_wrapper.name = name
                            else:
                                # Limited slice if no null terminator
                                max_name_len = min(
                                    256, total_size - fd_entry.name_offset)
                                if max_name_len > 0:
                                    name = fds_bytes[fd_entry.name_offset:fd_entry.name_offset+max_name_len].decode(
                                        'latin-1', errors='replace')
                                    fd_wrapper.name = name
                                else:
                                    fd_wrapper.name = "[unknown]"
                        except Exception as e:
                            self.logger.warning(
                                f"Error decoding name for FD {i}: {e}")
                            fd_wrapper.name = "[invalid name]"
                    else:
                        fd_wrapper.name = "[unknown]"

                    fds.append(fd_wrapper)
                    offset += fd_size
                except Exception as e:
                    self.logger.error(f"Error unpacking FD entry {i}: {e}")
                    break
            # Track how many FDs we've processed in this batch
            self.logger.debug(
                f"Retrieved {batch_count} file descriptors in this batch, total now: {len(fds)}")

            # Update current_fd for next iteration (pagination)
            # We need to update by batch_count, not the total accumulated fds
            # Otherwise we might skip entries or go into an infinite loop
            current_fd += batch_count

            # Break if we've got all available FDs from kernel
            if len(fds) >= total_count:
                break

            # Break if we've fetched enough FDs based on count parameter
            if count is not None and len(fds) >= count:
                break

        # Protection against incorrect data in the list or count mismatch
        if count is not None and len(fds) > count:
            fds = fds[:count]

        # Just return the list of FDs
        return fds

    def get_mapping_by_addr(self, addr):
        self.logger.debug(f"get_mapping_by_addr called: addr={addr:#x}")
        maps = yield from self.get_mappings()
        if maps:
            mapping = maps.get_mapping_by_addr(addr)
            if mapping:
                self.logger.debug(
                    f"Mapping found: {mapping.name} at {mapping.start:#x} - {mapping.end:#x}")
                return mapping
            else:
                self.logger.debug(f"No mapping found for addr={addr:#x}")

    def dump(self, mode=0, signal=0):
        """
        Trigger a core dump in the guest.

        Args:
            mode (int): Dump mode (0=full snapshot and coredump, 1=self abort, 2=custom signal)
            signal (int): Signal number to send (only used with mode=2)

        Returns:
            int: PID of the process that received the signal, or error code
        """
        response = yield ("dump", mode, signal)
        if response is None:
            self.logger.error(f"Failed to execute dump operation")
            return None
        return response

    def crash_snapshot(self):
        """
        Create a snapshot and core dump in the guest (default dump mode).

        Returns:
            int: PID of the process that received the signal, or error code
        """
        return (yield from self.dump(mode=0))

    def self_abort(self):
        """
        Send SIGABRT to the current process in the guest.

        Returns:
            int: PID of the process that received SIGABRT, or error code
        """
        return (yield from self.dump(mode=1))

    def self_signal(self, signal):
        """
        Send a custom signal to the current process in the guest.

        Args:
            signal (int): Signal number to send (1-31)

        Returns:
            int: PID of the process that received the signal, or error code
        """
        if not 1 <= signal <= 31:
            raise ValueError(
                f"Invalid signal number: {signal}. Must be between 1 and 31.")
        return (yield from self.dump(mode=2, signal=signal))

    def uninit(self):
        self._cleanup_all_interrupts()
