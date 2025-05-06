from pandare2 import PyPlugin
from penguin import getColoredLogger
import struct

CHUNK_SIZE = 4072
HYPER_REGISTER_MEM_REGION = 0xbebebebe

HYPER_OP_NONE = 0
HYPER_OP_READ = 1
HYPER_RESP_READ_OK = 2
HYPER_RESP_READ_FAIL = 3
HYPER_RESP_READ_PARTIAL = 4
HYPER_OP_WRITE = 5
HYPER_RESP_WRITE_OK = 6
HYPER_RESP_WRITE_FAIL = 7
HYPER_OP_READ_FD_NAME = 8
HYPER_OP_READ_PROCARGS = 9
HYPER_OP_READ_SOCKET_INFO = 10
HYPER_OP_READ_STR = 11
HYPER_OP_READ_FILE = 12
HYPER_OP_READ_PROCENV = 13
HYPER_OP_READ_PROCPID = 14
HYPER_RESP_READ_NUM = 15


class Hypermem(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("hypermem")
        self.panda = panda
        self.cpu_iterators = {}
        self.panda.hypercall(HYPER_REGISTER_MEM_REGION)(
            self._register_cpu_memregion)
        self.cpu_memregions = {}
        # Set endianness format character for struct operations
        self.endian_format = '<' if panda.endianness == 'little' else '>'

    def _read_memregion_state(self, cpu):
        cpu_memregion = self.cpu_memregions[cpu]
        mem = self.panda.virtual_memory_read(cpu, cpu_memregion, 8*3)
        op, addr, size = struct.unpack("<QQQ", mem)
        return op, addr, size

    def _read_memregion_data(self, cpu, size):
        cpu_memregion = self.cpu_memregions[cpu]
        if size > CHUNK_SIZE:
            self.logger.error(f"Size {size} exceeds chunk size {CHUNK_SIZE}")
            size = CHUNK_SIZE
        try:
            mem = self.panda.virtual_memory_read(cpu, cpu_memregion+24, size)
            return mem
        except ValueError as e:
            self.logger.error(f"Failed to read memory: {e}")

    def _write_memregion_state(self, cpu, op, addr, size):
        cpu_memregion = self.cpu_memregions[cpu]
        mem = struct.pack("<QQQ", op, addr, size)
        try:
            self.panda.virtual_memory_write(cpu, cpu_memregion, mem)
        except ValueError as e:
            self.logger.error(f"Failed to write memregion state: {e}")

    def _write_memregion_data(self, cpu, data):
        cpu_memregion = self.cpu_memregions[cpu]
        try:
            self.panda.virtual_memory_write(cpu, cpu_memregion+24, data)
        except ValueError as e:
            self.logger.error(f"Failed to write memregion data: {e}")

    def _handle_input_state(self, cpu):
        in_op = None
        op, addr, size = self._read_memregion_state(cpu)
        if op == HYPER_OP_NONE:
            pass
        elif op == HYPER_RESP_READ_OK:
            self.logger.debug(f"Read OK: {addr:#x} {size}")
            data = self._read_memregion_data(cpu, size)
            in_op = (op, data)
        elif op == HYPER_RESP_READ_PARTIAL:
            self.logger.debug(f"Read OK: {addr:#x} {size}")
            data = self._read_memregion_data(cpu, size)
            in_op = (op, data)
        elif op == HYPER_RESP_READ_NUM:
            in_op = (op, size)
        elif op == HYPER_RESP_WRITE_OK:
            pass
        elif op == HYPER_RESP_READ_FAIL:
            self.logger.error("Failed to read memory")
            pass
        else:
            self.logger.error(f"Unknown operation {op}")
        return in_op

    def _handle_output_cmd(self, cpu, cmd):
        match cmd:
            case ("read", addr, size):
                self._write_memregion_state(cpu, HYPER_OP_READ, addr, size)
            case ("read_str", addr):
                self._write_memregion_state(cpu, HYPER_OP_READ_STR, addr, 0)
            case ("read_fd_name", fd):
                self._write_memregion_state(cpu, HYPER_OP_READ_FD_NAME, fd, 0)
            case ("read_proc_args"):
                self._write_memregion_state(cpu, HYPER_OP_READ_PROCARGS, 0, 0)
            case ("read_proc_env"):
                self._write_memregion_state(cpu, HYPER_OP_READ_PROCENV, 0, 0)
            case ("read_proc_pid"):
                self._write_memregion_state(cpu, HYPER_OP_READ_PROCPID, 0, 0)
            case ("write", addr, data):
                self._write_memregion_state(
                    cpu, HYPER_OP_WRITE, addr, len(data))
                self._write_memregion_data(cpu, data)
            case None:
                self._write_memregion_state(cpu, HYPER_OP_NONE, 0, 0)
            case _:
                self.logger.error(f"Unknown command: {cmd}")

    def wrap(self, f):
        def wrapper(*args, **kwargs):
            cpu = self.panda.get_cpu()

            if cpu not in self.cpu_iterators or self.cpu_iterators[cpu] is None:
                self.logger.debug(f"Creating new iterator for CPU {cpu}")
                self.cpu_iterators[cpu] = f(*args, **kwargs)

                # in_op is assumed to have state None at the beginning
                in_op = None
                new_iterator = True
            else:
                in_op = self._handle_input_state(cpu)
                new_iterator = False

            try:
                if not in_op:
                    cmd = next(self.cpu_iterators[cpu])
                elif in_op[0] == HYPER_RESP_READ_OK:
                    cmd = self.cpu_iterators[cpu].send(in_op[1])
                elif in_op[0] == HYPER_RESP_READ_NUM:
                    cmd = self.cpu_iterators[cpu].send(in_op[1])
                elif in_op[0] == HYPER_RESP_READ_PARTIAL:
                    cmd = self.cpu_iterators[cpu].send(in_op[1])
                else:
                    raise Exception(f"Invalid state cmd is {in_op}")
            except StopIteration:
                self.cpu_iterators[cpu] = None
                cmd = None

            if new_iterator and cmd is None:
                # this is basically a no-op. Our functionality wasn't used
                return

            try:
                self._handle_output_cmd(cpu, cmd)
            except ValueError as e:
                self.logger.error(f"Failed to write memory {e}")
        return wrapper

    def _register_cpu_memregion(self, cpu):
        self.cpu_memregions[cpu] = self.panda.arch.get_arg(
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
                self.logger.error(
                    f"Failed to read memory at addr={chunk_addr}, size={chunk_size}")
                chunk = b"\x00" * chunk_size
            self.logger.debug(
                f"Received response from queue: {chunk} chunk_len={len(chunk)}")
            data += chunk
        data = data[:size]
        self.logger.debug(f"Total bytes read: {len(data)}")
        return data

    def read_str(self, addr):
        self.logger.debug(f"read_str called: addr={addr}")
        chunk = yield ("read_str", addr)
        if chunk:
            self.logger.debug(f"Received response from queue: {chunk}")
            return chunk.decode('latin-1', errors='replace')

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

    def read_fd_name(self, fd):
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
                f"File descriptor name read successfully: {args}")
            return args
        return []

    def get_proc_env(self):
        self.logger.debug("get_process_env called")
        proc_env = yield ("read_proc_env")
        if proc_env:
            args = [i.decode("latin-1").split("=")
                    for i in proc_env.split(b"\0") if i]
            env = {k: v for k, v in args}
            self.logger.debug(f"File descriptor name read successfully: {env}")
            return env
        return {}

    def get_proc_pid(self):
        self.logger.info("read_process_pid called")
        pid = yield ("read_proc_pid")
        if pid:
            self.logger.info(f"Process PID read successfully: {pid}")
            return pid
        return None
