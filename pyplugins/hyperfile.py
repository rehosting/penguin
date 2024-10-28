import struct
from pandare import PyPlugin

try:
    from penguin import yaml
except ImportError:
    import yaml

# Make sure these match hyperfs
HYPER_MAGIC = 0x51EC3692
HYPER_FILE_OP = 0
HYPER_GET_NUM_HYPERFILES = 1
HYPER_GET_HYPERFILE_PATHS = 2
HYPER_READ = 0
HYPER_WRITE = 1
HYPER_IOCTL = 2
HYPER_GETATTR = 3
RETRY = 0xDEADBEEF


def hyper(name):
    if name == "read":
        return HYPER_READ
    elif name == "write":
        return HYPER_WRITE
    elif name == "ioctl":
        return HYPER_IOCTL
    elif name == "getattr":
        return HYPER_GETATTR
    raise ValueError(f"Unknown hyperfile operation {name}")


def hyper2name(num):
    if num == HYPER_READ:
        return "read"
    elif num == HYPER_WRITE:
        return "write"
    elif num == HYPER_IOCTL:
        return "ioctl"
    elif num == HYPER_GETATTR:
        return "getattr"
    raise ValueError(f"Unknown hyperfile operation {num}")


class HyperFile(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.arch_bytes = panda.bits // 8
        self.log_file = self.get_arg("log_file")
        self.files = self.get_arg("models")
        self.logger = self.get_arg("logger")

        # Struct format strings for endianness and word size
        self.endian = '<' if panda.endianness == 'little' else '>'
        self.s_word, self.u_word = 'iI' if panda.bits == 32 else 'qQ'

        if self.files is None:
            # We can be imported without files, but we'll ignore it
            return

        if self.log_file:
            # Initialize a blank file so we can tail it
            open(self.log_file, "w").close()

        # We track when processes access or IOCTL files we've added here:
        self.results = {}  # path: {event: ... }
        # event="read": {bytes_read: X, data: "0"}
        # event="write": {bytes_written: X, data: ...}
        # event="icotl": {mode: {count: X, rv: Y}}

        assert isinstance(self.files, dict), f"Files should be dict, not {self.files}"

        self.default_model = {
            HYPER_READ: self.read_unhandled,
            HYPER_WRITE: self.write_unhandled,
            HYPER_IOCTL: self.ioctl,
            HYPER_GETATTR: self.getattr,
            "size": 0,
        }

        # files = {filename: {'read': func, 'write': func, 'ioctl': func}}}

        # On hypercall we dispatch to the appropriate handler: read, write, ioctl
        @panda.hypercall(HYPER_MAGIC)
        def before_hypercall(cpu):
            # We pass args in the arch-syscall ABI specified in pypanda's arch.py
            # arm: x8/r7 r0, r1, r2
            # mips: v0, a0, a1, a2
            hc_type = panda.arch.get_arg(cpu, 1, convention="syscall")
            if hc_type == HYPER_FILE_OP:
                self.handle_file_op(cpu)
            elif hc_type == HYPER_GET_NUM_HYPERFILES:
                self.handle_get_num_hyperfiles(cpu)
            elif hc_type == HYPER_GET_HYPERFILE_PATHS:
                self.handle_get_hyperfile_paths(cpu)

    def handle_get_num_hyperfiles(self, cpu):
        num_hyperfiles_addr_addr = self.panda.arch.get_arg(cpu, 2, convention="syscall")
        num_ptrs = self.panda.arch.get_arg(cpu, 3, convention="syscall")
        assert num_ptrs == 1
        try:
            num_hyperfiles_addr = self.panda.virtual_memory_read(cpu, num_hyperfiles_addr_addr, self.arch_bytes, fmt="int")
            self.panda.virtual_memory_write(
                cpu,
                num_hyperfiles_addr,
                struct.pack(f"{self.endian} {self.u_word}", len(self.files)),
            )
        except ValueError:
            # Memory r/w failed - tell guest to retry
            self.panda.arch.set_retval(cpu, RETRY)
            self.logger.debug("Failed to read/write number of hyperfiles from guest - retry")

    def handle_get_hyperfile_paths(self, cpu):
        hyperfile_paths_array_ptr = self.panda.arch.get_arg(cpu, 2, convention="syscall")
        n = len(self.files)
        assert n == self.panda.arch.get_arg(cpu, 3, convention="syscall")
        hyperfile_paths_ptrs = [None] * n
        for i in range(n):
            try:
                hyperfile_paths_ptrs[i] = self.panda.virtual_memory_read(
                    cpu,
                    hyperfile_paths_array_ptr + i * self.arch_bytes,
                    self.arch_bytes,
                    fmt="int",
                )
            except ValueError:
                self.panda.arch.set_retval(cpu, RETRY)
                self.logger.debug("Failed to read hyperfile path ptr from guest - retry")
                return
        for path, buf in zip(self.files.keys(), hyperfile_paths_ptrs):
            try:
                self.panda.virtual_memory_write(cpu, buf, path.encode())
            except ValueError:
                self.panda.arch.set_retval(cpu, RETRY)
                self.logger.debug("Failed to write hyperfile path to guest - retry")
                return

    def handle_file_op(self, cpu):
        buf_addr_addr = self.panda.arch.get_arg(cpu, 2, convention="syscall")
        num_ptrs = self.panda.arch.get_arg(cpu, 3, convention="syscall")
        assert num_ptrs == 1

        header_fmt = f"{self.endian} i {self.u_word}"
        read_fmt = write_fmt = f"{self.endian} {self.u_word} {self.u_word} q"
        ioctl_fmt = f"{self.endian} I {self.u_word}"
        getattr_fmt = f"{self.endian} {self.u_word}"
        hyperfs_data_size = struct.calcsize(header_fmt) + max(struct.calcsize(fmt) for fmt in (read_fmt, write_fmt, ioctl_fmt))

        try:
            buf_addr = self.panda.virtual_memory_read(cpu, buf_addr_addr, self.arch_bytes, fmt="int")
            buf = self.panda.virtual_memory_read(cpu, buf_addr, hyperfs_data_size, fmt="bytearray")
        except ValueError:
            # Memory read failed - tell guest to retry
            self.panda.arch.set_retval(cpu, RETRY)
            self.logger.debug("Failed to read hyperfile struct from guest - retry")
            return

        # Unpack request with our dynamic format string
        type_val, path_ptr = struct.unpack_from(header_fmt, buf)
        try:
            device_name = self.panda.read_str(cpu, path_ptr)
        except ValueError:
            # Memory read failed - tell guest to retry
            self.panda.arch.set_retval(cpu, RETRY)
            self.logger.debug("Failed to read hyperfile struct from guest - retry")
            return

        if not len(device_name):
            # XXX: why does this happen? Probably a bug somewhere else?
            self.logger.warning("Empty device name in hyperfile request - ignore")
            self.panda.arch.set_retval(cpu, self.panda.to_unsigned_guest(-22), failure=True)
            return

        sub_offset = struct.calcsize(header_fmt)

        # Ensure we have a model - if we don't, warn and add default
        if device_name not in self.files:
            self.logger.warning(f"Detected {hyper2name(type_val)} event on device {repr(device_name)} but device is not in config. Using defaults.")
            self.files[device_name] = {k: v for k, v in self.default_model.items()}  # XXX can't use deepcopy

        model = self.files[device_name]
        # Ensure our model specifies the current behavior - if not, warn and add default
        if type_val not in model:
            if not (type_val == HYPER_GETATTR and "size" in model):
                # If we have a size, we can handle getattr with out default method (return size) and it's fine. Otherwise warn
                self.logger.warning(f"Detected {hyper2name(type_val)} event on device {repr(device_name)} but this event is not modeled in config. Using default.")
            model[type_val] = self.default_model[type_val]

        # Dispatch based on the type of operation
        if type_val == HYPER_READ:
            buffer, length, offset = struct.unpack_from(read_fmt, buf, sub_offset)
            new_buffer, retval = model[type_val](device_name, buffer, length, offset)

            # We need to write new_buffer back into the struct at buffer
            # XXX: sizes? overflows?
            if len(new_buffer):
                try:
                    self.panda.virtual_memory_write(cpu, buffer, new_buffer)
                except ValueError:
                    self.logger.debug("Failed to write results of read into guest")
                    self.panda.arch.set_retval(cpu, RETRY)
                    # XXX: If we ever have stateful files, we'll need to tell it the read failed
                    return

            self.handle_result(device_name, "read", retval, length, new_buffer)

        elif type_val == HYPER_WRITE:
            buffer, length, offset = struct.unpack_from(write_fmt, buf, sub_offset)
            try:
                contents = self.panda.virtual_memory_read(cpu, buffer+offset, length)
            except ValueError:
                self.panda.arch.set_retval(cpu, RETRY)
                return

            retval = model[type_val](device_name, buffer, length, offset, contents)
            self.handle_result(device_name, "write", retval, length, offset, contents)

        elif type_val == HYPER_IOCTL:
            cmd, arg = struct.unpack_from(ioctl_fmt, buf, sub_offset)
            retval = model[type_val](device_name, cmd, arg)
            self.handle_result(device_name, "ioctl", retval, cmd, arg)

        elif type_val == HYPER_GETATTR:
            retval, size_data = model[type_val](device_name, model)
            size_bytes = struct.pack(f"{self.endian} q", size_data)
            self.handle_result(device_name, "getattr", retval, size_data)

            size_ptr, = struct.unpack_from(getattr_fmt, buf, sub_offset)
            try:
                self.panda.virtual_memory_write(cpu, size_ptr, size_bytes)
            except ValueError:
                self.logger.debug("Failed to write hyperfile size into guest - retry(?)")
                self.panda.arch.set_retval(cpu, RETRY)
                return

        self.panda.arch.set_retval(cpu, self.panda.to_unsigned_guest(retval))

    def handle_result(self, device_name, event, retval, *data):
        if device_name not in self.results:
            self.results[device_name] = {}

        if event not in self.results[device_name]:
            self.results[device_name][event] = []

        if event == "read":
            requested_length, buffer = data
            buffer = buffer.decode("utf-8", errors="ignore")
            result = {
                "readval": retval,
                "bytes_requested": requested_length,
                "data": buffer,
            }

        elif event == "write":
            length, offset, buffer = data
            buffer = buffer.decode("utf-8", errors="ignore")
            result = {
                "retval": retval,
                "bytes_requested": length,
                "offset": offset,
                "data": buffer,
            }

        elif event == "ioctl":
            cmd, arg = data
            result = {
                "cmd": cmd,
                "arg": arg,
                "retval": retval,
            }
        elif event == "getattr":
            result = {
                "size": data[0],
                "retval": retval,
            }
        else:
            raise ValueError(f"Unknown event {event}")
        self.results[device_name][event].append(result)

        # XXX TESTING ONLY, dump log in a stream?
        # with open(self.log_file, "w") as f:
        #    yaml.dump(self.results, f)

        # event="read": {bytes_read: X, data: "0"}
        # event="write": {bytes_written: X, data: ...}
        # event="icotl": {mode: {count: X, rv: Y}}

    # Function to handle read operations
    @staticmethod
    def read_zero(devname, buffer, length, offset):
        data = b"0"
        final_data = data[offset: offset + length]
        return (final_data, len(final_data))  # data, rv

    # Function to handle write operations
    @staticmethod
    def write_discard(devname, buffer, length, offset, contents):
        return length

    @staticmethod
    def ioctl(devname, cmd, arg):
        return 0

    @staticmethod
    def ioctl_unhandled(devname, cmd, arg):
        return -25  # -ENOTTY

    @staticmethod
    def read_unhandled(filename, buffer, length, offset):
        return (b"", -22)  # -EINVAL

    @staticmethod
    def write_unhandled(filename, buffer, length, offset, contents):
        return -22  # -EINVAL

    @staticmethod
    def getattr(device_name, model):
        """
        Return retval, size to write into buffer.
        Note we could refactor this to be different and take in the panda object as an arg
        and handle writing the getattr results into memory. For now we're just returning
        a retval + size that's getting written into guest memory by the caller.
        """
        return 0, model.get("size", 0)

    def uninit(self):
        if self.log_file is not None:
            with open(self.log_file, "w") as f:
                yaml.dump(self.results, f)
