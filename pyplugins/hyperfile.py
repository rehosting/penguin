import struct
from pandare import PyPlugin

try:
    from penguin import yaml
except ImportError:
    import yaml

# Make sure these match hyperfs
HYPER_MAGIC = 0x51EC3692
HYPER_READ = 0
HYPER_WRITE = 1
HYPER_IOCTL = 2
HYPER_GETATTR = 3


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
        self.log_file = self.get_arg("log_file")
        self.files = self.get_arg("models")
        self.logger = self.get_arg("logger")
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
        @panda.cb_guest_hypercall
        def before_hypercall(cpu):
            # We pass args in the arch-standard ABI specified in pypanda's arch.py
            # arm: r0, r1, r2
            # mips: a0, a1, a2
            num = panda.arch.get_arg(cpu, 0)
            if num != HYPER_MAGIC:
                return False  # Not a hypercall for us!

            arch_bytes = panda.bits // 8
            buf_addr_addr = panda.arch.get_arg(cpu, 1)
            num_ptrs = panda.arch.get_arg(cpu, 2)
            assert num_ptrs == 1

            # Build the format strings based on endian and word size
            endian = "<" if panda.endianness == "little" else ">"
            s_word, u_word = "iI" if panda.bits == 32 else "qQ"

            header_fmt = f"{endian} i {u_word}"
            read_fmt = write_fmt = f"{endian} {u_word} {u_word} q"
            ioctl_fmt = f"{endian} I {u_word}"
            getattr_fmt = f"{endian} {u_word}"
            hyperfs_data_size = struct.calcsize(header_fmt) + max(
                struct.calcsize(fmt) for fmt in (read_fmt, write_fmt, ioctl_fmt)
            )

            try:
                buf_addr = panda.virtual_memory_read(
                    cpu, buf_addr_addr, arch_bytes, fmt="int"
                )
                buf = panda.virtual_memory_read(
                    cpu, buf_addr, hyperfs_data_size, fmt="bytearray"
                )
            except ValueError:
                # Memory read failed - tell guest to retry
                panda.arch.set_retval(cpu, 1)  # non-zero = error
                self.logger.debug("Failed to read hyperfile struct from guest - retry")
                return True

            # Unpack request with our dynamic format string
            type_val, path_ptr = struct.unpack_from(header_fmt, buf)
            try:
                device_name = panda.read_str(cpu, path_ptr)
            except ValueError:
                # Memory read failed - tell guest to retry
                panda.arch.set_retval(cpu, 1)  # non-zero = error
                self.logger.debug("Failed to read hyperfile struct from guest - retry")
                return True

            sub_offset = struct.calcsize(header_fmt)

            # Ensure we have a model - if we don't, warn and add defult
            if device_name not in self.files:
                self.logger.warning(
                    f"Detected {hyper2name(type_val)} event on device {repr(device_name)} but device is not in config. Using defaults."
                )
                self.files[device_name] = {
                    k: v for k, v in self.default_model.items()
                }  # XXX can't use deepcopy

            model = self.files[device_name]
            # Ensure our model specifies the current behavior - if not, warn and add default
            if type_val not in model:
                if not (type_val == HYPER_GETATTR and "size" in model):
                    # If we have a size, we can handle getattr with out default method (return size) and it's fine. Otherwise warn
                    self.logger.warning(
                        f"Detected {hyper2name(type_val)} event on device {repr(device_name)} but this event is not modeled in config. Using default."
                    )
                model[type_val] = self.default_model[type_val]

            # print(f"Hyperfile {device_name}: using {model[type_val]}")

            # Dispatch based on the type of operation
            if type_val == HYPER_READ:
                buffer, length, offset = struct.unpack_from(read_fmt, buf, sub_offset)
                new_buffer, retval = model[type_val](
                    device_name, buffer, length, offset
                )  # hyper_read
                # print(f"Read of {length} bytes from {device_name} at offset {offset} returned {retval}: {new_buffer[:50]}")

                # We need to write new_buffer back into the struct at buffer
                # XXX: sizes? overflows?
                if len(new_buffer):
                    try:
                        panda.virtual_memory_write(cpu, buffer, new_buffer)
                    except ValueError:
                        print("Failed to write results of read into guest")
                        panda.arch.set_arg(cpu, 0, 1)  # non-zero = error
                        # XXX: If we ever have stateful files, we'll need to tell it the read failed
                        return True  # We consumed the hypercall, but we had a failure (in r0)

                self.handle_result(device_name, "read", retval, length, new_buffer)

            elif type_val == HYPER_WRITE:
                buffer, length, offset = struct.unpack_from(write_fmt, buf, sub_offset)
                try:
                    contents = panda.virtual_memory_read(
                        cpu, buffer + offset, length
                    )  # XXX correct use of offset?
                except ValueError:
                    panda.arch.set_arg(cpu, 0, 1)
                    return True  # We handled the hypercall. Guest needs to retry because nonzero r0

                retval = model[type_val](
                    device_name, buffer, length, offset, contents
                )  # hyper_write
                # print(f"Write of {length} bytes to {device_name} at offset {offset} returned {retval}")
                self.handle_result(
                    device_name, "write", retval, length, offset, contents
                )

            elif type_val == HYPER_IOCTL:
                cmd, arg = struct.unpack_from(ioctl_fmt, buf, sub_offset)
                retval = model[type_val](device_name, cmd, arg)  # hyper_ioctl
                # print(f"IOCTL of {cmd:x} to {device_name} with arg {arg} returned {retval}")
                self.handle_result(device_name, "ioctl", retval, cmd, arg)

            elif type_val == HYPER_GETATTR:
                retval, size_data = model[type_val](device_name, model)
                size_bytes = struct.pack(f"{endian} q", size_data)
                self.handle_result(device_name, "getattr", retval, size_data)

                (size_ptr,) = struct.unpack_from(getattr_fmt, buf, sub_offset)
                try:
                    panda.virtual_memory_write(cpu, size_ptr, size_bytes)
                except ValueError:
                    self.logger.debug(
                        "Failed to write hyperfile size into guest - retry(?)"
                    )
                    panda.arch.set_arg(cpu, 0, 1)  # non-zero = error
                    return True

            panda.arch.set_retval(cpu, panda.to_unsigned_guest(retval))
            return True

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
