from pandare import PyPlugin
from sys import path
from os.path import dirname, join as pjoin
from copy import deepcopy
import sys
import struct

try:
    from penguin import yaml
except ImportError:
    import yaml

# Make sure these match dyndev
HYPER_FILE_OP = 0x100200
HYPER_READ = 0
HYPER_WRITE = 1
HYPER_IOCTL = 2

def hyper(name):
    if name == "read":
        return HYPER_READ
    elif name == "write":
        return HYPER_WRITE
    elif name == "ioctl":
        return HYPER_IOCTL
    raise ValueError(f"Unknown hyperfile operation {name}")

def hyper2name(num):
    if num == HYPER_READ:
        return "read"
    elif num == HYPER_WRITE:
        return "write"
    elif num == HYPER_IOCTL:
        return "ioctl"
    raise ValueError(f"Unknown hyperfile operation {num}")

class HyperFile(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.log_file = self.get_arg("log_file")
        self.files = self.get_arg("models")

        if self.files is None:
            # We can be imported without files, but we'll ignore it
            return

        if self.log_file:
            # Initialize a blank file so we can tail it
            open(self.log_file, "w").close()

        # We track when processes access or IOCTL files we've added here:
        self.results = {} # path: {event: ... }
                                # event="read": {bytes_read: X, data: "0"}
                                # event="write": {bytes_written: X, data: ...}
                                # event="icotl": {mode: {count: X, rv: Y}}


        assert(isinstance(self.files, dict)), f"Files should be dict, not {self.files}"

        # files = {filename: {'read': func, 'write': func, 'ioctl': func}}}

        # On hypercall we dispatch to the appropriate handler: read, write, ioctl
        @panda.cb_guest_hypercall
        def before_hypercall(cpu):
            # We pass args in the arch-standard ABI specified in pypanda's arch.py
            # arm: r0, r1, r2
            # mips: a0, a1, a2
            num = panda.arch.get_arg(cpu, 0)
            if num != HYPER_FILE_OP:
                return False  # Not a hypercall for us!

            buf_addr = panda.arch.get_arg(cpu, 1)
            buf_size = panda.arch.get_arg(cpu, 2)

            try:
                buf = panda.virtual_memory_read(cpu, buf_addr, buf_size, fmt="bytearray")
            except ValueError:
                # Memory read failed - tell guest to retry
                panda.arch.set_arg(cpu, 0, 1)  # non-zero = error
                print("Failed to read hyperfile struct from guest - retry")
                return True

            # Unpack the hyper_file_op structure
            # Assuming 8 bytes for enum, 8 bytes for rv, 128 bytes for device_name
            # (you may need to adjust these sizes)
            # XXX Need to handle various guest widths

            # Build the format strings based on endian and word size
            endian_prefix = '<' if self.panda.endianness == 'little' else '>'
            word_char = 'I' if self.panda.bits == 32 else 'Q'  # 'I' for 4 bytes, 'Q' for 8 bytes

            # Create main format string
            format_str = f"{endian_prefix}{word_char} {word_char} 128s"

            # Unpack request with our dynamic format string
            type_val, rv, device_name = struct.unpack_from(format_str, buf, 0)
            if word_char == 'Q':
                type_val = type_val >> 32

            # Create sub-format string
            if type_val == HYPER_READ:
                read_format = f"{endian_prefix}{word_char} {word_char} Q"  # Assuming loff_t is 8 bytes
            elif type_val == HYPER_WRITE:
                write_format = f"{endian_prefix}{word_char} {word_char} Q" # Assuming loff_t is 8 bytes
            elif type_val == HYPER_IOCTL:
                ioctl_format = f"{endian_prefix}I {word_char}"  # Assuming 'cmd' is always 4 bytes

            sub_offset = struct.calcsize(format_str)

            device_name = device_name.decode('utf-8', errors='ignore')
            # device_name is null terminated - if a null byte is in it, truncate
            if '\x00' in device_name:
                device_name = device_name[:device_name.index('\x00')]

            if device_name in self.files:
                model = self.files[device_name]
            else:
                print(f"WARN: using default file model for {repr(device_name)}")
                model = {
                    HYPER_READ: self.read_unhandled,
                    HYPER_WRITE: self.write_unhandled,
                    HYPER_IOCTL: self.ioctl,
                }

            #print(f"Hyperfile {device_name}: using {model[type_val]}")

            # Dispatch based on the type of operation
            if type_val == HYPER_READ:
                buffer, length, offset = struct.unpack_from(read_format, buf, sub_offset)
                new_buffer, retval = model[type_val](device_name, buffer, length, offset) # hyper_read
                #print(f"Read of {length} bytes from {device_name} at offset {offset} returned {retval}: {new_buffer[:50]}")

                # We need to write new_buffer back into the struct at buffer
                # XXX: sizes? overflows?
                if len(new_buffer):
                    try:
                        panda.virtual_memory_write(cpu, buffer, new_buffer)
                    except ValueError:
                        print("Failed to write results of read into guest")
                        panda.arch.set_arg(cpu, 0, 1)  # non-zero = error
                        # XXX: If we ever have stateful files, we'll need to tell it the read failed
                        return True # We consumed the hypercall, but we had a failure (in r0)

                self.handle_result(device_name, "read", retval, length, new_buffer)

            elif type_val == HYPER_WRITE:
                buffer, length, offset = struct.unpack_from(write_format, buf, sub_offset)
                try:
                    contents = panda.virtual_memory_read(cpu, buffer+offset, length) # XXX correct use of offset?
                except ValueError:
                    panda.arch.set_arg(cpu, 0, 1)
                    return True # We handled the hypercall. Guest needs to retry because nonzero r0

                retval = model[type_val](device_name, buffer, length, offset, contents) # hyper_write
                #print(f"Write of {length} bytes to {device_name} at offset {offset} returned {retval}")
                self.handle_result(device_name, "write", retval, length, offset, contents)

            elif type_val == HYPER_IOCTL:
                cmd, arg = struct.unpack_from(ioctl_format, buf, sub_offset)
                retval = model[type_val](device_name, cmd, arg) # hyper_ioctl
                #print(f"IOCTL of {cmd:x} to {device_name} with arg {arg} returned {retval}")
                self.handle_result(device_name, "ioctl", retval, cmd, arg)

            # Now we need to write the return value back into the struct
            rv_offset = 4 if self.panda.bits == 32 else 8 # Skip one arg
            format_str = f"{endian_prefix}{word_char}"
            packed_rv = struct.pack(format_str, panda.to_unsigned_guest(retval))

            try:
                panda.virtual_memory_write(cpu, buf_addr+rv_offset, packed_rv)
            except ValueError:
                print(f"Failed to write retval back into struct at {buf_addr+rv_offset}")
                panda.arch.set_arg(cpu, 0, 1)
                return True # We handled the hypercall. Guest needs to retry because nonzero r0

            # Set the return value (modify this to actually change the struct in guest memory if needed)
            #print(f"Success! Handled {hyper2name(type_val)} request and returning retval {retval}")

            panda.arch.set_arg(cpu, 0, 0)
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
        else:
            raise ValueError(f"Unknown event {event}")
        self.results[device_name][event].append(result)

        # XXX TESTING ONLY, dump log in a stream?
        with open(self.log_file, "w") as f:
            yaml.dump(self.results, f)

        # event="read": {bytes_read: X, data: "0"}
        # event="write": {bytes_written: X, data: ...}
        # event="icotl": {mode: {count: X, rv: Y}}
        


    # Function to handle read operations
    def read_zero(self, devname, buffer, length, offset):
        data = b'0'
        final_data = data[offset:offset+length]
        return (final_data, len(final_data)) # data, rv

    # Function to handle write operations
    def write_discard(self, devname, buffer, length, offset, contents):
        return length

    # Function to handle ioctl operations
    def ioctl(self, devname, cmd, arg):
        return 0

    def read_unhandled(self, filename, buffer, length, offset):
        return (b'', -22) # -EINVAL

    def write_unhandled(self, filename, buffer, length, offset, contents):
        return -22 # -EINVAL

    def uninit(self):
        if self.log_file is not None:
            with open(self.log_file, "w") as f:
                yaml.dump(self.results, f)