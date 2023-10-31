from pandare import PyPlugin
from sys import path
from os.path import dirname, join as pjoin
from copy import deepcopy
import sys
import struct

try:
    from penguin import PenguinAnalysis, yaml
except ImportError:
    # We can still run as a PyPlugin, but we can't do post-run analysis
    import yaml
    PenguinAnalysis = object

# Make sure these match dyndev
HYPER_FILE_OP = 0x100200
HYPER_READ = 0
HYPER_WRITE = 1
HYPER_IOCTL = 2

class HyperFile(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")

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

            # Create sub-format string
            if type_val == HYPER_READ:
                read_format = f"{endian_prefix}{word_char} {word_char} Q"  # Assuming loff_t is 8 bytes
            elif type_val == HYPER_WRITE:
                write_format = f"{endian_prefix}{word_char} {word_char} Q" # Assuming loff_t is 8 bytes
            elif type_val == HYPER_IOCTL:
                ioctl_format = f"{endian_prefix}I {word_char}"  # Assuming 'cmd' is always 4 bytes


            device_name = device_name.rstrip(b'\0').decode('utf-8', errors='ignore') # Decode gets a junk character at the end?
            sub_offset = struct.calcsize(format_str)

            # Dispatch based on the type of operation
            if type_val == HYPER_READ:
                buffer, length, offset = struct.unpack_from(read_format, buf, sub_offset)
                new_buffer, retval = self.handle_read(buffer, length, offset)

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

            elif type_val == HYPER_WRITE:
                buffer, length, offset = struct.unpack_from(write_format, buf, sub_offset)
                try:
                    contents = panda.virtual_memory_read(cpu, buffer+offset, length) # XXX correct use of offset?
                except ValueError:
                    contents = None

                retval = self.handle_write(buffer, length, offset, contents)

            elif type_val == HYPER_IOCTL:
                cmd, arg = struct.unpack_from(ioctl_format, buf, sub_offset)
                retval = self.handle_ioctl(cmd, arg)


            # Now we need to write the return value back into the struct
            rv_offset = 4 if self.panda.bits == 32 else 8 # Skip one arg
            format_str = f"{endian_prefix}{word_char}"
            packed_rv = struct.pack(format_str, retval)

            try:
                panda.virtual_memory_write(cpu, buf_addr+rv_offset, packed_rv)
            except ValueError:
                print(f"Failed to write retval back into struct at {buf_addr+rv_offset}")
                panda.arch.set_arg(cpu, 0, 1)
                return True # We handled the hypercall. Guest needs to retry because nonzero r0

            # Set the return value (modify this to actually change the struct in guest memory if needed)
            #print(f"Success! Handled {type_val} request and returning retval {retval}")

            panda.arch.set_arg(cpu, 0, 0)
            return True


    # Function to handle read operations
    def handle_read(self, buffer, length, offset):
        #print("Handling read with args:", buffer, length,  offset)
        data = b'Hello from HyperFile!'

        # use offset to select into our data
        final_data = data[offset:offset+length]

        return (final_data, len(final_data)) # TODO: other things!

    # Function to handle write operations
    def handle_write(self, buffer, length, offset, contents):
        #print(f"Handling write of {contents} (length {length}) to {buffer} at offset {offset})")
        return length # TODO: do we ever want to pretend we did a partial write or anything else?

    # Function to handle ioctl operations
    def handle_ioctl(self, cmd, arg):
        #print(f"Handling ioctl with args: {cmd:x} {arg:x}")
        return 0  # TODO: return values?