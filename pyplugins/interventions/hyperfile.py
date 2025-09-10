"""
# HyperFile Plugin

This module implements the `HyperFile` plugin for the Penguin framework, enabling
hypercall-based file operations between a guest and the host. It provides a model
for virtual files that can be read, written, or controlled via ioctl/getattr
operations from the guest OS. The plugin is designed to be flexible and extensible,
allowing users to specify custom file behaviors via models.

## Features

- Handles hypercalls for file operations (`read`, `write`, `ioctl`, `getattr`)
- Supports dynamic file models for custom device/file behaviors
- Logs and tracks file operation results for analysis
- Provides default behaviors for unhandled operations

## Example Usage

```python
from pyplugins.interventions.hyperfile import HyperFile

# Register the plugin with Penguin, specifying file models and log file
plugin = HyperFile()
```

## File Model Example

```python
files = {
    "/dev/zero": {
        fops.HYP_READ: HyperFile.read_zero,
        fops.HYP_WRITE: HyperFile.write_discard,
        "size": 0,
    }
}
```

## Classes

- `HyperFile`: Main plugin class implementing the hypercall interface.

## Functions

- `hyper(name: str) -> int`: Map operation name to hyperfile operation constant.
- `hyper2name(num: int) -> str`: Map hyperfile operation constant to operation name.

"""

import struct
from typing import Any, Dict, Tuple
from penguin import Plugin
from hyper.consts import igloo_base_hypercalls as bconsts
from hyper.consts import hyperfs_ops as hops
from hyper.consts import hyperfs_file_ops as fops

HYP_RETRY = 0xdeadbeef

try:
    from penguin import yaml
except ImportError:
    import yaml


def hyper(name: str) -> int:
    """
    **Map a string operation name to its corresponding hyperfile operation constant.**

    **Parameters**
    - `name` (`str`): The operation name ("read", "write", "ioctl", "getattr").

    **Returns**
    - `int`: The corresponding hyperfile operation constant.

    **Raises**
    - `ValueError`: If the operation name is unknown.
    """
    if name == "read":
        return fops.HYP_READ
    elif name == "write":
        return fops.HYP_WRITE
    elif name == "ioctl":
        return fops.HYP_IOCTL
    elif name == "getattr":
        return fops.HYP_GETATTR
    raise ValueError(f"Unknown hyperfile operation {name}")


def hyper2name(num: int) -> str:
    """
    **Map a hyperfile operation constant to its string operation name.**

    **Parameters**
    - `num` (`int`): The hyperfile operation constant.

    **Returns**
    - `str`: The operation name.

    **Raises**
    - `ValueError`: If the operation constant is unknown.
    """
    if num == fops.HYP_READ:
        return "read"
    elif num == fops.HYP_WRITE:
        return "write"
    elif num == fops.HYP_IOCTL:
        return "ioctl"
    elif num == fops.HYP_GETATTR:
        return "getattr"
    raise ValueError(f"Unknown hyperfile operation {num}")


class HyperFile(Plugin):
    """
    **The HyperFile plugin implements a virtual file interface for the guest OS,
    allowing the guest to perform file operations via hypercalls.**

    **Attributes**
    - `arch_bytes` (`int`): Number of bytes per architecture word.
    - `log_file` (`Optional[str]`): Path to the log file for operation results.
    - `files` (`Optional[Dict[str, Dict]]`): File models for virtual devices.
    - `logger` (`Any`): Logger instance.
    - `endian` (`str`): Endianness format for struct packing.
    - `s_word`, `u_word` (`str`): Signed/unsigned word format for struct packing.
    - `results` (`Dict`): Stores results of file operations for logging.
    - `default_model` (`Dict`): Default model for unhandled file operations.
    """

    def __init__(self) -> None:
        """
        **Initialize the HyperFile plugin, set up file models, logging, and
        register hypercall handlers.**

        **Returns**
        - `None`
        """
        panda = self.panda
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

        assert isinstance(
            self.files, dict), f"Files should be dict, not {self.files}"

        self.default_model = {
            fops.HYP_READ: self.read_unhandled,
            fops.HYP_WRITE: self.write_unhandled,
            fops.HYP_IOCTL: self.ioctl,
            fops.HYP_GETATTR: self.getattr,
            "size": 0,
        }

        # files = {filename: {'read': func, 'write': func, 'ioctl': func}}}

        # On hypercall we dispatch to the appropriate handler: read, write,
        # ioctl
        @panda.hypercall(bconsts.IGLOO_HYPERFS_MAGIC)
        def before_hypercall(cpu):
            # We pass args in the arch-syscall ABI specified in pypanda's arch.py
            # arm: x8/r7 r0, r1, r2
            # mips: v0, a0, a1, a2
            hc_type = panda.arch.get_arg(cpu, 1, convention="syscall")
            if hc_type == hops.HYP_FILE_OP:
                self.handle_file_op(cpu)
            elif hc_type == hops.HYP_GET_NUM_HYPERFILES:
                self.handle_get_num_hyperfiles(cpu)
            elif hc_type == hops.HYP_GET_HYPERFILE_PATHS:
                self.handle_get_hyperfile_paths(cpu)

    def handle_get_num_hyperfiles(self, cpu: Any) -> None:
        """
        **Handle the hypercall to get the number of hyperfiles.**

        **Parameters**
        - `cpu` (`Any`): The CPU context from Panda.

        **Returns**
        - `None`
        """
        num_hyperfiles_addr = self.panda.arch.get_arg(
            cpu, 2, convention="syscall")
        try:
            self.panda.virtual_memory_write(
                cpu,
                num_hyperfiles_addr,
                struct.pack(f"{self.endian} {self.u_word}", len(self.files)),
            )
        except ValueError:
            # Memory r/w failed - tell guest to retry
            self.panda.arch.set_retval(cpu, HYP_RETRY)
            self.logger.debug(
                "Failed to read/write number of hyperfiles from guest - retry")

    def handle_get_hyperfile_paths(self, cpu: Any) -> None:
        """
        **Handle the hypercall to get the paths of all hyperfiles.**

        **Parameters**
        - `cpu` (`Any`): The CPU context from Panda.

        **Returns**
        - `None`
        """
        hyperfile_paths_array_ptr = self.panda.arch.get_arg(
            cpu, 2, convention="syscall")
        n = len(self.files)
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
                self.panda.arch.set_retval(cpu, HYP_RETRY)
                self.logger.debug(
                    "Failed to read hyperfile path ptr from guest - retry")
                return
        for path, buf in zip(self.files.keys(), hyperfile_paths_ptrs):
            try:
                self.panda.virtual_memory_write(cpu, buf, path.encode())
            except ValueError:
                self.panda.arch.set_retval(cpu, HYP_RETRY)
                self.logger.debug(
                    "Failed to write hyperfile path to guest - retry")
                return

    def handle_file_op(self, cpu: Any) -> None:
        """
        **Handle a file operation hypercall (read, write, ioctl, getattr).**

        **Parameters**
        - `cpu` (`Any`): The CPU context from Panda.

        **Returns**
        - `None`
        """
        header_fmt = f"{self.endian} i {self.u_word}"
        read_fmt = write_fmt = f"{self.endian} {self.u_word} {self.u_word} q"
        ioctl_fmt = f"{self.endian} I {self.u_word}"
        getattr_fmt = f"{self.endian} {self.u_word}"
        hyperfs_data_size = struct.calcsize(
            header_fmt) + max(struct.calcsize(fmt) for fmt in (read_fmt, write_fmt, ioctl_fmt))

        buf_addr = self.panda.arch.get_arg(cpu, 2, convention="syscall")
        try:
            buf = self.panda.virtual_memory_read(
                cpu, buf_addr, hyperfs_data_size, fmt="bytearray")
        except ValueError:
            # Memory read failed - tell guest to retry
            self.panda.arch.set_retval(cpu, HYP_RETRY)
            self.logger.debug(
                "Failed to read hyperfile struct from guest - retry")
            return

        # Unpack request with our dynamic format string
        type_val, path_ptr = struct.unpack_from(header_fmt, buf)
        try:
            device_name = self.panda.read_str(cpu, path_ptr)
        except ValueError:
            # Memory read failed - tell guest to retry
            self.panda.arch.set_retval(cpu, HYP_RETRY)
            self.logger.debug(
                "Failed to read hyperfile struct from guest - retry")
            return

        if not len(device_name):
            # XXX: why does this happen? Probably a bug somewhere else?
            self.logger.warning(
                "Empty device name in hyperfile request - ignore")
            self.panda.arch.set_retval(
                cpu, self.panda.to_unsigned_guest(-22), failure=True)
            return

        sub_offset = struct.calcsize(header_fmt)

        # Ensure we have a model - if we don't, warn and add default
        if device_name not in self.files:
            self.logger.warning(
                f"Detected {hyper2name(type_val)} event on device {repr(device_name)} but device is not in config. Using defaults.")
            self.files[device_name] = {
                k: v for k, v in self.default_model.items()}  # XXX can't use deepcopy

        model = self.files[device_name]
        # Ensure our model specifies the current behavior - if not, warn and
        # add default
        if type_val not in model:
            if not (type_val == fops.HYP_GETATTR and "size" in model):
                # If we have a size, we can handle getattr with out default
                # method (return size) and it's fine. Otherwise warn
                self.logger.warning(
                    f"Detected {hyper2name(type_val)} event on device {repr(device_name)} but this event is not modeled in config. Using default.")
            model[type_val] = self.default_model[type_val]

        # Dispatch based on the type of operation
        if type_val == fops.HYP_READ:
            buffer, length, offset = struct.unpack_from(
                read_fmt, buf, sub_offset)
            new_buffer, retval = model[type_val](
                device_name, buffer, length, offset)

            # We need to write new_buffer back into the struct at buffer
            # XXX: sizes? overflows?
            if len(new_buffer):
                try:
                    self.panda.virtual_memory_write(cpu, buffer, new_buffer)
                except ValueError:
                    self.logger.warning(
                        f"After reading hyperfile {device_name} failed to write result into guest memory at {buffer:x} - retry")
                    self.panda.arch.set_retval(cpu, HYP_RETRY)
                    # XXX: If we ever have stateful files, we'll need to tell
                    # it the read failed
                    return

            self.handle_result(device_name, "read", retval, length, new_buffer)

        elif type_val == fops.HYP_WRITE:
            buffer, length, offset = struct.unpack_from(
                write_fmt, buf, sub_offset)
            # We're writing data into our pseudofile. First we need to read what the guest
            # has given us as data to write
            # XXX offset is _internal_ to our data structures, it's how far into the file
            # we've seeked. It's NOT related to the guest buffer
            try:
                contents = self.panda.virtual_memory_read(cpu, buffer, length)
            except ValueError:
                self.logger.warning(
                    f"Before writing to hyperfile {device_name} failed to read data out of guest memory at {buffer:x} with offset {offset:x}")
                self.panda.arch.set_retval(cpu, HYP_RETRY)
                # XXX: We might be able to get stuck in a loop here if hyperfs isn't paging in
                # what we expect
                return

            retval = model[type_val](
                device_name, buffer, length, offset, contents)
            self.handle_result(
                device_name,
                "write",
                retval,
                length,
                offset,
                contents)

        elif type_val == fops.HYP_IOCTL:
            cmd, arg = struct.unpack_from(ioctl_fmt, buf, sub_offset)
            retval = model[type_val](device_name, cmd, arg)
            self.handle_result(device_name, "ioctl", retval, cmd, arg)

        elif type_val == fops.HYP_GETATTR:
            retval, size_data = model[type_val](device_name, model)
            size_bytes = struct.pack(f"{self.endian} q", size_data)
            self.handle_result(device_name, "getattr", retval, size_data)

            size_ptr, = struct.unpack_from(getattr_fmt, buf, sub_offset)
            try:
                self.panda.virtual_memory_write(cpu, size_ptr, size_bytes)
            except ValueError:
                self.logger.debug(
                    "Failed to write hyperfile size into guest - retry(?)")
                self.panda.arch.set_retval(cpu, HYP_RETRY)
                return

        self.panda.arch.set_retval(cpu, self.panda.to_unsigned_guest(retval))

    def handle_result(self, device_name: str, event: str,
                      retval: int, *data: Any) -> None:
        """
        **Record the result of a file operation for logging and analysis.**

        **Parameters**
        - `device_name` (`str`): The name of the device/file.
        - `event` (`str`): The event type ("read", "write", "ioctl", "getattr").
        - `retval` (`int`): The return value of the operation.
        - `*data` (`Any`): Additional data relevant to the event.

        **Returns**
        - `None`
        """
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
    def read_zero(devname: str, buffer: int, length: int,
                  offset: int) -> Tuple[bytes, int]:
        """
        **Return a buffer of zero bytes for read operations.**

        **Parameters**
        - `devname` (`str`): Device name.
        - `buffer` (`int`): Guest buffer address.
        - `length` (`int`): Number of bytes to read.
        - `offset` (`int`): Offset into the file.

        **Returns**
        - `Tuple[bytes, int]`: (Data read, number of bytes read)
        """
        data = b"0"
        final_data = data[offset: offset + length]
        return (final_data, len(final_data))  # data, rv

    # Function to handle write operations
    @staticmethod
    def write_discard(devname: str, buffer: int, length: int,
                      offset: int, contents: bytes) -> int:
        """
        **Discard written data and return the number of bytes written.**

        **Parameters**
        - `devname` (`str`): Device name.
        - `buffer` (`int`): Guest buffer address.
        - `length` (`int`): Number of bytes to write.
        - `offset` (`int`): Offset into the file.
        - `contents` (`bytes`): Data to write.

        **Returns**
        - `int`: Number of bytes written.
        """
        return length

    @staticmethod
    def ioctl(devname: str, cmd: int, arg: int) -> int:
        """
        **Handle an ioctl operation (default: always succeeds).**

        **Parameters**
        - `devname` (`str`): Device name.
        - `cmd` (`int`): IOCTL command.
        - `arg` (`int`): IOCTL argument.

        **Returns**
        - `int`: Return value (0 for success).
        """
        return 0

    @staticmethod
    def ioctl_unhandled(devname: str, cmd: int, arg: int) -> int:
        """
        **Handle an unhandled ioctl operation.**

        **Parameters**
        - `devname` (`str`): Device name.
        - `cmd` (`int`): IOCTL command.
        - `arg` (`int`): IOCTL argument.

        **Returns**
        - `int`: Return value (-25 for ENOTTY).
        """
        return -25  # -ENOTTY

    @staticmethod
    def read_unhandled(filename: str, buffer: int, length: int,
                       offset: int) -> Tuple[bytes, int]:
        """
        **Handle an unhandled read operation.**

        **Parameters**
        - `filename` (`str`): File name.
        - `buffer` (`int`): Guest buffer address.
        - `length` (`int`): Number of bytes to read.
        - `offset` (`int`): Offset into the file.

        **Returns**
        - `Tuple[bytes, int]`: (Empty bytes, -22 for EINVAL)
        """
        return (b"", -22)  # -EINVAL

    @staticmethod
    def write_unhandled(filename: str, buffer: int,
                        length: int, offset: int, contents: bytes) -> int:
        """
        **Handle an unhandled write operation.**

        **Parameters**
        - `filename` (`str`): File name.
        - `buffer` (`int`): Guest buffer address.
        - `length` (`int`): Number of bytes to write.
        - `offset` (`int`): Offset into the file.
        - `contents` (`bytes`): Data to write.

        **Returns**
        - `int`: Return value (-22 for EINVAL).
        """
        return -22  # -EINVAL

    @staticmethod
    def getattr(device_name: str, model: Dict[str, Any]) -> Tuple[int, int]:
        """
        **Handle a getattr operation, returning the file size.**

        **Parameters**
        - `device_name` (`str`): Device name.
        - `model` (`Dict[str, Any]`): File model dictionary.

        **Returns**
        - `Tuple[int, int]`: (Return value, file size)
        """
        """
        Return retval, size to write into buffer.
        Note we could refactor this to be different and take in the panda object as an arg
        and handle writing the getattr results into memory. For now we're just returning
        a retval + size that's getting written into guest memory by the caller.
        """
        return 0, model.get("size", 0)

    def uninit(self) -> None:
        """
        **Dump the results to the log file on plugin unload.**

        **Returns**
        - `None`
        """
        if self.log_file is not None:
            with open(self.log_file, "w") as f:
                yaml.dump(self.results, f)
