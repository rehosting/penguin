"""
# Memory Access Plugin (`mem.py`)

This module provides the `Mem` plugin for the Penguin framework, enabling safe and efficient reading and writing of guest memory via the hypervisor portal. It abstracts low-level memory operations, supporting chunked access, endianness handling, and architecture-specific pointer sizes. The plugin is designed to work with both PANDA and non-PANDA environments, and provides utilities for reading and writing bytes, integers, pointers, strings, arrays, and more.

## Features

- Read and write arbitrary bytes to guest memory.
- Read and write integers, longs, words, and pointers with correct endianness.
- Read and write null-terminated and UTF-8 strings.
- Read arrays of integers and lists of pointers or strings.
- Memory comparison and memset utilities.
- Handles chunking for large memory operations.
- Supports both PANDA and hypervisor portal backends.

## Example Usage

```python
from penguin import plugins

# Read 16 bytes from address 0x1000
data = yield from plugins.mem.read_bytes(0x1000, 16)

# Write a string to memory
yield from plugins.mem.write_str(0x2000, "hello world")

# Read a pointer-sized value
ptr = yield from plugins.mem.read_ptr(0x3000)

# Compare two memory regions
equal = yield from plugins.mem.memcmp(0x4000, 0x5000, 32)
```
"""

from penguin import Plugin
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd
from struct import pack, unpack
from typing import Optional, List, Union, Any, Generator


class Mem(Plugin):
    """
    ## Mem Plugin

    Provides guest memory access and manipulation via the hypervisor portal.

    ### Attributes
    - `endian_format` (`str`): Endianness format for struct packing/unpacking.
    - `try_panda` (`bool`): Whether to attempt PANDA-based memory access.
    """

    def __init__(self) -> None:
        """
        ### Initialize the Mem plugin

        Sets endianness and architecture-specific options.
        """
        self.endian_format = '<' if self.panda.endianness == 'little' else '>'
        self.try_panda = True if self.panda.arch != "riscv64" else False

    def write_bytes(self, addr: int, data: bytes,
                    pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        ### Write bytes to guest memory

        Writes bytes to guest memory at a specified address, handling chunking for large data.

        **Args:**
        - `addr` (`int`): Address to write to.
        - `data` (`bytes`): Data to write.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `int`: Number of bytes written.
        """
        self.logger.debug(
            f"write_bytes called: addr={addr}, data_len={len(data)}")
        cpu = None
        rsize = self.plugins.portal.regions_size
        for i in range((len(data) + rsize - 1) // rsize):
            offset = i * rsize
            chunk_addr = addr + offset
            chunk_data = data[offset:offset + rsize]
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
                yield PortalCmd(hop.HYPER_OP_WRITE, chunk_addr, len(chunk_data), pid, chunk_data)
        self.logger.debug(f"Total bytes written: {len(data)}")
        return len(data)

    def read_bytes(self, addr: int, size: int,
                   pid: Optional[int] = None) -> Generator[Any, Any, bytes]:
        """
        ### Read bytes from guest memory

        Reads bytes from guest memory at a specified address, handling chunking for large reads.

        **Args:**
        - `addr` (`int`): Address to read from.
        - `size` (`int`): Number of bytes to read.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `bytes`: Data read from memory.
        """
        self.logger.debug(f"read_bytes called: addr={addr}, size={size}")
        data = b""
        cpu = None
        rsize = self.plugins.portal.regions_size
        for i in range((size + rsize - 1) // rsize):
            offset = i * rsize
            chunk_addr = addr + offset
            chunk_size = min(rsize, size - offset)
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
                chunk = yield PortalCmd(hop.HYPER_OP_READ, chunk_addr, chunk_size, pid)
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

    def read_str(self, addr: int,
                 pid: Optional[int] = None) -> Generator[Any, Any, str]:
        """
        ### Read a null-terminated string from guest memory

        Reads a null-terminated string from guest memory at a specified address.

        **Args:**
        - `addr` (`int`): Address to read from.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `str`: String read from memory.
        """
        if addr != 0:
            self.logger.debug(f"read_str called: addr={addr:#x}")
            if self.try_panda:
                try:
                    chunk = self.panda.read_str(self.panda.get_cpu(), addr)
                    return chunk
                except ValueError:
                    pass
            chunk = yield PortalCmd(hop.HYPER_OP_READ_STR, addr, 0, pid)
            if chunk:
                self.logger.debug(f"Received response from queue: {chunk}")
                return chunk.decode('latin-1', errors='replace')
        return ""

    def read_int(self, addr: int,
                 pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        ### Read a 4-byte integer from guest memory

        Reads a 4-byte integer from guest memory at a specified address.

        **Args:**
        - `addr` (`int`): Address to read from.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `int` or `None`: Integer value read, or `None` on failure.
        """
        self.logger.debug(f"read_int called: addr={addr}")
        data = yield from self.read_bytes(addr, 4, pid)
        if len(data) != 4:
            self.logger.error(
                f"Failed to read int at addr={addr}, data_len={len(data)}")
            return None
        value = unpack(f"{self.endian_format}I", data)[0]
        self.logger.debug(f"Integer read successfully: value={value}")
        return value

    def read_long(
            self, addr: int, pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        ### Read an 8-byte long integer from guest memory

        Reads an 8-byte long integer from guest memory at a specified address.

        **Args:**
        - `addr` (`int`): Address to read from.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `int` or `None`: Long value read, or `None` on failure.
        """
        self.logger.debug(f"read_long called: addr={addr}")
        data = yield from self.read_bytes(addr, 8, pid)
        if len(data) != 8:
            self.logger.error(
                f"Failed to read long at addr={addr}, data_len={len(data)}")
            return None
        value = unpack(f"{self.endian_format}Q", data)[0]
        self.logger.debug(f"Long read successfully: value={value}")
        return value

    def read_ptr(self, addr: int,
                 pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        ### Read a pointer-sized value from guest memory

        Reads a pointer-sized value from guest memory at a specified address.

        **Args:**
        - `addr` (`int`): Address to read from.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `int` or `None`: Pointer value read, or `None` on failure.
        """
        if self.panda.bits == 32:
            ptr = yield from self.read_int(addr, pid)
        elif self.panda.bits == 64:
            ptr = yield from self.read_long(addr, pid)
        else:
            raise Exception("read_ptr: Could not determine bits")
        return ptr

    def write_int(self, addr: int, value: int,
                  pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        ### Write a 4-byte integer to guest memory

        Writes a 4-byte integer to guest memory at a specified address.

        **Args:**
        - `addr` (`int`): Address to write to.
        - `value` (`int`): Integer value to write.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `int`: Number of bytes written.
        """
        self.logger.debug(f"write_int called: addr={addr}, value={value}")
        # Pack the integer according to system endianness
        data = pack(f"{self.endian_format}I", value)
        bytes_written = yield from self.write_bytes(addr, data, pid)
        self.logger.debug(f"Integer written successfully: {value}")
        return bytes_written

    def write_long(self, addr: int, value: int,
                   pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        ### Write an 8-byte long integer to guest memory

        Writes an 8-byte long integer to guest memory at a specified address.

        **Args:**
        - `addr` (`int`): Address to write to.
        - `value` (`int`): Long value to write.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `int`: Number of bytes written.
        """
        self.logger.debug(f"write_long called: addr={addr}, value={value}")
        # Pack the long according to system endianness
        data = pack(f"{self.endian_format}Q", value)
        bytes_written = yield from self.write_bytes(addr, data, pid)
        self.logger.debug(f"Long written successfully: {value}")
        return bytes_written

    def write_ptr(self, addr: int, value: int,
                  pid: Optional[int] = None) -> Generator[Any, Any, None]:
        """
        ### Write a pointer-sized value to guest memory

        Writes a pointer-sized value to guest memory at a specified address.

        **Args:**
        - `addr` (`int`): Address to write to.
        - `value` (`int`): Pointer value to write.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `None`
        """
        if self.panda.bits == 32:
            yield from self.write_int(addr, value, pid)
        elif self.panda.bits == 64:
            yield from self.write_long(addr, value, pid)
        else:
            raise Exception("read_ptr: Could not determine bits")

    def write_str(self, addr: int, string: Union[str, bytes], null_terminate: bool = True,
                  pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        ### Write a string to guest memory

        Writes a string to guest memory at a specified address, optionally null-terminated.

        **Args:**
        - `addr` (`int`): Address to write to.
        - `string` (`str` or `bytes`): String to write.
        - `null_terminate` (`bool`, optional): Whether to append a null terminator (default: `True`).
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `int`: Number of bytes written.
        """
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

    def read_ptrlist(self, addr: int, length: int,
                     pid: Optional[int] = None) -> Generator[Any, Any, List[int]]:
        """
        ### Read a list of pointer values from guest memory

        Reads a list of pointer values from guest memory.

        **Args:**
        - `addr` (`int`): Address to start reading from.
        - `length` (`int`): Maximum number of pointers to read.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `list[int]`: List of pointer values.
        """
        ptrs = []
        ptrsize = int(self.panda.bits / 8)
        for start in range(length):
            ptr = yield from self.read_ptr(addr + (start * ptrsize), pid)
            if ptr == 0:
                break
            ptrs.append(ptr)
        return ptrs

    def read_char_ptrlist(self, addr: int, length: int,
                          pid: Optional[int] = None) -> Generator[Any, Any, List[str]]:
        """
        ### Read a list of null-terminated strings from a list of pointers

        Reads a list of null-terminated strings from a list of pointers in guest memory.

        **Args:**
        - `addr` (`int`): Address to start reading pointer list from.
        - `length` (`int`): Maximum number of pointers to read.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `list[str]`: List of strings read from memory.
        """
        ptrlist = yield from self.read_ptrlist(addr, length, pid)
        vals = []
        for start in range(len(ptrlist)):
            strs = yield from self.read_str(ptrlist[start], pid)
            vals.append(strs)
        return vals

    def read_int_array(self, addr: int, count: int,
                       pid: Optional[int] = None) -> Generator[Any, Any, List[int]]:
        """
        ### Read an array of 4-byte integers from guest memory

        Reads an array of 4-byte integers from guest memory.

        **Args:**
        - `addr` (`int`): Address to start reading from.
        - `count` (`int`): Number of integers to read.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `list[int]`: List of integers read from memory.
        """
        data = yield from self.read_bytes(addr, 4 * count, pid)
        if len(data) != 4 * count:
            self.logger.error(
                f"Failed to read int array at addr={addr}, expected {4*count} bytes, got {len(data)}")
            return []
        return list(unpack(f"{self.endian_format}{count}I", data))

    def write_int_array(
            self, addr: int, values: List[int], pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        ### Write an array of 4-byte integers to guest memory

        Writes an array of 4-byte integers to guest memory.

        **Args:**
        - `addr` (`int`): Address to start writing to.
        - `values` (`list[int]`): List of integers to write.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `int`: Number of bytes written.
        """
        data = pack(f"{self.endian_format}{len(values)}I", *values)
        return (yield from self.write_bytes(addr, data, pid))

    def read_utf8_str(
            self, addr: int, pid: Optional[int] = None) -> Generator[Any, Any, str]:
        """
        ### Read a null-terminated UTF-8 string from guest memory

        Reads a null-terminated UTF-8 string from guest memory at a specified address.

        **Args:**
        - `addr` (`int`): Address to read from.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `str`: UTF-8 string read from memory.
        """
        if addr != 0:
            self.logger.debug(f"read_utf8_str called: addr={addr:#x}")
            if self.try_panda:
                try:
                    chunk = self.panda.read_str(self.panda.get_cpu(), addr)
                    return chunk
                except ValueError:
                    pass
            chunk = yield PortalCmd(hop.HYPER_OP_READ_STR, addr, 0, pid)
            if chunk:
                self.logger.debug(f"Received response from queue: {chunk}")
                return chunk.decode('utf-8', errors='replace')
        return ""

    def read_byte(
            self, addr: int, pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        ### Read a single byte from guest memory

        Reads a single byte from guest memory.

        **Args:**
        - `addr` (`int`): Address to read from.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `int` or `None`: Byte value read (0-255), or `None` on failure.
        """
        data = yield from self.read_bytes(addr, 1, pid)
        if len(data) != 1:
            self.logger.error(f"Failed to read byte at addr={addr}")
            return None
        return data[0]

    def write_byte(self, addr: int, value: int,
                   pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        ### Write a single byte to guest memory

        Writes a single byte to guest memory.

        **Args:**
        - `addr` (`int`): Address to write to.
        - `value` (`int`): Byte value to write (0-255).
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `int`: Number of bytes written (should be 1).
        """
        data = bytes([value & 0xFF])
        return (yield from self.write_bytes(addr, data, pid))

    def read_word(
            self, addr: int, pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        ### Read a 2-byte word from guest memory

        Reads a 2-byte word from guest memory.

        **Args:**
        - `addr` (`int`): Address to read from.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `int` or `None`: Word value read, or `None` on failure.
        """
        data = yield from self.read_bytes(addr, 2, pid)
        if len(data) != 2:
            self.logger.error(f"Failed to read word at addr={addr}")
            return None
        return unpack(f"{self.endian_format}H", data)[0]

    def write_word(self, addr: int, value: int,
                   pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        ### Write a 2-byte word to guest memory

        Writes a 2-byte word to guest memory.

        **Args:**
        - `addr` (`int`): Address to write to.
        - `value` (`int`): Word value to write.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `int`: Number of bytes written (should be 2).
        """
        data = pack(f"{self.endian_format}H", value)
        return (yield from self.write_bytes(addr, data, pid))

    def memset(self, addr: int, value: int, size: int,
               pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        ### Set a region of guest memory to a specific byte value

        Sets a region of guest memory to a specific byte value.

        **Args:**
        - `addr` (`int`): Address to start setting.
        - `value` (`int`): Byte value to set (0-255).
        - `size` (`int`): Number of bytes to set.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `int`: Number of bytes written.
        """
        data = bytes([value & 0xFF]) * size
        return (yield from self.write_bytes(addr, data, pid))

    def memcmp(self, addr1: int, addr2: int, size: int,
               pid: Optional[int] = None) -> Generator[Any, Any, bool]:
        """
        ### Compare two regions of guest memory for equality

        Compares two regions of guest memory for equality.

        **Args:**
        - `addr1` (`int`): First address.
        - `addr2` (`int`): Second address.
        - `size` (`int`): Number of bytes to compare.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `bool`: `True` if memory regions are equal, `False` otherwise.
        """
        data1 = yield from self.read_bytes(addr1, size, pid)
        data2 = yield from self.read_bytes(addr2, size, pid)
        return data1 == data2

    def read_ptr_array(self, addr: int, pid: Optional[int] = None) -> Generator[Any, Any, List[str]]:
        """
        ### Read a NULL-terminated array of pointers to strings from guest memory using the portal's optimized handler.

        Uses the HYPER_OP_READ_PTR_ARRAY portal command for efficient reading.

        **Args:**
        - `addr` (`int`): Address of the pointer array in guest memory.
        - `pid` (`int`, optional): Process ID for context.

        **Returns:**
        - `List[str]`: List of strings read from the array.
        """
        from hyper.consts import HYPER_OP as hop
        from hyper.portal import PortalCmd
        buf = yield PortalCmd(hop.HYPER_OP_READ_PTR_ARRAY, addr, 0, pid)
        if not buf:
            return []
        # The buffer is a sequence of null-terminated strings
        result = []
        offset = 0
        while offset < len(buf):
            end = buf.find(b'\0', offset)
            if end == -1:
                break
            s = buf[offset:end].decode('latin-1', errors='replace')
            if s == '':
                break
            result.append(s)
            offset = end + 1
        return result
