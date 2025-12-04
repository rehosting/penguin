"""
Memory Access Plugin (mem.py)
=============================

This module provides the Mem plugin for the Penguin framework, enabling safe and efficient reading and writing of guest memory via the hypervisor portal. It abstracts low-level memory operations, supporting chunked access, endianness handling, and architecture-specific pointer sizes. The plugin is designed to work with both PANDA and non-PANDA environments, and provides utilities for reading and writing bytes, integers, pointers, strings, arrays, and more.

Features
--------

- Read and write arbitrary bytes to guest memory.
- Read and write integers, longs, words, and pointers with correct endianness.
- Read and write null-terminated and UTF-8 strings.
- Read arrays of integers and lists of pointers or strings.
- Memory comparison and memset utilities.
- Handles chunking for large memory operations.
- Supports both PANDA and hypervisor portal backends.

Example Usage
-------------

.. code-block:: python

    from penguin import plugins

    # Read 16 bytes from address 0x1000
    data = yield from plugins.mem.read_bytes(0x1000, 16)

    # Write a string to memory
    yield from plugins.mem.write_str(0x2000, "hello world")

    # Read a pointer-sized value
    ptr = yield from plugins.mem.read_ptr(0x3000)

    # Compare two memory regions
    equal = yield from plugins.mem.memcmp(0x4000, 0x5000, 32)
"""

from penguin import Plugin, plugins
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd
from struct import pack, unpack
from typing import Optional, List, Union, Any, Generator


class Mem(Plugin):
    """
    Mem Plugin
    ==========
    Provides guest memory access and manipulation via the hypervisor portal.

    Attributes
    ----------
    endian_format : str
        Endianness format for struct packing/unpacking.
    try_panda : bool
        Whether to attempt PANDA-based memory access.
    """

    def __init__(self) -> None:
        """
        Initialize the Mem plugin.

        Sets endianness and architecture-specific options.
        """
        if self.panda.endianness == 'little':
            self.endian_format = '<'
            self.endian_str = 'little'
        else:
            self.endian_format = '>'
            self.endian_str = 'big'
        self.try_panda = True if self.panda.arch != "riscv64" else False
        self.ptr_typ = f'uint{self.panda.bits}_t'

        # Cache specific FFI types and functions to avoid dot-lookup overhead
        self.ffi = self.panda.ffi
        self.libpanda = self.panda.libpanda
        self._read_external = self.libpanda.panda_virtual_memory_read_external
        self._write_external = self.libpanda.panda_virtual_memory_write_external

        # Pre-calculate constants
        self.addr_mask = 0xFFFFFFFF if self.panda.bits == 32 else 0xFFFFFFFFFFFFFFFF

        # Cache get_cpu to avoid self.panda lookup
        self._get_cpu = plugins.cas.get_cpu
        self.ptr_size = self.panda.bits
        self._rsize = None
        # Bind pointer methods
        if self.panda.bits == 32:
            self.read_ptr = self.read_int
            self.write_ptr = self.write_int
        else:
            self.read_ptr = self.read_long
            self.write_ptr = self.write_long

    def _get_rsize(self) -> int:
        """
        Helper to lazily fetch and cache the regions_size.
        This enables the plugin to load before the hypervisor connects.
        """
        if self._rsize:
            return self._rsize

        # Try to fetch from portal
        # getattr is safe if regions_size hasn't been set on Portal yet
        rsize = getattr(plugins.portal, 'regions_size', None)

        if rsize:
            self._rsize = rsize
            return rsize

        # Fallback default if portal isn't ready (prevents div/0 errors)
        return 4096

    def write_bytes(self, addr: int, data: bytes,
                    pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write bytes to guest memory.

        Writes bytes to guest memory at a specified address, handling chunking for large data.

        Parameters
        ----------
        addr : int
            Address to write to.
        data : bytes
            Data to write.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int
            Number of bytes written.
        """
        # Use memoryview to avoid copying bytes on slice
        view = memoryview(data)
        total_len = len(view)

        rsize = self._get_rsize()
        cpu = None

        # Handle single chunk (Fast Path)
        if total_len <= rsize:
            if self.try_panda:
                if cpu is None:
                    cpu = self._get_cpu()
                try:
                    addr_u = addr & self.addr_mask
                    self.write_bytes_panda(cpu, addr_u, data)
                    return total_len
                except ValueError:
                    pass
            yield PortalCmd(hop.HYPER_OP_WRITE, addr, total_len, pid, data)
            return total_len

        # Multi-chunk write
        num_chunks = (total_len + rsize - 1) // rsize

        for i in range(num_chunks):
            offset = i * rsize
            chunk_addr = addr + offset

            # Slicing memoryview is zero-copy
            chunk_view = view[offset:offset + rsize]
            chunk_len = len(chunk_view)

            success = False
            if self.try_panda:
                if cpu is None:
                    cpu = self._get_cpu()
                try:
                    addr_u = chunk_addr & self.addr_mask
                    # ffi.new accepts memoryview/buffer protocol
                    self.write_bytes_panda(cpu, addr_u, chunk_view)
                    success = True
                except ValueError:
                    pass

            if not success:
                # Convert view back to bytes for the portal command if needed
                yield PortalCmd(hop.HYPER_OP_WRITE, chunk_addr, chunk_len, pid, chunk_view.tobytes())

        return total_len

    def write_bytes_panda(self, cpu, addr: int, data: bytes) -> None:
        '''
        Write a bytearray into memory at the specified physical/virtual address
        '''
        length = len(data)
        c_buf = self.ffi.from_buffer(data)
        buf_a = self.ffi.cast("char*", c_buf)
        length_a = self.ffi.cast("int", length)
        err = self._write_external(cpu, addr, buf_a, length_a)

        if err < 0:
            raise ValueError(f"Memory write failed with err={err}")  # TODO: make a PANDA Exn class

    def read_bytes(self, addr: int, size: int,
                   pid: Optional[int] = None) -> Generator[Any, Any, bytes]:
        """
        Reads bytes from guest memory.
        Optimized with a Fast Path for single-chunk reads.
        """
        rsize = self._get_rsize()

        # --- FAST PATH: Single Chunk (Common Case) ---
        if size <= rsize:
            if self.try_panda:
                # We can assume CPU is needed here, get it once
                cpu = self._get_cpu()
                try:
                    # Masking is handled inside read_bytes_panda now to be safer/faster
                    return self.read_bytes_panda(cpu, addr, size)
                except ValueError:
                    pass

            # Fallback to Portal
            chunk = yield PortalCmd(hop.HYPER_OP_READ, addr, size, pid)
            if not chunk:
                return b"\x00" * size
            if len(chunk) != size:
                return chunk.ljust(size, b"\x00")
            return chunk

        # --- SLOW PATH: Multi-Chunk (Large Reads) ---
        read_chunks = []
        cpu = None

        # Calculate number of chunks needed
        # (size + rsize - 1) // rsize is equivalent to ceil(size / rsize)
        num_chunks = (size + rsize - 1) // rsize

        for i in range(num_chunks):
            offset = i * rsize
            chunk_addr = addr + offset
            # Calculate remaining bytes
            chunk_size = size - offset
            if chunk_size > rsize:
                chunk_size = rsize

            chunk = None
            if self.try_panda:
                if cpu is None:
                    cpu = self._get_cpu()
                try:
                    chunk = self.read_bytes_panda(cpu, chunk_addr, chunk_size)
                except ValueError:
                    pass

            if not chunk:
                chunk = yield PortalCmd(hop.HYPER_OP_READ, chunk_addr, chunk_size, pid)

            if not chunk:
                chunk = b"\x00" * chunk_size
            elif len(chunk) != chunk_size:
                chunk = chunk.ljust(chunk_size, b"\x00")
            read_chunks.append(chunk)
        # Optimization: Use b''.join only once at the end
        return b"".join(read_chunks)

    def read_bytes_panda(self, cpu, addr: int, size: int) -> bytes:
        """
        Optimized PANDA read.
        """
        # Create buffer
        buf = self.ffi.new("char[]", size)

        # Force unsigned logic using cached mask
        addr_u = addr & self.addr_mask

        buf_a = self.ffi.cast("char*", buf)
        length_a = self.ffi.cast("int", size)
        err = self._read_external(cpu, addr_u, buf_a, length_a)

        if err < 0:
            raise ValueError(f"Memory read failed at {addr:x}")

        return self.ffi.unpack(buf, size)

    def read_str(self, addr: int,
                 pid: Optional[int] = None) -> Generator[Any, Any, str]:
        """
        Read a null-terminated string from guest memory.

        Reads a null-terminated string from guest memory at a specified address.
        Optimized to read in page-aligned chunks to minimize overhead, with
        fallback to PortalCmd if memory is unmapped in the emulator.

        Parameters
        ----------
        addr : int
            Address to read from.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        str
            String read from memory.
        """
        if addr != 0:
            self.logger.debug(f"read_str called: addr={addr:#x}")

            result = bytearray()

            PAGE_SIZE = 0x1000
            # Portal has a max payload size of PAGE_SIZE - 48 (header overhead).
            # We align our chunks to this to ensure safe fallbacks.
            PORTAL_CHUNK_SIZE = PAGE_SIZE - 48

            # Safety limit: almost a page
            SAFE_MAX = 4096 - 24
            total_read = 0
            curr_addr = addr
            cpu = self._get_cpu()

            while total_read < SAFE_MAX:
                # 1. Calculate space left in current page
                page_offset = curr_addr & (PAGE_SIZE - 1)
                bytes_left_in_page = PAGE_SIZE - page_offset

                # 2. Determine read size
                # Cap at:
                # a) Remaining page space (don't cross page boundary)
                # b) Portal max chunk size (don't overflow portal buffer)
                # c) Remaining safety limit
                to_read = min(bytes_left_in_page, PORTAL_CHUNK_SIZE, SAFE_MAX - total_read)

                chunk = None

                # 3. Attempt PANDA direct read first
                if self.try_panda:
                    try:
                        chunk = self.read_bytes_panda(cpu, curr_addr, to_read)
                    except ValueError:
                        # Memory is not mapped in QEMU/PANDA.
                        # Fallthrough to PortalCmd below.
                        self.logger.debug(f"PANDA read failed at {curr_addr:#x}, falling back to portal")
                        chunk = None

                # 4. Fallback to PortalCmd if PANDA failed or is disabled
                if chunk is None:
                    # We pass `to_read` to ensure we don't request across a page boundary
                    # even via the portal, although the portal handles its own safety.
                    chunk = yield PortalCmd(hop.HYPER_OP_READ_STR, curr_addr, to_read, pid)

                if not chunk:
                    # If both methods failed or returned empty, we stop.
                    break

                # 5. Scan for NULL terminator
                null_idx = chunk.find(b'\x00')

                if null_idx != -1:
                    # Found terminator: append valid part and stop
                    result.extend(chunk[:null_idx])
                    break
                else:
                    # No terminator: append whole chunk and continue
                    result.extend(chunk)
                    total_read += len(chunk)
                    curr_addr += len(chunk)

            return result.decode('latin-1', errors='replace')

        return ""

    def read_str_panda(self, cpu, addr: int) -> str:
        """
        Read a null-terminated string from guest memory using PANDA only.

        Reads a null-terminated string from guest memory at a specified address,
        using PANDA's virtual_memory_read in page-aligned chunks. Never falls back
        to the portal.

        Parameters
        ----------
        cpu  : Any (CPUState)
        addr : int
            Address to read from.

        Returns
        -------
        str
            String read from memory.
        """
        if addr == 0:
            return ""
        self.logger.debug(f"read_str_panda called: addr={addr:#x}")

        result = bytearray()
        PAGE_SIZE = 0x1000
        SAFE_MAX = PAGE_SIZE
        total_read = 0
        curr_addr = addr

        while total_read < SAFE_MAX:
            page_offset = curr_addr & (PAGE_SIZE - 1)
            bytes_left_in_page = PAGE_SIZE - page_offset
            to_read = min(bytes_left_in_page, SAFE_MAX - total_read)
            try:
                chunk = self.read_bytes_panda(cpu, curr_addr, to_read)
            except ValueError:
                self.logger.debug(f"PANDA read failed at {curr_addr:#x}")
                break
            if not chunk:
                break
            null_idx = chunk.find(b'\x00')
            if null_idx != -1:
                result.extend(chunk[:null_idx])
                break
            else:
                result.extend(chunk)
                total_read += len(chunk)
                curr_addr += len(chunk)
        return result.decode('latin-1', errors='replace')

    def read_int(self, addr: int,
                 pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        Read a 4-byte integer from guest memory.

        Reads a 4-byte integer from guest memory at a specified address.

        Parameters
        ----------
        addr : int
            Address to read from.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int or None
            Integer value read, or None on failure.
        """
        self.logger.debug(f"read_int called: addr={addr}")
        data = yield from self.read_bytes(addr, 4, pid)
        if len(data) != 4:
            self.logger.error(
                f"Failed to read int at addr={addr}, data_len={len(data)}")
            return None
        value = int.from_bytes(data, self.endian_str)
        return value

    def read_long(
            self, addr: int, pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        Read an 8-byte long integer from guest memory.

        Reads an 8-byte long integer from guest memory at a specified address.

        Parameters
        ----------
        addr : int
            Address to read from.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int or None
            Long value read, or None on failure.
        """
        self.logger.debug(f"read_long called: addr={addr}")
        data = yield from self.read_bytes(addr, 8, pid)
        if len(data) != 8:
            self.logger.error(
                f"Failed to read long at addr={addr}, data_len={len(data)}")
            return None
        value = int.from_bytes(data, self.endian_str)
        return value

    def read_ptr(self, addr: int,
                 pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        Read a pointer-sized value from guest memory.

        Reads a pointer-sized value from guest memory at a specified address.

        Parameters
        ----------
        addr : int
            Address to read from.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int or None
            Pointer value read, or None on failure.
        """
        # this function is bound in __init__
        pass

    def write_int(self, addr: int, value: int,
                  pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write a 4-byte integer to guest memory.

        Writes a 4-byte integer to guest memory at a specified address.

        Parameters
        ----------
        addr : int
            Address to write to.
        value : int
            Integer value to write.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int
            Number of bytes written.
        """
        # Pack the integer according to system endianness
        data = value.to_bytes(4, self.endian_str)
        bytes_written = yield from self.write_bytes(addr, data, pid)
        return bytes_written

    def write_long(self, addr: int, value: int,
                   pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write an 8-byte long integer to guest memory.

        Writes an 8-byte long integer to guest memory at a specified address.

        Parameters
        ----------
        addr : int
            Address to write to.
        value : int
            Long value to write.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int
            Number of bytes written.
        """
        # Pack the long according to system endianness
        data = value.to_bytes(8, self.endian_str)
        bytes_written = yield from self.write_bytes(addr, data, pid)
        return bytes_written

    def write_ptr(self, addr: int, value: int,
                  pid: Optional[int] = None) -> Generator[Any, Any, None]:
        """
        Write a pointer-sized value to guest memory.

        Writes a pointer-sized value to guest memory at a specified address.

        Parameters
        ----------
        addr : int
            Address to write to.
        value : int
            Pointer value to write.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        None
        """
        # this function is bound in __init__
        pass

    def write_str(self, addr: int, string: Union[str, bytes], null_terminate: bool = True,
                  pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write a string to guest memory.

        Writes a string to guest memory at a specified address, optionally null-terminated.

        Parameters
        ----------
        addr : int
            Address to write to.
        string : str or bytes
            String to write.
        null_terminate : bool, optional
            Whether to append a null terminator (default: True).
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int
            Number of bytes written.
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
        Read a list of pointer values from guest memory.

        Reads a list of pointer values from guest memory.

        Parameters
        ----------
        addr : int
            Address to start reading from.
        length : int
            Maximum number of pointers to read.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        list of int
            List of pointer values.
        """
        ptrs = []
        ptrsize = self.ptr_size
        for start in range(length):
            ptr = yield from self.read_ptr(addr + (start * ptrsize), pid)
            if ptr == 0:
                break
            ptrs.append(ptr)
        return ptrs

    def read_char_ptrlist(self, addr: int, length: int,
                          pid: Optional[int] = None) -> Generator[Any, Any, List[str]]:
        """
        Read a list of null-terminated strings from a list of pointers.

        Reads a list of null-terminated strings from a list of pointers in guest memory.

        Parameters
        ----------
        addr : int
            Address to start reading pointer list from.
        length : int
            Maximum number of pointers to read.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        list of str
            List of strings read from memory.
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
        Read an array of 4-byte integers from guest memory.

        Reads an array of 4-byte integers from guest memory.

        Parameters
        ----------
        addr : int
            Address to start reading from.
        count : int
            Number of integers to read.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        list of int
            List of integers read from memory.
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
        Write an array of 4-byte integers to guest memory.

        Writes an array of 4-byte integers to guest memory.

        Parameters
        ----------
        addr : int
            Address to start writing to.
        values : list of int
            List of integers to write.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int
            Number of bytes written.
        """
        data = pack(f"{self.endian_format}{len(values)}I", *values)
        return (yield from self.write_bytes(addr, data, pid))

    def read_long_array(self, addr: int, count: int,
                        pid: Optional[int] = None) -> Generator[Any, Any, List[int]]:
        """
        Read an array of 8-byte long integers from guest memory.

        Reads an array of 8-byte long integers from guest memory.

        Parameters
        ----------
        addr : int
            Address to start reading from.
        count : int
            Number of longs to read.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        list of int
            List of long integers read from memory.
        """
        data = yield from self.read_bytes(addr, 8 * count, pid)
        if len(data) != 8 * count:
            self.logger.error(
                f"Failed to read long array at addr={addr}, expected {8*count} bytes, got {len(data)}")
            return []
        return list(unpack(f"{self.endian_format}{count}Q", data))

    def read_uint64_array(self, addr: int, count: int, pid: Optional[int] = None) -> Generator[Any, Any, List[int]]:
        """
        Read an array of 8-byte unsigned integers from guest memory.

        Reads an array of 8-byte unsigned integers from guest memory.

        Parameters
        ----------
        addr : int
            Address to start reading from.
        count : int
            Number of uint64s to read.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        list of int
            List of uint64s read from memory.
        """
        return (yield from self.read_long_array(addr, count, pid))

    def read_utf8_str(
            self, addr: int, pid: Optional[int] = None) -> Generator[Any, Any, str]:
        """
        Read a null-terminated UTF-8 string from guest memory.

        Reads a null-terminated UTF-8 string from guest memory at a specified address.

        Parameters
        ----------
        addr : int
            Address to read from.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        str
            UTF-8 string read from memory.
        """
        if addr != 0:
            chunk = yield from self.read_str(addr, pid)
            if chunk:
                self.logger.debug(f"Received response from queue: {chunk}")
                return chunk.encode('latin-1').decode('utf-8', errors='replace')
        return ""

    def read_byte(
            self, addr: int, pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        Read a single byte from guest memory.

        Reads a single byte from guest memory.

        Parameters
        ----------
        addr : int
            Address to read from.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int or None
            Byte value read (0-255), or None on failure.
        """
        data = yield from self.read_bytes(addr, 1, pid)
        if len(data) != 1:
            self.logger.error(f"Failed to read byte at addr={addr}")
            return None
        return data[0]

    def write_byte(self, addr: int, value: int,
                   pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write a single byte to guest memory.

        Writes a single byte to guest memory.

        Parameters
        ----------
        addr : int
            Address to write to.
        value : int
            Byte value to write (0-255).
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int
            Number of bytes written (should be 1).
        """
        data = bytes([value & 0xFF])
        return (yield from self.write_bytes(addr, data, pid))

    def read_word(
            self, addr: int, pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        Read a 2-byte word from guest memory.

        Reads a 2-byte word from guest memory.

        Parameters
        ----------
        addr : int
            Address to read from.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int or None
            Word value read, or None on failure.
        """
        data = yield from self.read_bytes(addr, 2, pid)
        if len(data) != 2:
            self.logger.error(f"Failed to read word at addr={addr}")
            return None
        return int.from_bytes(data, self.endian_str)

    def write_word(self, addr: int, value: int,
                   pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write a 2-byte word to guest memory.

        Writes a 2-byte word to guest memory.

        Parameters
        ----------
        addr : int
            Address to write to.
        value : int
            Word value to write.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int
            Number of bytes written (should be 2).
        """
        data = value.to_bytes(2, self.endian_str)
        return (yield from self.write_bytes(addr, data, pid))

    def memset(self, addr: int, value: int, size: int,
               pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Set a region of guest memory to a specific byte value.

        Sets a region of guest memory to a specific byte value.

        Parameters
        ----------
        addr : int
            Address to start setting.
        value : int
            Byte value to set (0-255).
        size : int
            Number of bytes to set.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int
            Number of bytes written.
        """
        data = bytes([value & 0xFF]) * size
        return (yield from self.write_bytes(addr, data, pid))

    def memcmp(self, addr1: int, addr2: int, size: int,
               pid: Optional[int] = None) -> Generator[Any, Any, bool]:
        """
        Compare two regions of guest memory for equality.

        Compares two regions of guest memory for equality.

        Parameters
        ----------
        addr1 : int
            First address.
        addr2 : int
            Second address.
        size : int
            Number of bytes to compare.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        bool
            True if memory regions are equal, False otherwise.
        """
        data1 = yield from self.read_bytes(addr1, size, pid)
        data2 = yield from self.read_bytes(addr2, size, pid)
        return data1 == data2

    def read_ptr_array(self, addr: int, pid: Optional[int] = None) -> Generator[Any, Any, List[str]]:
        """
        Read a NULL-terminated array of pointers to strings from guest memory using the portal's optimized handler.

        Uses the HYPER_OP_READ_PTR_ARRAY portal command for efficient reading.

        Parameters
        ----------
        addr : int
            Address of the pointer array in guest memory.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        list of str
            List of strings read from the array.
        """
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
