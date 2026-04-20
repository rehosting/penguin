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
from dwarffi import Ptr


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
        self._get_cpu = self.panda.get_cpu
        self.ptr_size = self.panda.bits // 8
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

    def write_bytes(self, addr: Union[int, Ptr], data: bytes,
                    pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write bytes to guest memory.

        Writes bytes to guest memory at a specified address, handling chunking for large data.

        Parameters
        ----------
        addr : int or Ptr
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
        if isinstance(addr, Ptr):
            addr = addr.address

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

    def write_bytes_panda(self, cpu, addr: Union[int, Ptr], data: bytes) -> None:
        '''
        Write a bytearray into memory at the specified physical/virtual address
        '''
        if isinstance(addr, Ptr):
            addr = addr.address
            
        length = len(data)
        c_buf = self.ffi.from_buffer(data)
        buf_a = self.ffi.cast("char*", c_buf)
        length_a = self.ffi.cast("int", length)
        err = self._write_external(cpu, addr, buf_a, length_a)

        if err < 0:
            raise ValueError(f"Memory write failed with err={err}")  # TODO: make a PANDA Exn class

    def read_bytes(self, addr: Union[int, Ptr], size: int,
                   pid: Optional[int] = None) -> Generator[Any, Any, bytes]:
        """
        Reads bytes from guest memory.
        Optimized with a Fast Path for single-chunk reads.
        """
        if isinstance(addr, Ptr):
            addr = addr.address

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

    def read_bytes_panda(self, cpu, addr: Union[int, Ptr], size: int) -> bytes:
        """
        Optimized PANDA read.
        """
        if isinstance(addr, Ptr):
            addr = addr.address

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

    def read_str(self, addr: Union[int, Ptr],
                 pid: Optional[int] = None) -> Generator[Any, Any, str]:
        """
        Read a null-terminated string from guest memory.

        Reads a null-terminated string from guest memory at a specified address.
        Optimized to read in page-aligned chunks to minimize overhead, with
        fallback to PortalCmd if memory is unmapped in the emulator.

        Parameters
        ----------
        addr : int or Ptr
            Address to read from.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        str
            String read from memory.
        """
        if isinstance(addr, Ptr):
            addr = addr.address

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

    def read_str_panda(self, cpu, addr: Union[int, Ptr]) -> str:
        """
        Read a null-terminated string from guest memory using PANDA only.

        Reads a null-terminated string from guest memory at a specified address,
        using PANDA's virtual_memory_read in page-aligned chunks. Never falls back
        to the portal.

        Parameters
        ----------
        cpu  : Any (CPUState)
        addr : int or Ptr
            Address to read from.

        Returns
        -------
        str
            String read from memory.
        """
        if isinstance(addr, Ptr):
            addr = addr.address

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

    def read_int(self, addr: Union[int, Ptr],
                 pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        Read a 4-byte integer from guest memory.

        Reads a 4-byte integer from guest memory at a specified address.

        Parameters
        ----------
        addr : int or Ptr
            Address to read from.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int or None
            Integer value read, or None on failure.
        """
        if isinstance(addr, Ptr):
            addr = addr.address

        self.logger.debug(f"read_int called: addr={addr:#x}")
        data = yield from self.read_bytes(addr, 4, pid)
        if len(data) != 4:
            self.logger.error(
                f"Failed to read int at addr={addr:#x}, data_len={len(data)}")
            return None
        value = int.from_bytes(data, self.endian_str)
        return value

    def read_long(
            self, addr: Union[int, Ptr], pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        Read an 8-byte long integer from guest memory.

        Reads an 8-byte long integer from guest memory at a specified address.

        Parameters
        ----------
        addr : int or Ptr
            Address to read from.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int or None
            Long value read, or None on failure.
        """
        if isinstance(addr, Ptr):
            addr = addr.address

        self.logger.debug(f"read_long called: addr={addr:#x}")
        data = yield from self.read_bytes(addr, 8, pid)
        if len(data) != 8:
            self.logger.error(
                f"Failed to read long at addr={addr:#x}, data_len={len(data)}")
            return None
        value = int.from_bytes(data, self.endian_str)
        return value

    def read_ptr(self, addr: Union[int, Ptr],
                 pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        Read a pointer-sized value from guest memory.

        Reads a pointer-sized value from guest memory at a specified address.

        Parameters
        ----------
        addr : int or Ptr
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

    def write_int(self, addr: Union[int, Ptr], value: int,
                  pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write a 4-byte integer to guest memory.

        Writes a 4-byte integer to guest memory at a specified address.

        Parameters
        ----------
        addr : int or Ptr
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
        if isinstance(addr, Ptr):
            addr = addr.address

        # Pack the integer according to system endianness
        data = value.to_bytes(4, self.endian_str)
        bytes_written = yield from self.write_bytes(addr, data, pid)
        return bytes_written

    def write_long(self, addr: Union[int, Ptr], value: int,
                   pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write an 8-byte long integer to guest memory.

        Writes an 8-byte long integer to guest memory at a specified address.

        Parameters
        ----------
        addr : int or Ptr
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
        if isinstance(addr, Ptr):
            addr = addr.address

        # Pack the long according to system endianness
        data = value.to_bytes(8, self.endian_str)
        bytes_written = yield from self.write_bytes(addr, data, pid)
        return bytes_written

    def write_ptr(self, addr: Union[int, Ptr], value: int,
                  pid: Optional[int] = None) -> Generator[Any, Any, None]:
        """
        Write a pointer-sized value to guest memory.

        Writes a pointer-sized value to guest memory at a specified address.

        Parameters
        ----------
        addr : int or Ptr
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

    def write_str(self, addr: Union[int, Ptr], string: Union[str, bytes], null_terminate: bool = True,
                  pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write a string to guest memory.

        Writes a string to guest memory at a specified address, optionally null-terminated.

        Parameters
        ----------
        addr : int or Ptr
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
        if isinstance(addr, Ptr):
            addr = addr.address

        self.logger.debug(
            f"write_str called: addr={addr:#x}, string_len={len(string)}")
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

    def read_ptrlist(self, addr: Union[int, Ptr], length: int,
                     pid: Optional[int] = None) -> Generator[Any, Any, List[int]]:
        """
        Read a list of pointer values from guest memory.

        Reads a list of pointer values from guest memory.

        Parameters
        ----------
        addr : int or Ptr
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
        if isinstance(addr, Ptr):
            addr = addr.address

        ptrs = []
        ptrsize = self.ptr_size
        for start in range(length):
            ptr = yield from self.read_ptr(addr + (start * ptrsize), pid)
            if ptr == 0:
                break
            ptrs.append(ptr)
        return ptrs

    def read_char_ptrlist(self, addr: Union[int, Ptr], length: int,
                          pid: Optional[int] = None) -> Generator[Any, Any, List[str]]:
        """
        Read a list of null-terminated strings from a list of pointers.

        Reads a list of null-terminated strings from a list of pointers in guest memory.

        Parameters
        ----------
        addr : int or Ptr
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
        if isinstance(addr, Ptr):
            addr = addr.address

        ptrlist = yield from self.read_ptrlist(addr, length, pid)
        vals = []
        for start in range(len(ptrlist)):
            strs = yield from self.read_str(ptrlist[start], pid)
            vals.append(strs)
        return vals

    def read_int_array(self, addr: Union[int, Ptr], count: int,
                       pid: Optional[int] = None) -> Generator[Any, Any, List[int]]:
        """
        Read an array of 4-byte integers from guest memory.

        Reads an array of 4-byte integers from guest memory.

        Parameters
        ----------
        addr : int or Ptr
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
        if isinstance(addr, Ptr):
            addr = addr.address

        data = yield from self.read_bytes(addr, 4 * count, pid)
        if len(data) != 4 * count:
            self.logger.error(
                f"Failed to read int array at addr={addr:#x}, expected {4*count} bytes, got {len(data)}")
            return []
        return list(unpack(f"{self.endian_format}{count}I", data))

    def write_int_array(
            self, addr: Union[int, Ptr], values: List[int], pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write an array of 4-byte integers to guest memory.

        Writes an array of 4-byte integers to guest memory.

        Parameters
        ----------
        addr : int or Ptr
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
        if isinstance(addr, Ptr):
            addr = addr.address

        data = pack(f"{self.endian_format}{len(values)}I", *values)
        return (yield from self.write_bytes(addr, data, pid))

    def read_long_array(self, addr: Union[int, Ptr], count: int,
                        pid: Optional[int] = None) -> Generator[Any, Any, List[int]]:
        """
        Read an array of 8-byte long integers from guest memory.

        Reads an array of 8-byte long integers from guest memory.

        Parameters
        ----------
        addr : int or Ptr
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
        if isinstance(addr, Ptr):
            addr = addr.address

        data = yield from self.read_bytes(addr, 8 * count, pid)
        if len(data) != 8 * count:
            self.logger.error(
                f"Failed to read long array at addr={addr:#x}, expected {8*count} bytes, got {len(data)}")
            return []
        return list(unpack(f"{self.endian_format}{count}Q", data))

    def read_uint64_array(self, addr: Union[int, Ptr], count: int, pid: Optional[int] = None) -> Generator[Any, Any, List[int]]:
        """
        Read an array of 8-byte unsigned integers from guest memory.

        Reads an array of 8-byte unsigned integers from guest memory.

        Parameters
        ----------
        addr : int or Ptr
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
        if isinstance(addr, Ptr):
            addr = addr.address

        return (yield from self.read_long_array(addr, count, pid))

    def read_utf8_str(
            self, addr: Union[int, Ptr], pid: Optional[int] = None) -> Generator[Any, Any, str]:
        """
        Read a null-terminated UTF-8 string from guest memory.

        Reads a null-terminated UTF-8 string from guest memory at a specified address.

        Parameters
        ----------
        addr : int or Ptr
            Address to read from.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        str
            UTF-8 string read from memory.
        """
        if isinstance(addr, Ptr):
            addr = addr.address

        if addr != 0:
            chunk = yield from self.read_str(addr, pid)
            if chunk:
                self.logger.debug(f"Received response from queue: {chunk}")
                return chunk.encode('latin-1').decode('utf-8', errors='replace')
        return ""

    def read_byte(
            self, addr: Union[int, Ptr], pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        Read a single byte from guest memory.

        Reads a single byte from guest memory.

        Parameters
        ----------
        addr : int or Ptr
            Address to read from.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int or None
            Byte value read (0-255), or None on failure.
        """
        if isinstance(addr, Ptr):
            addr = addr.address

        data = yield from self.read_bytes(addr, 1, pid)
        if len(data) != 1:
            self.logger.error(f"Failed to read byte at addr={addr:#x}")
            return None
        return data[0]

    def write_byte(self, addr: Union[int, Ptr], value: int,
                   pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write a single byte to guest memory.

        Writes a single byte to guest memory.

        Parameters
        ----------
        addr : int or Ptr
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
        if isinstance(addr, Ptr):
            addr = addr.address

        data = bytes([value & 0xFF])
        return (yield from self.write_bytes(addr, data, pid))

    def read_word(
            self, addr: Union[int, Ptr], pid: Optional[int] = None) -> Generator[Any, Any, Optional[int]]:
        """
        Read a 2-byte word from guest memory.

        Reads a 2-byte word from guest memory.

        Parameters
        ----------
        addr : int or Ptr
            Address to read from.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int or None
            Word value read, or None on failure.
        """
        if isinstance(addr, Ptr):
            addr = addr.address

        data = yield from self.read_bytes(addr, 2, pid)
        if len(data) != 2:
            self.logger.error(f"Failed to read word at addr={addr:#x}")
            return None
        return int.from_bytes(data, self.endian_str)

    def write_word(self, addr: Union[int, Ptr], value: int,
                   pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write a 2-byte word to guest memory.

        Writes a 2-byte word to guest memory.

        Parameters
        ----------
        addr : int or Ptr
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
        if isinstance(addr, Ptr):
            addr = addr.address

        data = value.to_bytes(2, self.endian_str)
        return (yield from self.write_bytes(addr, data, pid))

    def memset(self, addr: Union[int, Ptr], value: int, size: int,
               pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Set a region of guest memory to a specific byte value.

        Sets a region of guest memory to a specific byte value.

        Parameters
        ----------
        addr : int or Ptr
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
        if isinstance(addr, Ptr):
            addr = addr.address

        data = bytes([value & 0xFF]) * size
        return (yield from self.write_bytes(addr, data, pid))

    def memcmp(self, addr1: Union[int, Ptr], addr2: Union[int, Ptr], size: int,
               pid: Optional[int] = None) -> Generator[Any, Any, bool]:
        """
        Compare two regions of guest memory for equality.

        Compares two regions of guest memory for equality.

        Parameters
        ----------
        addr1 : int or Ptr
            First address.
        addr2 : int or Ptr
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
        if isinstance(addr1, Ptr):
            addr1 = addr1.address
        if isinstance(addr2, Ptr):
            addr2 = addr2.address

        data1 = yield from self.read_bytes(addr1, size, pid)
        data2 = yield from self.read_bytes(addr2, size, pid)
        return data1 == data2

    def read_ptr_array(self, addr: Union[int, Ptr], pid: Optional[int] = None) -> Generator[Any, Any, List[str]]:
        """
        Read a NULL-terminated array of pointers to strings from guest memory using the portal's optimized handler.

        Uses the HYPER_OP_READ_PTR_ARRAY portal command for efficient reading.

        Parameters
        ----------
        addr : int or Ptr
            Address of the pointer array in guest memory.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        list of str
            List of strings read from the array.
        """
        if isinstance(addr, Ptr):
            addr = addr.address

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

    def copy_buf_guest(self, data: bytes) -> Generator[Any, Any, int]:
        """
        Copy a buffer into guest kernel memory and return the guest address.

        Uses the HYPER_OP_COPY_BUF_GUEST portal command to allocate and copy a buffer
        into guest kernel memory. Handles chunking if the buffer is larger than the portal region.

        Parameters
        ----------
        data : bytes
            The data to copy into guest memory.

        Returns
        -------
        int
            Guest address of the copied buffer, or 0 on failure.
        """
        rsize = self._get_rsize()
        total_len = len(data)
        view = memoryview(data)
        # Only the first chunk is copied by the kernel, but the allocation is for the full size
        first_chunk = view[:rsize]
        # Request allocation of the full buffer, but only send the first chunk
        addr = yield PortalCmd(hop.HYPER_OP_COPY_BUF_GUEST, 0, total_len, None, first_chunk.tobytes())
        if addr:
            guest_addr = addr
        else:
            self.logger.error("Failed to allocate guest buffer via COPY_BUF_GUEST")
            return 0
        # Write the rest of the data, if any, to the allocated buffer
        offset = len(first_chunk)
        if offset < total_len:
            # Write remaining data to guest buffer at guest_addr + offset
            yield from self.write_bytes(guest_addr + offset, view[offset:], None)
        return guest_addr

    def write_deref(self, ptr: Ptr, value: Any, pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Write a Python value or dictionary directly to the memory address pointed 
        to by a dwarffi Ptr. Automatically handles size, endianness, padding, 
        and nested struct serialization via dwarffi's type system.

        Parameters
        ----------
        ptr : Ptr
            A dwarffi pointer object pointing to the destination address.
        value : Any
            The value to write. Can be a primitive (int, bytes) or a dict 
            for deep struct initialization.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int
            Number of bytes written.
        """
        if not isinstance(ptr, Ptr):
            raise TypeError("write_deref requires a dwarffi.Ptr object.")

        # Extract the C-type name that the pointer points to
        target_type_name = ptr.points_to_type_name
        if not target_type_name:
            raise ValueError(f"Could not determine the target type for pointer: {ptr}")

        try:
            # Delegate all packing, alignment, and endianness logic to dwarffi.
            # ffi.new allocates a local, detached instance of the target type,
            # populating it with the provided value (primitive or nested dict).
            dummy_instance = plugins.kffi.ffi.new(target_type_name, init=value)
            packed_bytes = bytes(dummy_instance)
        except Exception as e:
            self.logger.error(f"Failed to serialize type {target_type_name}: {e}")
            raise

        # Write the packed bytes directly to the physical/virtual address
        yield from self.write_bytes(ptr.address, packed_bytes, pid)
        return len(packed_bytes)
    
    def write(self, addr: Union[int, Ptr], data: Any, size: Optional[int] = None, 
              pid: Optional[int] = None) -> Generator[Any, Any, int]:
        """
        Smart dispatcher for memory writes. Examines the address type and data type 
        to automatically select the correct write method.

        Parameters
        ----------
        addr : int or Ptr
            The destination address or a dwarffi Ptr object.
        data : Any
            The data to write (bytes, str, int, list, or dict/object for Ptrs).
        size : int, optional
            Explicit size override for integer writes.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        int
            Number of bytes written.
        """
        # 1. Data-Type Driven Write (For raw int addresses or explicit buffers)
        # If the payload is bytes or str, the user explicitly wants a buffer write, 
        # which overrides dwarffi's single-element pointer sizing.
        if isinstance(data, bytes):
            return (yield from self.write_bytes(addr, data, pid))
            
        elif isinstance(data, str):
            return (yield from self.write_str(addr, data, pid=pid))
            
        # 2. Pointer-Driven Write (Deep Structs / Primitives)
        if isinstance(addr, Ptr):
            return (yield from self.write_deref(addr, data, pid))
            
        # 3. Primitive Fallbacks
        elif isinstance(data, int):
            if size == 1:
                return (yield from self.write_byte(addr, data, pid))
            elif size == 2:
                return (yield from self.write_word(addr, data, pid))
            elif size == 8:
                return (yield from self.write_long(addr, data, pid))
            elif size == 4:
                return (yield from self.write_int(addr, data, pid))
            else:
                # Default to the architecture's native pointer size
                return (yield from self.write_ptr(addr, data, pid))
                
        elif isinstance(data, list):
            # Heuristic: assume a list of integers
            return (yield from self.write_int_array(addr, data, pid))
            
        else:
            raise TypeError(f"Cannot dispatch write for unsupported data type: {type(data)}")

    def read(self, addr: Union[int, Ptr], size: Optional[int] = None, 
             fmt: Union[type, str, None] = None, pid: Optional[int] = None) -> Generator[Any, Any, Any]:
        """
        Smart dispatcher for memory reads. Automatically infers sizes and types
        if a dwarffi Ptr is provided.

        Parameters
        ----------
        addr : int or Ptr
            The source address or a dwarffi Ptr object.
        size : int, optional
            Number of bytes (or elements) to read. Can be inferred from Ptr.
        fmt : type or str, optional
            The requested return format (bytes, str, int, list, 'ptr'). Default is bytes.
        pid : int, optional
            Process ID for context.

        Returns
        -------
        Any
            The read data in the requested format.
        """
        actual_fmt = fmt
        
        # 1. Infer size from Ptr using kffi's type system
        if isinstance(addr, Ptr) and size is None:
            # Resolve the type name through the DWARF-backed kffi
            target_type = plugins.kffi.ffi.get_type(addr.points_to_type_name)
            if target_type and hasattr(target_type, 'size'):
                size = target_type.size

        # 2. Only attempt to infer format if 'fmt' is None
        if isinstance(addr, Ptr) and actual_fmt is None:
            target_info = addr.points_to_type_info
            if target_info:
                kind = target_info.get("kind")
                name = target_info.get("name", "")
                if kind == "base":
                    if "char" in name: 
                        actual_fmt = str
                    elif any(x in name for x in ("int", "long", "size_t", "loff_t", "short")):
                        actual_fmt = int
                elif kind == "pointer":
                    actual_fmt = "ptr"

        # 3. Default to bytes for raw addresses or ambiguous cases
        if actual_fmt is None:
            actual_fmt = bytes

        # 4. Dispatch based on the determined format
        if actual_fmt is bytes or actual_fmt == "bytes":
            if size is None: 
                raise ValueError("Size required for bytes read.")
            return (yield from self.read_bytes(addr, size, pid))
        elif actual_fmt is str or actual_fmt == "str":
            return (yield from self.read_str(addr, pid))
        elif actual_fmt is int or actual_fmt == "int":
            if size == 1:
                return (yield from self.read_byte(addr, pid))
            if size == 2:
                return (yield from self.read_word(addr, pid))
            if size == 8:
                return (yield from self.read_long(addr, pid))
            if size == 4: 
                return (yield from self.read_int(addr, pid))
            return (yield from self.read_ptr(addr, pid))
        elif actual_fmt == "ptr":
            return (yield from self.read_ptr(addr, pid))
        elif actual_fmt is list or actual_fmt == "list":
            if size is None: 
                raise ValueError("Count required for list read.")
            return (yield from self.read_int_array(addr, size, pid))
        raise ValueError(f"Unknown read format: {actual_fmt}")