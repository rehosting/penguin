"""
Memory access plugin for reading and writing guest memory via the hypervisor portal.
Provides utilities for reading/writing bytes, integers, pointers, and strings.
"""

from penguin import Plugin
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd
from struct import pack, unpack

class Mem(Plugin):
    """
    Plugin for guest memory access and manipulation via the hypervisor portal.
    """
    def __init__(self):
        """
        Initialize the Mem plugin, setting endianness and architecture-specific options.
        """
        self.endian_format = '<' if self.panda.endianness == 'little' else '>'
        self.try_panda = True if self.panda.arch != "riscv64" else False
    
    def write_bytes(self, addr, data, pid=None):
        """
        Write bytes to guest memory at a specified address, handling chunking for large data.

        Args:
            addr (int): Address to write to
            data (bytes): Data to write
            pid (int, optional): Process ID for context (default: None)

        Returns:
            int: Number of bytes written
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

    def read_bytes(self, addr, size, pid=None):
        """
        Read bytes from guest memory at a specified address, handling chunking for large reads.

        Args:
            addr (int): Address to read from
            size (int): Number of bytes to read
            pid (int, optional): Process ID for context (default: None)

        Returns:
            bytes: Data read from memory
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

    def read_str(self, addr, pid=None):
        """
        Read a null-terminated string from guest memory at a specified address.

        Args:
            addr (int): Address to read from
            pid (int, optional): Process ID for context (default: None)

        Returns:
            str: String read from memory
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

    def read_int(self, addr, pid=None):
        """
        Read a 4-byte integer from guest memory at a specified address.

        Args:
            addr (int): Address to read from
            pid (int, optional): Process ID for context (default: None)

        Returns:
            int or None: Integer value read, or None on failure
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

    def read_long(self, addr, pid=None):
        """
        Read an 8-byte long integer from guest memory at a specified address.

        Args:
            addr (int): Address to read from
            pid (int, optional): Process ID for context (default: None)

        Returns:
            int or None: Long value read, or None on failure
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

    def read_ptr(self, addr, pid=None):
        """
        Read a pointer-sized value from guest memory at a specified address.

        Args:
            addr (int): Address to read from
            pid (int, optional): Process ID for context (default: None)

        Returns:
            int: Pointer value read
        """
        if self.panda.bits == 32:
            ptr = yield from self.read_int(addr, pid)
        elif self.panda.bits == 64:
            ptr = yield from self.read_long(addr, pid)
        else:
            raise Exception("read_ptr: Could not determine bits")
        return ptr

    def write_int(self, addr, value, pid=None):
        """
        Write a 4-byte integer to guest memory at a specified address.

        Args:
            addr (int): Address to write to
            value (int): Integer value to write
            pid (int, optional): Process ID for context (default: None)

        Returns:
            int: Number of bytes written
        """
        self.logger.debug(f"write_int called: addr={addr}, value={value}")
        # Pack the integer according to system endianness
        data = pack(f"{self.endian_format}I", value)
        bytes_written = yield from self.write_bytes(addr, data, pid)
        self.logger.debug(f"Integer written successfully: {value}")
        return bytes_written

    def write_long(self, addr, value, pid=None):
        """
        Write an 8-byte long integer to guest memory at a specified address.

        Args:
            addr (int): Address to write to
            value (int): Long value to write
            pid (int, optional): Process ID for context (default: None)

        Returns:
            int: Number of bytes written
        """
        self.logger.debug(f"write_long called: addr={addr}, value={value}")
        # Pack the long according to system endianness
        data = pack(f"{self.endian_format}Q", value)
        bytes_written = yield from self.write_bytes(addr, data, pid)
        self.logger.debug(f"Long written successfully: {value}")
        return bytes_written

    def write_ptr(self, addr, value, pid=None):
        """
        Write a pointer-sized value to guest memory at a specified address.

        Args:
            addr (int): Address to write to
            value (int): Pointer value to write
            pid (int, optional): Process ID for context (default: None)
        """
        if self.panda.bits == 32:
            yield from self.write_int(addr, value, pid)
        elif self.panda.bits == 64:
            yield from self.write_long(addr, value, pid)
        else:
            raise Exception("read_ptr: Could not determine bits")

    def write_str(self, addr, string, null_terminate=True, pid=None):
        """
        Write a string to guest memory at a specified address, optionally null-terminated.

        Args:
            addr (int): Address to write to
            string (str or bytes): String to write
            null_terminate (bool, optional): Whether to append a null terminator (default: True)
            pid (int, optional): Process ID for context (default: None)

        Returns:
            int: Number of bytes written
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
    
    def read_ptrlist(self, addr, length, pid=None):
        """
        Read a list of pointer values from guest memory.

        Args:
            addr (int): Address to start reading from
            length (int): Maximum number of pointers to read
            pid (int, optional): Process ID for context (default: None)

        Returns:
            list: List of pointer values
        """
        ptrs = []
        ptrsize = int(self.panda.bits/8)
        for start in range(length):
            ptr = yield from self.read_ptr(addr + (start * ptrsize), pid)
            if ptr == 0:
                break
            ptrs.append(ptr)
        return ptrs

    def read_char_ptrlist(self, addr, length, pid=None):
        """
        Read a list of null-terminated strings from a list of pointers in guest memory.

        Args:
            addr (int): Address to start reading pointer list from
            length (int): Maximum number of pointers to read
            pid (int, optional): Process ID for context (default: None)

        Returns:
            list: List of strings read from memory
        """
        ptrlist = yield from self.read_ptrlist(addr, length, pid)
        vals = []
        for start in range(len(ptrlist)):
            strs = yield from self.read_str(ptrlist[start], pid)
            vals.append(strs)
        return vals
    
    def read_int_array(self, addr, count, pid=None):
        """
        Read an array of 4-byte integers from guest memory.

        Args:
            addr (int): Address to start reading from
            count (int): Number of integers to read
            pid (int, optional): Process ID for context (default: None)

        Returns:
            list: List of integers read from memory
        """
        data = yield from self.read_bytes(addr, 4 * count, pid)
        if len(data) != 4 * count:
            self.logger.error(f"Failed to read int array at addr={addr}, expected {4*count} bytes, got {len(data)}")
            return []
        return list(unpack(f"{self.endian_format}{count}I", data))

    def write_int_array(self, addr, values, pid=None):
        """
        Write an array of 4-byte integers to guest memory.

        Args:
            addr (int): Address to start writing to
            values (list): List of integers to write
            pid (int, optional): Process ID for context (default: None)

        Returns:
            int: Number of bytes written
        """
        data = pack(f"{self.endian_format}{len(values)}I", *values)
        return (yield from self.write_bytes(addr, data, pid))

    def read_utf8_str(self, addr, pid=None):
        """
        Read a null-terminated UTF-8 string from guest memory at a specified address.

        Args:
            addr (int): Address to read from
            pid (int, optional): Process ID for context (default: None)

        Returns:
            str: UTF-8 string read from memory
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

    def read_byte(self, addr, pid=None):
        """
        Read a single byte from guest memory.

        Args:
            addr (int): Address to read from
            pid (int, optional): Process ID for context (default: None)

        Returns:
            int: Byte value read (0-255), or None on failure
        """
        data = yield from self.read_bytes(addr, 1, pid)
        if len(data) != 1:
            self.logger.error(f"Failed to read byte at addr={addr}")
            return None
        return data[0]

    def write_byte(self, addr, value, pid=None):
        """
        Write a single byte to guest memory.

        Args:
            addr (int): Address to write to
            value (int): Byte value to write (0-255)
            pid (int, optional): Process ID for context (default: None)

        Returns:
            int: Number of bytes written (should be 1)
        """
        data = bytes([value & 0xFF])
        return (yield from self.write_bytes(addr, data, pid))

    def read_word(self, addr, pid=None):
        """
        Read a 2-byte word from guest memory.

        Args:
            addr (int): Address to read from
            pid (int, optional): Process ID for context (default: None)

        Returns:
            int or None: Word value read, or None on failure
        """
        data = yield from self.read_bytes(addr, 2, pid)
        if len(data) != 2:
            self.logger.error(f"Failed to read word at addr={addr}")
            return None
        return unpack(f"{self.endian_format}H", data)[0]

    def write_word(self, addr, value, pid=None):
        """
        Write a 2-byte word to guest memory.

        Args:
            addr (int): Address to write to
            value (int): Word value to write
            pid (int, optional): Process ID for context (default: None)

        Returns:
            int: Number of bytes written (should be 2)
        """
        data = pack(f"{self.endian_format}H", value)
        return (yield from self.write_bytes(addr, data, pid))

    def memset(self, addr, value, size, pid=None):
        """
        Set a region of guest memory to a specific byte value.

        Args:
            addr (int): Address to start setting
            value (int): Byte value to set (0-255)
            size (int): Number of bytes to set
            pid (int, optional): Process ID for context (default: None)

        Returns:
            int: Number of bytes written
        """
        data = bytes([value & 0xFF]) * size
        return (yield from self.write_bytes(addr, data, pid))

    def memcmp(self, addr1, addr2, size, pid=None):
        """
        Compare two regions of guest memory for equality.

        Args:
            addr1 (int): First address
            addr2 (int): Second address
            size (int): Number of bytes to compare
            pid (int, optional): Process ID for context (default: None)

        Returns:
            bool: True if memory regions are equal, False otherwise
        """
        data1 = yield from self.read_bytes(addr1, size, pid)
        data2 = yield from self.read_bytes(addr2, size, pid)
        return data1 == data2

