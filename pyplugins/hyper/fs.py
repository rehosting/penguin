"""
FS plugin for user-space file and program operations via the hypervisor portal.
Provides methods for reading, writing, and executing files in the guest system.
"""

from penguin import Plugin
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd

class FS(Plugin):
    """
    FS plugin for interacting with files and executing programs in the guest via the hypervisor portal.
    """
    def read_file(self, fname, size=None, offset=0):
        """
        Read a file from a specified offset with optional size limit.
        If size is not specified, reads the entire file from the given offset.

        Args:
            fname (str): Path to the file
            size (int, optional): Size limit. If None, reads entire file
            offset (int, optional): Offset in bytes where to start reading (default: 0)

        Returns:
            bytes: The file data as bytes
        """
        fname_bytes = fname.encode('latin-1')[:255] + b'\0'

        rsize = self.plugins.portal.regions_size

        # Handle the case where we want to read a specific amount
        if size is not None:
            # If size is small enough, do a single read
            if size <= rsize - 1:
                data = yield PortalCmd(hop.HYPER_OP_READ_FILE, offset, size, None, fname_bytes)
                return data

            # For larger sizes, read in chunks
            all_data = b""
            current_offset = offset
            bytes_remaining = size

            while bytes_remaining > 0:
                chunk_size = min(rsize - 1, bytes_remaining)
                self.logger.debug(
                    f"Reading file chunk: {fname}, offset={current_offset}, size={chunk_size}")

                chunk = yield PortalCmd(hop.HYPER_OP_READ_FILE, current_offset, chunk_size, None, fname_bytes)

                if not chunk:
                    self.logger.debug(
                        f"No data returned at offset {current_offset}, stopping read")
                    break

                all_data += chunk
                current_offset += len(chunk)
                bytes_remaining -= len(chunk)

                # If we got less data than requested, we've reached EOF
                if len(chunk) < chunk_size:
                    self.logger.debug(
                        f"Reached EOF at offset {current_offset} (requested {chunk_size}, got {len(chunk)})")
                    break

            return all_data

        # If size is not specified, read the entire file in chunks
        all_data = b""
        current_offset = offset
        chunk_size = rsize - 1

        while True:
            self.logger.debug(
                f"Reading file chunk: {fname}, offset={current_offset}, size={chunk_size}")

            chunk = yield PortalCmd(hop.HYPER_OP_READ_FILE, current_offset, chunk_size, None, fname_bytes)

            if not chunk:
                self.logger.debug(
                    f"No data returned at offset {current_offset}, stopping read")
                break

            all_data += chunk
            current_offset += len(chunk)

            # If we got less data than requested, we've reached EOF
            if len(chunk) < chunk_size:
                self.logger.debug(
                    f"Reached EOF at offset {current_offset} (requested {chunk_size}, got {len(chunk)})")
                break

        return all_data

    def write_file(self, fname, data, offset=0):
        """
        Write data to a file at a specified offset.
        Handles chunking for large data automatically.

        Args:
            fname (str): Path to the file
            data (bytes or str): Data to write to the file
            offset (int, optional): Offset in bytes where to start writing (default: 0)

        Returns:
            int: Number of bytes written
        """
        # Convert string data to bytes if necessary
        if isinstance(data, str):
            data = data.encode('latin-1')

        fname_bytes = fname.encode('latin-1')[:255] + b'\0'
        rsize = self.plugins.portal.regions_size

        # Calculate the maximum data size that can fit in one region
        max_data_size = rsize - len(fname_bytes)

        # If data is small enough, do a single write
        if len(data) <= max_data_size:
            self.logger.debug(
                f"Writing {len(data)} bytes to file {fname} at offset {offset}")
            bytes_written = yield PortalCmd(hop.HYPER_OP_WRITE_FILE, offset, len(data), None, fname_bytes + data)
            return bytes_written

        # For larger files, write in chunks
        total_bytes = 0
        current_offset = offset
        current_pos = 0

        while current_pos < len(data):
            # Calculate maximum chunk size to fit in memory region, considering filename length
            max_chunk = max_data_size - 16  # Add safety margin
            chunk_size = min(max_chunk, len(data) - current_pos)

            self.logger.debug(
                f"Writing file chunk: {fname}, offset={current_offset}, size={chunk_size}")
            chunk = data[current_pos:current_pos + chunk_size]

            bytes_written = yield PortalCmd(hop.HYPER_OP_WRITE_FILE, current_offset, len(chunk), None, fname_bytes + chunk)

            if not bytes_written:
                self.logger.error(
                    f"Failed to write chunk at offset {current_offset}")
                break

            total_bytes += bytes_written
            current_offset += bytes_written
            current_pos += chunk_size

            # If we couldn't write the full chunk, stop
            if bytes_written < chunk_size:
                self.logger.debug(
                    f"Partial write: wrote {bytes_written} of {chunk_size} bytes")
                break

        self.logger.debug(f"Total bytes written to file: {total_bytes}")
        return total_bytes

    def exec_program(self, exe_path=None, argv=None, envp=None, wait=False):
        """
        Execute a program using the kernel's call_usermodehelper function.

        Args:
            exe_path (str, optional): Path to executable
            argv (list, optional): List of arguments (including program name as first arg)
            envp (dict, optional): Dictionary of environment variables
            wait (bool, optional): Whether to wait for program to complete

        Returns:
            int: Return code from execution
        """

        if not exe_path:
            exe_path = argv[0]

        self.logger.debug(
            f"exec_program called: exe_path={exe_path}, wait={wait}")

        # Prepare the data buffer using a list of bytes objects
        data_parts = []

        # Add executable path (null-terminated)
        data_parts.append(exe_path.encode('latin-1') + b'\0')

        # Add argv (null-separated, double-null terminated)
        if argv:
            for arg in argv:
                data_parts.append(arg.encode('latin-1') + b'\0')
        data_parts.append(b'\0')  # Double null termination

        # Add environment variables (null-separated, double-null terminated)
        if envp:
            for key, value in envp.items():
                env_string = f"{key}={value}"
                data_parts.append(env_string.encode('latin-1') + b'\0')
        data_parts.append(b'\0')  # Double null termination

        data_parts.append(b'\0')  # Just null termination

        # Convert the list to a single bytes object
        data = b''.join(data_parts)

        # Call the kernel with the prepared data
        # The wait mode is passed in header.addr field
        result = yield PortalCmd(hop.HYPER_OP_EXEC, wait, len(data), None, data)

        self.logger.debug(f"exec_program result: {result}")
        return result
