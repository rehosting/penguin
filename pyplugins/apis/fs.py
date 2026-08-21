"""
FS API Plugin
=============

This module provides the FS plugin for the penguin framework, enabling interaction with the guest filesystem.
It exposes methods for reading, writing, and querying files and directories in the guest, and can be used
by other plugins to perform filesystem operations.

Features
--------

- Read files from the guest filesystem.
- Write data to files in the guest.
- Execute programs in the guest environment.
- Supports chunked operations for large files.
- Abstracts guest filesystem access for analysis and automation.

Example Usage
-------------

::

    from penguin import plugins

    # Read a file from the guest
    content = yield from plugins.fs.read_file("/etc/passwd")

    # Write to a file in the guest
    yield from plugins.fs.write_file("/tmp/test.txt", "hello world")

    # Execute a program in the guest
    yield from plugins.fs.exec_program("/bin/ls", argv=["ls", "-l", "/"])
"""

from penguin import Plugin, plugins
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd

kffi = plugins.kffi


class PortalFileError(OSError):
    """A guest file operation failed in the guest, as opposed to returning no data.

    Subclasses ``OSError`` so existing ``except Exception`` / ``except OSError``
    handlers keep working, while callers that care can tell "the read did not
    happen" from "the file is empty". Before this existed, a refused read came
    back as ``None`` and was indistinguishable from an empty file -- which is
    how unreadable ``/proc`` files silently presented as "no data" instead of as
    an error.
    """


# Synthetic (VFS-backed) filesystems whose files are generated on demand: they
# commonly report st_size 0 and only yield data through sequential reads, so a
# plain offset+size read can fail on them even though the path exists and the
# guest itself can cat it. Named here purely to make the error message useful.
_SYNTHETIC_PREFIXES = ("/proc", "/sys", "/debugfs", "/sys/kernel/debug")


# Just the handful worth naming; anything else prints as a bare number.
_ERRNO_NAMES = {2: "ENOENT", 13: "EACCES", 21: "EISDIR", 22: "EINVAL",
                5: "EIO", 1: "EPERM", 12: "ENOMEM", 40: "ELOOP"}
_FS_MAGIC_NAMES = {0x9fa0: "procfs", 0x62656572: "sysfs", 0x64626720: "debugfs",
                   0x1cd1: "devpts", 0x01021994: "tmpfs"}


def _errno_name(n: int) -> str:
    return _ERRNO_NAMES.get(n, f"errno {n}")


def _fs_name(magic: int) -> str:
    return _FS_MAGIC_NAMES.get(magic, f"fs magic {magic:#x}")


def _read_fail_hint(fname: str) -> str:
    if fname.startswith(_SYNTHETIC_PREFIXES):
        return (f" -- {fname} is on a synthetic (VFS) filesystem whose files are "
                "generated on demand; these cannot be read with a stateless "
                "offset+size read even when the guest can read them itself. Use "
                "read_file_seq (igloo_driver vfs_* ops), which holds the file "
                "open across reads. Do not treat this as an empty file.")
    return ""


class FS(Plugin):
    """
    FS Plugin
    =========

    Provides methods for interacting with the guest filesystem, including reading, writing,
    and listing files and directories.

    Methods
    -------
    read_file
        Read a file from the guest filesystem.
    write_file
        Write data to a file in the guest filesystem.
    exec_program
        Execute a program in the guest environment.

    Note
    ----
    All methods are generated and their signatures and types are enforced.
    """

    # ------------------------------------------------------------------ #
    # Sequential (synthetic-filesystem) reads
    # ------------------------------------------------------------------ #
    def _vfs_supported(self) -> bool:
        """True when the pinned igloo_driver carries the vfs_* ops.

        Checked rather than assumed: penguin can run against an older driver
        release, and an AttributeError deep inside a read is a much worse
        failure than falling back to the stateless op.
        """
        return getattr(hop, "HYPER_OP_VFS_OPEN", None) is not None

    def read_file_seq(self, fname: str, size: int = None) -> bytes:
        """Read a file by holding it open across reads (vfs_open/read/close).

        This is the only way to read a synthetic filesystem correctly. procfs,
        sysfs and debugfs generate their contents at open time and serve them
        through sequential reads of that one open file, so the stateless
        "open, seek, read, close" op re-generates the content on every chunk and
        cannot produce a coherent result -- and for many such files it produces
        nothing at all.

        Raises :class:`PortalFileError` carrying the guest-side errno when the
        open or a read fails, so the caller learns *why* instead of receiving an
        empty buffer.
        """
        if not self._vfs_supported():
            raise PortalFileError(
                f"read_file_seq({fname!r}) needs the igloo_driver vfs_* portal "
                "ops, which the pinned driver does not provide; bump the "
                "igloo-driver pin (flake.nix)")

        fname_bytes = fname.encode('latin-1')[:255] + b'\0'
        raw = yield PortalCmd(hop.HYPER_OP_VFS_OPEN, 0, 0, None, fname_bytes)
        if not raw:
            raise PortalFileError(
                f"vfs_open({fname!r}) got no response from the guest")

        res = kffi.from_buffer("vfs_open_result", raw)
        err, handle = int(res.error), int(res.handle)
        if err or not handle:
            raise PortalFileError(
                f"vfs_open({fname!r}) failed: errno {-err} "
                f"({_errno_name(-err)}){_read_fail_hint(fname)}")

        fs_magic = int(res.fs_magic)
        self.logger.debug(
            f"vfs_open({fname}) -> handle {handle} on {_fs_name(fs_magic)}")

        rsize = self.plugins.portal.regions_size
        hdr = kffi.sizeof("vfs_read_result")
        chunk = max(1, rsize - hdr - 1)
        out = b""
        try:
            while True:
                want = chunk if size is None else min(chunk, size - len(out))
                if want <= 0:
                    break
                raw = yield PortalCmd(hop.HYPER_OP_VFS_READ, handle, want, None)
                if not raw:
                    raise PortalFileError(
                        f"vfs_read({fname!r}) got no response from the guest")
                r = kffi.from_buffer("vfs_read_result", raw)
                rerr, nbytes, eof = int(r.error), int(r.nbytes), int(r.eof)
                if rerr:
                    raise PortalFileError(
                        f"vfs_read({fname!r}) failed after {len(out)} bytes: "
                        f"errno {-rerr} ({_errno_name(-rerr)})")
                if nbytes:
                    out += bytes(raw[hdr:hdr + nbytes])
                # eof is a successful read of nothing: stop, do not error.
                if eof or nbytes == 0:
                    break
        finally:
            # Always hand the handle back, including on the error paths above:
            # the driver's table is 16 slots and leaking them forces it to
            # reclaim the oldest, which would break an unrelated reader.
            yield PortalCmd(hop.HYPER_OP_VFS_CLOSE, handle, 0, None)

        return out

    def read_file(self, fname: str, size: int = None,
                  offset: int = 0) -> bytes:
        """
        Read a file from the guest filesystem.

        Parameters
        ----------
        fname : str
            Path to the file in the guest.
        size : int, optional
            Size limit. If None, reads entire file.
        offset : int, optional
            Offset in bytes where to start reading (default: 0).

        Returns
        -------
        bytes
            The file data as bytes.

        Raises
        ------
        Exception
            If the file cannot be read.

        Reads the specified file from the guest filesystem, optionally limiting the read to a specific size and offset.
        If `size` is not specified, the entire file is read in chunks.

        > **Note:** This method is generated and type-checked.
        """
        # Synthetic filesystems must be read sequentially from one open file
        # (see read_file_seq). Route them there automatically so callers do not
        # each have to know which paths are special -- and so existing callers
        # reading /proc start working rather than silently getting nothing.
        if fname.startswith(_SYNTHETIC_PREFIXES) and self._vfs_supported():
            data = yield from self.read_file_seq(fname, size=size)
            return data

        fname_bytes = fname.encode('latin-1')[:255] + b'\0'

        rsize = self.plugins.portal.regions_size

        # Handle the case where we want to read a specific amount
        if size is not None:
            # If size is small enough, do a single read
            if size <= rsize - 1:
                data = yield PortalCmd(hop.HYPER_OP_READ_FILE, offset, size, None, fname_bytes)
                if data is None:
                    raise PortalFileError(
                        f"read_file({fname!r}) failed in the guest"
                        f"{_read_fail_hint(fname)}")
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
                    if not all_data:
                        # Nothing at all came back: the read failed rather than
                        # hitting EOF, so say so instead of returning b"".
                        raise PortalFileError(
                            f"read_file({fname!r}) returned no data at offset "
                            f"{current_offset}{_read_fail_hint(fname)}")
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

    def write_file(self, fname: str, data: bytes | str, offset: int = 0) -> int:
        """
        Write data to a file in the guest filesystem.

        Parameters
        ----------
        fname : str
            Path to the file in the guest.
        data : bytes or str
            Data to write to the file.
        offset : int, optional
            Offset in bytes where to start writing (default: 0).

        Returns
        -------
        int
            Number of bytes written.

        Raises
        ------
        Exception
            If the file cannot be written.

        Overwrites the file if it exists, or creates it if it does not. Handles large writes in chunks.

        > **Note:** This method is generated and type-checked.
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
            # Calculate maximum chunk size to fit in memory region, considering
            # filename length
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

    def exec_program(
        self,
        exe_path: str = None,
        argv: list[str] = None,
        envp: dict[str, str] = None,
        wait: bool = False
    ) -> int:
        """
        Execute a program in the guest environment.

        Parameters
        ----------
        exe_path : str, optional
            Path to executable. If not provided, uses `argv[0]`.
        argv : list of str, optional
            List of arguments (including program name as first arg).
        envp : dict of str, optional
            Dictionary of environment variables.
        wait : bool, optional
            Whether to wait for program to complete.

        Returns
        -------
        int
            Return code from execution.

        Raises
        ------
        Exception
            If the program cannot be executed.

        Executes a program in the guest using the kernel's `call_usermodehelper` function. Optionally waits for completion.

        > **Note:** This method is generated and type-checked.
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
