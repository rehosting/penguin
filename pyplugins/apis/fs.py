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

import posixpath

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


# Synthetic (VFS-backed) filesystem roots whose files are generated on demand:
# they commonly report st_size 0 and only yield data through sequential reads,
# so a plain offset+size read can fail on them even though the path exists and
# the guest itself can cat it.
#
# Roots, matched on a path BOUNDARY. A bare startswith() sent /system/bin/sh and
# /sysroot/etc/passwd down the synthetic path -- and /system is everywhere in
# Android-derived firmware. "/debugfs" is gone (it was never a real mount point)
# and "/sys/kernel/debug" with it, being under /sys already.
_SYNTHETIC_ROOTS = ("/proc", "/sys")

# The portal path field. Longer paths were silently truncated to fit, which does
# not fail -- it opens a DIFFERENT file and returns its contents as though they
# were the requested file's.
_PATH_MAX = 255

# read_file_seq walks a file it cannot stat, so the loop needs a bound that does
# not depend on the driver behaving. At a 4 KB chunk this is 64 MB -- far past any
# real synthetic file (the largest seen is /proc/kallsyms at ~4 MB, ~1000 reads),
# so reaching it means a driver that never reports EOF rather than a big file.
# Every iteration is a guest round trip, so an unbounded loop is not merely slow,
# it is a hang.
_MAX_SEQ_READS = 16384

# The same bound for the STATELESS full-file read, which had none at all. A
# read_file(path) with no size stops when a read comes back empty, so a file
# that never ends -- /dev/zero, /dev/urandom, a growing log, a modelled
# pseudofile that regenerates per read -- span forever. At a 4 KB chunk this is
# ~66 MB, past any firmware file worth pulling through a hypercall one page at
# a time.
_MAX_STATELESS_READS = 16384


def _is_synthetic(fname: str) -> bool:
    """True if ``fname`` is under a synthetic-filesystem root.

    Normalized first so that ``//proc/x`` and ``/etc/../proc/x`` -- the same
    file as ``/proc/x`` -- take the same code path as it does. They previously
    routed to the stateless op while ``/proc/x`` routed to the sequential one,
    so on a modern kernel the same file worked or EINVAL'd depending purely on
    how the caller spelled it.
    """
    norm = posixpath.normpath(fname)
    # POSIX leaves a leading "//" implementation-defined and normpath preserves
    # it, so "//proc/x" stayed un-normalized and routed differently from
    # "/proc/x" -- the same file, two code paths, one of which EINVALs on 6.13.
    if norm.startswith("//"):
        norm = "/" + norm.lstrip("/")
    return any(norm == r or norm.startswith(r + "/") for r in _SYNTHETIC_ROOTS)


def _encode_path(fname: str) -> bytes:
    """Path -> NUL-terminated portal bytes, refusing what cannot be sent whole.

    Both failure modes here used to be silent: an over-long path was truncated
    (reading a different file) and a non-latin-1 path raised a bare
    UnicodeEncodeError out of the middle of a read, which callers catching
    OSError never saw.
    """
    try:
        raw = fname.encode('latin-1')
    except UnicodeEncodeError as e:
        raise PortalFileError(
            f"path {fname!r} is not encodable for the portal path field "
            f"(latin-1): {e}") from e
    if len(raw) > _PATH_MAX:
        raise PortalFileError(
            f"path is {len(raw)} bytes, over the portal limit of {_PATH_MAX}; "
            f"refusing to truncate it because the truncated path names a "
            f"different file: {fname!r}")
    return raw + b'\0'


def _encode_data(data) -> bytes:
    """Bytes for the portal, or a PortalFileError explaining why not.

    A str that latin-1 cannot carry used to raise a bare UnicodeEncodeError from
    the middle of write_file, which reads as a bug in the plugin rather than as
    a rejected argument.
    """
    if isinstance(data, bytes):
        return data
    try:
        return data.encode('latin-1')
    except UnicodeEncodeError as e:
        raise PortalFileError(
            f"data is not encodable for the portal (latin-1): {e}. Encode it "
            f"yourself and pass bytes if you want a specific encoding.") from e


def _encode_arg(value, what: str) -> bytes:
    """Encode one NUL-terminated field of the exec blob.

    The blob is a flat NUL-separated buffer, so an embedded NUL does not travel
    as data -- it ends the field early and turns the remainder into the NEXT
    field. argv=["sh", "-c", "echo hi\0; rm -rf /"] therefore passes "echo hi"
    and then a separate argument, silently, and the exec still reports success.
    Anything assembled from config or guest-derived strings can have arguments
    appended to it this way, so the NUL is rejected rather than dropped.
    """
    try:
        raw = value.encode('latin-1')
    except UnicodeEncodeError as e:
        raise PortalFileError(
            f"{what} {value!r} is not encodable for the portal "
            f"(latin-1): {e}") from e
    if b'\0' in raw:
        raise PortalFileError(
            f"{what} {value!r} contains a NUL byte. The exec blob is "
            f"NUL-separated, so this would not pass through as data -- it would "
            f"end the field early and turn the rest into another argument.")
    return raw + b'\0'


# Just the handful worth naming; anything else prints as a bare number.
# EBADF/EBUSY/ENFILE/EAGAIN all come from the driver's handle table or its
# non-blocking open rather than from the file, and each means something the
# caller can act on -- so they must not print as bare numbers.
_ERRNO_NAMES = {2: "ENOENT", 13: "EACCES", 21: "EISDIR", 22: "EINVAL",
                5: "EIO", 1: "EPERM", 12: "ENOMEM", 40: "ELOOP",
                9: "EBADF", 16: "EBUSY", 23: "ENFILE", 11: "EAGAIN"}

# Errno -> what the caller should do about it. These are the answers that used
# to require reading portal_vfs.c.
_ERRNO_HINTS = {
    9: (" -- EBADF is the driver's handle table, not the file: the handle was "
        "never valid, was already closed, or was reclaimed because the host "
        "leaked 16 handles. It is deliberately distinct from EINVAL, which is "
        "what the kernel's own read path returns for a file it will not serve."),
    16: (" -- EBUSY means another read is in flight on this same handle. A "
         "handle is single-reader by design (two readers would interleave "
         "chunks of one seq_file and corrupt both), so retry rather than "
         "treating this as a property of the file."),
    23: (" -- ENFILE means all of the driver's 16 handle slots have a read in "
         "flight, so none could be reclaimed. Transient: retry. If it persists, "
         "some caller is holding handles across a yield it never returns from."),
    11: (" -- EAGAIN: the file would block and the driver opens O_NONBLOCK on "
         "purpose (a FIFO with no writer, /proc/kmsg with an empty buffer). "
         "This is a file that has no data right now, not an unreadable one; "
         "before O_NONBLOCK it hung the portal instead of telling you."),
}
_FS_MAGIC_NAMES = {0x9fa0: "procfs", 0x62656572: "sysfs", 0x64626720: "debugfs",
                   0x1cd1: "devpts", 0x01021994: "tmpfs"}


def _errno_name(n: int) -> str:
    return _ERRNO_NAMES.get(n, f"errno {n}")


def _errno_hint(n: int) -> str:
    return _ERRNO_HINTS.get(n, "")


def _fs_name(magic: int) -> str:
    return _FS_MAGIC_NAMES.get(magic, f"fs magic {magic:#x}")


def _read_fail_hint(fname: str) -> str:
    if _is_synthetic(fname):
        return (f" -- {fname} is on a synthetic (VFS) filesystem whose files are "
                "generated on demand. For reads, a multi-chunk stateless read "
                "cannot handle these coherently; use read_file_seq (igloo_driver "
                "vfs_* ops), which holds the file open. Note that on kernels from "
                "~5.10 some of these paths (/proc/<pid>/*, /proc/net/*, and any "
                "MODELLED pseudofile whose model implements read() rather than "
                "read_iter()) are refused by __kernel_read for "
                "BOTH read ops because of their f_op, even though the guest "
                "itself can read them -- so a failure here is not necessarily "
                "fixed by switching ops. There is no sequential WRITE op at all. "
                "Either way, do not read this as an empty file.")
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
    _warned_no_vfs = False

    def _max_seq_reads(self) -> int:
        """Indirection so a test can lower the bound; 16384 reads cannot be
        driven in a test at any sane cost."""
        return _MAX_SEQ_READS

    def _vfs_supported(self) -> bool:
        """True when the pinned igloo_driver carries the vfs_* ops.

        Checked rather than assumed: penguin can run against an older driver
        release, and an AttributeError deep inside a read is a much worse
        failure than falling back to the stateless op.
        """
        return getattr(hop, "HYPER_OP_VFS_OPEN", None) is not None

    def read_file_seq(self, fname: str, size: int = None,
                      offset: int = 0) -> bytes:
        """Read a file by holding it open across reads (vfs_open/read/close).

        procfs, sysfs and debugfs generate their contents at open time and serve
        them through sequential reads of that one open file, and report st_size
        0. The stateless "open, seek, read, close" op re-generates the content
        per chunk, so a *multi-chunk* read of such a file cannot produce a
        coherent result. This holds one file open, so it can.

        What this does NOT fix, measured rather than assumed: whether a
        synthetic file is readable from the driver at all is decided by its
        ``f_op``, not by statefulness. On kernels from ~5.10, ``__kernel_read``
        refuses any file that has ``->read`` set or lacks ``->read_iter``
        (``warn_unsupported`` -> EINVAL), which rules out ``/proc/<pid>/*`` and
        ``/proc/net/*`` for *both* ops -- while ``/proc/version``,
        ``/proc/mounts`` and sysfs read fine through either. On 4.10 there is no
        such guard and the stateless op reads all of them. So this op is the
        right shape for synthetic files, but it is not what makes them readable;
        see igloo_driver's portal_vfs.c header for the partition.

        Raises :class:`PortalFileError` carrying the guest-side errno when the
        open or a read fails, so the caller learns *why* instead of receiving an
        empty buffer.
        """
        if not self._vfs_supported():
            raise PortalFileError(
                f"read_file_seq({fname!r}) needs the igloo_driver vfs_* portal "
                "ops, which the pinned driver does not provide; bump the "
                "igloo-driver pin (flake.nix)")

        if size is not None and size < 0:
            raise PortalFileError(f"read_file_seq({fname!r}): size={size} is "
                                  "negative")
        if size == 0:
            return b""
        if offset < 0:
            raise PortalFileError(f"read_file_seq({fname!r}): offset={offset} "
                                  "is negative")

        fname_bytes = _encode_path(fname)
        raw = yield PortalCmd(hop.HYPER_OP_VFS_OPEN, 0, 0, None, fname_bytes)
        if not raw:
            raise PortalFileError(
                f"vfs_open({fname!r}) got no response from the guest")

        res = kffi.from_buffer("vfs_open_result", raw)
        err, handle = int(res.error), int(res.handle)
        if err:
            raise PortalFileError(
                f"vfs_open({fname!r}) failed: errno {-err} "
                f"({_errno_name(-err)}){_errno_hint(-err)}"
                f"{_read_fail_hint(fname)}")
        if not handle:
            # Reported success and gave us nothing to read from. Said plainly
            # rather than dressed up as "errno 0", which is what it used to
            # print -- along with a synthetic-filesystem hint that pointed at
            # the wrong thing entirely for what is a driver bug.
            raise PortalFileError(
                f"vfs_open({fname!r}) reported success but returned handle 0; "
                f"the driver's open path is broken")

        fs_magic = int(res.fs_magic)
        self.logger.debug(
            f"vfs_open({fname}) -> handle {handle} on {_fs_name(fs_magic)}")

        rsize = self.plugins.portal.regions_size
        hdr = kffi.sizeof("vfs_read_result")
        chunk = max(1, rsize - hdr - 1)
        # Accumulated in a list, not with `out += got`. Concatenating bytes in a
        # loop copies the whole buffer every iteration, so a 4 MB file over
        # ~1000 chunks moved gigabytes for no reason -- slow enough that the
        # loop bound below looked like a hang when it was only quadratic.
        parts = []
        out_len = 0
        # A seq_file has no seek: the only way to reach an offset is to read and
        # discard up to it. Done here rather than rejected because read_file
        # accepts an offset, and silently ignoring it -- which is what happened
        # before -- returns the wrong bytes with no error at all.
        skip = offset
        try:
            for _ in range(self._max_seq_reads()):
                # Discarded bytes do not count toward `size`, so a capped read
                # still has to pull `skip` extra bytes off the front.
                want = (chunk if size is None
                        else min(chunk, skip + size - out_len))
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
                        f"vfs_read({fname!r}) failed after {out_len} bytes: "
                        f"errno {-rerr} ({_errno_name(-rerr)})"
                        f"{_errno_hint(-rerr)}")
                if nbytes:
                    got = bytes(raw[hdr:hdr + nbytes])
                    if skip:
                        drop = min(skip, len(got))
                        got, skip = got[drop:], skip - drop
                    parts.append(got)
                    out_len += len(got)
                # eof is a successful read of nothing: stop, do not error.
                if eof or nbytes == 0:
                    break
            else:
                raise PortalFileError(
                    f"vfs_read({fname!r}) never reported EOF after "
                    f"{self._max_seq_reads()} reads ({out_len} bytes); refusing "
                    f"to loop further")
        except GeneratorExit:
            # A PortalCmd cannot be yielded while the generator is being closed,
            # so the handle cannot be returned here. Warn instead of raising
            # RuntimeError("generator ignored GeneratorExit"), which is what
            # happened before and lost the real story: the caller abandoned the
            # read and the driver now has to reclaim the slot.
            self.logger.warning(
                f"read_file_seq({fname}) abandoned mid-read; handle {handle} "
                "cannot be closed from here and the driver will have to reclaim "
                "the slot")
            raise
        except BaseException:
            # Hand the handle back on the error paths too: the table is 16 slots
            # and a leak forces the driver to reclaim the oldest, breaking an
            # unrelated reader far from the cause.
            yield PortalCmd(hop.HYPER_OP_VFS_CLOSE, handle, 0, None)
            raise
        yield PortalCmd(hop.HYPER_OP_VFS_CLOSE, handle, 0, None)
        return b"".join(parts)

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
        if size is not None and size < 0:
            raise PortalFileError(f"read_file({fname!r}): size={size} is negative")
        if size == 0:
            # Asked for nothing, return nothing. Passed through, the driver reads
            # requested_size == 0 as "as much as fits" and hands back a whole
            # chunk -- the opposite of what the caller asked for.
            return b""
        if offset < 0:
            raise PortalFileError(f"read_file({fname!r}): offset={offset} is "
                                  "negative")

        if _is_synthetic(fname):
            if self._vfs_supported():
                # offset is forwarded, not dropped. It used to be silently
                # discarded here, so a caller asking for offset N got the bytes
                # at 0 and no indication anything had been ignored.
                data = yield from self.read_file_seq(
                    fname, size=size, offset=offset)
                return data
            # Falling back is not free: on kernels from ~5.10 the stateless op
            # cannot read large parts of procfs at all, so say so once rather
            # than letting the caller silently receive nothing.
            if not self._warned_no_vfs:
                self._warned_no_vfs = True
                self.logger.warning(
                    "the pinned igloo_driver has no vfs_* ops, so synthetic "
                    "reads (%s) fall back to the stateless op, which cannot "
                    "read /proc/<pid>/* or /proc/net/* on kernels from ~5.10. "
                    "Bump the igloo-driver pin.", fname)

        fname_bytes = _encode_path(fname)

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
            parts = []
            got_any = False
            current_offset = offset
            bytes_remaining = size

            while bytes_remaining > 0:
                chunk_size = min(rsize - 1, bytes_remaining)
                self.logger.debug(
                    f"Reading file chunk: {fname}, offset={current_offset}, size={chunk_size}")

                chunk = yield PortalCmd(hop.HYPER_OP_READ_FILE, current_offset, chunk_size, None, fname_bytes)

                if not chunk:
                    if not got_any and current_offset == offset:
                        # Nothing at all came back on the FIRST read. The
                        # stateless op reports EOF as a failure, so a genuinely
                        # empty file is indistinguishable from a failed read
                        # here -- see the note on the size=None path, which
                        # returns b"" for the same case. Raising for one and
                        # returning b"" for the other gave the same file two
                        # different behaviours depending on `size`, so this
                        # branch now matches: empty, with a warning.
                        self.logger.warning(
                            f"read_file({fname}) returned no data at offset "
                            f"{current_offset}; treating as empty. The stateless "
                            f"op cannot distinguish EOF from failure"
                            f"{_read_fail_hint(fname)}")
                        return b""
                    self.logger.debug(
                        f"No data returned at offset {current_offset}, stopping read")
                    break

                parts.append(chunk)
                got_any = True
                current_offset += len(chunk)
                bytes_remaining -= len(chunk)

                # A SHORT read is not EOF. This op is a pread, and a pread on a
                # chardev, a pipe or anything with a short-read habit returns
                # less than asked for routinely. Treating that as end-of-file
                # truncated the read silently -- the caller got a prefix with no
                # indication the rest existed. Termination comes from an empty
                # read instead, which costs one extra round trip on the last
                # chunk and is the only signal that actually means "no more".

            return b"".join(parts)

        # If size is not specified, read the entire file in chunks
        parts = []
        total = 0
        current_offset = offset
        chunk_size = rsize - 1

        # Bounded. Without a bound this loop only ended when a read came back
        # empty, so a file that never ends -- /dev/zero, /dev/urandom, a growing
        # log -- span forever, one guest round trip at a time, with no marker and
        # nothing to distinguish it from the emulation having wedged.
        for _ in range(_MAX_STATELESS_READS):
            self.logger.debug(
                f"Reading file chunk: {fname}, offset={current_offset}, size={chunk_size}")

            chunk = yield PortalCmd(hop.HYPER_OP_READ_FILE, current_offset, chunk_size, None, fname_bytes)

            if not chunk:
                self.logger.debug(
                    f"No data returned at offset {current_offset}, stopping read")
                break

            parts.append(chunk)
            total += len(chunk)
            current_offset += len(chunk)
            # Short read is not EOF here either; see the note on the sized path.
        else:
            raise PortalFileError(
                f"read_file({fname!r}) never reported EOF after "
                f"{_MAX_STATELESS_READS} reads ({total} bytes); refusing to "
                f"loop further. A file with no end (/dev/zero, /dev/urandom, a "
                f"growing log) cannot be read whole -- pass an explicit size.")

        return b"".join(parts)

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
        data = _encode_data(data)
        if offset < 0:
            # read_file validates this; write_file passed it straight to the
            # driver, which casts it to an unsigned offset and writes somewhere
            # the caller did not name.
            raise PortalFileError(
                f"write_file({fname!r}): offset={offset} is negative")

        fname_bytes = _encode_path(fname)
        rsize = self.plugins.portal.regions_size

        # Calculate the maximum data size that can fit in one region
        max_data_size = rsize - len(fname_bytes)
        if max_data_size <= 16:
            # A long path in a small region leaves no room for data. Unguarded,
            # the chunk size went negative, every slice was empty, and the write
            # returned 0 as though the guest had refused it.
            raise PortalFileError(
                f"write_file({fname!r}): the path takes {len(fname_bytes)} of "
                f"the {rsize}-byte portal region, leaving no room for data")

        # If data is small enough, do a single write
        if len(data) <= max_data_size:
            self.logger.debug(
                f"Writing {len(data)} bytes to file {fname} at offset {offset}")
            bytes_written = yield PortalCmd(hop.HYPER_OP_WRITE_FILE, offset, len(data), None, fname_bytes + data)
            if bytes_written is None:
                # The same conflation this module fixed for reads was still live
                # for writes: a refused write returned None, which a caller
                # reading it as a count sees as 0 bytes written -- i.e. as a
                # successful write of nothing.
                raise PortalFileError(
                    f"write_file({fname!r}) failed in the guest"
                    f"{_read_fail_hint(fname)}")
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

            # Everything below used to `break` and return a short count. That
            # gave one function two behaviours depending only on the size of the
            # data: a small write raised on refusal, a large one reported
            # success having written a prefix. A caller comparing the count
            # against len(data) catches it; one that does not has silently
            # truncated the file.
            if bytes_written is None:
                raise PortalFileError(
                    f"write_file({fname!r}) was refused at offset "
                    f"{current_offset} after {total_bytes} of {len(data)} bytes"
                    f"{_read_fail_hint(fname)}")
            if bytes_written > chunk_size:
                # An impossible count. Left alone, current_offset advanced by it
                # while current_pos advanced by the chunk size, so every later
                # chunk landed at the wrong offset and the total over-reported:
                # a corrupted file returned as a success.
                raise PortalFileError(
                    f"write_file({fname!r}) reported {bytes_written} bytes "
                    f"written for a {chunk_size}-byte chunk -- more bytes than "
                    f"it was given, so the offset can no longer be trusted")
            if bytes_written < chunk_size:
                raise PortalFileError(
                    f"write_file({fname!r}) wrote {total_bytes + bytes_written} "
                    f"of {len(data)} bytes and then stopped ({bytes_written} of "
                    f"a {chunk_size}-byte chunk at offset {current_offset}). The "
                    f"file now holds a prefix of what you passed.")

            total_bytes += bytes_written
            current_offset += bytes_written
            current_pos += bytes_written

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
            With ``wait=True``, the program's return code. With ``wait=False``
            (the default) the call returns as soon as the guest has been asked
            to run it, so the value only says the request was accepted -- it is
            not the program's exit status, which is not known yet.

        Raises
        ------
        PortalFileError
            If there is no program to run, an argument cannot be carried by the
            portal (non-latin-1, or containing a NUL), the request does not fit
            in one portal region, or the guest does not answer.

        Executes a program in the guest using the kernel's `call_usermodehelper` function. Optionally waits for completion.

        > **Note:** This method is generated and type-checked.
        """
        if not exe_path:
            if not argv:
                # Was `argv[0]` on a None/empty argv: TypeError: 'NoneType'
                # object is not subscriptable, thrown from inside a filesystem
                # API, which reads as a bug in the plugin rather than as a
                # missing argument.
                raise PortalFileError(
                    "exec_program needs either exe_path or a non-empty argv; "
                    f"got exe_path={exe_path!r}, argv={argv!r}")
            exe_path = argv[0]

        self.logger.debug(
            f"exec_program called: exe_path={exe_path}, wait={wait}")

        # Prepare the data buffer using a list of bytes objects
        data_parts = []

        # Add executable path (null-terminated)
        data_parts.append(_encode_arg(exe_path, "exe_path"))

        # Add argv (null-separated, double-null terminated)
        if argv:
            for i, arg in enumerate(argv):
                data_parts.append(_encode_arg(arg, f"argv[{i}]"))
        data_parts.append(b'\0')  # Double null termination

        # Add environment variables (null-separated, double-null terminated)
        if envp:
            for key, value in envp.items():
                data_parts.append(_encode_arg(f"{key}={value}", f"envp[{key!r}]"))
        data_parts.append(b'\0')  # Double null termination

        data_parts.append(b'\0')  # Just null termination

        # Convert the list to a single bytes object
        data = b''.join(data_parts)

        # One portal region holds the whole blob. Overflowing it does not fail:
        # whatever falls off the end is dropped, so a long argv becomes a
        # DIFFERENT, shorter command line -- and it still executes.
        rsize = self.plugins.portal.regions_size
        if len(data) > rsize:
            raise PortalFileError(
                f"exec_program blob is {len(data)} bytes, over the "
                f"{rsize}-byte portal region; refusing to truncate it because a "
                f"truncated argv is a different command that would still run. "
                f"exe_path={exe_path!r}, {len(argv or [])} args, "
                f"{len(envp or {})} env vars")

        # Call the kernel with the prepared data
        # The wait mode is passed in header.addr field
        result = yield PortalCmd(hop.HYPER_OP_EXEC, wait, len(data), None, data)

        self.logger.debug(f"exec_program result: {result}")
        if result is None:
            # None is not a return code. `if not result` reads it as success and
            # `result == 0` reads it as failure, so neither caller learns that
            # the exec did not happen -- the same conflation fixed for reads and
            # then for writes.
            raise PortalFileError(
                f"exec_program({exe_path!r}) got no response from the guest, so "
                f"whether the program ran is unknown")
        return result
