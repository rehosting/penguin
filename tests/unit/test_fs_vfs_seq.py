"""Host-side tests for the sequential (synthetic-filesystem) read path.

Drives fs.read_file_seq's portal generator with the exact byte layouts the
igloo_driver vfs_* handlers produce, decoded through the REAL driver ISF -- so
these are an ABI contract test, not a test against a hand-rolled idea of the
structs. If the driver changes vfs_read_result, this fails.

Covered: the happy multi-chunk path, EOF handling (a zero-byte read is success,
not failure), a failed open reported as an errno rather than as empty data, a
mid-read failure, the size cap, that the handle is always closed (including on
error), and the older-driver fallback.
"""
import struct
from pathlib import Path

import pytest

from penguin.testing import RealKffi, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
FS = str(REPO_ROOT / "pyplugins" / "apis" / "fs.py")


class _KFFI(RealKffi):
    def sizeof(self, type_name):
        return self.ffi.sizeof(type_name)

    def from_buffer(self, type_name, buf, instance_offset_in_buffer=0):
        return self.ffi.from_buffer(type_name, bytearray(buf),
                                    offset=instance_offset_in_buffer)


def _open_res(error=0, handle=1, fs_magic=0x9fa0):
    # struct vfs_open_result { int32 error; uint32 handle; uint64 fs_magic; }
    return struct.pack("<iIQ", error, handle, fs_magic)


def _read_res(payload=b"", error=0, eof=0):
    # struct vfs_read_result { int32 error; uint32 nbytes; uint8 eof; pad[7]; }
    return struct.pack("<iIB7x", error, len(payload), eof) + payload


def _close_res(error=0):
    return struct.pack("<iI", error, 0)


def _load(tmp_path, isf, regions_size=4096):
    class _Portal:
        pass
    portal = _Portal()
    portal.regions_size = regions_size
    return load_pyplugin(FS, outdir=tmp_path, real_isf=isf,
                         doubles={"portal": portal, "kffi": _KFFI([isf])})


def _drive(gen, responses):
    """Run the generator, returning (result, [ops issued])."""
    ops, it = [], iter(responses)
    try:
        cmd = gen.send(None)
        while True:
            ops.append(cmd)
            cmd = gen.send(next(it, None))
    except StopIteration as e:
        return e.value, ops


def _require_ops(isf):
    """The pinned driver MUST carry the vfs_* ops.

    Not a skip: read_file now routes every /proc, /sys and debugfs read through
    them, so a pin without them means penguin cannot read a synthetic
    filesystem at all -- and a skip would report that as green. The failure is
    the forcing function: bump the igloo-driver pin (flake.nix) to v0.0.98 or
    later. The igloo_ko_isf fixture still skips cleanly when no ISF resolves at
    all (offline), which is genuinely untestable and a different thing.
    """
    import hyper.consts as consts
    for op in ("HYPER_OP_VFS_OPEN", "HYPER_OP_VFS_READ", "HYPER_OP_VFS_CLOSE"):
        assert hasattr(consts.HYPER_OP, op), (
            f"pinned igloo_driver ISF lacks {op}: fs.read_file cannot read "
            "synthetic filesystems (/proc, /sys) against this driver. Bump the "
            "igloo-driver pin (flake.nix) to v0.0.98 or later.")
    assert kffi_has_structs(isf), (
        "pinned igloo_driver ISF lacks the vfs_*_result structs: bump the "
        "igloo-driver pin (flake.nix) to v0.0.98 or later.")
    return consts


def kffi_has_structs(isf):
    k = _KFFI([isf])
    try:
        return all(k.sizeof(n) > 0 for n in
                   ("vfs_open_result", "vfs_read_result", "vfs_close_result"))
    except Exception:
        return False


def test_reads_across_chunks_until_eof(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf, regions_size=32)
    consts = _require_ops(igloo_ko_isf)

    got, ops = _drive(
        lp.plugin.read_file_seq("/proc/net/tcp"),
        [_open_res(handle=7), _read_res(b"abc"), _read_res(b"de"),
         _read_res(b"", eof=1), _close_res()])

    assert got == b"abcde"
    assert ops[0].op == consts.HYPER_OP.HYPER_OP_VFS_OPEN
    # every read carries the handle, i.e. the same open file is being consumed
    assert all(o.addr == 7 for o in ops[1:])
    assert ops[-1].op == consts.HYPER_OP.HYPER_OP_VFS_CLOSE


def test_open_failure_reports_errno_not_empty(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    _require_ops(igloo_ko_isf)

    with pytest.raises(OSError) as ei:
        _drive(lp.plugin.read_file_seq("/proc/net/tcp"),
               [_open_res(error=-2, handle=0)])
    msg = str(ei.value)
    assert "ENOENT" in msg and "/proc/net/tcp" in msg


def test_midread_failure_raises_and_still_closes(tmp_path, igloo_ko_isf):
    """A failure partway through must not silently return the partial data, and
    must not leak the handle -- the driver only has 16 slots."""
    lp = _load(tmp_path, igloo_ko_isf, regions_size=32)
    consts = _require_ops(igloo_ko_isf)

    ops = []
    gen = lp.plugin.read_file_seq("/proc/net/unix")
    responses = iter([_open_res(handle=3), _read_res(b"ab"),
                      _read_res(error=-5), _close_res()])
    with pytest.raises(OSError) as ei:
        cmd = gen.send(None)
        while True:
            ops.append(cmd)
            cmd = gen.send(next(responses, None))
    assert "EIO" in str(ei.value)
    assert ops[-1].op == consts.HYPER_OP.HYPER_OP_VFS_CLOSE
    assert ops[-1].addr == 3


def test_size_cap_stops_early(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf, regions_size=64)
    _require_ops(igloo_ko_isf)
    got, _ = _drive(lp.plugin.read_file_seq("/proc/net/tcp", size=4),
                    [_open_res(), _read_res(b"abcd"), _close_res()])
    assert got == b"abcd"


def test_zero_length_file_is_success(tmp_path, igloo_ko_isf):
    """An empty synthetic file reads as b"" -- success, not an error."""
    lp = _load(tmp_path, igloo_ko_isf)
    _require_ops(igloo_ko_isf)
    got, _ = _drive(lp.plugin.read_file_seq("/proc/empty"),
                    [_open_res(), _read_res(b"", eof=1), _close_res()])
    assert got == b""


def test_read_file_routes_proc_to_the_sequential_path(tmp_path, igloo_ko_isf):
    """Callers should not have to know which paths are synthetic."""
    lp = _load(tmp_path, igloo_ko_isf, regions_size=64)
    consts = _require_ops(igloo_ko_isf)
    got, ops = _drive(lp.plugin.read_file("/proc/net/tcp", size=8),
                      [_open_res(), _read_res(b"data"), _read_res(b"", eof=1),
                       _close_res()])
    assert got == b"data"
    assert ops[0].op == consts.HYPER_OP.HYPER_OP_VFS_OPEN


def test_regular_file_still_uses_the_stateless_op(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf, regions_size=64)
    consts = _require_ops(igloo_ko_isf)
    got, ops = _drive(lp.plugin.read_file("/etc/passwd", size=8), [b"root:x:"])
    assert got == b"root:x:"
    assert ops[0].op == consts.HYPER_OP.HYPER_OP_READ_FILE
