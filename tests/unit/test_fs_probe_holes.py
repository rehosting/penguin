"""Adversarial tests for fs.read_file / read_file_seq / write_file.

Each of these came out of probing the API for holes rather than from confirming
intended behaviour, and every one of them failed when it was first written. They
are grouped by what the hole cost, because that is what decides whether a fix is
worth it: silently wrong data is worse than a confusing error, which is worse
than a crash.
"""
import struct
import pytest
from pathlib import Path
from penguin.testing import RealKffi, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
FS = str(REPO_ROOT / "pyplugins" / "apis" / "fs.py")


class _KFFI(RealKffi):
    def sizeof(self, t):
        return self.ffi.sizeof(t)

    def from_buffer(self, t, buf, instance_offset_in_buffer=0):
        return self.ffi.from_buffer(t, bytearray(buf),
                                    offset=instance_offset_in_buffer)


class _Portal:
    regions_size = 4072


def _open_res(error=0, handle=7, magic=0x9fa0):
    return struct.pack("<iIQ", error, handle, magic)


def _read_res(p=b"", error=0, eof=0):
    return struct.pack("<iIB7x", error, len(p), eof) + p


def _close_res(error=0):
    return struct.pack("<iI", error, 0)


def _drive(gen, responses, limit=5000):
    """Run a generator to completion, capturing what it yielded.

    Bounded so a probe that makes the code spin reports a hang instead of
    hanging the suite.
    """
    ops, it = [], iter(responses)
    try:
        c = gen.send(None)
        for _ in range(limit):
            ops.append(c)
            c = gen.send(next(it, None))
        return ("HUNG", limit), ops
    except StopIteration as e:
        return e.value, ops
    except Exception as e:
        return ("RAISED", type(e).__name__, str(e)), ops


class _Log:
    """Recorder in place of the plugin's logger.

    caplog does not see it: the plugin logs through a coloredlogs logger that
    does not propagate to the root handler, so a warning-was-emitted assertion
    against caplog silently passes for the wrong reason.
    """

    def __init__(self):
        self.messages = []

    def _rec(self, msg, *a, **kw):
        try:
            self.messages.append(str(msg) % a if a else str(msg))
        except Exception:
            self.messages.append(str(msg))

    warning = error = info = debug = _rec

    def __contains__(self, needle):
        return any(needle in m for m in self.messages)


@pytest.fixture
def fs(tmp_path, igloo_ko_isf):
    lp = load_pyplugin(FS, outdir=tmp_path, real_isf=igloo_ko_isf,
                       doubles={"portal": _Portal(),
                                "kffi": _KFFI([igloo_ko_isf])})
    lp.plugin.logger = _Log()
    return lp.plugin


def _seq(*payloads, eof=True):
    out = [_open_res()] + [_read_res(p) for p in payloads]
    if eof:
        out.append(_read_res(b"", eof=1))
    return out + [_close_res()]


# --------------------------------------------------------------------------- #
# Silently wrong data. The worst class: the call succeeds and the caller acts on
# bytes that are not what it asked for.
# --------------------------------------------------------------------------- #

def test_offset_is_honoured_on_synthetic_paths(fs):
    """read_file(offset=N) on /proc must not quietly return the bytes at 0.

    A seq_file cannot seek, so the offset is reached by reading and discarding.
    Dropping the argument instead -- which is what happened -- returns plausible
    data from the wrong place with no error anywhere.
    """
    r, _ = _drive(fs.read_file("/proc/x", size=4, offset=4),
                  _seq(b"AAAABBBB"))
    assert r == b"BBBB", f"offset ignored; got {r!r}"


def test_over_long_path_is_refused_not_truncated(fs):
    """A path past the portal's 255-byte field must not be cut down.

    Truncation does not fail -- it names a DIFFERENT file and returns its
    contents as though they were the requested file's.
    """
    long_path = "/proc/" + "a" * 300 + "/target"
    r, ops = _drive(fs.read_file_seq(long_path), _seq(b"wrong file"))
    assert isinstance(r, tuple) and r[1] == "PortalFileError", f"got {r!r}"
    assert "255" in r[2]
    assert not ops, "a truncated path was still sent to the guest"


def test_double_slash_routes_like_the_same_file(fs):
    """//proc/x is /proc/x; it must not take a different code path.

    posixpath.normpath preserves a leading "//" (POSIX leaves it
    implementation-defined), so this spelling routed to the stateless op while
    /proc/x routed to the sequential one -- and on 6.13 one works and the other
    EINVALs.
    """
    a, _ = _drive(fs.read_file("//proc/version", size=4), _seq(b"ABCD"))
    b, _ = _drive(fs.read_file("/proc/version", size=4), _seq(b"ABCD"))
    assert a == b == b"ABCD", f"//proc -> {a!r}, /proc -> {b!r}"


def test_dotdot_path_routes_by_its_target(fs):
    r, _ = _drive(fs.read_file("/etc/../proc/version", size=4), _seq(b"ABCD"))
    assert r == b"ABCD"


def test_non_synthetic_lookalikes_are_not_rerouted(fs):
    """/system and /sysroot are not synthetic filesystems.

    A bare startswith() sent both down the sequential path -- and /system/bin/sh
    exists in a large share of real firmware.
    """
    for path in ("/system/bin/sh", "/sysroot/etc/passwd", "/procfoo/bar"):
        r, ops = _drive(fs.read_file(path, size=4), [b"DATA"])
        assert r == b"DATA", f"{path} -> {r!r}"
        assert len(ops) == 1, f"{path} took the sequential path ({len(ops)} ops)"


# --------------------------------------------------------------------------- #
# Silent failure: the call "succeeds" and the caller cannot tell it did nothing.
# --------------------------------------------------------------------------- #

def test_failed_write_raises_rather_than_returning_none(fs):
    """write_file returned None on refusal, which reads as "0 bytes written".

    The same conflation this module fixed for reads, still live for writes --
    and there is no sequential write op, so every synthetic write hits it.
    """
    r, _ = _drive(fs.write_file("/proc/sys/kernel/ostype", b"x"), [None])
    assert isinstance(r, tuple) and r[1] == "PortalFileError", f"got {r!r}"


def test_size_zero_returns_nothing(fs):
    """The driver reads requested_size == 0 as "as much as fits"."""
    r, _ = _drive(fs.read_file("/etc/passwd", size=0), [b"a whole chunk"])
    assert r == b"", f"size=0 returned {r!r}"


def test_empty_file_behaves_the_same_at_every_size(fs):
    """One file must not have three behaviours depending on `size`.

    The stateless op reports EOF as failure, so an empty regular file is
    indistinguishable from a failed read. Whatever we choose, it has to be the
    same choice for size=None, a small size and a chunked size -- it used to
    return b"" for one and raise for the other two.
    """
    nosize, _ = _drive(fs.read_file("/tmp/empty"), [None, None])
    chunked, _ = _drive(fs.read_file("/tmp/empty", size=9000), [None, None])
    assert nosize == chunked == b"", f"size=None -> {nosize!r}, 9000 -> {chunked!r}"


# --------------------------------------------------------------------------- #
# Hangs and crashes.
# --------------------------------------------------------------------------- #

def test_a_driver_that_never_reports_eof_is_bounded(fs, monkeypatch):
    """Every iteration is a guest round trip, so an unbounded loop is a hang.

    A hang is the worst failure shape in CI: it produces no marker and looks
    exactly like infra flake.
    """
    monkeypatch.setattr(type(fs), "_max_seq_reads", lambda self: 8)
    never = [_open_res()] + [_read_res(b"z" * 64)] * 50
    r, ops = _drive(fs.read_file_seq("/proc/version"), never, limit=200)
    assert isinstance(r, tuple) and r[1] == "PortalFileError", f"got {r!r}"
    assert "never reported EOF" in r[2]


def test_abandoning_a_read_does_not_raise_runtime_error(fs):
    """A PortalCmd cannot be yielded while the generator is closing.

    Closing over a `finally: yield` raised RuntimeError("generator ignored
    GeneratorExit"), which both crashed the caller and buried the real story:
    the handle was not returned and the driver has to reclaim the slot.
    """
    gen = fs.read_file_seq("/proc/version")
    gen.send(None)
    gen.send(_open_res(handle=5))
    gen.close()          # must not raise
    assert "abandoned mid-read" in fs.logger, (
        "the leaked handle was not reported")


def test_non_encodable_path_gives_a_portal_error(fs):
    """A bare UnicodeEncodeError from inside a read is not catchable by callers
    handling OSError, and says nothing about which call failed."""
    r, _ = _drive(fs.read_file_seq("/proc/中文"), _seq(b"x"))
    assert isinstance(r, tuple) and r[1] == "PortalFileError", f"got {r!r}"


def test_negative_size_and_offset_are_refused(fs):
    for kwargs in ({"size": -5}, {"offset": -1}):
        r, ops = _drive(fs.read_file("/etc/passwd", **kwargs), [b"data"])
        assert isinstance(r, tuple) and r[1] == "PortalFileError", \
            f"{kwargs} -> {r!r}"
        assert not ops, f"{kwargs} was still sent to the guest"


# --------------------------------------------------------------------------- #
# Confusing diagnostics. Not wrong, but they sent us to the wrong place.
# --------------------------------------------------------------------------- #

def test_handle_zero_is_not_reported_as_errno_zero(fs):
    """error=0 with handle=0 is a driver bug, not an errno.

    It used to print "errno 0 (errno 0)" and append a synthetic-filesystem hint
    that pointed at entirely the wrong thing.
    """
    r, _ = _drive(fs.read_file_seq("/proc/version"),
                  [_open_res(error=0, handle=0)])
    assert isinstance(r, tuple) and r[1] == "PortalFileError"
    assert "errno 0" not in r[2], r[2]
    assert "handle 0" in r[2]


def test_missing_vfs_ops_warns_before_falling_back(fs):
    """On an old driver, synthetic reads silently used the broken op.

    The fallback returns nothing for large parts of procfs on >=5.10, so a
    silent fallback is a silent wrong answer.
    """
    mod = type(fs).read_file.__globals__
    real_hop = mod["hop"]

    class NoVfs:
        def __getattr__(self, n):
            if n.startswith("HYPER_OP_VFS"):
                raise AttributeError(n)
            return getattr(real_hop, n)

    mod["hop"] = NoVfs()
    try:
        r, ops = _drive(fs.read_file("/proc/net/tcp", size=64), [b"stateless"])
    finally:
        mod["hop"] = real_hop
    assert r == b"stateless"
    assert "no vfs_* ops" in fs.logger, \
        "fell back to the stateless op with no warning"


# --------------------------------------------------------------------------- #
# Confirmed NOT holes. Kept so a regression shows up as a failure.
# --------------------------------------------------------------------------- #

def test_interleaved_reads_keep_distinct_handles(fs):
    g1, g2 = fs.read_file_seq("/proc/one"), fs.read_file_seq("/proc/two")
    g1.send(None)
    g2.send(None)
    c1 = g1.send(_open_res(handle=11))
    c2 = g2.send(_open_res(handle=22))
    assert (c1.addr, c2.addr) == (11, 22)


def test_bogus_nbytes_cannot_overread_the_region(fs):
    """The driver claiming more bytes than it sent must not read past the buffer."""
    r, _ = _drive(fs.read_file_seq("/proc/version"),
                  [_open_res(), struct.pack("<iIB7x", 0, 100000, 0) + b"tiny",
                   _read_res(b"", eof=1), _close_res()])
    assert r == b"tiny", f"got {r!r}"
