"""Adversarial tests for the STATELESS read path and for write_file.

The earlier probe pass covered read_file's routing and read_file_seq. It left
two whole paths untouched: the stateless chunked read (what every regular-file
read uses) and write_file's chunked branch. Both turned out to repeat holes that
had already been fixed one function away -- which is the useful finding here: a
fix applied to one of three loops reads as "fixed" and is not.

Grouped by cost, worst first.
"""
import struct
import pytest
from pathlib import Path
from penguin.testing import RealKffi, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
FS = str(REPO_ROOT / "pyplugins" / "apis" / "fs.py")

CHUNK = 4072 - 1        # rsize - 1, what the stateless path asks for


class _KFFI(RealKffi):
    def sizeof(self, t):
        return self.ffi.sizeof(t)

    def from_buffer(self, t, buf, instance_offset_in_buffer=0):
        return self.ffi.from_buffer(t, bytearray(buf),
                                    offset=instance_offset_in_buffer)


class _Portal:
    regions_size = 4072


class _Log:
    """The plugin's coloredlogs logger does not propagate, so caplog is blind."""

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


def _drive(gen, responses, limit=20000):
    """Run to completion. Bounded, so a spin reports as HUNG rather than hangs.

    The limit sits just above the code's own cap (_MAX_STATELESS_READS,
    16384): high enough that a loop reaching it really has no bound, low enough
    that the probe finishes. It had to be raised to find this at all -- and at
    100000 the probe itself timed out, which was the second finding: the reads
    accumulated with `all_data += chunk`, so the copying was quadratic.
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


class _Endless:
    """A driver that always returns a full chunk: /dev/zero, /dev/urandom, a
    growing log, a modelled pseudofile that regenerates per read."""

    def __iter__(self):
        return self

    def __next__(self):
        return b"\0" * CHUNK


# --------------------------------------------------------------------------- #
# Hangs. Every iteration is a guest round trip, so an unbounded loop is not
# slow, it is a hang -- and in CI a hang produces no marker at all, which reads
# as infrastructure rather than as a bug.
# --------------------------------------------------------------------------- #

def test_a_file_that_never_ends_does_not_hang_the_full_read(fs):
    """read_file(path) with no size must be bounded.

    read_file_seq got this bound; the stateless loop -- which is what every
    regular-file read uses -- did not, so read_file("/dev/zero") span forever.
    """
    r, ops = _drive(fs.read_file("/dev/zero"), _Endless())
    assert r[0] != "HUNG", f"unbounded after {len(ops)} guest round trips"
    assert r[0] == "RAISED" and "PortalFileError" in r[1], r


def test_the_bound_names_the_cap_and_the_path(fs):
    """A bound that fires has to say what it means, or it reads as corruption."""
    r, _ = _drive(fs.read_file("/dev/zero"), _Endless())
    msg = r[2]
    assert "/dev/zero" in msg
    assert "never reported EOF" in msg or "cap" in msg


# --------------------------------------------------------------------------- #
# Silently wrong data.
# --------------------------------------------------------------------------- #

def test_a_short_read_is_not_treated_as_eof(fs):
    """The stateless op is a pread: a short read does not mean end-of-file.

    Treating it as EOF truncates silently -- the caller gets a prefix and no
    indication that the rest exists. It is what a chardev or a pipe does on
    every read.
    """
    r, _ = _drive(fs.read_file("/etc/big"),
                  [b"A" * 100, b"B" * 100, b""])
    assert r == b"A" * 100 + b"B" * 100, \
        f"stopped after the first short read: got {len(r) if isinstance(r, bytes) else r}"


def test_a_driver_that_writes_more_than_it_was_given_is_caught(fs):
    """A write reporting more bytes than we sent desynchronises the offset.

    current_offset advances by the reported count while current_pos advances by
    the chunk size, so every later chunk lands at the wrong offset AND the
    returned total over-reports. Corrupting a file while returning success is
    the worst outcome available here.
    """
    data = b"x" * (CHUNK * 3)
    r, _ = _drive(fs.write_file("/tmp/f", data), [10**9, 10**9, 10**9])
    assert r[0] == "RAISED", f"accepted an impossible write count: {r!r}"
    assert "more bytes" in r[2] or "impossible" in r[2]


# --------------------------------------------------------------------------- #
# Silent failure.
# --------------------------------------------------------------------------- #

def test_a_refused_chunk_mid_write_is_not_a_partial_success(fs):
    """The single-write path raises on a refusal; the chunked path returned.

    Same function, two behaviours depending only on how big the data is: a small
    write raises, a large one returns a short count with no error. A caller that
    checks the count against len(data) catches it; one that does not has
    silently truncated the file.
    """
    data = b"y" * (CHUNK * 3)
    r, _ = _drive(fs.write_file("/tmp/f", data), [CHUNK, None])
    assert r[0] == "RAISED", f"partial write reported as success: {r!r}"
    assert "/tmp/f" in r[2]


def test_a_zero_length_chunk_write_is_not_a_partial_success(fs):
    """0 and None were conflated in the chunked path, as they were for reads."""
    data = b"y" * (CHUNK * 3)
    r, _ = _drive(fs.write_file("/tmp/f", data), [CHUNK, 0])
    assert r[0] == "RAISED", f"a zero-byte write reported as success: {r!r}"


def test_negative_write_offset_is_refused(fs):
    """read_file validates this; write_file passed it to the driver, which casts
    it to an unsigned offset and writes somewhere unintended."""
    r, _ = _drive(fs.write_file("/tmp/f", b"x", offset=-1), [1])
    assert r[0] == "RAISED", r
    assert "negative" in r[2]


def test_unencodable_write_data_is_refused_clearly(fs):
    """A str the portal cannot carry must fail as a file error, not as a bare
    UnicodeEncodeError from the middle of an operation."""
    r, _ = _drive(fs.write_file("/tmp/f", "☃ snowman"), [1])
    assert r[0] == "RAISED", r
    assert r[1] == "PortalFileError", r
    assert "latin-1" in r[2] or "encodable" in r[2]
