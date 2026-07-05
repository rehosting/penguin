"""In-place harness coverage for the pseudofile *read* models
(pyplugins/hyperfile/models/read.py), driven host-side with no PANDA/guest.

These models back ``read: {model: ...}`` in a pseudofile config and are the
host-side logic a huge share of the guest-boot matrix ultimately exercises: they
decide what bytes a modelled ``/dev``/``/proc``/``/sys`` file serves. Each
``read()`` is a portal generator — ``offset = yield from plugins.kffi.deref(...)``
then ``yield from plugins.mem.write(user_buf, chunk)`` — so we drive it through
the harness pump with a ``kffi`` double (deref returns the offset we pass as the
pointer) and a ``mem`` double that records what would be written to the guest.

The models are plain mixin classes (not ``Plugin`` subclasses), so we import the
module via ``load_module`` and instantiate them directly.
"""
from pathlib import Path

import pytest

from penguin.testing import drive, load_module

REPO_ROOT = Path(__file__).resolve().parents[2]
READ = str(REPO_ROOT / "pyplugins" / "hyperfile" / "models" / "read.py")

USER_BUF = 0x1000  # opaque guest address token


class _KFFI:
    def deref(self, ptr):
        yield from ()          # portal generator: no guest round-trip in a double
        return int(ptr)        # we pass the offset value *as* the pointer


class _Mem:
    def __init__(self):
        self.writes = []

    def write(self, addr, data):
        yield from ()
        self.writes.append((addr, data))


class _PtRegs:
    retval = None


@pytest.fixture(scope="module")
def env():
    mem = _Mem()
    mod, _mgr = load_module(READ, doubles={"kffi": _KFFI(), "mem": mem})
    return mod, mem


def _read(env, model, size, offset):
    """Drive model.read(...) once; return (retval, served_bytes_or_None)."""
    _mod, mem = env
    mem.writes.clear()
    pt = _PtRegs()
    drive(model.read(pt, None, USER_BUF, size, offset))
    served = next((data for (addr, data) in mem.writes if addr == USER_BUF), None)
    return pt.retval, served


def test_const_buf_serves_bytes_and_advances_offset(env):
    mod, mem = env
    rv, served = _read(env, mod.ReadConstBuf(const_buf="hello"), size=100, offset=0)
    assert rv == 5 and served == b"hello"
    # the offset pointer is bumped to the new position (5)
    assert (0, 5) in [(a, d) for (a, d) in mem.writes if a == 0]


def test_const_buf_null_terminate(env):
    mod, _ = env
    rv, served = _read(env, mod.ReadConstBuf(const_buf="ab", null_terminate=True),
                       size=10, offset=0)
    assert rv == 3 and served == b"ab\x00"


def test_const_buf_partial_read_from_offset(env):
    mod, _ = env
    rv, served = _read(env, mod.ReadConstBuf(const_buf="abcdef"), size=2, offset=2)
    assert rv == 2 and served == b"cd"


def test_const_buf_offset_past_end_is_eof(env):
    mod, _ = env
    rv, served = _read(env, mod.ReadConstBuf(const_buf="hi"), size=10, offset=5)
    assert rv == 0 and served is None  # nothing written


def test_zero_one_empty_presets(env):
    mod, _ = env
    assert _read(env, mod.ReadZero(), 10, 0) == (1, b"0")
    assert _read(env, mod.ReadOne(), 10, 0) == (1, b"1")
    assert _read(env, mod.ReadEmpty(), 10, 0) == (0, None)


def test_default_returns_einval(env):
    mod, _ = env
    # ReadDefault.read is a plain (non-generator) method that just sets -EINVAL.
    rv, served = _read(env, mod.ReadDefault(), 10, 0)
    assert rv == -22 and served is None


def test_cycle_repeats_buffer_to_fill_request(env):
    mod, _ = env
    rv, served = _read(env, mod.ReadCycle(buffer="ab"), size=5, offset=0)
    assert rv == 5 and served == b"ababa"


def test_zero_cycle_fills_with_zeros(env):
    mod, _ = env
    rv, served = _read(env, mod.ReadZeroCycle(), size=4, offset=0)
    assert rv == 4 and served == b"0000"


def test_cycle_empty_buffer_is_eof(env):
    mod, _ = env
    rv, served = _read(env, mod.ReadCycle(buffer=""), size=4, offset=0)
    assert rv == 0 and served is None


def test_sequence_advances_then_holds_last(env):
    mod, _ = env
    seq = mod.ReadSequence(vals=["busy", "ready"])
    assert _read(env, seq, 10, 0) == (4, b"busy")
    assert _read(env, seq, 10, 0) == (5, b"ready")
    assert _read(env, seq, 10, 0) == (5, b"ready")  # exhausted -> holds tail


def test_sequence_cycle_wraps(env):
    mod, _ = env
    seq = mod.ReadSequence(vals=["a", "b"], cycle=True)
    assert _read(env, seq, 10, 0)[1] == b"a"
    assert _read(env, seq, 10, 0)[1] == b"b"
    assert _read(env, seq, 10, 0)[1] == b"a"  # wrapped around


def test_stateful_serves_seeded_value(env):
    mod, _ = env
    rv, served = _read(env, mod.ReadStateful(initial="xy"), size=10, offset=0)
    assert rv == 2 and served == b"xy"


def test_const_map_renders_sparse_offsets_with_padding(env):
    mod, _ = env
    m = mod.ReadConstMap(vals={0: "AB", 4: "CD"}, size=8, pad=b"\x00")
    rv, served = _read(env, m, size=100, offset=0)
    assert rv == 8 and served == b"AB\x00\x00CD\x00\x00"
