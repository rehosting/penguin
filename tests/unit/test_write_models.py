"""In-place harness coverage for the pseudofile *write* models
(pyplugins/hyperfile/models/write.py), driven host-side with no PANDA/guest.

These back ``write: {model: ...}`` in a pseudofile config. Each ``write()`` is a
portal generator that reads the guest payload via ``plugins.mem.read`` and (for
the recording models) derefs/bumps the offset pointer. We drive them through the
pump with a ``mem`` double whose ``read`` returns the payload under test and a
``kffi`` double whose ``deref`` returns the offset we pass as the pointer.
"""
from pathlib import Path

import pytest

from penguin.testing import drive, load_module

REPO_ROOT = Path(__file__).resolve().parents[2]
WRITE = str(REPO_ROOT / "pyplugins" / "hyperfile" / "models" / "write.py")

USER_BUF = 0x2000


class _KFFI:
    def deref(self, ptr):
        yield from ()
        return int(ptr)


class _Mem:
    def __init__(self):
        self.read_data = b""
        self.writes = []

    def read(self, addr, size, fmt=None):
        yield from ()
        return self.read_data[:size]

    def write(self, addr, data):
        yield from ()
        self.writes.append((addr, data))


class _PtRegs:
    retval = None


@pytest.fixture(scope="module")
def env():
    mem = _Mem()
    mod, _mgr = load_module(WRITE, doubles={"kffi": _KFFI(), "mem": mem})
    return mod, mem


def _write(env, model, payload=b"", offset=0):
    _mod, mem = env
    mem.read_data = payload
    mem.writes.clear()
    pt = _PtRegs()
    drive(model.write(pt, None, USER_BUF, len(payload), offset))
    return pt.retval


def test_discard_returns_size_without_recording(env):
    mod, _ = env
    assert _write(env, mod.WriteDiscard(), payload=b"junk") == 4


def test_return_const(env):
    mod, _ = env
    assert _write(env, mod.WriteReturnConst(const=7), payload=b"x") == 7


def test_unhandled_returns_einval(env):
    mod, _ = env
    assert _write(env, mod.WriteUnhandled(), payload=b"x") == -22


def test_record_stores_payload_and_bumps_offset(env):
    mod, mem = env
    rec = mod.WriteRecord()
    assert _write(env, rec, payload=b"AB", offset=0) == 2
    assert rec.written_data == b"AB"
    assert (0, 2) in mem.writes  # offset pointer advanced to 2


def test_record_overwrites_at_offset(env):
    mod, _ = env
    rec = mod.WriteRecord()
    _write(env, rec, payload=b"AB", offset=0)
    _write(env, rec, payload=b"CD", offset=2)
    assert rec.written_data == b"ABCD"
    _write(env, rec, payload=b"XY", offset=0)
    assert rec.written_data == b"XYCD"


def test_record_zero_pads_gap_before_offset(env):
    mod, _ = env
    rec = mod.WriteRecord()
    _write(env, rec, payload=b"Z", offset=3)
    assert rec.written_data == b"\x00\x00\x00Z"


def test_default_is_record(env):
    mod, _ = env
    rec = mod.WriteDefault()
    _write(env, rec, payload=b"hi", offset=0)
    assert rec.written_data == b"hi"
