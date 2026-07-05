"""In-place harness coverage for the pseudofile *lseek* models
(pyplugins/hyperfile/models/seek.py), driven host-side with no PANDA/guest.

``SeekDefault`` implements SEEK_SET/CUR/END offset arithmetic against the node's
reported ``SIZE``, clamped to ``[0, SIZE]``, reading/writing ``file->f_pos`` via
``plugins.kffi.read_field``/``write_field``. ``SeekUnsupported`` rejects with
-ESPIPE. We drive them through the pump with a ``kffi`` double.
"""
from pathlib import Path

import pytest

from penguin.testing import drive, load_module

REPO_ROOT = Path(__file__).resolve().parents[2]
SEEK = str(REPO_ROOT / "pyplugins" / "hyperfile" / "models" / "seek.py")

FILE = object()  # opaque struct file* token
SEEK_SET, SEEK_CUR, SEEK_END = 0, 1, 2


class _KFFI:
    def __init__(self):
        self.cur = 0            # current f_pos returned by read_field
        self.field_writes = []

    def read_field(self, obj, typ, field):
        yield from ()
        return self.cur

    def write_field(self, obj, typ, field, val):
        yield from ()
        self.field_writes.append((field, val))


class _PtRegs:
    retval = None


@pytest.fixture(scope="module")
def env():
    kffi = _KFFI()
    mod, _mgr = load_module(SEEK, doubles={"kffi": kffi})
    return mod, kffi


def _lseek(env, model, offset, whence, cur=0):
    _mod, kffi = env
    kffi.cur = cur
    kffi.field_writes.clear()
    pt = _PtRegs()
    drive(model.lseek(pt, FILE, offset, whence))
    return pt.retval, kffi.field_writes


def _default(mod, size=100):
    m = mod.SeekDefault()
    m.SIZE = size
    return m


def test_seek_set_sets_absolute_offset(env):
    mod, _ = env
    rv, writes = _lseek(env, _default(mod), offset=50, whence=SEEK_SET)
    assert rv == 50 and writes == [("f_pos", 50)]


def test_seek_cur_is_relative_to_current(env):
    mod, _ = env
    rv, _w = _lseek(env, _default(mod), offset=10, whence=SEEK_CUR, cur=20)
    assert rv == 30


def test_seek_end_is_relative_to_size(env):
    mod, _ = env
    rv, _w = _lseek(env, _default(mod), offset=-10, whence=SEEK_END)
    assert rv == 90  # SIZE(100) - 10


def test_seek_out_of_range_is_einval(env):
    mod, _ = env
    rv, writes = _lseek(env, _default(mod), offset=200, whence=SEEK_SET)
    assert rv == -22 and writes == []  # clamped-out, f_pos untouched


def test_seek_negative_is_einval(env):
    mod, _ = env
    rv, _w = _lseek(env, _default(mod), offset=-1, whence=SEEK_SET)
    assert rv == -22


def test_bad_whence_is_einval(env):
    mod, _ = env
    rv, _w = _lseek(env, _default(mod), offset=0, whence=5)
    assert rv == -22


def test_seek_unsupported_returns_espipe(env):
    mod, _ = env
    pt = _PtRegs()
    drive(mod.SeekUnsupported().lseek(pt, FILE, 0, SEEK_SET))
    assert pt.retval == -29
