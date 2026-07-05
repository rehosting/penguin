"""In-place harness coverage for the pseudofile *ioctl* models
(pyplugins/hyperfile/models/ioctl.py), driven host-side with no PANDA/guest.

These back ``ioctl: {...}`` in a pseudofile config: the simple return models, the
buffer-writing model, and the command-map dispatcher (exact / string / wildcard
match, with -ENOTTY for unhandled commands). Buffer-writing paths are portal
generators (``yield from plugins.mem.write``), so they run through the pump.
"""
from pathlib import Path

import pytest

from penguin.testing import drive, load_module

REPO_ROOT = Path(__file__).resolve().parents[2]
IOCTL = str(REPO_ROOT / "pyplugins" / "hyperfile" / "models" / "ioctl.py")

FILE = object()
ENOTTY = -25


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
    mod, _mgr = load_module(IOCTL, doubles={"mem": mem})
    return mod, mem


def _ioctl(env, model, cmd, arg):
    _mod, mem = env
    mem.writes.clear()
    pt = _PtRegs()
    drive(model.ioctl(pt, FILE, cmd, arg))
    return pt.retval, mem.writes


def test_zero_and_unhandled_return_models(env):
    mod, _ = env
    assert _ioctl(env, mod.IoctlZero(), 1, 0)[0] == 0
    assert _ioctl(env, mod.IoctlUnhandled(), 1, 0)[0] == ENOTTY
    assert _ioctl(env, mod.IoctlReturnMixin(ioctl_retval=42), 1, 0)[0] == 42


def test_write_data_arg_fills_user_pointer(env):
    mod, _ = env
    rv, writes = _ioctl(env, mod.IoctlWriteDataArg(ioctl_data=b"DATA"),
                        cmd=1, arg=0x3000)
    assert rv == 0 and writes == [(0x3000, b"DATA")]


def test_write_data_arg_skips_null_pointer(env):
    mod, _ = env
    rv, writes = _ioctl(env, mod.IoctlWriteDataArg(ioctl_data=b"DATA"),
                        cmd=1, arg=0)
    assert rv == 0 and writes == []  # NULL arg -> nothing written


def test_dispatcher_exact_match(env):
    mod, _ = env
    disp = mod.IoctlDispatcher(ioctl_handlers={5: mod.IoctlReturnConst(99)})
    assert _ioctl(env, disp, cmd=5, arg=0)[0] == 99


def test_dispatcher_string_keyed_handler(env):
    mod, _ = env
    # YAML sometimes yields string keys; the dispatcher falls back to str(cmd).
    disp = mod.IoctlDispatcher(ioctl_handlers={"5": mod.IoctlReturnConst(7)})
    assert _ioctl(env, disp, cmd=5, arg=0)[0] == 7


def test_dispatcher_wildcard_and_unhandled(env):
    mod, _ = env
    disp = mod.IoctlDispatcher(ioctl_handlers={"*": mod.IoctlReturnConst(3)})
    assert _ioctl(env, disp, cmd=1234, arg=0)[0] == 3
    empty = mod.IoctlDispatcher(ioctl_handlers={})
    assert _ioctl(env, empty, cmd=1, arg=0)[0] == ENOTTY


def test_dispatcher_routes_to_write_data_handler(env):
    mod, _ = env
    disp = mod.IoctlDispatcher(
        ioctl_handlers={7: mod.IoctlWriteData(data=b"XY", val=0)})
    rv, writes = _ioctl(env, disp, cmd=7, arg=0x4000)
    assert rv == 0 and writes == [(0x4000, b"XY")]


def test_compat_dispatcher_matches_and_falls_back(env):
    mod, mem = env
    disp = mod.CompatIoctlDispatcher(
        compat_ioctl_handlers={9: mod.IoctlReturnConst(1)})
    pt = _PtRegs()
    drive(disp.compat_ioctl(pt, FILE, 9, 0))
    assert pt.retval == 1
    pt2 = _PtRegs()
    drive(disp.compat_ioctl(pt2, FILE, 100, 0))
    assert pt2.retval == ENOTTY
