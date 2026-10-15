"""Host-side tests for the pt_regs wrapper (pyplugins/wrappers/ptregs_wrap.py):
an AArch32 task's registers on an arm64 kernel, read as ARM's uregs, and the
wrapper's own state kept off the wrapped pt_regs."""
from pathlib import Path
from types import SimpleNamespace

import pytest

from penguin.testing import load_module

PY = Path(__file__).resolve().parents[2] / "pyplugins"


@pytest.fixture(scope="module")
def ptregs():
    mod, _ = load_module(str(PY / "wrappers" / "ptregs_wrap.py"))
    return mod


def _panda(arch):
    return SimpleNamespace(arch_name=arch, bits=64, endianness="little")


class _Arm64Regs:
    def __init__(self, pstate):
        self.regs = [0x100000000 + i for i in range(31)]
        self.sp, self.pc, self.pstate = 0x7ff0, 0x4000, pstate
        self.orig_x0, self.syscallno = 0x100000000, 7


def test_arm64_compat_task_reads_regs_as_uregs(ptregs):
    r = _Arm64Regs(pstate=0x10)         # AArch32 user mode
    w = ptregs.get_pt_regs_wrapper(_panda("aarch64"), r)
    assert [w.get_syscall_arg(i) for i in range(6)] == list(range(6))
    assert w.get_syscall_number() == 7  # r7
    assert w.get_retval() == 0 and w.get_register("r12") == 12
    assert w.get_pc() == 0x4000
    w.retval = -2
    assert r.regs[0] == 0xfffffffe     # a compat task's 32-bit value


def test_arm64_native_task_unchanged(ptregs):
    r = _Arm64Regs(pstate=0)
    w = ptregs.get_pt_regs_wrapper(_panda("aarch64"), r)
    assert w.get_syscall_arg(1) == 0x100000001
    assert w.get_syscall_number() == 7  # syscallno


def test_wrapper_state_stays_off_pt_regs(ptregs):
    class Strict:
        """a pt_regs that records what is set on it"""
        def __init__(self):
            object.__setattr__(self, "set", [])
            object.__setattr__(self, "cs", 0x33)

        def __setattr__(self, k, v):
            self.set.append(k)

    r = Strict()
    w = ptregs.get_pt_regs_wrapper(_panda("x86_64"), r)
    w._is_compatibility_mode()
    w._get_x86_delegate()
    assert r.set == []
