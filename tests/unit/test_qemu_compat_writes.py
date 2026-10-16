"""Host-side tests for guest-memory writes with the guest's permissions
(pyplugins/compat/qemu_compat.py, pyplugins/apis/mem.py): under TCG
mem.write_bytes' direct write is QEMU's permission-checked one, and a write
the guest would refuse goes to the portal instead of the debug write; under
KVM, or without the checked write, the debug write remains."""
import threading
from pathlib import Path

import cffi
import pytest

from penguin.testing import drive, load_module

PY = Path(__file__).resolve().parents[2] / "pyplugins"


class FakeLib:
    def __init__(self, checked=True, allow=True):
        self.calls = []
        self.allow = allow
        if checked:
            self.penguin_syscall_write_memory = self._checked

    def _checked(self, cpu, addr, ptr, n):
        self.calls.append(("checked", addr, n))
        return self.allow

    def cpu_memory_rw_debug(self, cpu, addr, ptr, n, is_write):
        self.calls.append(("debug", int(addr), int(n), is_write))
        return 0


@pytest.fixture(scope="module")
def qc():
    mod, _ = load_module(str(PY / "compat" / "qemu_compat.py"))
    return mod


def _libpanda(qc, lib, mode="system"):
    q = qc.QemuCompat.__new__(qc.QemuCompat)
    q.lib, q.mode, q.bits = lib, mode, 64
    q.ffi = cffi.FFI()
    q.ffi.cdef("typedef uint64_t vaddr;")
    q._thread_state = threading.local()
    q._call_with_bql = lambda fn: fn()
    return qc.KVMLibPandaMock(lib, q.ffi, q)


def test_checked_write_under_tcg(qc):
    lib = FakeLib()
    lp = _libpanda(qc, lib)
    assert lp.panda_virtual_memory_write_checked(None, 0x1000, b"abcdefgh", 8) == 0
    lib.allow = False
    assert lp.panda_virtual_memory_write_checked(None, 0x1000, b"abcdefgh", 8) == -1
    assert [c[0] for c in lib.calls] == ["checked", "checked"]
    # the direct writers' path is unchanged
    lp.panda_virtual_memory_write_external(None, 0x2000, b"ab", 2)
    assert lib.calls[-1] == ("debug", 0x2000, 2, True)


def test_kernel_half_and_empty_writes(qc):
    """the kernel's half keeps the direct write outside a trap callback (from
    a user-mode hypercall the user permissions would refuse it); nothing to
    write is written"""
    lib = FakeLib(allow=False)
    lp = _libpanda(qc, lib)
    assert lp.panda_virtual_memory_write_checked(None, 0xffffffffc0277bf8, b"x" * 8, 8) == 0
    assert lp.panda_virtual_memory_write_checked(None, 0x7fff0000, b"", 0) == 0
    assert [c[0] for c in lib.calls] == ["debug"]
    lp.qemu._thread_state.syscall_trap = True
    assert lp.panda_virtual_memory_write_checked(None, 0xffffffffc0277bf8, b"x" * 8, 8) == -1
    assert lib.calls[-1][0] == "checked"


def test_no_checked_write_under_kvm_or_without_it(qc):
    for lp in (_libpanda(qc, FakeLib(), mode="kvm"), _libpanda(qc, FakeLib(checked=False))):
        assert getattr(lp, "panda_virtual_memory_write_checked", None) is None


@pytest.fixture
def mem(igloo_ko_isf):
    mod, _ = load_module(str(PY / "apis" / "mem.py"), real_isf=igloo_ko_isf)
    return mod


def _mem(mem, checked):
    m = mem.Mem.__new__(mem.Mem)
    debug = []
    m.ffi = cffi.FFI()
    m.try_panda, m.addr_mask, m._rsize = True, (1 << 64) - 1, 4096
    m._get_cpu = lambda: None
    m._write_checked = checked
    m._write_external = lambda cpu, addr, buf, n: debug.append(addr) or 0
    return m, debug


def test_write_bytes_refused_goes_to_the_portal(mem):
    writes = []
    m, debug = _mem(mem, lambda cpu, addr, buf, n: writes.append(addr) or -1)
    g = m.write_bytes(0x5000, b"data")
    cmd = next(g)
    assert cmd.op is not None and cmd.addr == 0x5000 and writes == [0x5000] and not debug
    assert drive(g) == 4


def test_write_bytes_checked_or_debug(mem):
    m, debug = _mem(mem, lambda cpu, addr, buf, n: 0)
    assert drive(m.write_bytes(0x5000, b"data")) == 4 and not debug
    m, debug = _mem(mem, None)
    assert drive(m.write_bytes(0x6000, b"data")) == 4 and debug == [0x6000]
