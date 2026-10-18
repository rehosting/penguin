"""Host-side tests for HostOSI (pyplugins/apis/hostosi.py): its calls'
decoding of QEMU's answers, against fakes of the ISF and the QEMU library.
The layout it gives QEMU is test_osi_layout.py's; the walks themselves
(system/penguin-osi.c) are tested under QEMU, against the guest's /proc."""
from pathlib import Path
from types import SimpleNamespace

import cffi
import pytest

from penguin.testing import drive, load_module
from osi_fakes import modern_isf

PY = Path(__file__).resolve().parents[2] / "pyplugins"


@pytest.fixture(scope="module")
def ffi():
    qc, _ = load_module(str(PY / "compat" / "qemu_compat.py"))
    f = cffi.FFI()
    f.cdef("typedef _Bool bool; typedef struct CPUState CPUState;" + qc.PENGUIN_OSI_CDEF)
    return f


@pytest.fixture
def hostosi(igloo_ko_isf):
    # the apis package's import needs hyper.consts: a real driver ISF
    mod, _ = load_module(str(PY / "apis" / "hostosi.py"), real_isf=igloo_ko_isf)
    mod.set_osi_layout.__globals__["_layout_set"].clear()
    return mod


# --- HostOSI's calls, on a fake QEMU library ---

CUR, OTHER = 0xffff888001000000, 0xffff888002000000


class FakeLib:
    """penguin_osi_*: the current task (pid 10) and another (pid 20)"""

    def __init__(self, ffi):
        self.ffi = ffi
        self.reads = []

    def penguin_osi_set_layout(self, p):
        return True

    def penguin_osi_task(self, cpu, pid):
        return {10: CUR, 20: OTHER}.get(pid, 0)

    def penguin_osi_proc(self, cpu, task, p):
        if task not in (CUR, OTHER):
            return False
        p.task, p.pid, p.tgid, p.ppid = task, 10 if task == CUR else 20, 10, 1
        p.comm = b"httpd" if task == CUR else b"worker"
        p.arg_start, p.arg_end = 0x7000, 0x7000 + len(b"/bin/httpd\0-f\0")
        p.env_start, p.env_end = 0x8000, 0x8000 + len(b"A=1\0B=x=y\0")
        p.uid, p.euid = 0, 1000
        return True

    def penguin_osi_procs(self, cpu, tasks, n):
        tasks[0], tasks[1] = CUR, OTHER
        return 2

    def _put(self, strs, off, s):
        self.ffi.memmove(strs + off, s + b"\0", len(s) + 1)
        return off + len(s) + 1

    def penguin_osi_fds(self, cpu, task, start, out, mx, strs, slen):
        names = [(0, b"/dev/null"), (3, b"socket:[1234]"), (7, b"/tmp/x (deleted)")]
        used = 0
        k = 0
        for fd, s in names:
            if fd < start or k == mx:
                continue
            out[k].fd, out[k].name, out[k].file = fd, used, 0xf000 + fd
            used = self._put(strs, used, s)
            k += 1
        return k

    def penguin_osi_fd_path(self, cpu, task, fd, buf, n):
        s = {-100: b"/www", 3: b"socket:[1234]"}.get(fd)
        if s is None:
            return -1
        self._put(buf, 0, s)
        return len(s)

    def penguin_osi_exe_path(self, cpu, task, buf, n):
        self._put(buf, 0, b"/usr/sbin/httpd")
        return 15

    def penguin_osi_mappings(self, cpu, task, out, mx, strs, slen):
        out[0].start, out[0].end, out[0].offset = 0x400000, 0x401000, 0
        out[0].perms, out[0].name = b"r-xp", 0
        used = self._put(strs, 0, b"/usr/sbin/httpd")
        out[1].start, out[1].end, out[1].perms, out[1].name = 0x500000, 0x521000, b"rw-p", used
        self._put(strs, used, b"[heap]")
        return 2

    def penguin_osi_user_read(self, cpu, task, va, buf, n):
        self.reads.append((task, va, n))
        data = {0x7000: b"/bin/wkr\0-v\0\0\0", 0x8000: b"A=1\0B=x=y\0"}[va][:n]
        self.ffi.memmove(buf, data, len(data))
        return len(data) - (va == 0x8000)          # the environment comes back short


@pytest.fixture
def osi(hostosi, ffi):
    lib = FakeLib(ffi)
    state = SimpleNamespace(task=CUR)
    mem_reads = []

    def read_bytes(addr, n):
        mem_reads.append((addr, n))
        return {0x7000: b"/bin/httpd\0-f\0", 0x8000: b"A=1\0B=x=y\0"}[addr][:n]
        yield

    hostosi.plugins = SimpleNamespace(kffi=SimpleNamespace(ffi=modern_isf()),
                                      mem=SimpleNamespace(read_bytes=read_bytes))
    o = hostosi.HostOSI.__new__(hostosi.HostOSI)
    o.panda = SimpleNamespace(ffi=ffi, lib=lib, bits=64, endianness="little",
                              arch_name="x86_64", get_cpu=lambda: ffi.NULL,
                              _callback_state=lambda: state)
    o.__init__()
    o.mem_reads, o.state = mem_reads, state
    return o


def test_rejects_other_kernels(hostosi, ffi):
    o = hostosi.HostOSI.__new__(hostosi.HostOSI)
    hostosi.plugins = SimpleNamespace(kffi=SimpleNamespace(ffi=modern_isf()))
    # 32-bit ARM is read; another 32-bit kernel is not
    o.panda = SimpleNamespace(ffi=ffi, lib=FakeLib(ffi), bits=32, endianness="little",
                              arch_name="mipsel")
    with pytest.raises(RuntimeError):
        o.__init__()


def test_proc_and_procs(osi):
    p = drive(osi.get_proc())
    assert (p.pid, p.ppid, p.name, p.euid) == (10, 1, "httpd", 1000)
    assert drive(osi.get_proc(pid=20)).name == "worker"
    assert drive(osi.get_proc(pid=99)) is None
    assert [q.pid for q in drive(osi.get_all_procs())] == [10, 20]


def test_args_env_current_through_mem(osi):
    """the current task's memory is plugins.mem's (it may fault in)"""
    assert drive(osi.get_args()) == ["/bin/httpd", "-f"]
    assert drive(osi.get_env()) == {"A": "1", "B": "x=y"}
    assert drive(osi.get_proc_name()) == "httpd"
    assert osi.mem_reads == [(0x7000, 14), (0x8000, 10), (0x7000, 14)]
    assert osi.lib.reads == []


def test_args_env_other_through_page_tables(osi):
    """another task's: QEMU's page walk, no faults; short is a failure"""
    assert drive(osi.get_args(pid=20)) == ["/bin/wkr", "-v"]
    assert drive(osi.get_env(pid=20)) is None
    assert drive(osi.get_proc_name(pid=20)) == "wkr"
    assert [r[0] for r in osi.lib.reads] == [OTHER] * 3
    assert osi.mem_reads == []


def test_fds_and_names(osi):
    fds = drive(osi.get_fds())
    assert [(f.fd, f.name, f.file) for f in fds] == [
        (0, "/dev/null", 0xf000), (3, "socket:[1234]", 0xf003), (7, "/tmp/x (deleted)", 0xf007)]
    assert [f.fd for f in drive(osi.get_fds(start_fd=1, count=1))] == [3]
    assert drive(osi.get_fd_name(3)) == "socket:[1234]"
    assert drive(osi.get_fd_name(5)) is None
    assert drive(osi.get_fd_name((1 << 64) - 1)) is None     # mmap's fd -1, as a register
    assert drive(osi.get_fd_name(3 | 0xffffffff00000000)) == "socket:[1234]"  # the low 32 bits
    assert drive(osi.get_cwd()) == "/www"
    assert drive(osi.get_proc_exe()) == "/usr/sbin/httpd"


def test_mappings(osi):
    m = drive(osi.get_mappings())
    assert [(x.base, x.size, x.perms, x.name) for x in m] == [
        (0x400000, 0x1000, "r-xp", "/usr/sbin/httpd"), (0x500000, 0x21000, "rw-p", "[heap]")]


def test_no_current_task(osi):
    """outside a syscall callback there is no current task: nothing, not garbage"""
    osi.state.task = 0
    assert drive(osi.get_proc()) is None
    assert drive(osi.get_fds()) is None
    assert drive(osi.get_args()) is None


def test_labels(osi):
    """each answer's rung label: safe-point for the current task at its trap,
    possibly-torn for another task or the process list, unavailable for None"""
    from compat.osi_label import labeled
    args, label = drive(labeled(osi, osi.get_args()))
    assert args == ["/bin/httpd", "-f"] and label[:2] == ("L0", "safe-point")
    drive(osi.get_args(pid=20))
    assert osi.last_label.consistency == "possibly-torn"
    drive(osi.get_all_procs())
    assert osi.last_label.consistency == "possibly-torn"
    assert drive(osi.get_proc(pid=99)) is None and osi.last_label.consistency == "unavailable"
    osi._smp = 2            # the task's mm may change under a sibling thread
    drive(osi.get_fds())
    assert osi.last_label.consistency == "possibly-torn"
    drive(osi.get_proc())   # its own fields do not
    assert osi.last_label.consistency == "safe-point"
