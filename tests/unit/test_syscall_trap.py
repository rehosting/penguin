"""Host-side tests for the Syscalls plugin's trap backend
(pyplugins/compat/syscall_trap.py): its pure-Python parts, against fakes of
the QEMU library.  The engine itself (system/penguin-syscalls.c) is tested
under QEMU."""
from pathlib import Path
from types import SimpleNamespace

import cffi
import pytest

from penguin.testing import load_module

PY = Path(__file__).resolve().parents[2] / "pyplugins"
M64 = (1 << 64) - 1


@pytest.fixture(scope="module")
def ffi():
    qc, _ = load_module(str(PY / "compat" / "qemu_compat.py"))
    f = cffi.FFI()
    f.cdef("typedef _Bool bool; typedef struct CPUState CPUState;" + qc.SYSCALL_TRAP_CDEF)
    return f


@pytest.fixture
def trap(igloo_ko_isf):
    mod, _ = load_module(str(PY / "compat" / "syscall_trap.py"), real_isf=igloo_ko_isf)
    return mod


def test_trap_event_fields(trap, ffi):
    ev = ffi.new("struct penguin_sc_event *")
    ev.hook, ev.syscall_name, ev.argc = 9, b"openat", 4
    sce = trap.TrapEvent(ffi, ffi.NULL, ev)
    assert sce.name == "openat" and sce.hook.address == 9 and sce.argc == 4
    sce.retval = M64                    # wraps as dwarffi's long does
    assert ev.retval == -1
    sce.args[1] = -1
    assert ev.args[1] == M64 and sce.args[1] == M64 and len(sce.args) == 6
    sce.skip_syscall = 1
    assert ev.skip_syscall is True


def _backend(trap, ffi, **kw):
    b = trap.TrapBackend.__new__(trap.TrapBackend)
    b.ffi, b.runs, b.wbufs, b.unsupported, b.numbers = ffi, {}, {}, set(), {}
    for k, v in kw.items():
        setattr(b, k, v)
    return b


def test_filters_as_igloo_builds_them(trap, ffi, igloo_ko_isf):
    sc, _ = load_module(str(PY / "apis" / "syscalls.py"), real_isf=igloo_ko_isf)
    VF = sc.ValueFilter
    got = {}

    def register(h):
        got["h"] = h
        got["pat"] = ffi.string(h.arg_filters[1].pattern)
        return 5
    b = _backend(trap, ffi, lib=SimpleNamespace(penguin_syscall_register=register))
    hid = b.register({"name": "openat", "on_enter": True, "procname": "x" * 20,
                      "arg_filters": [3, VF.string_endswith("status"), "/proc/",
                                      VF.range(1, 9), None, VF.bitmask_set(0xf0)],
                      "retval_filter": VF.error(), "pid_filter": 42})
    h = got["h"]
    assert hid == 5 and h.on_enter and not h.on_return
    assert ffi.string(h.name) == b"openat" and ffi.string(h.comm_filter) == b"x" * 15
    assert h.pid_filter_enabled and h.filter_pid == 42 and h.scope_filter_enabled
    f = h.arg_filters
    assert (f[0].enabled, f[0].type, f[0].value) == (True, 0, 3)
    assert f[1].type == 14 and got["pat"] == b"status" and f[1].pattern_len == 6
    assert f[2].type == 13 and f[2].pattern_len == 6
    assert (f[3].type, f[3].min_value, f[3].max_value) == (6, 1, 9)
    assert not f[4].enabled
    assert f[5].type == 9 and f[5].bitmask == 0xf0
    assert h.retval_filter.enabled and h.retval_filter.type == 8


def test_osi_filters(trap, ffi, igloo_ko_isf):
    """an fd argument's name and the exe: string filters QEMU decides"""
    sc, _ = load_module(str(PY / "apis" / "syscalls.py"), real_isf=igloo_ko_isf)
    VF = sc.ValueFilter
    got = {}

    def register(h):
        got["h"] = h
        got["fd"] = ffi.string(h.arg_filters[0].pattern)
        got["exe"] = ffi.string(h.exe_filter.pattern)
        return 6
    b = _backend(trap, ffi, lib=SimpleNamespace(penguin_syscall_register=register))
    b.register({"name": "write", "on_enter": True,
                "arg_filters": [VF.fd_path(VF.string_endswith("/dev/null")), 4],
                "exe_filter": VF.string_endswith("/httpd")})
    h = got["h"]
    f0, f1 = h.arg_filters[0], h.arg_filters[1]
    assert (f0.enabled, f0.type, f0.subject, got["fd"]) == (True, 14, 1, b"/dev/null")
    assert (f1.subject, f1.value) == (0, 4)
    assert h.exe_filter.enabled and h.exe_filter.type == 14 and got["exe"] == b"/httpd"
    assert VF.string_endswith("x").subject is None


def test_commands_and_answers(trap, ffi, igloo_ko_isf):
    portal, _ = load_module(str(PY / "hyper" / "portal.py"), real_isf=igloo_ko_isf)
    Cmd = portal.PortalCmd
    b = _backend(trap, ffi)
    assert b._command(Cmd("read", addr=-8, size=16)) == (trap.OP_READ, M64 - 7, 16, None)
    assert b._command(Cmd("read_str", addr=0x10)) == (trap.OP_READ_STR, 0x10, 0, None)
    assert b._command(Cmd("write", addr=0x20, data=b"ab")) == (trap.OP_WRITE, 0x20, 2, b"ab")
    assert b._command(Cmd("read", addr=1, size=1, pid=7)) is None   # another task
    assert b._command(Cmd("osi_proc")) is None
    cmd = ffi.new("struct penguin_sc_cmd *")
    buf = ffi.new("char[]", b"xyz")
    cmd.op, cmd.status, cmd.buf, cmd.len = trap.OP_READ, trap.PARTIAL, buf, 2
    assert b._answer(cmd) == b"xy"
    cmd.status = trap.FAIL
    assert b._answer(cmd) is None
    cmd.op, cmd.status = trap.OP_WRITE, trap.OK
    assert b._answer(cmd) is None


def test_coroutine_suspended_across_commands(trap, ffi, igloo_ko_isf):
    portal, _ = load_module(str(PY / "hyper" / "portal.py"), real_isf=igloo_ko_isf)
    seen = []

    def callback(sce):
        try:
            data = yield portal.PortalCmd("read", addr=0x1000, size=3)
            seen.append(data)
            yield portal.PortalCmd("write", addr=0x2000, data=b"ok")
            sce.retval = 7
        finally:
            seen.append("closed")

    state = SimpleNamespace(cpu=None)
    b = _backend(trap, ffi, s=SimpleNamespace(_trap_event=callback),
                 panda=SimpleNamespace(_callback_state=lambda: state))
    ev = ffi.new("struct penguin_sc_event *")
    cmd = ffi.new("struct penguin_sc_cmd *")
    ev.call = 1
    b._on_event(ffi.NULL, ev, cmd, ffi.NULL)
    assert (cmd.op, cmd.addr, cmd.size) == (trap.OP_READ, 0x1000, 3) and 1 in b.runs
    buf = ffi.new("char[]", b"abc")
    cmd.status, cmd.buf, cmd.len = trap.OK, buf, 3
    b._on_event(ffi.NULL, ev, cmd, ffi.NULL)
    assert seen == [b"abc"] and cmd.op == trap.OP_WRITE
    assert ffi.string(ffi.cast("char *", cmd.data), 2) == b"ok"
    cmd.status = trap.OK
    b._on_event(ffi.NULL, ev, cmd, ffi.NULL)
    assert cmd.op == trap.OP_NONE and ev.retval == 7 and not b.runs and not b.wbufs
    assert seen == [b"abc", "closed"] and state.cpu is None
    # the engine drops a call that waits: the coroutine is closed
    ev.call = 2
    cmd.op = trap.OP_NONE
    b._on_event(ffi.NULL, ev, cmd, ffi.NULL)
    cmd.op = trap.OP_ABORT
    b._on_event(ffi.NULL, ev, cmd, ffi.NULL)
    assert seen[-1] == "closed" and not b.runs


def test_names_at_boot(trap, ffi):
    meta = {"openat": (0x1000, 257, 4), "llseek": (0x2000, -1, 5), "fstat": (0x3000, 5, 2)}
    names = []

    def read(cs, addr, buf, n):
        for base, nr, nargs in meta.values():
            if addr in (base + 8, base + 12):
                v = nr if addr == base + 8 else nargs
                ffi.buffer(buf, 4)[:] = (v & 0xffffffff).to_bytes(4, "little")
                return True
        return False

    syms = {f"__syscall_meta__{k}": SimpleNamespace(address=v[0]) for k, v in meta.items()}
    kffi = SimpleNamespace(symbols=syms, offsetof=lambda t, f: {"syscall_nr": 8,
                                                                "nb_args": 12}[f],
                           get_symbol=lambda name: None)
    lib = SimpleNamespace(penguin_syscall_read_memory=read,
                          penguin_syscall_set_name=lambda *a: names.append(a))
    b = _backend(trap, ffi, kffi=kffi, lib=lib, native="x86_64", compat="i386", big=False)
    b._on_boot(ffi.NULL, ffi.NULL)
    assert (0, 257, b"openat", 4) in names and (0, 5, b"fstat", 2) in names
    assert not any(n[2] == b"llseek" for n in names)     # not numbered: no name
    # i386: openat is 295, fstat 108, fstat64 197 (named as the native fstat)
    assert (1, 295, b"openat", 4) in names and (1, 108, b"fstat", 2) in names
    assert (1, 197, b"fstat", 2) in names
    assert b.numbers == {"openat": 257, "fstat": 5}


def test_numbers_from_sys_call_table(trap, ffi):
    """calls without metadata get their number from the function their
    sys_call_table entry points to; sys_ni_syscall's aliases get none"""
    A, N, M, X, T = 0x1000, 0x2000, 0x3000, 0x4000, 0x9000
    syms = {"sys_call_table": T, "sys_read": A, "sys_ni_syscall": N,
            "sys_quotactl": N, "sys_mmap": M, "jiffies": X}
    table = [A, N, M, N, X, M]          # X: not a syscall function, the end
    mem = b"".join(v.to_bytes(8, "little") for v in table).ljust(512, b"\0")

    def read(cs, addr, buf, n):
        if addr != T:
            return False
        ffi.buffer(buf, n)[:] = mem[:n]
        return True

    kffi = SimpleNamespace(
        symbols={k: SimpleNamespace(address=v) for k, v in syms.items()},
        get_symbol=lambda name: SimpleNamespace(address=syms[name]) if name in syms else None)
    b = _backend(trap, ffi, kffi=kffi, big=False,
                 lib=SimpleNamespace(penguin_syscall_read_memory=read))
    b.numbers = {"read": 0}
    b._table_numbers(ffi.NULL)
    assert b.numbers == {"read": 0, "mmap": 2}
    assert b.number("mmap") == 2 and b.number("quotactl") is None


def test_inject_command_and_answer(trap, ffi):
    b = _backend(trap, ffi)
    assert b._command(trap.InjectCmd(9, (0, -1))) == (trap.OP_SYSCALL, 9, (0, M64), None)
    seen = []

    def callback(sce):
        seen.append((yield trap.InjectCmd(39, ())))
        seen.append((yield trap.InjectCmd(59, (1, 2, 3))))

    state = SimpleNamespace(cpu=None)
    b.s = SimpleNamespace(_trap_event=callback)
    b.panda = SimpleNamespace(_callback_state=lambda: state)
    ev = ffi.new("struct penguin_sc_event *")
    cmd = ffi.new("struct penguin_sc_cmd *")
    ev.call = 3
    b._on_event(ffi.NULL, ev, cmd, ffi.NULL)
    assert (cmd.op, cmd.num, list(cmd.args)) == (trap.OP_SYSCALL, 39, [0] * 6)
    cmd.status, cmd.ret = trap.OK, -38
    b._on_event(ffi.NULL, ev, cmd, ffi.NULL)
    assert seen == [-38] and (cmd.op, cmd.num, list(cmd.args)) == (
        trap.OP_SYSCALL, 59, [1, 2, 3, 0, 0, 0])
    cmd.status = trap.FAIL                      # refused: nothing ran
    b._on_event(ffi.NULL, ev, cmd, ffi.NULL)
    assert seen == [-38, None] and cmd.op == trap.OP_NONE and not b.runs


def test_syscalls_inject(trap, igloo_ko_isf):
    sc, _ = load_module(str(PY / "apis" / "syscalls.py"), real_isf=igloo_ko_isf)
    s = sc.Syscalls.__new__(sc.Syscalls)

    def run(g, answer=None):
        try:
            c = next(g)
        except StopIteration as e:
            return "returned", e.value
        try:
            g.send(answer)
        except StopIteration as e:
            return c, e.value
        raise AssertionError("more than one command")

    s._trap = None                              # the igloo backend: no injecting
    assert run(s.inject("getpid")) == ("returned", None)
    s._trap = SimpleNamespace(number={"getpid": 39}.get)
    c, v = run(s.inject("getpid"), 4242)
    assert (type(c).__name__, c.num, c.args, v) == ("InjectCmd", 39, (), 4242)
    c, v = run(s.inject(62, 7, -1), 0)
    assert (c.num, c.args) == (62, (7, M64))
    assert run(s.inject("nosuch")) == ("returned", None)
    assert run(s.inject(1, *range(7))) == ("returned", None)
