#!/usr/bin/env python3
"""Drive bugbench's fd map and event-pid shortcut on the host.

Run: python3 analysis/fastsnap/test_bugbench_cache.py

WHY THIS EXISTS. The lean path removes two portal round trips per lap by
answering from a cache instead of asking the guest. Every failure mode of that
is SILENT and produces a complete, plausible, entirely wrong run:

  * a stale fd sends inputs to the dynamic loader's read of its own shared
    library and the victim never starts -- which is not hypothetical, it is
    what the FIRST design of this cache did, for 2,786 inputs, on a run that
    reported a rate;
  * a wrong pid attributes a crash to an input the crashing process never
    received, and crashes_attributed.yaml looks exactly the same;
  * an audit that treats "the instrument could not look" as "the cache is
    wrong" reports corruption on a healthy run -- which this file's subject
    also did, twice, before this test existed.

None of those raise. So the cache is driven here, against a fake guest that is
explicit about which questions were asked, and the assertions are about WHERE
each answer came from -- not merely that an answer arrived.
"""
import ast
import pathlib
import sys
import tempfile
import types

HERE = pathlib.Path(__file__).resolve().parent
PLUGIN = HERE / "bugbench.py"


class FakeGuest:
    """Counts every question asked of it, so "the cache was used" is a
    measurement rather than an inference."""

    def __init__(self):
        self.fdnames = {}         # fd -> name, as the guest sees it
        self.pid = 231
        self.create_time = 9000
        self.n_get_fd_name = 0
        self.n_get_proc = 0
        self.n_read_str = 0
        self.writes = []          # (buf, payload)
        self.blind = False        # make get_fd_name fail to resolve

    # -- plugins.osi --
    def get_fd_name(self, fd, pid=None):
        self.n_get_fd_name += 1
        if self.blind:
            return None
        return self.fdnames.get(fd)
        yield                                               # noqa: unreachable

    def get_proc(self, pid=None):
        self.n_get_proc += 1
        return types.SimpleNamespace(pid=self.pid)
        yield                                               # noqa: unreachable

    # -- plugins.mem --
    def write_bytes(self, buf, payload):
        self.writes.append((buf, bytes(payload)))
        return None
        yield                                               # noqa: unreachable

    def read_str(self, addr, pid=None):
        self.n_read_str = self.n_read_str + 1
        return self._pending_path
        yield                                               # noqa: unreachable


class FakeLogger:
    def __init__(self):
        self.errors = []

    def info(self, *a):
        pass

    def warning(self, *a):
        pass

    def error(self, *a):
        self.errors.append(" ".join(str(x) for x in a))


def load_class(guest):
    """Exec the plugin the way penguin does: into a synthetic module with the
    penguin import stripped and the stubs already in place, so the file under
    test is the one that ships."""
    tree = ast.parse(PLUGIN.read_text())
    body = [n for n in tree.body
            if not (isinstance(n, ast.ImportFrom) and n.module == "penguin")]
    cls = next(n for n in body if isinstance(n, ast.ClassDef))
    cls.bases = []
    mod = types.ModuleType("bugbench_under_test")
    sys.modules["bugbench_under_test"] = mod

    class _Sys:
        def syscall(self, *a, **k):
            return lambda fn: fn

    class _SignalMonitor:
        def register_hook(self, **k):
            pass

    class _Plugins:
        syscalls = _Sys()
        osi = guest
        mem = guest
        signals = types.SimpleNamespace(signal_name_to_num=lambda n: 11)
        signal_monitor = _SignalMonitor()

        @staticmethod
        def subscribe(*a, **k):
            pass

    # Injected BEFORE the exec, because the module does
    # `syscalls = plugins.syscalls` at import time.
    mod.__dict__["plugins"] = _Plugins()
    mod.__dict__["Plugin"] = object
    exec(compile(ast.fix_missing_locations(ast.Module(body=body,
                                                     type_ignores=[])),
                 "bugbench_file", "exec"), mod.__dict__)
    return mod.__dict__[cls.name], mod


def make(tmpdir, guest, **args):
    cls, mod = load_class(guest)

    class Harnessed(cls):
        def __init__(self):
            self.logger = FakeLogger()
            self._args = dict(outdir=str(tmpdir), comm="v", mode="fuzz",
                              fd_suffix="/zero", **args)
            super().__init__()

        def get_arg(self, k):
            return self._args.get(k)

    return Harnessed()


def _drive(gen):
    """Consume a plugin hook the way penguin's machinery does. The hooks are
    generators; calling one runs nothing at all, so a test that merely called
    it would exercise no code and pass unconditionally."""
    assert isinstance(gen, types.GeneratorType), \
        "the hook is no longer a generator; penguin yields from it"
    try:
        while True:
            next(gen)
    except StopIteration:
        pass


def syscall_obj(guest, retval=32):
    return types.SimpleNamespace(retval=retval, pid=guest.pid,
                                 create_time=guest.create_time)


def do_read(p, guest, fd, count=32):
    _drive(p.on_read(None, types.SimpleNamespace(name="read"),
                     syscall_obj(guest), fd, 0x1000, count))


def do_open(p, guest, fd, path):
    guest.fdnames[fd] = path
    guest._pending_path = path
    _drive(p.on_open_ret(None, types.SimpleNamespace(name="openat"),
                         types.SimpleNamespace(retval=fd, pid=guest.pid,
                                               create_time=guest.create_time),
                         -100, 0x2000, 0, 0))


def do_close(p, guest, fd):
    guest.fdnames.pop(fd, None)
    _drive(p.on_close(None, types.SimpleNamespace(name="close"),
                      syscall_obj(guest), fd))


OK = []


def check(name):
    def deco(fn):
        OK.append((name, fn))
        return fn
    return deco


@check("a recycled fd number does not serve the previous file's name")
def t_recycled(tmp):
    # THE HISTORICAL BUG, as a test. The dynamic loader opens libgcc as fd 3,
    # closes it, and the victim's own open() is handed 3 back. A map that
    # cannot forget injects fuzz into the loader's read of its own ELF.
    g = FakeGuest()
    p = make(tmp, g, fast=True, verify_first=0, revalidate_every=10**9)
    do_open(p, g, 3, "/igloo/dylibs/libgcc_s.so.1")
    do_read(p, g, 3)
    assert not g.writes, "injected into the dynamic loader's descriptor"
    assert p.n_skipped == 1
    do_close(p, g, 3)
    assert p._fdmap == {}, "close did not forget fd 3"
    do_open(p, g, 3, "/dev/zero")
    do_read(p, g, 3)
    assert len(g.writes) == 1, "the victim's own fd 3 got no input"
    assert p.n_sent == 1


@check("steady state asks the guest nothing: no fd walk, no current-task read")
def t_no_portal(tmp):
    g = FakeGuest()
    p = make(tmp, g, fast=True, verify_first=2, revalidate_every=10**9)
    do_open(p, g, 3, "/dev/zero")
    for _ in range(3):
        do_read(p, g, 3)
    fd0, proc0 = g.n_get_fd_name, g.n_get_proc
    for _ in range(500):
        do_read(p, g, 3)
    assert g.n_get_fd_name == fd0, \
        f"{g.n_get_fd_name - fd0} fd walks in 500 steady-state reads"
    assert g.n_get_proc == proc0, \
        f"{g.n_get_proc - proc0} current-task reads in 500 steady-state reads"
    assert p.n_sent == 503
    assert p.pid_from_event is True


@check("the event pid is checked against the guest before it is trusted")
def t_pid_checked(tmp):
    g = FakeGuest()
    p = make(tmp, g, fast=True, verify_first=50, revalidate_every=10**9)
    do_open(p, g, 3, "/dev/zero")
    for _ in range(49):
        do_read(p, g, 3)
    assert p.pid_from_event is None, "trusted the event pid before checking it"
    assert g.n_get_proc == 49, "stopped asking the guest before the check ended"
    do_read(p, g, 3)
    assert p.pid_from_event is True
    n = g.n_get_proc
    for _ in range(20):
        do_read(p, g, 3)
    assert g.n_get_proc == n, "still paying for the pid after trusting it"


@check("an event pid that disagrees with the guest is not adopted")
def t_pid_disagrees(tmp):
    # A field that is PRESENT and means something else -- a tgid where
    # signal_deliver reports a thread id -- would break the input-to-crash join
    # and nothing downstream could notice.
    g = FakeGuest()
    p = make(tmp, g, fast=True, verify_first=5, revalidate_every=10**9)
    do_open(p, g, 3, "/dev/zero")
    for _ in range(3):
        do_read(p, g, 3)
    g.pid = 999                       # the guest's answer moves; syscall.pid
    for _ in range(3):                # is read from the same fake, so make
        _drive(p.on_read(None, types.SimpleNamespace(name="read"),
                         types.SimpleNamespace(retval=32, pid=231,
                                               create_time=g.create_time),
                         3, 0x1000, 32))
    assert p.pid_from_event is False, "adopted an event pid the guest contradicts"
    n = g.n_get_proc
    do_read(p, g, 3)
    assert g.n_get_proc == n + 1, "dropped the round trip after a disagreement"


@check("an audit that cannot look is not a disagreement")
def t_audit_blind(tmp):
    # -1 is not 0, one level up: get_fd_name() returning nothing is the
    # instrument failing, and the first version of this check reported it as a
    # corrupt map on a run whose map was fine.
    g = FakeGuest()
    p = make(tmp, g, fast=True, verify_first=0, revalidate_every=4)
    do_open(p, g, 3, "/dev/zero")
    for _ in range(4):            # n_sent reaches 4, so the NEXT read audits
        do_read(p, g, 3)
    g.blind = True
    do_read(p, g, 3)                  # lands on an audit
    g.blind = False
    assert p.n_audit_blind >= 1, "the blind audit was not counted"
    assert p.cache_errors == [], f"a blind audit was charged as a disagreement: {p.cache_errors}"
    assert p._fdmap, "a blind audit dropped a map it said nothing about"


@check("an audit that finds a different file drops the map and errors")
def t_audit_disagrees(tmp):
    g = FakeGuest()
    p = make(tmp, g, fast=True, verify_first=0, revalidate_every=4)
    do_open(p, g, 3, "/dev/zero")
    for _ in range(4):            # n_sent reaches 4, so the NEXT read audits
        do_read(p, g, 3)
    g.fdnames[3] = "/igloo/dylibs/libgcc_s.so.1"
    do_read(p, g, 3)                  # lands on an audit
    assert p.cache_errors, "a map serving the wrong file passed its own audit"
    assert p._fdmap == {}, "kept a map the audit just disproved"
    assert p.logger.errors, "the disagreement was not reported as an error"


@check("a recycled pid does not inherit the previous process's descriptors")
def t_recycled_pid(tmp):
    g = FakeGuest()
    p = make(tmp, g, fast=True, verify_first=0, revalidate_every=10**9)
    do_open(p, g, 3, "/dev/zero")
    do_read(p, g, 3)
    n = g.n_get_fd_name
    g.create_time = 9001              # same pid, a different process
    g.fdnames[3] = "/igloo/dylibs/libgcc_s.so.1"
    do_read(p, g, 3)
    assert g.n_get_fd_name == n + 1, \
        "served a recycled pid from the previous process's map"
    assert len(g.writes) == 1, "injected into the new process's fd 3 unchecked"


@check("fast=false asks the guest every time, as it always did")
def t_slow_path(tmp):
    g = FakeGuest()
    p = make(tmp, g, fast=False)
    g.fdnames[3] = "/dev/zero"
    for _ in range(20):
        do_read(p, g, 3)
    assert g.n_get_fd_name == 20, f"fast=false skipped {20 - g.n_get_fd_name} walks"
    assert g.n_get_proc == 20
    assert p.n_sent == 20


if __name__ == "__main__":
    bad = 0
    for name, fn in OK:
        with tempfile.TemporaryDirectory() as tmp:
            try:
                fn(pathlib.Path(tmp))
                print(f"ok  {name}")
            except AssertionError as e:
                bad += 1
                print(f"FAIL {name}\n     {e}")
    print("\nPASS" if not bad else f"\n{bad} FAILED")
    sys.exit(1 if bad else 0)
