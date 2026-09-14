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

        # A REAL registry and a REAL subscribe. A stub that swallowed both
        # would let every lap-join assertion below be written against a
        # feature that had quietly fallen back to the pid join -- the same
        # shape as an arm_progress counter name that resolves to nothing, and
        # as a fastloop publish into a namespace with no `register`.
        # Keyed by CLASS name, the way plugin_manager keys it
        # (`name = pluginclass.__name__`), with the same case-insensitive
        # accessor beside it. The first version of this stub was keyed
        # "fastloop" and every test below passed while the real run fell
        # back to the pid join, because the real key is "FastLoop".
        plugins = {}
        _subs = {}

        @staticmethod
        def get_plugin_by_name(want):
            for k, v in _Plugins.plugins.items():
                if k.lower() == want.lower():
                    return v
            return None

        @staticmethod
        def subscribe(plugin, event, cb):
            _Plugins._subs.setdefault((id(plugin), event), []).append(cb)

        @staticmethod
        def _fire(plugin, event, *a):
            for cb in _Plugins._subs.get((id(plugin), event), []):
                cb(*a)

    # Injected BEFORE the exec, because the module does
    # `syscalls = plugins.syscalls` at import time.
    mod.__dict__["plugins"] = _Plugins()
    mod.__dict__["Plugin"] = object
    exec(compile(ast.fix_missing_locations(ast.Module(body=body,
                                                     type_ignores=[])),
                 "bugbench_file", "exec"), mod.__dict__)
    return mod.__dict__[cls.name], mod


def make(tmpdir, guest, with_fastloop=False, **args):
    cls, mod = load_class(guest)
    if with_fastloop:
        mod.plugins.plugins["FastLoop"] = types.SimpleNamespace(name="FastLoop")

    class Harnessed(cls):
        def __init__(self):
            self.logger = FakeLogger()
            self._args = dict(outdir=str(tmpdir), comm="v", mode="fuzz",
                              fd_suffix="/zero", **args)
            super().__init__()

        def get_arg(self, k):
            return self._args.get(k)

    h = Harnessed()
    h._test_mod = mod
    return h


def lap(p, n, closed_by="hit"):
    """Fastloop announcing the iteration now starting."""
    mod = p._test_mod
    mod.plugins._fire(mod.plugins.plugins["FastLoop"], "on_lap", n, closed_by)


def do_crash(p, guest, pid=None, comm="v", pc=0x400123):
    ev = types.SimpleNamespace(sig=11, drop=False, pid=guest.pid if pid is None
                               else pid, pc=pc, regs=None, comm=comm)
    p.on_signal_deliver(None, ev)


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


# ---- THE PER-INPUT SCOPE ---------------------------------------------------
#
# The pid join answers "which input crashed this?" with a run-scoped table, in
# a mode where each lap is an independent execution. It is right most of the
# time and it was silently wrong for 2,786 consecutive inputs once. The lap
# boundary is the only thing that can make the answer exact, and these tests
# are about whether the exactness is real or merely asserted.


@check("without fastloop the join is unchanged, and says so")
def t_no_loop(tmp):
    # The falsifier for every test below: the fallback must still work, and
    # must not claim a scope it does not have.
    g = FakeGuest()
    p = make(tmp, g, fast=True, verify_first=0, revalidate_every=10**9)
    do_open(p, g, 3, "/dev/zero")
    do_read(p, g, 3)
    do_crash(p, g)
    row = p.attributed[-1]
    assert row["join"] == "last-input-to-pid", row
    assert row["lap"] is None, row
    assert p.sent[-1]["lap"] is None, p.sent[-1]
    assert p.n_join_lap == 0 and p.n_join_pid == 1, (p.n_join_lap, p.n_join_pid)


@check("with a lap boundary the crash joins to that lap's input, exactly")
def t_lap_join(tmp):
    g = FakeGuest()
    p = make(tmp, g, with_fastloop=True, fast=True, verify_first=0,
             revalidate_every=10**9)
    do_open(p, g, 3, "/dev/zero")
    do_read(p, g, 3)                 # binds on the first read
    lap(p, 7)
    do_read(p, g, 3)
    do_crash(p, g)
    row = p.attributed[-1]
    assert row["join"] == "lap", row
    assert row["join_exact"] is True, row
    assert row["lap"] == 7 and row["lap_inputs"] == 1, row
    assert row["input_seq"] == p.sent[-1]["seq"], (row, p.sent[-1])
    assert p.sent[-1]["lap"] == 7, p.sent[-1]


@check("a rewind with no input delivered leaves the crash unjoined, not misjoined")
def t_lap_no_input(tmp):
    # THE CASE THE PID JOIN GETS WRONG BY CONSTRUCTION. A lap that crashed
    # before any input reached the victim has no input to blame, but
    # last_by_pid still holds the PREVIOUS lap's input and would name it --
    # an input that this execution never received.
    g = FakeGuest()
    p = make(tmp, g, with_fastloop=True, fast=True, verify_first=0,
             revalidate_every=10**9)
    do_open(p, g, 3, "/dev/zero")
    do_read(p, g, 3)
    lap(p, 1)
    do_read(p, g, 3)                 # lap 1's input
    lap(p, 2)                        # lap 2 delivers nothing
    do_crash(p, g)
    row = p.attributed[-1]
    assert row["attributed"] is False, row
    assert row["lap"] == 2 and row["lap_inputs"] == 0, row
    assert "input_seq" not in row, row


@check("when the loop stops, the tail is not stamped with the lap that ended")
def t_lap_end(tmp):
    g = FakeGuest()
    p = make(tmp, g, with_fastloop=True, fast=True, verify_first=0,
             revalidate_every=10**9)
    do_open(p, g, 3, "/dev/zero")
    do_read(p, g, 3)
    lap(p, 9)
    do_read(p, g, 3)
    do_crash(p, g)
    assert p.attributed[-1]["join"] == "lap", p.attributed[-1]
    lap(p, None, "end")
    assert p.lap is None, p.lap
    do_read(p, g, 3)                 # a tail input, no loop behind it
    do_crash(p, g)
    row = p.attributed[-1]
    assert row["join"] == "last-input-to-pid", row
    assert row["lap"] is None and row["lap_inputs"] is None, row
    assert p.sent[-1]["lap"] is None, p.sent[-1]


@check("the two joins disagreeing is counted, not quietly resolved")
def t_join_disagree(tmp):
    # The cross-check. Both joins are computed whenever both exist, precisely
    # so the weaker one stops being trusted on faith: every run in this lane
    # before the boundary existed used the pid join alone and had no way to
    # know how often it named the wrong execution.
    g = FakeGuest()
    p = make(tmp, g, with_fastloop=True, fast=True, verify_first=0,
             revalidate_every=10**9)
    do_open(p, g, 3, "/dev/zero")
    do_read(p, g, 3)
    lap(p, 1)
    do_read(p, g, 3)                 # seq 1 -> pid 231
    lap(p, 2)
    # A different process gets lap 2's input; the crash is in pid 231, whose
    # last input was lap 1's. The pid join would name seq 1.
    g.pid = 999
    g.create_time = 9001
    do_open(p, g, 4, "/dev/zero")
    do_read(p, g, 4)                 # seq 2 -> pid 999
    do_crash(p, g, pid=231)
    row = p.attributed[-1]
    assert row["join"] == "lap" and row["input_seq"] == 2, row
    assert p.n_join_disagree == 1, p.n_join_disagree


@check("two inputs in one lap is not called exact, and is counted")
def t_lap_multi(tmp):
    # The lap join is exact BY CONSTRUCTION only when the lap delivered one
    # input. Claiming exactness otherwise would be the pid join wearing a
    # better name.
    g = FakeGuest()
    p = make(tmp, g, with_fastloop=True, fast=True, verify_first=0,
             revalidate_every=10**9)
    do_open(p, g, 3, "/dev/zero")
    do_read(p, g, 3)
    lap(p, 1)
    do_read(p, g, 3)
    do_read(p, g, 3)
    do_crash(p, g)
    row = p.attributed[-1]
    assert row["join"] == "lap", row
    assert row["join_exact"] is False, row
    assert row["lap_inputs"] == 2, row
    lap(p, 2)
    assert p.lap_multi == 1, p.lap_multi


@check("bugbench does not LOAD a fastloop that is not configured")
def t_no_autoload(tmp):
    # `plugins.fastloop` would load one. Standing a second measurement
    # harness up in the middle of the run it is supposed to be measuring is
    # a worse failure than not having the boundary at all.
    g = FakeGuest()
    p = make(tmp, g, fast=True, verify_first=0, revalidate_every=10**9)
    do_open(p, g, 3, "/dev/zero")
    do_read(p, g, 3)
    assert p._test_mod.plugins.plugins == {}, p._test_mod.plugins.plugins
    assert p._lap_bound is True, "the bind was never attempted"


@check("the bind is attempted once, not on every injection")
def t_bind_once(tmp):
    g = FakeGuest()
    p = make(tmp, g, with_fastloop=True, fast=True, verify_first=0,
             revalidate_every=10**9)
    do_open(p, g, 3, "/dev/zero")
    for _ in range(10):
        do_read(p, g, 3)
    subs = p._test_mod.plugins._subs
    n = sum(len(v) for k, v in subs.items() if k[1] == "on_lap")
    assert n == 1, f"subscribed {n} times"


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
