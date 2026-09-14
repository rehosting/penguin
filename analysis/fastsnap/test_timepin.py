#!/usr/bin/env python3
"""Drive timepin on the host, before spending a boot on it.

The failure this file exists to catch is a clock that LOOKS pinned. A plugin
that answers every `gettimeofday` from a virtual clock, and then lets that
clock run forward across laps, produces exactly the divergence it was added to
remove -- while reporting that it pinned N calls. So the assertions below are
mostly about REWIND: that the second traversal of a span reads the same instants
as the first, byte for byte.

Run: python3 analysis/fastsnap/test_timepin.py
"""
import ast
import pathlib
import struct
import sys
import tempfile
import types

HERE = pathlib.Path(__file__).resolve().parent


class FakeMem:
    def __init__(self):
        self.writes = []
        self.contents = {}

    def write_bytes(self, addr, data):
        self.writes.append((int(addr), bytes(data)))
        self.contents[int(addr)] = bytes(data)
        return iter(())


class FakeSyscall:
    """`skip_syscall` starts False on purpose: a test that pre-set it True
    would pass a plugin that never suppresses the real syscall."""

    def __init__(self, retval=-1):
        self.retval = retval
        self.skip_syscall = False


class FakeLogger:
    def __init__(self):
        self.warnings = []
        self.infos = []

    def info(self, *a):
        self.infos.append(" ".join(str(x) for x in a))

    def warning(self, *a):
        self.warnings.append(" ".join(str(x) for x in a))

    def error(self, *a):
        self.warnings.append(" ".join(str(x) for x in a))

    def debug(self, *a):
        pass


def load_class():
    tree = ast.parse((HERE / "timepin.py").read_text())
    keep = [n for n in tree.body
            if isinstance(n, ast.Import) and n.names[0].name == "struct"]
    assigns = [n for n in tree.body if isinstance(n, ast.Assign)
               and getattr(n.targets[0], "id", "") in ("USEC", "NSEC")]
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef))
    cls.bases = []
    mod = types.ModuleType("timepin_under_test")
    sys.modules["timepin_under_test"] = mod
    body = ast.Module(body=keep + assigns + [cls], type_ignores=[])
    exec(compile(ast.fix_missing_locations(body), "timepin_under_test", "exec"),
         mod.__dict__)
    return mod.__dict__[cls.name], mod


def make(tmpdir, lap_available=True, **args):
    cls, mod = load_class()
    mem = FakeMem()
    registered = []

    class FakeSyscalls:
        def syscall(self, name, **kw):
            def deco(fn):
                # Two syscalls are architecture-optional and the plugin must
                # survive their absence, so the fake refuses them the way a
                # real target without them would.
                if name in ("on_sys_time_enter", "on_sys_clock_gettime64_enter",
                            "on_sys_alarm_enter") and args.get("no_optional"):
                    raise KeyError(name)
                registered.append((name, kw))
                return fn
            return deco

    fake = types.SimpleNamespace(syscalls=FakeSyscalls(), mem=mem)
    if lap_available:
        fake.fastloop = object()
        fake.subscribe = lambda *a, **k: None
    mod.plugins = fake
    mod.syscalls = fake.syscalls

    class Harnessed(cls):
        def __init__(self):
            self.logger = FakeLogger()
            self._args = dict(outdir=str(tmpdir), comm="v")
            self._args.update({k: v for k, v in args.items()
                               if k != "no_optional"})
            super().__init__()

        def get_arg(self, k):
            return self._args.get(k)

    return Harnessed(), mem, registered


def gtod(p, addr=0x1000):
    sc = FakeSyscall()
    list(p.on_gettimeofday(None, None, sc, addr, 0))
    return sc


def main():
    tmp = tempfile.mkdtemp()
    n = 0

    def ok(cond, msg):
        nonlocal n
        assert cond, msg
        n += 1

    # ---- WHAT IT REGISTERS -------------------------------------------
    p, mem, reg = make(tmp)
    names = [x for x, _ in reg]
    ok("on_sys_gettimeofday_enter" in names, names)
    ok("on_sys_clock_gettime_enter" in names, names)
    ok("on_sys_nanosleep_enter" in names, names)
    ok("on_sys_clock_nanosleep_enter" in names, names)

    # 0 must actually disable. `x or default` made snapfeed's `mutate: 0`
    # unreachable; the same helper is used here and the same trap applies.
    p0, _, reg0 = make(tmp, pin_time=0)
    ok(not any("gettimeofday" in x for x, _ in reg0),
       "pin_time=0 still registered the clock hooks: " + str(reg0))
    ok(any("nanosleep" in x for x, _ in reg0),
       "pin_time=0 wrongly disabled sleep collapse too")
    p1, _, reg1 = make(tmp, collapse_sleep=0)
    ok(not any("nanosleep" in x for x, _ in reg1),
       "collapse_sleep=0 still registered the sleep hooks: " + str(reg1))

    # An architecture without time()/alarm()/clock_gettime64 must not take the
    # plugin down on registration.
    pO, _, regO = make(tmp, no_optional=True)
    ok(any("gettimeofday" in x for x, _ in regO),
       "a missing optional syscall killed the mandatory hooks")

    # ---- IT ACTUALLY ANSWERS -----------------------------------------
    p, mem, _ = make(tmp, base_s=1000, tick_us=1000)
    sc = gtod(p)
    ok(sc.skip_syscall is True, "the real gettimeofday was left to run")
    ok(sc.retval == 0, sc.retval)
    ok(len(mem.writes) == 1, mem.writes)
    addr, data = mem.writes[0]
    ok(addr == 0x1000, addr)
    sec, usec = struct.unpack("<ii", data)
    ok(sec == 1000, f"base_s ignored: {sec}")
    ok(usec == 0, usec)

    # A NULL timeval must not be written to. Writing to 0 would fault the
    # guest on a call that is legal.
    before = len(mem.writes)
    sc = gtod(p, addr=0)
    ok(len(mem.writes) == before, "wrote through a NULL timeval")
    ok(sc.skip_syscall is True, "NULL timeval left the syscall running")

    # ---- IT ADVANCES WITHIN A LAP ------------------------------------
    p, mem, _ = make(tmp, base_s=1000, tick_us=1000)
    gtod(p); gtod(p); gtod(p)
    vals = [struct.unpack("<ii", d)[1] for _, d in mem.writes]
    ok(vals == [0, 1000, 2000], f"clock did not tick by tick_us: {vals}")
    ok(all(b > a for a, b in zip(vals, vals[1:])),
       "a frozen clock wedges `while (time(NULL) < deadline)`")

    # ---- AND REWINDS ACROSS ONE -- THE WHOLE POINT -------------------
    p, mem, _ = make(tmp, base_s=1000, tick_us=1000)
    for _ in range(3):
        gtod(p)
    first = [d for _, d in mem.writes]
    p.on_lap()
    mem.writes.clear()
    for _ in range(3):
        gtod(p)
    second = [d for _, d in mem.writes]
    ok(first == second,
       "the replayed span read different instants than the traversal it is "
       f"compared against: {first} vs {second}")
    ok(p.n_lap_resets == 1, p.n_lap_resets)

    # Without the rewind it must NOT match -- otherwise the test above would
    # pass on a plugin whose clock never moved at all.
    p, mem, _ = make(tmp, base_s=1000, tick_us=1000)
    for _ in range(3):
        gtod(p)
    a = [d for _, d in mem.writes]
    mem.writes.clear()
    for _ in range(3):
        gtod(p)
    ok(a != [d for _, d in mem.writes],
       "the clock does not advance at all, so the rewind test is vacuous")

    # ---- UNITS -------------------------------------------------------
    # clock_gettime is nanoseconds, gettimeofday microseconds. Getting this
    # wrong is silent and makes the guest see a clock 1000x off.
    p, mem, _ = make(tmp, base_s=1000, tick_us=1000)
    sc = FakeSyscall()
    list(p.on_clock_gettime(None, None, sc, 0, 0x2000))
    sec, nsec = struct.unpack("<ii", mem.writes[0][1])
    ok(sec == 1000 and nsec == 0, (sec, nsec))
    sc = FakeSyscall()
    list(p.on_clock_gettime(None, None, sc, 0, 0x2000))
    sec, nsec = struct.unpack("<ii", mem.writes[1][1])
    ok(nsec == 1_000_000, f"clock_gettime returned microseconds, not nanos: {nsec}")

    # ---- WORD SIZE AND BYTE ORDER ------------------------------------
    p, mem, _ = make(tmp, base_s=1000, word=8)
    gtod(p)
    ok(len(mem.writes[0][1]) == 16, f"64-bit timeval was {len(mem.writes[0][1])} bytes")
    p, mem, _ = make(tmp, base_s=1000, endian=">")
    gtod(p)
    ok(struct.unpack(">ii", mem.writes[0][1])[0] == 1000,
       "big-endian target got little-endian fields")

    # ---- SLEEPS ------------------------------------------------------
    p, mem, _ = make(tmp)
    sc = FakeSyscall()
    list(p.on_nanosleep(None, None, sc, 0x10, 0x20))
    ok(sc.skip_syscall is True and sc.retval == 0, (sc.skip_syscall, sc.retval))
    ok(mem.contents[0x20] == struct.pack("<ii", 0, 0),
       "a collapsed sleep left a stale remainder, so a retry loop sleeps on garbage")
    ok(p.n_sleep == 1, p.n_sleep)

    before = len(mem.writes)
    sc = FakeSyscall()
    list(p.on_nanosleep(None, None, sc, 0x10, 0))
    ok(len(mem.writes) == before, "wrote through a NULL remainder")
    ok(sc.skip_syscall is True, "NULL remainder left the sleep running")

    sc = FakeSyscall()
    list(p.on_clock_nanosleep(None, None, sc, 0, 0, 0x10, 0x20))
    ok(sc.skip_syscall is True, "clock_nanosleep was not collapsed")

    # collapse_sleep=0 must leave the sleep alone AND say so.
    p, mem, _ = make(tmp, collapse_sleep=0)
    sc = FakeSyscall()
    list(p.on_nanosleep(None, None, sc, 0x10, 0x20))
    ok(sc.skip_syscall is False, "collapse_sleep=0 still collapsed the sleep")
    ok(p.n_sleep_pass == 1, p.n_sleep_pass)

    # ---- THE CAP -----------------------------------------------------
    # A collapsed sleep turns a waiting guest into a spinning one. Unbounded,
    # a retry loop whose condition never comes true spins for the whole lap.
    p, mem, _ = make(tmp, max_collapse=3)
    for _ in range(5):
        sc = FakeSyscall()
        list(p.on_nanosleep(None, None, sc, 0x10, 0))
    ok(p.n_sleep == 3, f"the per-lap collapse cap did not hold: {p.n_sleep}")
    ok(p.n_sleep_pass == 2, p.n_sleep_pass)
    ok(sc.skip_syscall is False, "past the cap the sleep must really run")
    p.on_lap()
    sc = FakeSyscall()
    list(p.on_nanosleep(None, None, sc, 0x10, 0))
    ok(sc.skip_syscall is True, "the cap was not rewound with the lap")

    # ---- REPRODUCIBILITY ---------------------------------------------
    a, mema, _ = make(tmp, base_s=1234.5, tick_us=7)
    b, memb, _ = make(tmp, base_s=1234.5, tick_us=7)
    for _ in range(4):
        gtod(a); gtod(b)
    ok([d for _, d in mema.writes] == [d for _, d in memb.writes],
       "a fixed base_s did not reproduce across instances")

    # ---- THE WAYS IT CAN BE QUIETLY WRONG ----------------------------
    p, _, _ = make(tmp, lap_available=False)
    ok(p.lap_subscribed is False, "the fake lap event was supposed to be absent")
    ok(any("NOT rewound" in w for w in p.logger.warnings),
       "pinning without rewinding was not warned about: " + str(p.logger.warnings))

    p, _, _ = make(tmp, lap_available=False, pin_time=0)
    ok(not p.logger.warnings,
       "warned about an unrewound clock while the clock was off: "
       + str(p.logger.warnings))

    p, _, _ = make(tmp)
    p.uninit()
    ok(any("NOTHING asked for the time" in w for w in p.logger.warnings),
       "a run where no hook ever fired reported clean: " + str(p.logger.warnings))

    p, mem, _ = make(tmp)
    gtod(p)
    p.uninit()
    ok(not any("NOTHING asked" in w for w in p.logger.warnings),
       "warned about a silent run that was not silent")

    print(f"timepin: {n} assertions passed")


if __name__ == "__main__":
    main()
