#!/usr/bin/env python3
"""Drive snapfeed on the host, before spending a boot on it.

The failure this file exists to catch is not a crash. It is a feeder that
feeds nothing while the loop around it reports a magnificent rate -- which has
already happened once in this lane: 200,000 laps at 0.294 ms and 3,396 exec/s,
for a guest nothing was being injected into. So the assertions here are about
whether the delivery ACTUALLY HAPPENED and whether a run that delivered nothing
says so, not merely about not raising.

Run: python3 analysis/fastsnap/test_snapfeed.py
"""
import ast
import json
import pathlib
import sys
import tempfile
import types

HERE = pathlib.Path(__file__).resolve().parent


class FakeMem:
    """Guest memory, and a record of every write into it."""

    def __init__(self):
        self.writes = []        # (addr, bytes)
        self.contents = {}

    def write_bytes(self, addr, data):
        self.writes.append((int(addr), bytes(data)))
        self.contents[int(addr)] = bytes(data)
        return iter(())         # a generator, as the real API is

    def read_bytes(self, addr, size=0):
        yield
        return self.contents.get(int(addr), b"")[:size]


class FakeSyscall:
    """What the driver hands the hook, and what it reads back afterwards.

    `skip_syscall` starting False is the important part: a test that
    pre-set it True would pass a plugin that never suppresses the real read,
    which is the single thing this plugin exists to do.
    """

    def __init__(self, retval=0):
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


def load_class():
    tree = ast.parse((HERE / "snapfeed.py").read_text())
    keep = [n for n in tree.body
            if isinstance(n, ast.Import)
            and n.names[0].name in ("json", "os", "random", "time")]
    assigns = [n for n in tree.body if isinstance(n, ast.Assign)
               and getattr(n.targets[0], "id", "") in ("SEEDS", "HEADERS")]
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef))
    cls.bases = []
    mod = types.ModuleType("snapfeed_under_test")
    sys.modules["snapfeed_under_test"] = mod
    body = ast.Module(body=keep + assigns + [cls], type_ignores=[])
    exec(compile(ast.fix_missing_locations(body), "snapfeed_under_test", "exec"),
         mod.__dict__)
    return mod.__dict__[cls.name], mod


def make(tmpdir, **args):
    cls, mod = load_class()
    mem = FakeMem()
    registered = []

    class FakeSyscalls:
        def syscall(self, name, **kw):
            def deco(fn):
                registered.append(name)
                return fn
            return deco

    fake_plugins = types.SimpleNamespace(syscalls=FakeSyscalls(), mem=mem)
    mod.plugins = fake_plugins
    mod.syscalls = fake_plugins.syscalls

    class Harnessed(cls):
        def __init__(self):
            self.logger = FakeLogger()
            self._args = dict(outdir=str(tmpdir), comm="v")
            self._args.update(args)
            super().__init__()

        def get_arg(self, k):
            return self._args.get(k)

    p = Harnessed()
    return p, mem, registered


def feed(p, fd, buf, count, retval=0):
    """Drive the enter hook to completion and hand back the syscall object."""
    sc = FakeSyscall(retval)
    list(p.on_read_enter(None, None, sc, fd, buf, count))
    return sc


def main():
    tmp = tempfile.mkdtemp()

    # ---- THE HOOKS IT CLAIMS TO REGISTER ------------------------------
    p, mem, registered = make(tmp)
    assert "on_sys_read_enter" in registered, registered
    assert "on_sys_accept_return" in registered, registered
    assert "on_sys_accept4_return" in registered, registered
    assert not any("read_return" in r for r in registered), (
        "hooking read RETURN would mean the real read already ran and the "
        "host-side dependence this plugin removes is still there: " + str(registered))
    print("ok  snapfeed: hooks read ENTER, not read return")

    # ---- LEARNING THE CONNECTION FDS ----------------------------------
    p, mem, _ = make(tmp)
    p.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    assert p.fds == {7} and p.n_accept == 1, (p.fds, p.n_accept)
    p.on_accept(None, None, FakeSyscall(retval=-9), 3, 0, 0)
    assert p.fds == {7} and p.n_accept == 1, (
        "a failed accept must not put -9 in the fd set")
    print("ok  snapfeed: connection fds come from accept, and a failed accept "
          "adds nothing")

    # ---- THE DELIVERY -------------------------------------------------
    p, mem, _ = make(tmp)
    p.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    sc = feed(p, 7, 0x1000, 4096)
    assert mem.writes, "nothing was written into the guest buffer"
    addr, payload = mem.writes[-1]
    assert addr == 0x1000, addr
    assert sc.retval == len(payload), (sc.retval, len(payload))
    assert sc.skip_syscall is True, (
        "the real read() still runs, so the guest still depends on host-side "
        "data and the reset still cannot rewind the iteration")
    assert p.n_sent == 1, p.n_sent
    print(f"ok  snapfeed: a read on a learned fd is answered from guest RAM "
          f"({len(payload)} bytes) and the real syscall is skipped")

    # ---- AND THE READS IT MUST NOT TOUCH ------------------------------
    p, mem, _ = make(tmp)
    p.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    sc = feed(p, 9, 0x2000, 4096)          # a file, not the connection
    assert not mem.writes, mem.writes
    assert sc.skip_syscall is False, (
        "skipping a read this plugin did not answer loses the guest's data")
    assert sc.retval == 0 and p.n_sent == 0
    assert p.n_unmatched == 1, p.n_unmatched
    print("ok  snapfeed: a read on an unlearned fd is left entirely alone")

    # A zero-length read is not a delivery opportunity.
    sc = feed(p, 7, 0x3000, 0)
    assert sc.skip_syscall is False and p.n_sent == 0
    print("ok  snapfeed: a zero-length read is not fed")

    # ---- BUFFER BOUND -------------------------------------------------
    # Writing past `count` corrupts the guest heap and manufactures crashes
    # that are the harness's fault, not the target's.
    p, mem, _ = make(tmp)
    p.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    for limit in (8, 16, 64, 300):
        sc = feed(p, 7, 0x1000, limit)
        _, payload = mem.writes[-1]
        assert len(payload) <= limit, (len(payload), limit)
        assert sc.retval <= limit, (sc.retval, limit)
    print("ok  snapfeed: every payload is truncated to the size the guest asked for")

    # ---- PASSTHROUGH IS OFF BY DEFAULT --------------------------------
    # A passthrough read goes to the host, which is the one thing this plugin
    # exists to remove from the iteration.
    p, mem, _ = make(tmp)
    assert p.passthrough == 0.0, p.passthrough
    p.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    for _ in range(200):
        sc = feed(p, 7, 0x1000, 4096)
        assert sc.skip_syscall is True
    assert p.n_pass == 0 and p.n_sent == 200, (p.n_pass, p.n_sent)
    print("ok  snapfeed: with the default config NOTHING reaches the host")

    p, mem, _ = make(tmp, passthrough=1.0)
    p.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    sc = feed(p, 7, 0x1000, 4096)
    assert sc.skip_syscall is False and p.n_pass == 1 and p.n_sent == 0
    print("ok  snapfeed: passthrough=1.0 hands every read back to the host")

    # ---- DETERMINISM --------------------------------------------------
    a, mem_a, _ = make(tmp, seed=99)
    b, mem_b, _ = make(tmp, seed=99)
    for q in (a, b):
        q.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    for _ in range(25):
        feed(a, 7, 0x1000, 4096)
        feed(b, 7, 0x1000, 4096)
    assert [w[1] for w in mem_a.writes] == [w[1] for w in mem_b.writes], \
        "same seed produced different payloads; a crash could not be replayed"
    print("ok  snapfeed: the same seed delivers byte-identical payloads")

    # mutate=0 delivers a seed unchanged, so a control run is a control.
    p, mem, _ = make(tmp, mutate=0)
    p.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    feed(p, 7, 0x1000, 4096)
    assert mem.writes[-1][1] in [s[:4096] for s in load_class()[1].SEEDS], \
        mem.writes[-1][1]
    print("ok  snapfeed: mutate=0 delivers an unmutated seed")

    # ---- THE CONTROL THAT MATTERS -------------------------------------
    # A feeder that fed nothing must say so, loudly, in a file the loop's
    # reader will see. Silence here looks exactly like a very fast loop.
    p, mem, _ = make(tmp)
    for _ in range(3):
        feed(p, 9, 0x2000, 4096)           # never a learned fd
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "snapfeed.json"))
    assert out["n_sent"] == 0
    assert out["verdict"].startswith("FED NOTHING"), out["verdict"]
    assert "unfed guest" in out["verdict"], out["verdict"]
    print("ok  snapfeed: a run that fed nothing says FED NOTHING, in the file")

    # Fed, but the victim never answered -- also not a clean result.
    p, mem, _ = make(tmp)
    p.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    feed(p, 7, 0x1000, 4096)
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "snapfeed.json"))
    assert "wrote NO parseable response" in out["verdict"], out["verdict"]
    print("ok  snapfeed: fed-but-silent is called out, not reported as clean")

    # The healthy case, with a response tallied.
    p, mem, _ = make(tmp)
    p.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    feed(p, 7, 0x1000, 4096)
    mem.contents[0x5000] = b"HTTP/1.1 200 OK\r\n"
    list(p.on_writev(None, None, FakeSyscall(retval=17), 7, 0x5000, 1))
    assert p.responses == {"200": 1}, p.responses
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "snapfeed.json"))
    assert out["verdict"].startswith("fed 1 inputs"), out["verdict"]
    assert out["responses"] == {"200": 1}, out
    print("ok  snapfeed: a healthy run reports what the victim answered")

    # ---- THE WARNING WHILE THE RUN IS STILL GOING ---------------------
    p, mem, _ = make(tmp)
    for _ in range(2000):
        feed(p, 9, 0x2000, 4096)
    assert any("NOT ONE on a learned connection fd" in w
               for w in p.logger.warnings), p.logger.warnings
    print("ok  snapfeed: it warns mid-run, not only in the post-mortem")

    print("\nPASS")


if __name__ == "__main__":
    main()
