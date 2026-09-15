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
        self.ptrs = {}

    def write_bytes(self, addr, data):
        self.writes.append((int(addr), bytes(data)))
        self.contents[int(addr)] = bytes(data)
        return iter(())         # a generator, as the real API is

    def read_bytes(self, addr, size=0):
        yield
        return self.contents.get(int(addr), b"")[:size]

    def read_ptr(self, addr):
        """Guest pointer read. Unset addresses return 0, the way a read of
        unmapped-but-zeroed memory would."""
        yield
        return self.ptrs.get(int(addr), 0)


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
                registered.append((name, kw))
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
    names = [n for n, _ in registered]
    assert "on_sys_read_enter" in names, names
    assert "on_sys_accept_return" in names, names
    assert "on_sys_accept4_return" in names, names
    assert "on_sys_recv_enter" in names, (
        "a victim that takes its sockets with recv() is fed nothing: target C "
        "accepted 556 connections and issued 8 read() calls, none on a learned "
        "fd. " + str(names))
    assert "on_sys_recvfrom_enter" in names, names
    assert "on_sys_writev_enter" in names, names
    assert "on_sys_write_enter" in names, (
        "a victim that answers with write() instead of writev() would tally "
        "no responses, and the wedged-victim control would fire on a healthy "
        "run: " + str(names))
    assert not any("writev_return" in n for n in names), (
        "hooking writev RETURN means the response already went to a socket "
        "whose peer exclusive mode has frozen: " + str(names))
    assert not any("read_return" in n for n in names), (
        "hooking read RETURN would mean the real read already ran and the "
        "host-side dependence this plugin removes is still there: " + str(names))
    print("ok  snapfeed: hooks read ENTER, not read return")

    # THE PIN HAS TO BE ASKED FOR.
    # The driver's pin is inert unless a hook sets pin_filter_enabled, and a
    # pin that nothing consults reports active=1 with hits_in=0 and hits_out=0
    # -- which is exactly what a correctly-working pin would look like if you
    # only checked that it was set. Measured on a real run before this
    # assertion existed.
    p2, _, reg2 = make(tmp, pin_filter=1)
    assert all(kw.get("pin_filter") for _, kw in reg2), reg2
    p3, _, reg3 = make(tmp)
    assert not any(kw.get("pin_filter") for _, kw in reg3), reg3
    print("ok  snapfeed: pin_filter=1 makes every hook opt into the pin, and "
          "the default asks for nothing")

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
    #
    # The iovec layout is the point. `iov` is an ARRAY OF IOVECS, so the
    # payload is behind one pointer indirection. Reading `iov` directly
    # returns the struct's own bytes, which never start with "HTTP/", and the
    # tally is then silently always empty -- the control that catches a wedged
    # victim would read "no responses" on a perfectly healthy one. This
    # fixture only resolves if the plugin follows the pointer.
    p, mem, _ = make(tmp)
    p.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    feed(p, 7, 0x1000, 4096)
    mem.ptrs[0x5000] = 0x6000          # iov[0].iov_base
    mem.ptrs[0x5004] = 17              # iov[0].iov_len
    mem.contents[0x6000] = b"HTTP/1.1 200 OK\r\n"
    mem.contents[0x5000] = b"\x00\x60\x00\x00\x11\x00\x00\x00"   # the struct bytes
    sc = FakeSyscall()
    list(p.on_writev_enter(None, None, sc, 7, 0x5000, 1))
    assert p.responses == {"200": 1}, (
        f"{p.responses} -- the tally read the iovec struct instead of "
        f"following iov_base")
    # Swallowing is OFF by default: with a live client, output drives input.
    # Measured on target B, where swallowing the response stopped the client
    # pipelining and moved the forward gaps from ~183 ms to ~1038 ms.
    assert sc.skip_syscall is False, (
        "swallowing by default starves a live client of the response it "
        "needs before sending the next request")
    print("ok  snapfeed: the response tally follows iov_base, and the write "
          "is NOT swallowed by default")

    q2, qmem2, _ = make(tmp, swallow_writes=1)
    q2.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    qmem2.ptrs[0x5000] = 0x6000
    qmem2.ptrs[0x5004] = 17
    qmem2.contents[0x6000] = b"HTTP/1.1 200 OK\r\n"
    sc = FakeSyscall()
    list(q2.on_writev_enter(None, None, sc, 7, 0x5000, 1))
    assert sc.skip_syscall is True and sc.retval == 17, (sc.retval, sc.skip_syscall)
    print("ok  snapfeed: swallow_writes=1 skips the write, for exclusive mode "
          "where the peer is frozen and cannot drain the socket")

    # ---- THE CENSUS ---------------------------------------------------
    # Three hypotheses about where the victim waits have been wrong, each
    # costing a build and a run. The census counts without intervening, so
    # the next run NAMES the blocking syscall instead of testing another guess.
    # ...but it is OFF by default, because it is not free. Each of those
    # fifteen hooks costs a full portal round trip -- ~93 us measured, against
    # an unhooked syscall's 1.16 us -- on syscalls a busy server makes
    # constantly. The Python body really is one increment; getting to the body
    # is the 93 us. This asserts the default, because the cost of the old
    # default was invisible precisely because nothing asserted anything.
    off, _, offreg = make(tmp)
    offnames = [n for n, _ in offreg]
    for unwanted in ("on_sys_epoll_wait_enter", "on_sys_poll_enter",
                     "on_sys_futex_enter", "on_sys_close_enter"):
        assert unwanted not in offnames, (
            f"{unwanted} registered with census off", offnames)
    assert off.census_on is False
    # Learning connection fds must survive the census going away: it hooks
    # accept RETURN, which is a different hook from the census's accept ENTER.
    # Turning the census off must not cost snapfeed its fd table.
    for want in ("on_sys_accept_return", "on_sys_accept4_return"):
        assert want in offnames, (want, offnames)

    c, _, creg = make(tmp, census=1)
    cnames = [n for n, _ in creg]
    for want in ("on_sys_epoll_wait_enter", "on_sys_poll_enter",
                 "on_sys_accept_enter", "on_sys_nanosleep_enter"):
        assert want in cnames, (want, cnames)
    assert c.census_on is True
    print("ok  snapfeed: the census is off by default and `census: 1` "
          "restores it; accept-return fd learning is independent of it")
    # A census hook must be a generator (penguin drives every hook with
    # `yield from`) and must not touch the syscall.
    h = c._census("epoll_wait")
    sc = FakeSyscall()
    g = h(None, None, sc, 1, 2, 3)
    assert hasattr(g, "__next__"), "census hook is not a generator"
    for _ in g:
        pass
    assert c.census["epoll_wait"] == 1, c.census
    assert sc.skip_syscall is False and sc.retval == 0, (
        "a census hook intervened; it must only count")
    print("ok  snapfeed: the census counts blocking syscalls without touching "
          "them")

    for _ in range(3):
        for _ in c._census("accept")(None, None, FakeSyscall(), 1):
            pass
        for _ in c._census("accept4")(None, None, FakeSyscall(), 1):
            pass
    c.uninit()
    out = json.load(open(pathlib.Path(tmp) / "snapfeed.json"))
    assert out["census"]["epoll_wait"] == 1, out["census"]
    # Identical counts are almost certainly one syscall under two names --
    # accept/accept4 came back 542/542 on a real run. Flagged so nobody adds
    # them together.
    assert ["accept", "accept4"] in out["census_aliases"], out["census_aliases"]
    # Aliases must be caught when the counts are CLOSE, not only equal:
    # accept/accept4 came back 542/542 four times and then 734/738, which an
    # equality test misses while it is just as certainly one call under two
    # names.
    c2, _, _ = make(tmp)
    c2.census = {"accept": 734, "accept4": 738, "close": 826}
    c2.uninit()
    o2 = json.load(open(pathlib.Path(tmp) / "snapfeed.json"))
    assert ["accept", "accept4"] in o2["census_aliases"], o2["census_aliases"]
    assert ["accept", "close"] not in o2["census_aliases"], o2["census_aliases"]
    print("ok  snapfeed: near-equal counts are flagged as aliases, unrelated "
          "ones are not")
    # And the DOMINANT call is named, because a name being present is not a
    # mechanism: recvfrom appeared 6 times and was read as "this is how it
    # reads sockets" when 675 of 681 feeds came through read().
    assert out["census_top"] in ("accept", "accept4"), out["census_top"]
    print("ok  snapfeed: the census flags aliased names and names the dominant "
          "call, the two ways it was misread")

    # ---- EOF, OR THE CONNECTION NEVER ENDS ----------------------------
    # A feeder that always returns a full request never lets the victim see
    # the connection end. Measured: SIX accepts against 1,561,776 feeds on a
    # connection-per-request victim, after which the `accept` detector had
    # nothing left to fire on and the loop could not arm.
    e, emem, _ = make(tmp, feeds_per_conn=1)
    e.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    sc = feed(e, 7, 0x1000, 4096)
    assert sc.retval > 0 and e.n_sent == 1, (sc.retval, e.n_sent)
    sc = feed(e, 7, 0x1000, 4096)
    assert sc.retval == 0 and sc.skip_syscall is True, (
        f"second read on the same connection returned {sc.retval}; the victim "
        f"never sees EOF and never closes")
    assert e.n_eof == 1 and e.n_sent == 1, (e.n_eof, e.n_sent)
    print("ok  snapfeed: feeds_per_conn=1 ends the connection with EOF")

    # The fd must STILL BE LEARNED after EOF: the victim's response comes on
    # that same fd moments later. Discarding it there reported "wrote NO
    # parseable response" on a victim answering perfectly well, and left the
    # loop's replayed reads unfed.
    assert 7 in e.fds, "fd forgotten at EOF; the response will not be tallied"
    emem.ptrs[0x5000] = 0x6000
    emem.ptrs[0x5004] = 17
    emem.contents[0x6000] = b"HTTP/1.1 200 OK\r\n"
    list(e.on_writev_enter(None, None, FakeSyscall(), 7, 0x5000, 1))
    assert e.responses == {"200": 1}, e.responses
    print("ok  snapfeed: the response after EOF is still tallied on that fd")

    # accept() is what resets the allowance -- that is the event that means
    # "new connection".
    e.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    sc = feed(e, 7, 0x1000, 4096)
    assert sc.retval > 0 and e.n_sent == 2, (sc.retval, e.n_sent)
    print("ok  snapfeed: accept resets the allowance, not EOF")

    # ---- AND THE REPLAY MUST GET WHAT THE FORWARD PASS GOT -------------
    # fd_feeds lives in host Python; the guest's fd state does not. Without a
    # rewind, a replayed span that was FED a request gets EOF instead -- the
    # feeder manufacturing exactly the divergence the fidelity check exists to
    # catch.
    e2, _, _ = make(tmp, feeds_per_conn=1)
    e2.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    first = feed(e2, 7, 0x1000, 4096)
    assert first.retval > 0
    again = feed(e2, 7, 0x1000, 4096)
    assert again.retval == 0, "expected EOF before the lap reset"
    e2.on_lap()                                   # the loop rewound the guest
    replay = feed(e2, 7, 0x1000, 4096)
    assert replay.retval > 0, (
        "the replayed read got EOF where the forward pass got a request; the "
        "feeder is manufacturing the divergence")
    assert e2.n_lap_resets == 1, e2.n_lap_resets
    print("ok  snapfeed: a lap rewind restores the feed allowance, so the "
          "replay gets what the forward pass got")

    # Unlimited by default, which is right for a keep-alive victim.
    k, _, _ = make(tmp)
    assert k.feeds_per_conn == 0
    k.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    for _ in range(50):
        sc = feed(k, 7, 0x1000, 4096)
        assert sc.retval > 0
    assert k.n_eof == 0 and k.n_sent == 50
    print("ok  snapfeed: unlimited by default, for a keep-alive victim")

    # And the runaway is NAMED, not left to be inferred from a big number.
    r2, _, _ = make(tmp)
    r2.n_accept = 6
    r2.n_sent = 1561776
    r2.responses = {"200": 1}
    r2.uninit()
    o = json.load(open(pathlib.Path(tmp) / "snapfeed.json"))
    assert o["verdict"].startswith("RUNAWAY"), o["verdict"]
    assert "feeds_per_conn" in o["verdict"], o["verdict"]
    print("ok  snapfeed: 1.5M feeds across 6 connections is reported as RUNAWAY")

    # recv() feeds exactly as read() does.
    r, rmem, _ = make(tmp)
    r.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    sc = FakeSyscall()
    list(r.on_recv_enter(None, None, sc, 7, 0x1000, 4096, 0))
    assert rmem.writes and sc.skip_syscall is True, (rmem.writes, sc.skip_syscall)
    assert sc.retval == len(rmem.writes[-1][1]) and r.n_sent == 1, sc.retval
    print("ok  snapfeed: recv() is fed exactly as read() is")

    sc = FakeSyscall()
    list(r.on_recv_enter(None, None, sc, 9, 0x2000, 4096, 0))
    assert sc.skip_syscall is False and r.n_sent == 1, "fed recv on unlearned fd"
    print("ok  snapfeed: recv() on an unlearned fd is left alone")

    # ---- select(), the syscall a victim blocks in BEFORE read() -------
    # Feeding read() cannot help a victim that never reaches it. Target A gets
    # to read() directly and won 28x; target B blocks in select first and sat
    # at 1038 ms a lap while snapfeed fed perfectly well into a victim that
    # was not listening. Both vendor httpds here import exactly
    # `accept read recv select`.
    FDSET = 128

    def fdset(*fds):
        b = bytearray(FDSET)
        for fd in fds:
            b[fd >> 3] |= 1 << (fd & 7)
        return bytes(b)

    sel, smem, sreg = make(tmp)
    assert any(n.startswith("on_sys_select") or n.startswith("on_sys__newselect")
               for n, _ in sreg), sreg
    sel.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    smem.contents[0x8000] = fdset(3, 7)        # listening fd AND our conn fd
    smem.contents[0x8100] = fdset()            # write set the guest passed in
    sc = FakeSyscall()
    list(sel.on_select_enter(None, None, sc, 16, 0x8000, 0x8100, 0, 0))
    assert sc.skip_syscall is True and sc.retval == 1, (sc.skip_syscall, sc.retval)
    got = smem.contents[0x8000]
    assert (got[7 >> 3] >> (7 & 7)) & 1, "fd 7 not reported ready"
    assert not ((got[3 >> 3] >> (3 & 7)) & 1), (
        "fd 3 reported ready -- select must return ONLY descriptors this "
        "plugin can actually satisfy, and it cannot satisfy the listening fd")
    print("ok  snapfeed: select is answered for fed fds only, without reaching "
          "the host")

    # A select waiting on something else entirely is LEFT ALONE. The victim
    # may be waiting on a timer or a pipe this plugin knows nothing about, and
    # claiming readiness there corrupts its logic rather than accelerating it.
    sc = FakeSyscall()
    smem.contents[0x8000] = fdset(3, 9)
    list(sel.on_select_enter(None, None, sc, 16, 0x8000, 0, 0, 0))
    assert sc.skip_syscall is False, "answered a select with none of our fds in it"
    assert sel.n_select_pass > 0
    print("ok  snapfeed: a select on fds we cannot satisfy is left to the host")

    # nfds must be honoured: an fd above it is not in the set being asked about.
    sc = FakeSyscall()
    smem.contents[0x8000] = fdset(7)
    list(sel.on_select_enter(None, None, sc, 4, 0x8000, 0, 0, 0))
    assert sc.skip_syscall is False, "answered for fd 7 when nfds was 4"
    print("ok  snapfeed: nfds bounds which descriptors select may answer for")

    # Switchable off.
    off, _, oreg = make(tmp, answer_select=0)
    assert not any("select" in n for n, _ in oreg), oreg
    print("ok  snapfeed: answer_select=0 registers no select hook at all")

    # write(), for a victim that does not use writev at all.
    w, wmem, _ = make(tmp)
    w.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    wmem.contents[0x7000] = b"HTTP/1.0 500 Err\r\n"
    sc = FakeSyscall()
    list(w.on_write_enter(None, None, sc, 7, 0x7000, 18))
    assert w.responses == {"500": 1}, w.responses
    assert sc.skip_syscall is False, "write swallowed by default"
    print("ok  snapfeed: a victim answering with write() is tallied too")

    sc = FakeSyscall()
    list(w.on_write_enter(None, None, sc, 9, 0x7000, 18))
    assert w.responses == {"500": 1}, "tallied a write on an unlearned fd"
    print("ok  snapfeed: write() on an unlearned fd is ignored")

    # A write on an fd we do not own is not ours to swallow.
    sc = FakeSyscall()
    list(p.on_writev_enter(None, None, sc, 9, 0x5000, 1))
    assert sc.skip_syscall is False, "swallowed a write to something else"
    print("ok  snapfeed: a write on an unlearned fd is left alone")

    # Explicitly off behaves the same as the default.
    q, qmem, _ = make(tmp, swallow_writes=0)
    q.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    qmem.ptrs[0x5000] = 0x6000
    qmem.ptrs[0x5004] = 17
    qmem.contents[0x6000] = b"HTTP/1.1 404 NF\r\n"
    sc = FakeSyscall()
    list(q.on_writev_enter(None, None, sc, 7, 0x5000, 1))
    assert sc.skip_syscall is False and q.responses == {"404": 1}, (
        sc.skip_syscall, q.responses)
    print("ok  snapfeed: swallow_writes=0 still tallies but lets the write out")

    p, mem, _ = make(tmp)
    p.on_accept(None, None, FakeSyscall(retval=7), 3, 0, 0)
    feed(p, 7, 0x1000, 4096)
    mem.ptrs[0x5000] = 0x6000
    mem.ptrs[0x5004] = 17
    mem.contents[0x6000] = b"HTTP/1.1 200 OK\r\n"
    list(p.on_writev_enter(None, None, FakeSyscall(), 7, 0x5000, 1))
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
