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
            # one_outstanding defaults ON in the plugin: feed a request,
            # then withhold until the victim answers. Most tests here drive
            # the feed path directly, several feeds in a row with no response
            # in between, and are about WHAT gets fed rather than about the
            # alternation. They keep the unbounded behaviour explicitly; the
            # alternation has its own tests below.
            self._args = dict(outdir=str(tmpdir), comm="v", one_outstanding=0)
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
    # NOT epoll_wait: answer_epoll registers that one functionally, to answer
    # it rather than to count it. These four are census-only, so their absence
    # is what actually distinguishes census off from census on.
    for unwanted in ("on_sys_poll_enter", "on_sys_futex_enter",
                     "on_sys_close_enter", "on_sys_nanosleep_enter"):
        assert unwanted not in offnames, (
            f"{unwanted} registered with census off", offnames)
    # ...and the functional epoll hooks are present regardless of the census.
    for want in ("on_sys_epoll_wait_enter", "on_sys_epoll_ctl_enter"):
        assert want in offnames, (want, offnames)
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

    # ---- ANSWERING epoll ------------------------------------------------
    # The select answer only helps a victim that calls select. Target A's
    # lighttpd uses epoll, so n_select came back 0 while every forward
    # traversal sat at 1048-1051 ms and the laps were flat to 0.02% -- a
    # timer, not a workload. snapfeed's own comment had already recorded the
    # select form of this at 1038 ms per lap. Same bug, one syscall over.
    q, qmem, _ = make(tmp, answer_epoll=1)
    DATA = b"\xef\xbe\xad\xde\x11\x22\x33\x44"   # the victim's payload
    EVP, EVOUT = 0x9000, 0x9100
    # epoll_ctl(ADD) is watched, not answered: it is how the payload is learnt.
    EPOLLIN_LE = (0x001).to_bytes(4, "little")
    qmem.contents[EVP] = EPOLLIN_LE + bytes(4) + DATA    # events, pad, data
    sc = FakeSyscall()
    list(q.on_epoll_ctl_enter(None, None, sc, 7, q.EPOLL_CTL_ADD, 5, EVP))
    assert q.epoll_reg[5] == (0x001, DATA), q.epoll_reg
    assert sc.skip_syscall is False, "epoll_ctl must run; it is only observed"

    # With a learned+registered fd, epoll_wait is answered without the host.
    q.fds.add(5)
    sc = FakeSyscall()
    list(q.on_epoll_wait_enter(None, None, sc, 7, EVOUT, 16))
    assert sc.skip_syscall is True and sc.retval == 1, (sc.skip_syscall, sc.retval)
    ev = qmem.contents[EVOUT]
    assert len(ev) == q.epoll_ev_size, len(ev)
    assert int.from_bytes(ev[0:4], "little") == q.EPOLLIN, ev[:4].hex()
    # THE PAYLOAD MUST COME BACK EXACTLY. lighttpd stores a pointer to its
    # connection object here and dereferences whatever epoll_wait returns; a
    # synthesised event with the right fd and the wrong data is worse than no
    # event at all.
    assert ev[q.epoll_data_off:q.epoll_data_off + 8] == DATA, ev.hex()
    print("ok  snapfeed: epoll_wait is answered for a fed fd, returning the "
          "exact data payload epoll_ctl registered")

    # An fd this plugin is NOT feeding is left alone -- the victim may be
    # waiting on a timer, a pipe or a listening socket, and claiming
    # readiness there corrupts its logic rather than accelerating it.
    q2, q2mem, _ = make(tmp, answer_epoll=1)
    q2.epoll_reg[9] = (0x001, DATA)   # registered, but never fed
    sc = FakeSyscall()
    list(q2.on_epoll_wait_enter(None, None, sc, 7, EVOUT, 16))
    assert sc.skip_syscall is False, "answered an epoll for an unfed fd"
    assert q2.n_epoll_pass == 1, q2.n_epoll_pass
    print("ok  snapfeed: an epoll_wait on fds it does not feed is left to the "
          "host")

    # EPOLL_CTL_DEL forgets, so a closed-then-reused fd cannot be answered
    # with a stale payload pointing at a freed connection object.
    q3, _, _ = make(tmp, answer_epoll=1)
    q3.epoll_reg[5] = (0x001, DATA)
    list(q3.on_epoll_ctl_enter(None, None, FakeSyscall(), 7,
                               q3.EPOLL_CTL_DEL, 5, 0))
    assert 5 not in q3.epoll_reg, q3.epoll_reg
    print("ok  snapfeed: EPOLL_CTL_DEL forgets the payload, so a reused fd is "
          "never answered with a pointer to a freed object")

    # Big-endian targets: a byte-swapped EPOLLIN is 0x01000000, which is not a
    # readiness bit the victim recognises -- it would see an event with no
    # flags and loop, looking exactly like this plugin doing nothing.
    q4, q4mem, _ = make(tmp, answer_epoll=1)
    q4._little = False
    q4.epoll_reg[5] = (0x001, DATA)
    q4.fds.add(5)
    list(q4.on_epoll_wait_enter(None, None, FakeSyscall(), 7, EVOUT, 16))
    ev = q4mem.contents[EVOUT]
    assert int.from_bytes(ev[0:4], "big") == q4.EPOLLIN, ev[:4].hex()
    print("ok  snapfeed: the events word goes out in the guest's byte order")

    # A victim that has switched to EPOLLOUT is waiting to WRITE, and saying
    # "readable" there is how this plugin starved the write path: 267,914
    # requests fed against 104 responses written, with lighttpd re-arming
    # through EPOLL_CTL_MOD 134,044 times trying to get a writable event it
    # was never given. The loop detects writev, so no responses meant no laps
    # at all -- iters=0 after ten minutes.
    q5, _, _ = make(tmp, answer_epoll=1)
    EPOLLOUT = 0x004
    q5.epoll_reg[5] = (EPOLLOUT, DATA)     # flushing a reply, not reading
    q5.fds.add(5)
    sc = FakeSyscall()
    list(q5.on_epoll_wait_enter(None, None, sc, 7, EVOUT, 16))
    assert sc.skip_syscall is False, (
        "claimed EPOLLIN for a victim waiting to write")
    assert q5.n_epoll_pass == 1, q5.n_epoll_pass
    print("ok  snapfeed: an fd whose interest is EPOLLOUT is left alone, so "
          "the victim can finish writing its response")

    # ---- ONE OUTSTANDING REQUEST ----------------------------------------
    # Invisible while the victim blocked in epoll_wait, because that wait WAS
    # the throttle: 7,224 feeds produced 4,569 responses. Answering epoll
    # removed it and the feeder turned out to have none of its own -- 328,052
    # requests fed against 85 responses written, because snapfeed answers
    # every read() and lighttpd therefore never saw a would-block, never left
    # its read loop, and never reached the writev the loop detects.
    r, rmem, _ = make(tmp, one_outstanding=1)
    r.fds.add(3)
    sc = FakeSyscall()
    list(r.on_read_enter(None, None, sc, 3, 0x1000, 512))
    assert sc.skip_syscall is True, "first request was not fed"
    assert 3 in r.pending, r.pending

    # Second read WITHOUT a response in between is left to the host, which on
    # a non-blocking socket returns EAGAIN -- the signal that sends the victim
    # off to write its reply.
    sc2 = FakeSyscall()
    list(r.on_read_enter(None, None, sc2, 3, 0x1000, 512))
    assert sc2.skip_syscall is False, "fed a second request before the first "\
                                      "was answered"
    assert r.n_withheld == 1, r.n_withheld
    # ...and epoll must agree with the read path, or the victim spins on a
    # readable event whose read then declines to feed.
    r.epoll_reg[3] = (0x001, b"12345678")
    sc3 = FakeSyscall()
    list(r.on_epoll_wait_enter(None, None, sc3, 7, 0xA000, 16))
    assert sc3.skip_syscall is False, "epoll said readable with a request "\
                                      "still outstanding"

    # The victim writes: that is the response, and the next request may go.
    rmem.ptrs[0x5000] = 0x6000
    rmem.contents[0x6000] = b"HTTP/1.1 200 OK\r\n"
    list(r.on_writev_enter(None, None, FakeSyscall(), 3, 0x5000, 1))
    assert 3 not in r.pending, r.pending
    sc4 = FakeSyscall()
    list(r.on_read_enter(None, None, sc4, 3, 0x1000, 512))
    assert sc4.skip_syscall is True, "not fed again after the response"
    print("ok  snapfeed: one outstanding request per connection -- the next "
          "feed waits for the victim's response, which is the iteration "
          "boundary the loop detects")

    # A lap rewind puts the guest back before the request was fed, so the
    # victim is NOT waiting on a response it never received. Leaving pending
    # set would withhold the replayed span's first feed and stall the lap.
    r2, _, _ = make(tmp, one_outstanding=1)
    r2.fds.add(3)
    list(r2.on_read_enter(None, None, FakeSyscall(), 3, 0x1000, 512))
    assert 3 in r2.pending
    r2.on_lap()
    assert not r2.pending, r2.pending
    sc = FakeSyscall()
    list(r2.on_read_enter(None, None, sc, 3, 0x1000, 512))
    assert sc.skip_syscall is True, "replayed span was not fed"
    print("ok  snapfeed: a lap rewind clears the outstanding set, so the "
          "replayed span gets the feed the forward pass got")

    # EVERY pass must record a reason. The first cut of this diagnostic
    # shipped with the reason-increments missing -- the counter said 2,279
    # passes and the breakdown said {} -- so a whole run was spent producing
    # an empty answer to the question it existed to settle. The invariant is
    # cheap to assert and the failure is silent without it.
    for name, setup in (
        ("no_state",    lambda q: None),                      # no fds at all
        ("disjoint",    lambda q: (q.fds.add(3),
                                   q.epoll_reg.__setitem__(9, (0x001, b"8"*8)))),
        ("outstanding", lambda q: (q.fds.add(3),
                                   q.epoll_reg.__setitem__(3, (0x001, b"8"*8)),
                                   q.pending.add(3))),
        ("no_epollin",  lambda q: (q.fds.add(3),
                                   q.epoll_reg.__setitem__(3, (0x004, b"8"*8)))),
    ):
        qq, _, _ = make(tmp, answer_epoll=1, one_outstanding=1)
        setup(qq)
        before = qq.n_epoll_pass
        list(qq.on_epoll_wait_enter(None, None, FakeSyscall(), 7, 0xB000, 16))
        assert qq.n_epoll_pass == before + 1, name
        assert sum(qq._epass.values()) == 1, (name, qq._epass)
        assert qq._epass.get(name) == 1, (name, qq._epass)
    print("ok  snapfeed: every epoll pass records WHY -- no_state, disjoint, "
          "outstanding and no_epollin are distinguishable rather than one "
          "undifferentiated counter")

    # ---- keep-alive: the feeder must not ask for a connection it cannot
    # replace ------------------------------------------------------------
    #
    # snapfeed feeds ACCEPTED fds and cannot synthesise accept(). Run 103 put
    # that beyond argument: one held-open connection, a feed that closed it,
    # and a guest left with a single socket in CLOSE_WAIT and nothing to
    # serve for the rest of the run.
    mod = load_class()[1]

    # The seed that does it, in isolation -- HTTP/1.0 with no Connection
    # header is a close by default, and it is 1 of the 5 seeds.
    assert any(b"HTTP/1.0" in seed for seed in mod.SEEDS), \
        "this test is pinned to a seed set that contains a closing request"

    q, mem, _ = make(tmp, keepalive=1, mutate=0, one_outstanding=0)
    q.fds.add(3)
    for _ in range(40):
        list(q.on_read_enter(None, None, FakeSyscall(), 3, 0x1000, 4096))
    fed = [w[1] for w in mem.writes]
    assert fed, "nothing was fed"
    assert not any(b"HTTP/1.0" in f for f in fed), \
        [f for f in fed if b"HTTP/1.0" in f][:1]
    assert not any(b": close" in f.lower() for f in fed), \
        [f for f in fed if b": close" in f.lower()][:1]
    assert q.n_keepalive_fixed > 0, "40 feeds from 5 seeds and none was fixed"
    print("ok  snapfeed: keepalive rewrites the requests that would close the "
          "connection this feeder cannot reopen")

    # OFF by default, because those closing requests are real inputs and a
    # fuzzer wants them. A silently-on normaliser would be feeding the victim
    # a narrower input set than the seed list claims.
    q, mem, _ = make(tmp, mutate=0, one_outstanding=0)
    assert q.keepalive is False
    q.fds.add(3)
    for _ in range(40):
        list(q.on_read_enter(None, None, FakeSyscall(), 3, 0x1000, 4096))
    assert any(b"HTTP/1.0" in w[1] for w in mem.writes), \
        "the closing seed must still reach the victim by default"
    assert q.n_keepalive_fixed == 0
    print("ok  snapfeed: keepalive is off by default -- the closing inputs "
          "still get fed")

    # It repairs the connection header, NOT the request. A truncated or
    # mangled request is the point of mutation; a feeder that tidied those
    # would be feeding its own seeds back.
    q, _, _ = make(tmp, keepalive=1, mutate=0, one_outstanding=0)
    mangled = q._keep_alive(b"GET / HTTP/1.0\r\nConnection: close\r\n\r", 4096)
    assert mangled == b"GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r", mangled
    assert q._keep_alive(b"GET /x HT", 4096) == b"GET /x HT", "truncation kept"
    print("ok  snapfeed: keepalive fixes the hang-up, not the mangling")

    # ---- complete_request: a request the victim cannot answer STOPS the
    # loop, it does not slow it -----------------------------------------
    #
    # one_outstanding withholds the next feed until the victim answers,
    # because the answer is the iteration boundary. mutate() truncates one op
    # in five, so without this the victim waits for a request-remainder that
    # is never coming and the loop stalls until its read-idle timeout.
    q, _, _ = make(tmp, complete_request=1, one_outstanding=0)

    # Truncated mid-headers: terminated, nothing else touched.
    got = q._complete(b"GET /index.html HTTP/1.1\r\nHos", 4096)
    assert got == b"GET /index.html HTTP/1.1\r\nHos\r\n\r\n", got

    # A request that is already complete is returned untouched, and does not
    # count as a repair.
    n = q.n_completed
    intact = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    assert q._complete(intact, 4096) == intact
    assert q.n_completed == n, "an intact request was counted as repaired"

    # Content-Length longer than the body it declares: the COUNT moves, never
    # the body. Padding would invent bytes the fuzzer did not choose.
    got = q._complete(b"POST /x HTTP/1.1\r\nContent-Length: 400\r\n\r\nAB", 4096)
    assert got == b"POST /x HTTP/1.1\r\nContent-Length: 2\r\n\r\nAB", got

    # A Content-Length the mutator turned into non-digits is left alone: the
    # victim answers that with a 400 rather than waiting, so it is already
    # answerable.
    weird = b"POST /x HTTP/1.1\r\nContent-Length: 4\x00 0\r\n\r\nAB"
    assert q._complete(weird, 4096) == weird

    # `limit` is respected even when the terminator has to be made room for.
    got = q._complete(b"GET /" + b"A" * 100, 20)
    assert len(got) == 20, len(got)
    assert got.endswith(b"\r\n\r\n"), got

    # Corruption that is NOT a completeness problem survives: junk headers,
    # oversized values, duplicated separators, a mangled request line.
    for keep in (b"GET / HTTP/1.1\r\nCookie: a,,b,,,c\r\n\r\n",
                 b"\x01\x02 / HTTP/1.1\r\nHost: x\r\n\r\n",
                 b"GET / HTTP/1.1\r\nRange: bytes=0-,-1,0-0\r\n\r\n"):
        assert q._complete(keep, 4096) == keep, keep

    # Off by default.
    q2, _, _ = make(tmp, one_outstanding=0)
    assert q2.complete_request is False
    print("ok  snapfeed: complete_request terminates a truncated request and "
          "corrects a lying Content-Length, and changes nothing else")

    corpus_tests(tmp)

    print("\nPASS")


def corpus_tests(tmp):
    """The coverage-guided corpus.

    Ordered so the negative controls carry the weight. A corpus is the
    easiest thing in this plugin to fake: any list that grows looks like
    guidance working, and a list that stays empty looks like an honest
    negative result. Both of those are wrong more often than they are right,
    so most of what follows asserts that something does NOT happen.
    """
    # ---- OFF BY DEFAULT, and off means off -----------------------------
    p, _, _ = make(tmp)
    assert p.corpus_on is False
    feed(p, 4, 0x1000, 4096)
    p.on_lap(1, "hit", 99, 2800)
    assert p.corpus == [], p.corpus
    assert p.n_corpus_draw == 0
    # Nothing is even recorded per lap when it is off: the feed path must not
    # start accumulating a list that nothing ever drains.
    assert p._lap_fed == [], p._lap_fed
    print("ok  snapfeed: the corpus is off by default, and off means it "
          "neither collects nor is drawn from")

    # ---- A LAP THAT REACHED SOMEWHERE NEW BANKS ITS INPUT --------------
    p, _, _ = make(tmp, corpus=1)
    p.fds.add(4)
    sc = feed(p, 4, 0x1000, 4096)
    fed_bytes = p._lap_fed[0][0]
    assert fed_bytes, "nothing was recorded as fed"
    p.on_lap(1, "hit", 3, 2800)
    assert p.corpus == [fed_bytes], (p.corpus, fed_bytes)
    assert p.n_corpus_add == 1
    print("ok  snapfeed: an input whose lap found new edges goes into the "
          "corpus, as the bytes the victim actually read")

    # ---- AND A LAP THAT FOUND NOTHING BANKS NOTHING --------------------
    # The control for the line above: a corpus that grew on every lap would
    # pass that assertion and be worthless.
    p, _, _ = make(tmp, corpus=1)
    p.fds.add(4)
    feed(p, 4, 0x1000, 4096)
    p.on_lap(1, "hit", 0, 2800)
    assert p.corpus == [], p.corpus
    print("ok  snapfeed: a lap that found no new edges banks nothing")

    # ---- ATTRIBUTION IS PER LAP ----------------------------------------
    # An input fed during lap N must not be banked by lap N+1's coverage.
    # Without the clear this passes silently and the corpus fills with inputs
    # credited for the NEXT lap's discoveries -- off by one, forever.
    p, _, _ = make(tmp, corpus=1)
    p.fds.add(4)
    feed(p, 4, 0x1000, 4096)
    p.on_lap(1, "hit", 0, 2800)        # lap 1 found nothing
    p.on_lap(2, "hit", 7, 2800)        # lap 2 found something, but fed nothing
    assert p.corpus == [], (
        "lap 2's novelty was credited to lap 1's input: " + str(p.corpus))
    print("ok  snapfeed: an input is only eligible for the lap it was fed "
          "into, so novelty is never credited to the previous lap's input")

    # ---- THE BOUNDARY GUARD --------------------------------------------
    # This workload's laps are bimodal. A connection-boundary lap replays a
    # guest fork+exec worth ~29,000 edges against a typical ~2,800, and it
    # reports enormous novelty that the input had nothing to do with. Those
    # are the laps a corpus rates highest, which is why the guard exists.
    p, _, _ = make(tmp, corpus=1)
    p.fds.add(4)
    for i in range(64):                       # establish the median
        p.on_lap(i, "hit", 0, 2800)
    feed(p, 4, 0x1000, 4096)
    p.on_lap(99, "hit", 26000, 29000)         # a boundary lap
    assert p.corpus == [], (
        "a 29,000-edge boundary lap was allowed into the corpus: " +
        str(p.corpus))
    assert p.n_corpus_reject_boundary == 1, p.n_corpus_reject_boundary
    print("ok  snapfeed: a connection-boundary lap is refused however new it "
          "looks, and the refusal is counted")

    # ...AND THE GUARD IS NOT SIMPLY REFUSING EVERYTHING.
    # A guard that rejected every lap would pass the assertion above and
    # silently disable the whole feature.
    p, _, _ = make(tmp, corpus=1)
    p.fds.add(4)
    for i in range(64):
        p.on_lap(i, "hit", 0, 2800)
    feed(p, 4, 0x1000, 4096)
    p.on_lap(99, "hit", 4, 3100)              # an ordinary lap
    assert len(p.corpus) == 1, (p.corpus, p.n_corpus_reject_boundary)
    assert p.n_corpus_reject_boundary == 0
    print("ok  snapfeed: an ordinary lap still gets through the boundary "
          "guard, so the guard is a filter and not an off switch")

    # ---- COVERAGE OFF READS AS 'FOUND NOTHING' UNLESS IT IS NAMED ------
    # The failure this lane keeps meeting, in its newest costume: with
    # fastloop's coverage off, new_edges arrives as None on every lap, the
    # corpus stays empty, and the run looks like a clean negative result
    # about guidance. It is a wiring fault.
    p, _, _ = make(tmp, corpus=1)
    p.fds.add(4)
    for i in range(600):
        feed(p, 4, 0x1000, 4096)
        p.on_lap(i, "hit", None, None)
    assert p.corpus == []
    assert p._cov_absent_laps == 600, p._cov_absent_laps
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "snapfeed.json"))
    assert out["corpus_verdict"].startswith("CORPUS NEVER OFFERED"), \
        out.get("corpus_verdict")
    assert "coverage: 0" in out["corpus_verdict"], out["corpus_verdict"]
    print("ok  snapfeed: a corpus run with coverage off says so in the file, "
          "instead of reporting an empty corpus as a negative result")

    # ---- DEDUP ----------------------------------------------------------
    # Driven through _corpus_lap rather than through feed(). `mutate=0` does
    # NOT make consecutive feeds identical -- the base is still drawn at
    # random from the five seeds -- and an earlier version of this test
    # assumed it did, then "failed" on correct behaviour.
    p, _, _ = make(tmp, corpus=1)
    for i in range(5):
        p._corpus_lap([(b"GET /same HTTP/1.1\r\n\r\n", "seed")], 1, 2800)
    assert len(p.corpus) == 1, p.corpus
    assert p.n_corpus_dup == 4, p.n_corpus_dup
    assert p.n_corpus_add == 1, p.n_corpus_add
    print("ok  snapfeed: the same bytes discovered twice are one entry")

    # ---- THE CAP, AND THAT EVICTION KEEPS THE DEDUP SET HONEST ---------
    # The bug worth testing for: evicting from the list without removing the
    # entry from the dedup set. The corpus then refuses to re-admit a payload
    # it no longer holds, and quietly shrinks its reachable variety over a
    # long run while every counter still looks healthy.
    p, _, _ = make(tmp, corpus=1, corpus_max=8)
    for i in range(200):
        p._corpus_lap([(b"GET /%d HTTP/1.1\r\n\r\n" % i, "seed")], 1, 2800)
    assert len(p.corpus) == 8, len(p.corpus)
    assert p.n_corpus_evict > 0, p.n_corpus_evict
    assert set(p.corpus) <= p._corpus_seen, "corpus holds bytes not in the set"
    assert len(p._corpus_seen) == len(set(p._corpus_seen))
    # Every payload still held must be re-findable; nothing in the list may
    # have been dropped from the set by an eviction of a DIFFERENT entry.
    for held in p.corpus:
        assert held in p._corpus_seen
    print("ok  snapfeed: the corpus stays at its cap by replacement, and "
          "eviction keeps the dedup set consistent with what is held")

    # ---- IT IS ACTUALLY DRAWN FROM -------------------------------------
    p, _, _ = make(tmp, corpus=1, corpus_p=1.0)
    p.corpus.append(b"GET /banked HTTP/1.1\r\nHost: x\r\n\r\n")
    base, prov = p._mutation_base()
    assert prov == "corpus", prov
    assert base == b"GET /banked HTTP/1.1\r\nHost: x\r\n\r\n"
    assert p.n_corpus_draw == 1
    # ...and at corpus_p=0 it is collected and never used, which the report
    # calls out rather than leaving as a silently inert run.
    q, _, _ = make(tmp, corpus=1, corpus_p=0.0)
    q.corpus.append(b"x")
    _, prov = q._mutation_base()
    assert prov == "seed", prov
    print("ok  snapfeed: mutation draws from the corpus at corpus_p=1 and "
          "never at corpus_p=0")

    # ---- PROVENANCE SURVIVES TO THE LAP BOUNDARY -----------------------
    # Corpus SIZE cannot say whether guidance is working -- it grows just as
    # happily when every discovery still comes from a seed. The split does.
    p, _, _ = make(tmp, corpus=1, corpus_p=1.0)
    p.fds.add(4)
    p.corpus.append(b"GET /banked HTTP/1.1\r\nHost: x\r\n\r\n")
    feed(p, 4, 0x1000, 4096)
    assert p._lap_fed[0][1] == "corpus", p._lap_fed
    p.on_lap(1, "hit", 2, 2800)
    assert p.n_new_from_corpus == 1, p.n_new_from_corpus
    assert p.n_new_from_seed == 0, p.n_new_from_seed
    print("ok  snapfeed: a discovery made from a corpus entry is counted "
          "separately from one made from a seed")

    # ---- THE LIFT RATIO, AND WHAT IT REFUSES TO REPORT -----------------
    # corpus_lift is the primary result: new edges per corpus-derived input
    # against new edges per seed-derived input, both from the same run. It
    # must be None -- not 0, not 1 -- whenever it cannot be computed, because
    # a lift of 1.0 reads as "the corpus makes no difference" and that is a
    # finding, whereas "nothing was measured" is not.
    p, _, _ = make(tmp, corpus=1)
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "snapfeed.json"))
    assert out["corpus_lift"] is None, out["corpus_lift"]

    p, _, _ = make(tmp, corpus=1)
    p.n_corpus_input, p.n_seed_input = 100, 100
    p.edges_from_corpus, p.edges_from_seed = 300, 100
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "snapfeed.json"))
    assert out["corpus_lift"] == 3.0, out["corpus_lift"]
    # A corpus that was never drawn from cannot have a lift either.
    p, _, _ = make(tmp, corpus=1)
    p.n_seed_input, p.edges_from_seed = 100, 100
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "snapfeed.json"))
    assert out["corpus_lift"] is None, out["corpus_lift"]
    print("ok  snapfeed: corpus_lift reports a ratio when both arms have "
          "inputs, and None -- never 1.0 -- when it has nothing to compare")

    # Edge attribution is skipped, but LAP attribution is kept, when a lap fed
    # more than one payload: neither can be said to have caused the coverage.
    p, _, _ = make(tmp, corpus=1)
    p._corpus_lap([(b"a", "corpus"), (b"b", "seed")], 40, 2800)
    assert p.n_multi_fed_laps == 1
    assert p.corpus == [], "a lap that fed two payloads banked one of them"
    assert p.edges_from_corpus == 0 and p.edges_from_seed == 0
    assert p.n_new_from_corpus == 0 and p.n_new_from_seed == 0
    assert p.n_corpus_input == 0 and p.n_seed_input == 0
    print("ok  snapfeed: a lap that fed two inputs attributes to neither arm "
          "and banks nothing, and says how often that happened")

    # THE WARMUP BATCH, which is the same rule doing its real job.
    # `_lap_fed` starts accumulating when the plugin does, so the first lap
    # after arming carries every feed made during warmup -- ~150 on this
    # target. Banking that batch on one lap's novelty would put a run's worth
    # of warmup traffic into the corpus in a single step.
    p, _, _ = make(tmp, corpus=1)
    p.fds.add(4)
    for _ in range(150):                 # warmup: fed, but no lap yet
        feed(p, 4, 0x1000, 4096)
    assert len(p._lap_fed) == 150, len(p._lap_fed)
    p.on_lap(1, "hit", 400, 2800)        # first lap, and it found plenty
    assert p.corpus == [], (
        f"the warmup batch was banked: {len(p.corpus)} entries")
    assert p.n_multi_fed_laps == 1
    print("ok  snapfeed: the first lap's backlog of warmup feeds is refused "
          "rather than banked wholesale on one lap's novelty")

    # ---- THE DENOMINATOR COUNTS EVERY ATTRIBUTABLE LAP -----------------
    # Not only the ones that discovered something. Counting inputs where they
    # are DRAWN would count warmup feeds -- all seed-derived, none with a lap
    # to earn edges in -- which deflates the seed arm and inflates the lift.
    # That is the one direction a bias here must not run.
    p, _, _ = make(tmp, corpus=1)
    p.fds.add(4)
    for _ in range(20):                  # warmup draws, never in a lap
        feed(p, 4, 0x1000, 4096)
    p._lap_fed = []
    for i in range(10):                  # ten laps, one input each, no news
        p._corpus_lap([(b"s%d" % i, "seed")], 0, 2800)
    assert p.n_seed_input == 10, p.n_seed_input
    assert p.n_seed_draw == 20, p.n_seed_draw
    assert p.n_seed_input < p.n_seed_draw, (
        "inputs are being counted where they are drawn, so warmup feeds are "
        "in the denominator")
    print("ok  snapfeed: the lift's denominator counts inputs at the lap "
          "boundary, so warmup feeds cannot inflate it")

    # ---- THE SIGNATURE MATCHES WHAT fastloop ACTUALLY PUBLISHES --------
    # plugin_manager's publish() calls cb(*args) with the publisher's own
    # arguments only -- no (plugin, event) prefix. This method used to name
    # its first two parameters `plugin` and `event`, which was wrong and
    # harmless only because nothing read them. Asserted positionally so the
    # names cannot drift back.
    p, _, _ = make(tmp, corpus=1)
    p.fds.add(4)
    feed(p, 4, 0x1000, 4096)
    p.on_lap(7, "signal", 5, 2900)
    assert len(p.corpus) == 1, (
        "on_lap did not read (lap, closed_by, new_edges, lap_edges) from its "
        "positional arguments")
    print("ok  snapfeed: on_lap reads the arguments fastloop actually "
          "publishes, positionally")


if __name__ == "__main__":
    main()
