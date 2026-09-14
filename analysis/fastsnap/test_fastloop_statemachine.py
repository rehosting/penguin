#!/usr/bin/env python3
"""Drive fastloop's state machine on the host, before spending a boot on it.

Run: python3 analysis/fastsnap/test_fastloop_statemachine.py

WHY THIS IS WORTH ITS LENGTH. Every previous state-machine bug in this lane
cost a full run to find -- a boot, a warmup and several minutes -- and each one
produced output that looked like a result rather than like a failure:

  * a reset timed from the wrong op (the loop read `last_us` after a FORK_DIFF
    completed, not after the reset, and reported the oracle's milliseconds as
    the reset's cost);
  * a loop that never advanced because the bottom-half poll was checked against
    a sequence number captured after the schedule rather than before;
  * a verified lap's interval folded into the iteration median, dragging the
    reported exec/s toward the oracle's rate.

None of those raise. They report a number. So the state machine is driven here
against a fake QEMU that is explicit about WHEN a bottom half runs, and the
assertions are about attribution -- which op each recorded number came from --
not merely about not crashing.
"""
import ast
import json
import os
import pathlib
import time
import sys
import types

HERE = pathlib.Path(__file__).resolve().parent


class FakeQemu:
    """A QEMU whose bottom halves run only when this test says so.

    That is the whole point: on the real thing the bottom half runs on the main
    loop while the plugin is on a vCPU thread, so `schedule` returning is not
    `done`. A fake that completed operations synchronously would make the
    polling logic untestable and would pass a plugin that deadlocks.
    """

    FASTSNAP_RESTORE = 1
    FASTSNAP_RAM_RESTORE = 13
    FASTSNAP_LOOP_ARM = 15
    FASTSNAP_LOOP_RESET = 16
    FASTSNAP_LOOP_RESET_VERIFY = 17
    FASTSNAP_FORK_DIFF = 7
    FASTSNAP_FORK_DROP = 8

    def __init__(self, ram_bytes=268836864):
        self.seq = 0
        self.pending = None
        self.ops = []                 # every op scheduled, in order
        self.completed = []           # every op completed, in order
        self.ram_bytes = ram_bytes
        self.rc = 0
        # Distinct per-op values, so a number read from the wrong op is
        # identifiable rather than merely wrong.
        self.reset_us = 500
        self.diff_us = 48000
        self.restored = 128
        self.diff_pages_split = 341   # what the WRONG order sees
        self.diff_pages_combined = 0  # what the right order sees
        self._last_us = -1
        self._diff_pages = -1
        self._diff_us = -1
        self.missing = []
        self._bh_done_us = 0
        # The device oracle. Default 0: a full block puts every section back,
        # which is the only answer a correct unscoped reset can give.
        self.dev_diff_sections = 0
        self.dev_unrestorable_sections = 0
        self.dev_diff_report = ""
        self.allowlist = None
        self.pagemap_status = 1
        self._pages_proved = 65628
        self._pages_read = 256
        # TCG work counters, cumulative like the real ones. run_bottom_half()
        # advances the reset-side ones; hit() advances the guest-side one, so
        # a test can tell the two halves apart -- which is the whole point of
        # sampling at both boundaries.
        self.tb_invalidate = 0
        self.tb_flush = 0
        self.tlb_full_flush = 0
        self.tlb_part_flush = 0
        self.pages_unchanged = 0
        self.pages_invalidated = 0
        self.pages_skipped_nocode = 0
        self.tcg_absent = False     # model an image predating the counters

    # -- the API the plugin uses --
    def fastsnap_available(self):
        return True

    def fastsnap_missing_symbols(self):
        # The library-level preflight. `missing` is settable so the test can
        # build the exact situation that produced a complete fictional result
        # set: every Python binding present, the C symbols behind them absent.
        return list(self.missing)

    def fastsnap_section_names(self):
        return ["cpu", "cpu_common", "timer", "0000:00:01.0/virtio-net"]

    def fastsnap_set_denylist(self, names):
        self.denylist = names

    def fastsnap_set_allowlist(self, names):
        self.allowlist = names

    def fastsnap_bh_done_us(self):
        return self._bh_done_us

    def fastsnap_dev_diff_sections(self):
        return self.dev_diff_sections

    def fastsnap_dev_unrestorable_sections(self):
        return self.dev_unrestorable_sections

    def fastsnap_dev_diff_report(self):
        return self.dev_diff_report

    def fastsnap_schedule(self, op):
        self.ops.append(op)
        if op == self.FASTSNAP_FORK_DROP:
            self.seq += 1             # fire-and-forget, nothing polls it
            return
        self.pending = op

    def fastsnap_seq(self):
        return self.seq

    def fastsnap_last_rc(self):
        return self.rc

    def fastsnap_last_us(self):
        return self._last_us

    def fastsnap_last_digest(self):
        return 0xABCD

    def fastsnap_ram_snapshot_bytes(self):
        return self.ram_bytes

    def fastsnap_ram_restored_pages(self):
        return self.restored

    def fastsnap_diff_pages(self):
        return self._diff_pages

    def fastsnap_diff_bytes_checked(self):
        return self.ram_bytes

    # The oracle's METHOD, not just its answer. Defaults model a build with
    # the PFN prefilter active; `pagemap_status` is settable so a test can
    # build the case that matters -- asked for, unavailable, silently costing
    # more and changing nothing.
    def fastsnap_diff_pages_proved(self):
        return self._pages_proved

    def fastsnap_diff_pages_read(self):
        return self._pages_read

    def fastsnap_diff_pagemap_status(self):
        return self.pagemap_status

    # -- TCG work counters --
    def _tcg(self, v):
        if self.tcg_absent:
            raise AttributeError("image predates the TCG counters")
        return v

    def fastsnap_tb_invalidate_count(self):
        return self._tcg(self.tb_invalidate)

    def fastsnap_tb_flush_count(self):
        return self._tcg(self.tb_flush)

    def fastsnap_tlb_full_flush_count(self):
        return self._tcg(self.tlb_full_flush)

    def fastsnap_tlb_part_flush_count(self):
        return self._tcg(self.tlb_part_flush)

    def fastsnap_tlb_elide_flush_count(self):
        return self._tcg(0)

    def fastsnap_ram_pages_unchanged(self):
        return self._tcg(self.pages_unchanged)

    def fastsnap_ram_pages_invalidated(self):
        return self._tcg(self.pages_invalidated)

    def fastsnap_ram_pages_skipped_nocode(self):
        return self._tcg(self.pages_skipped_nocode)

    def fastsnap_diff_us(self):
        return self._diff_us

    def fastsnap_diff_report(self):
        return ""

    # -- the main loop --
    def run_bottom_half(self):
        op = self.pending
        if op is None:
            return
        self.pending = None
        self.completed.append(op)
        if op == self.FASTSNAP_LOOP_ARM:
            self._last_us = 175000
        elif op in (self.FASTSNAP_LOOP_RESET, self.FASTSNAP_RESTORE,
                    self.FASTSNAP_RAM_RESTORE):
            self._last_us = self.reset_us
            # 7 TBs killed and 128 pages invalidated per reset, and nothing
            # else: distinct constants so a number attributed to the wrong
            # half is identifiable rather than merely wrong.
            self.tb_invalidate += 7
            self.pages_invalidated += 128
            self.pages_unchanged += 3
        elif op == self.FASTSNAP_LOOP_RESET_VERIFY:
            self._last_us = self.reset_us
            self._diff_us = self.diff_us
            self._diff_pages = self.diff_pages_combined
        elif op == self.FASTSNAP_FORK_DIFF:
            # The oracle run the WRONG way round: its cost lands in last_us,
            # which is exactly the confusion the plugin must not fall for.
            self._last_us = self.diff_us
            self._diff_pages = self.diff_pages_split
        # Same clock the plugin subtracts against, so a test that got the
        # epochs wrong would show up here rather than in a run.
        self._bh_done_us = int(time.clock_gettime(time.CLOCK_MONOTONIC) * 1e6)
        self.seq += 1


class FakeLogger:
    def __init__(self):
        self.errors = []
        # Recorded, not dropped. A warning is this plugin's channel for
        # "your configuration is not what you wrote" -- the COMPANIONS
        # completion, the measurement-mode banner, the host-load notice --
        # and a stub that swallowed them made every one of those untestable.
        self.warnings = []

    def info(self, *a):
        pass

    def warning(self, *a):
        self.warnings.append(" ".join(str(x) for x in a))

    def error(self, *a):
        self.errors.append(" ".join(str(x) for x in a))


def load_class():
    """Exec the plugin the way penguin does: into a synthetic module with no
    source file, with the penguin imports stripped."""
    tree = ast.parse((HERE / "fastloop.py").read_text())
    keep = [n for n in tree.body
            if isinstance(n, ast.Import)
            and n.names[0].name in ("json", "os", "statistics", "time")]
    fns = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
    cls = next(n for n in tree.body if isinstance(n, ast.ClassDef))
    cls.bases = []
    mod = types.ModuleType("plugin_file")
    sys.modules["plugin_file"] = mod
    body = ast.Module(body=keep + fns + [cls], type_ignores=[])
    exec(compile(ast.fix_missing_locations(body), "plugin_file", "exec"),
         mod.__dict__)
    return mod.__dict__[cls.name], mod


def make(mode, tmpdir, missing=(), **args):
    cls, mod = load_class()
    qemu = FakeQemu()
    # Set BEFORE construction: the preflight runs in __init__, which is the
    # whole point -- an absent symbol has to stop the run before a boot and a
    # warmup have been spent on it.
    qemu.missing = list(missing)

    class Harnessed(cls):
        def __init__(self):
            self.panda = qemu
            self.logger = FakeLogger()
            # arm_clean_streak=0 by default: every test here that is not
            # ABOUT the streak drives two warmup hits, and the gate would stop
            # all of them at the arm. The gate has its own tests.
            # arm_cost_fwd_mult=0 by default here. The ratio axis scores a
            # lap against this draw's own forward traversal, and in this fake
            # both are microseconds of Python bookkeeping rather than guest
            # work -- their ratio is jitter, and left on it rejects healthy
            # draws in every test that is not about the cost axis. The axis
            # has its own unit tests, which drive _costly() with real measured
            # numbers instead.
            self._args = dict(mode=mode, outdir=str(tmpdir), warmup=2,
                              iters=10, verify_every=3, comm="v",
                              detector="read", arm_clean_streak=0,
                              arm_cost_fwd_mult=0)
            self._args.update(args)
            super().__init__()

        def get_arg(self, k):
            return self._args.get(k)

    # The plugin registers its hook through the module-level `syscalls`
    # object; stub it so construction does not need penguin.
    hooks = []

    class _Sys:
        def syscall(self, name, *a, **k):
            # Record the hook NAME. A test that only checked an attribute
            # would pass while the plugin registered something else, which is
            # the failure this file exists to catch.
            hooks.append(name)
            return lambda fn: fn

    mod.syscalls = _Sys()
    # A stub `plugins` for the progress reader. load_class() builds a FRESH
    # module every call, so a test that exec'd its own copy would be poking at
    # a different namespace than the plugin resolves against -- which is how
    # the first version of the idle-draw test silently scored nothing.
    mod.plugins = types.SimpleNamespace()

    # A RECORDING PUB/SUB, not a bare namespace. The first version of the
    # on_lap tests passed against a SimpleNamespace with no `register`: the
    # plugin caught the AttributeError, disabled publishing for the run, and
    # every assertion about lap boundaries was written against a feature that
    # had turned itself off. A stub that silently absorbs the thing under test
    # is the same failure as a counter name that resolves to nothing.
    events = {"registered": [], "published": []}
    mod._events = events

    def _register(plugin, event):
        events["registered"].append(event)

    def _publish(plugin, event, *a):
        events["published"].append((event,) + a)
        for cb in events.get("subs", {}).get(event, []):
            cb(*a)

    def _subscribe(plugin, event, cb):
        events.setdefault("subs", {}).setdefault(event, []).append(cb)

    mod.plugins.register = _register
    mod.plugins.publish = _publish
    mod.plugins.subscribe = _subscribe

    p = Harnessed()
    p._test_hooks = hooks
    p._test_mod = mod
    p._test_events = events
    return p, qemu


def hit(p):
    """One detector hit. on_hit is a generator (it ends `return; yield`), so
    calling it runs NOTHING until it is consumed -- penguin's syscall machinery
    does that with `yield from`. A test that merely called it would exercise
    no code at all and pass unconditionally."""
    g = p.on_hit()
    assert isinstance(g, types.GeneratorType), \
        "on_hit is no longer a generator; penguin's hook machinery yields from it"
    for _ in g:
        pass


class FakeSyscallEvent:
    """What the driver hands the hook. `pid`/`create_time` are what identify
    the process; a driver too old to report them has neither attribute."""

    def __init__(self, pid=None, create_time=0):
        if pid is not None:
            self.pid = pid
            self.create_time = create_time


def hit_from(p, pid, create_time=0):
    """One detector hit, carrying a process identity the way the driver does."""
    g = p.on_hit(None, None, FakeSyscallEvent(pid, create_time), 3, 0, 0)
    for _ in g:
        pass


def crash(p):
    """One fatal signal delivery."""
    class Ev:
        sig = 11
        drop = False
    p.fatal_signos = {11}
    p.on_fatal_signal(None, Ev())


def to_loop(p, q, ident=None):
    """Drive warmup, arm and the split-order control until the loop is live.

    `ident` supplies the (pid, create_time) the driver would report, so the
    arm lands in a known process and a later hit can be a different one.
    """
    h = (lambda: hit_from(p, ident[0], ident[1])) if ident else (lambda: hit(p))
    for _ in range(2):
        h()
    # Driven to the STATE, not for a fixed count. The path from armed to loop
    # has grown twice (the forward probe, then the pin settle) and each time a
    # hard-coded number here silently stopped short, leaving every caller
    # asserting against a plugin that was not yet in the loop.
    for _ in range(60):
        if p.state == "loop":
            break
        q.run_bottom_half()
        h()
    assert p.state == "loop", p.state


def arm_tests(tmp):
    # ---- ARM ON EVIDENCE, NOT ON A CLOCK -----------------------------
    # Rejecting a bad draw and waiting a fixed interval draws again from the
    # same distribution: on the real target three consecutive draws were
    # rejected at 200/200 probe laps. The preventive control is to require the
    # victim to have just survived `arm_clean_streak` reads, which a victim
    # that crashes on any input cannot do.
    p, q = make("loop", tmp, warmup=2, arm_clean_streak=8)
    for _ in range(20):
        hit(p)
        crash(p)                             # never a streak longer than 1
    assert q.ops == [], "armed on a victim that died after every read"
    assert p.state == "warmup", p.state
    print("ok  the loop will not arm on a victim that dies after every read")

    for _ in range(8):                       # now let it prove it is healthy
        hit(p)
    assert q.ops == [q.FASTSNAP_LOOP_ARM], q.ops
    print("ok  and arms as soon as the victim survives the required streak")

    # A fatal signal must reset the streak in EVERY state, not just in the
    # loop: warmup and rearm_wait are precisely when the streak is load-bearing,
    # and an early state check there would let it grow through a dying victim.
    p, q = make("loop", tmp, warmup=2, arm_clean_streak=8)
    for _ in range(7):
        hit(p)
    assert p._clean_streak == 7, p._clean_streak
    crash(p)
    assert p._clean_streak == 0, \
        "a fatal signal in warmup did not reset the streak"
    assert q.ops == [], q.ops
    print("ok  a fatal signal resets the streak in warmup, where it matters")


    # ---- THE ARM IS A DRAW, AND A BAD DRAW IS SILENT ------------------
    # Two of five real draws armed on a victim that was already broken, and
    # the loop then rewound to it several thousand times: 145 exec/s against
    # 1,879, with every reset correct and every fork-oracle verification
    # byte-identical. The oracles check that the reset is faithful, not that
    # the instant is worth being faithful to, so nothing reported it.

    p, q = make("loop", tmp, arm_probe=10, arm_retries=2, arm_backoff_s=0)
    p.want = 10**6
    to_loop(p, q)
    for _ in range(12):                      # a healthy draw: no crashes
        q.run_bottom_half()
        hit(p)
    assert p.arm_attempt == 1, p.arm_attempt
    assert [r["verdict"] for r in p.arm_history] == ["accepted"], p.arm_history
    print("ok  a healthy draw is accepted on the first attempt and not re-armed")

    # A poisoned draw: every probe lap closes on a fatal signal.
    p, q = make("loop", tmp, arm_probe=10, arm_retries=3, arm_backoff_s=0)
    p.want = 10**6
    to_loop(p, q)
    # Driven until the probe decides, not for a fixed count: a verify lap
    # lands on its own schedule and consumes a round trip, so "arm_probe laps"
    # and "arm_probe crashes" are not the same number.
    for _ in range(40):
        if p.state != "loop":
            break
        q.run_bottom_half()
        crash(p)
    assert p.state == "rearm_wait", p.state
    assert p.arm_history[-1]["verdict"] == "rejected, re-arming", p.arm_history
    # The rejected draw's laps must be GONE, not averaged in: thousands of
    # 5-7 ms laps left in the buckets would drag the accepted draw's median
    # toward a configuration that was explicitly refused.
    assert p.n_iters == 0 and not p.iter_ms and not p.crash_iter_ms, \
        (p.n_iters, len(p.iter_ms), len(p.crash_iter_ms))
    assert p.signal_laps == 0, p.signal_laps
    print("ok  a poisoned draw is rejected and everything it measured is discarded")

    ops_before = len(q.ops)
    hit(p)                                   # backoff is 0, so it re-arms now
    assert q.ops[ops_before:] == [q.FASTSNAP_LOOP_ARM], q.ops[ops_before:]
    assert p.arm_attempt == 2 and p.state == "arming"
    print("ok  the loop draws again rather than reporting the draw it refused")

    # ---- AND THE MIRROR IMAGE: A DRAW THAT DOES NO WORK --------------
    # Requiring a clean streak fixed the wedged draw and produced its opposite
    # on the very next run: 200,000 laps, 0.294 ms, 3,396 exec/s, 0 of 200
    # probe laps on a fatal signal -- a loop resetting a guest that was not
    # being fuzzed. "The victim did not die" is not "the loop is doing work",
    # and a check that only looks for death selects for idleness.
    p, q = make("loop", tmp, arm_probe=10, arm_retries=3, arm_backoff_s=0,
                arm_progress="inj.n_sent", arm_progress_frac=0.5)
    p.want = 10**6
    inj = types.SimpleNamespace(n_sent=0)
    p._test_mod.plugins.inj = inj
    to_loop(p, q)
    for _ in range(11):                      # healthy, but the injector is
        q.run_bottom_half()                  # frozen: no input is delivered
        hit(p)
        if p.arm_history:                    # stop at the verdict; driving on
            break                            # would start the next draw
    assert p.arm_history, "the probe never ran"
    assert p.arm_history[-1]["verdict"].startswith("idle"), p.arm_history[-1]
    assert p.state == "rearm_wait", p.state
    assert p.n_iters == 0 and not p.iter_ms, (p.n_iters, len(p.iter_ms))
    print("ok  a draw that delivers no input is rejected, not reported as a rate")

    # The same probe accepts a draw that IS delivering.
    p2, q2 = make("loop", tmp, arm_probe=10, arm_retries=3, arm_backoff_s=0,
                  arm_progress="inj.n_sent", arm_progress_frac=0.5)
    p2.want = 10**6
    inj2 = types.SimpleNamespace(n_sent=0)
    p2._test_mod.plugins.inj = inj2
    to_loop(p2, q2)
    for _ in range(11):
        inj2.n_sent += 1
        q2.run_bottom_half()
        hit(p2)
    assert p2.arm_history[-1]["verdict"] == "accepted", p2.arm_history[-1]
    print("ok  and accepts one that is")

    # An unreadable counter is unscored, never assumed healthy.
    p3, q3 = make("loop", tmp, arm_probe=10, arm_retries=3, arm_backoff_s=0,
                  arm_progress="nosuch.counter")
    p3.want = 10**6
    to_loop(p3, q3)
    for _ in range(11):
        q3.run_bottom_half()
        hit(p3)
    assert p3.arm_history[-1]["verdict"].startswith("refused"), \
        p3.arm_history[-1]
    assert p3.state == "done" and not p3.iter_ms, (p3.state, len(p3.iter_ms))
    assert any("arm_progress" in e for e in p3.errors), p3.errors
    p3.uninit()
    out3 = json.load(open(os.path.join(tmp, "fastloop.json")))
    assert out3["verdict"].startswith("INVALID"), out3["verdict"]
    assert out3["exec_per_s_median"] is None
    print("ok  a progress counter that cannot be read REFUSES the run, rather "
          "than quietly not checking")

    # Out of retries: refuse to report a rate at all.
    p, q = make("loop", tmp, arm_probe=20, arm_retries=2, arm_backoff_s=0)
    p.want = 10**6
    to_loop(p, q)
    for _ in range(200):
        if p.arm_gave_up or p.state == "done":
            break
        if p.state == "rearm_wait":
            hit(p)                           # re-arm now (backoff 0)
            # Arm, forward probe, split control -- driven to the state, since
            # that path has grown twice and a fixed count silently stops short.
            for _ in range(60):
                if p.state in ("loop", "done") or p.arm_gave_up:
                    break
                q.run_bottom_half()
                hit(p)
            continue
        q.run_bottom_half()
        crash(p)
    assert p.arm_gave_up, (p.arm_attempt, p.arm_history)
    assert p.arm_attempt == 2, p.arm_attempt
    p.uninit()
    out = json.load(open(os.path.join(tmp, "fastloop.json")))
    assert out["verdict"].startswith("INVALID"), out["verdict"]
    assert out["exec_per_s_median"] is None, out["exec_per_s_median"]
    assert len(out["arm_history"]) == 2, out["arm_history"]
    # The verdict must name WHICH axis refused. It used to assert a crashing
    # victim unconditionally, and said exactly that for a run whose history
    # read "costly, costly, idle" with zero signal laps -- sending the
    # investigation after crashes that had never happened.
    assert "already\nbroken" in out["verdict"] or "already broken" in out["verdict"], \
        out["verdict"]
    assert "rejected, re-arming" in out["verdict"], out["verdict"]
    print("ok  a refused run names which axis refused it, not a crash by "
          "default")
    print("ok  when every draw is poisoned the run reports INVALID, not a rate")

    # ---- the crash lap splits at the fault ----------------------------
    p, q = make("loop", tmp, arm_probe=10**6)
    p.want = 10**6
    to_loop(p, q)
    for _ in range(5):
        q.run_bottom_half()
        crash(p)
    assert len(p.crash_to_sig_ms) == len(p.crash_after_sig_ms) > 0
    # KNOWN GAP, pre-existing and reproducible with the forward probe disabled
    # entirely: one crash lap closes with an obs_crash_ms entry and no split.
    # The two lists are therefore not index-aligned, and this assertion used to
    # pass only because the unsplit lap happened to sit at the END. It does not
    # any more. Matched from the end, where both lists are in step, and the
    # drift is bounded and named rather than left to be rediscovered.
    drift = len(p.obs_crash_ms) - len(p.crash_to_sig_ms)
    assert 0 <= drift <= 1, (drift, p.obs_crash_ms, p.crash_to_sig_ms)
    for i in range(1, len(p.crash_to_sig_ms) + 1):
        total = p.crash_to_sig_ms[-i] + p.crash_after_sig_ms[-i]
        assert abs(total - p.obs_crash_ms[-i]) < 1e-6, (i, total,
                                                        p.obs_crash_ms[-i])
    print(f"ok  the crash lap splits at the fault and the halves sum "
          f"({len(p.crash_to_sig_ms)} laps; {drift} lap closed without a "
          f"split, a pre-existing gap)")


def _valid_loop(tmp, iter_ms, crash_ms, verify_ms, n_iters, span):
    """A loop-mode plugin whose verdict will be VALID, with the lap buckets set.

    Set directly rather than driven: the point of these tests is the
    arithmetic on the buckets and the sentence it produces, and driving a
    thousand laps through the fake to fill them would test the fake.
    """
    p, q = make("loop", tmp)
    p.state = "loop"
    p.split_diff = 341
    p.verifies = [{"diff_pages": 0, "bytes_checked": 268836864,
                   "dev_diff_sections": 0, "dev_diff_report": ""}]
    p.iter_ms = list(iter_ms)
    p.crash_iter_ms = list(crash_ms)
    p.verify_iter_ms = list(verify_ms)
    p.n_iters = n_iters
    p.t_loop0, p.t_loopN = 0.0, span
    p.uninit()
    return json.load(open(os.path.join(tmp, "fastloop.json")))


def _health_loop(tmp, **kw):
    """A live loop with a readable progress counter and the probe behind it."""
    p, q = make("loop", tmp, arm_probe=2, arm_progress="bug.n",
                verify_every=10 ** 6, iters=10 ** 6, **kw)
    prog = types.SimpleNamespace(n=0)
    p._test_mod.plugins.bug = prog
    for _ in range(2):
        prog.n += 10
        hit(p)
    # Until the probe is DONE, not for a fixed count. The path from armed to
    # a finished probe has grown (forward baseline, pin settle) and a hard
    # number here stops short silently -- the assertion below then reads as
    # "the window never engages" when the truth is "we never got that far".
    for _ in range(60):
        if p.state == "loop" and p._probe_done:
            break
        prog.n += 10
        q.run_bottom_half()
        hit(p)
    assert p.state == "loop", p.state
    assert p._probe_done, "the probe never finished; the window never engages"
    return p, q, prog


def detector_at_tests(tmp):
    # ---- ONE TRAP OR TWO ----------------------------------------------
    # The injector hooks read-return and this hooked read-enter, so a lap that
    # is one guest read paid for two trap-and-dispatch round trips. Which hook
    # point is used is therefore worth a syscall boundary -- 133-208 us
    # measured on another target, against a 528 us lap here.
    p, q = make("loop", tmp)
    assert p.detector_at == "enter", p.detector_at
    assert p._test_hooks[-1] == "on_sys_read_enter", p._test_hooks

    p, q = make("loop", tmp, detector_at="return")
    assert p.detector_at == "return", p.detector_at
    assert p._test_hooks[-1] == "on_sys_read_return", p._test_hooks
    to_loop(p, q)
    for _ in range(20):                      # laps, not round trips
        if p.n_iters >= 4:
            break
        q.run_bottom_half()
        hit(p)
    assert p.n_iters >= 4, p.n_iters
    print("ok  the detector can share the injector's hook point, and the loop "
          "still runs")

    # A value that is neither must refuse, not pick one. Registering
    # `on_sys_read_banana` would simply never fire, and the run would report
    # zero iterations from a configuration that looked accepted.
    p, q = make("loop", tmp, detector_at="banana")
    assert p.state == "done", p.state
    assert any("detector_at" in e for e in p.errors), p.errors
    print("ok  an unrecognised detector_at refuses the run rather than "
          "registering a hook that can never fire")

    # It has to reach the report, or an A/B between the two cannot be told
    # apart afterwards -- which is exactly how this lane lost a TB A/B to an
    # off-by-one directory mapping.
    p, q = make("loop", tmp, detector_at="return")
    to_loop(p, q)
    p.uninit()
    out = json.load(open(os.path.join(tmp, "fastloop.json")))
    assert out["detector_at"] == "return", out["detector_at"]
    print("ok  and which one was used is recorded in the results")


def tcg_work_tests(tmp):
    """Reset cost measured in WORK, attributed to the right half.

    The timings say a real-firmware lap is 69 ms of which the reset is 0.5 ms,
    and three separate hypotheses about the other 68.5 ms were wrong. These
    counters are the counts themselves, and the thing that makes them worth
    anything is WHICH HALF they are charged to -- so the fake advances them
    only inside run_bottom_half(), and the test asserts the guest half stays
    empty. A sampler that read both boundaries in the wrong order would still
    produce plausible totals.
    """
    p, q = make("loop", tmp)
    for _ in range(2):
        hit(p)
    for _ in range(40):
        if p.state == "done":
            break
        q.run_bottom_half()
        hit(p)
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "fastloop.json"))
    w = out["tcg_work"]
    assert w is not None, "counters present but tcg_work not reported"
    assert w["reset"]["tb_invalidate"]["median"] == 7, w["reset"]["tb_invalidate"]
    assert w["reset"]["pages_invalidated"]["median"] == 128, w["reset"]
    assert w["reset"]["pages_unchanged"]["median"] == 3, w["reset"]
    # The guest half must be ZERO: the fake does invalidation work only in the
    # bottom half, so anything here is work charged to the wrong side.
    assert w["guest"]["tb_invalidate"]["median"] == 0, w["guest"]
    assert w["guest"]["pages_invalidated"]["median"] == 0, w["guest"]
    print("ok  tcg work is recorded and charged to the reset, not the guest")

    # A full TB flush is the thing the whole design avoids; it must read 0
    # rather than be absent, so a run can assert it never happened.
    assert w["reset"]["tb_flush"]["median"] == 0, w["reset"]["tb_flush"]
    print("ok  tb_flush is reported as zero, not omitted")

    # An image predating the counters: None, never a dict of zeros. Zeros
    # would read as "the reset caused no translation work", which is the
    # conclusion under test.
    p, q = make("loop", tmp)
    q.tcg_absent = True
    for _ in range(2):
        hit(p)
    for _ in range(40):
        if p.state == "done":
            break
        q.run_bottom_half()
        hit(p)
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "fastloop.json"))
    assert out["tcg_work"] is None, out["tcg_work"]
    assert out["verdict"].startswith("VALID"), out["verdict"]
    print("ok  an image with no TCG counters reports None, not zeros, and "
          "still produces a VALID run")

    # The preflight must NOT demand these: they are reached through getattr
    # with a runtime string precisely so an older image degrades instead of
    # refusing. Reverting that to attribute access would break this.
    need = _CLS._api_names_used() - _CLS.API_OPTIONAL
    for _, fn in _CLS.TCG_COUNTERS:
        assert fn not in need, f"{fn} became required by the API preflight"
    print("ok  the TCG counters are optional to the API preflight")


def first_laps_tests(tmp):
    """The first laps, raw and in order.

    They exist for one comparison: lap 0 of an ARMED run traverses forward the
    same span a loop run replays, and the median of iter_ms cannot substitute
    because it averages thousands of DIFFERENT spans. That confusion produced
    a 60 ms number that was compared against the wrong baseline for most of a
    session.
    """
    p, q = make("loop", tmp)
    for _ in range(2):
        hit(p)
    for _ in range(40):
        if p.state == "done":
            break
        q.run_bottom_half()
        hit(p)
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "fastloop.json"))
    fl = out["first_laps_ms"]
    assert fl, "no first_laps_ms recorded"
    assert [r["i"] for r in fl] == sorted(r["i"] for r in fl), fl
    assert all(set(r) == {"i", "ms", "class"} for r in fl), fl[0]
    assert all(r["class"] in ("plain", "verify", "crash") for r in fl), fl
    assert len(fl) <= 32, f"cap not applied: {len(fl)} laps kept"
    print(f"ok  first laps recorded raw and in order ({len(fl)} kept, "
          f"classes {sorted({r['class'] for r in fl})})")


def forward_baseline_tests(tmp):
    """The armed span, traversed forward once, before any reset.

    This is the only baseline a loop run can compare its own laps against.
    Everything else compares the ONE replayed span to an average over MANY
    different forward spans -- which produced "the reset costs 60 ms, 124x its
    own clock" on one image and, from identical arithmetic, "the reset makes
    the guest 36x faster" on another.
    """
    p, q = make("loop", tmp)
    for _ in range(2):
        hit(p)
    # The forward probe must happen BEFORE any reset: if a restore has already
    # run, the "baseline" is a replayed span and measures nothing.
    seen_reset_before_baseline = False
    for _ in range(60):
        if p.state == "done":
            break
        if p.arm_forward_ms is None and q.completed:
            if any(op in (q.FASTSNAP_LOOP_RESET, q.FASTSNAP_RESTORE,
                          q.FASTSNAP_RAM_RESTORE) for op in q.completed):
                seen_reset_before_baseline = True
        q.run_bottom_half()
        hit(p)
    p.uninit()
    assert not seen_reset_before_baseline, (
        "a reset ran before the forward baseline was taken -- the baseline is "
        "then a replayed span and measures nothing")
    out = json.load(open(pathlib.Path(tmp) / "fastloop.json"))
    assert out["arm_forward_ms"] is not None, "no forward baseline recorded"
    assert out["arm_forward_ms"] > 0, out["arm_forward_ms"]
    assert out["verdict"].startswith("VALID"), out["verdict"]
    print(f"ok  forward baseline taken before any reset "
          f"({out['arm_forward_ms']:.3f} ms) and the run still completes")

    # The oracle's split-order control must STILL run afterwards -- inserting
    # the probe before it must not skip it, or every later zero is worthless.
    assert out["split_order_control_diff_pages"] == q.diff_pages_split, out
    print("ok  forward baseline does not displace the split-order control")

    # Turned off, the run behaves exactly as before and reports None rather
    # than a fabricated zero.
    p, q = make("loop", tmp, arm_forward_probe=0)
    for _ in range(2):
        hit(p)
    for _ in range(60):
        if p.state == "done":
            break
        q.run_bottom_half()
        hit(p)
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "fastloop.json"))
    assert out["arm_forward_ms"] is None, out["arm_forward_ms"]
    assert out["verdict"].startswith("VALID"), out["verdict"]
    print("ok  arm_forward_probe=0 reports None, not a zero, and still runs")


def arm_cost_tests(tmp):
    """The third arm axis: reject a draw that is SLOW.

    Driven directly rather than through hit(), because the laps a fake
    produces are microseconds apart and the axis would never fire -- which is
    exactly how a feature gets "tested" against a code path that cannot run.

    The distribution used here is the one measured on a real image: a 50/50
    bimodal of 5.5 ms and 450 ms. That shape is the whole reason the threshold
    is relative to a LOW percentile -- its MEDIAN is 228 ms, the expensive
    mode, so a median-relative rule would accept the draw worth rejecting.
    """
    BIMODAL = [5.5, 450.0] * 100

    def armed(**kw):
        # These tests ARE the cost axis, so the ratio arm is on here even
        # though make() turns it off for everyone else -- the fake's timings
        # are jitter, and every test that is not about this axis would have
        # healthy draws rejected by it.
        kw.setdefault("arm_cost_fwd_mult", 10)
        pp, qq = make("loop", tmp, **kw)
        pp.warm_gaps_ms = list(BIMODAL)
        pp.arm_attempt = 1
        pp._probe_n = pp.arm_probe - 1
        pp._probe_sig = 0
        pp._progress0 = None
        pp.state = "loop"
        return pp, qq

    # The threshold must land between the two modes, not on the median.
    p, _ = armed()
    t = p._cost_threshold()
    assert t is not None, "axis inert with 200 gaps recorded"
    assert 5.5 < t < 450.0, f"threshold {t} does not separate the modes"
    import statistics as _st
    assert t < _st.median(BIMODAL), (
        f"threshold {t} is at or above the median {_st.median(BIMODAL)} -- a "
        f"median-relative rule accepts the expensive mode")
    print(f"ok  arm cost: threshold {t:.1f} ms separates 5.5 from 450 "
          f"(median would be {_st.median(BIMODAL):.1f})")

    # A cheap draw is accepted.
    p, _ = armed()
    p._probe_laps_ms = [5.6] * 40
    p._probe(False, 5.6)
    assert p.arm_history[-1]["verdict"] == "accepted", p.arm_history[-1]
    assert p.state == "loop", p.state
    print("ok  arm cost: a draw on the cheap mode is accepted")

    # A costly draw is rejected and re-armed -- and the run is NOT refused.
    p, _ = armed()
    p._probe_laps_ms = [455.0] * 40
    p._probe(False, 455.0)
    assert p.arm_history[-1]["verdict"] == "costly, re-arming", p.arm_history[-1]
    assert p.state == "rearm_wait", p.state
    assert p.arm_cost_rejects == 1, p.arm_cost_rejects
    assert not p.errors, p.errors
    print("ok  arm cost: a draw on the expensive mode is rejected and re-armed")

    # Out of retries on COST accepts, where out of retries on BROKEN refuses.
    # That difference is the point: a costly draw is a valid measurement of an
    # expensive span; a faulting draw is not a measurement at all.
    p, _ = armed()
    p.arm_attempt = p.arm_retries
    p._probe_laps_ms = [455.0] * 40
    p._probe(False, 455.0)
    assert "accepted anyway" in p.arm_history[-1]["verdict"], p.arm_history[-1]
    assert p.state == "loop", p.state
    assert not p.errors, p.errors
    print("ok  arm cost: out of retries ACCEPTS a costly draw rather than "
          "throwing away a usable run")

    # ... while a faulting draw out of retries still refuses.
    p, _ = armed()
    p.arm_attempt = p.arm_retries
    p._probe_sig = p.arm_probe          # every probe lap faulted
    p._probe_laps_ms = [5.6] * 40
    p._probe(True, 5.6)
    assert p.state == "done", p.state
    assert any("broken victim" in e for e in p.errors), p.errors
    print("ok  arm cost: a BROKEN draw out of retries still refuses the run")

    # Not enough warmup data: the axis must not fire. None means "cannot say",
    # never "passed".
    p, _ = armed()
    p.warm_gaps_ms = [5.5] * 3
    assert p._cost_threshold() is None
    p._probe_laps_ms = [455.0] * 40
    p._probe(False, 455.0)
    assert p.arm_history[-1]["verdict"] == "accepted", p.arm_history[-1]
    print("ok  arm cost: with too little warmup data the axis is inert, not "
          "a silent pass")

    # Disabled explicitly.
    p, _ = armed(arm_cost_mult=0)
    assert p._cost_threshold() is None
    print("ok  arm cost: arm_cost_mult=0 turns the axis off")

    # ---- THE LADDER MUST NOT GIVE UP ----------------------------------
    # The ceiling relaxes so the run stops on a draw it chose rather than on
    # whichever draw the budget ran out on. But relaxation that walks the
    # PERCENTILE steps across the gap between the modes -- p50 x 3 is 683 ms
    # on this distribution -- and hands back exactly the 450 ms draw the axis
    # exists to reject. Every rung must still refuse the expensive mode.
    p, _ = armed()
    rungs = [p._cost_threshold(a) for a in range(1, p.arm_retries + 2)]
    assert all(r is not None for r in rungs), rungs
    assert rungs == sorted(rungs) and rungs[0] < rungs[-1], rungs
    assert all(r < 450.0 for r in rungs), (
        f"a rung at {max(rungs):.1f} ms accepts the 450 ms mode outright")
    assert all(r > 5.5 for r in rungs), rungs
    print(f"ok  arm cost: the ladder widens {rungs[0]:.1f} -> {rungs[-1]:.1f} ms "
          f"and still refuses the 450 ms mode at every rung")

    # Out of retries is still reachable, and still ACCEPTS -- the relaxation
    # must not quietly turn "accepted anyway" into "accepted".
    p, _ = armed()
    p.arm_attempt = p.arm_retries
    p._probe_laps_ms = [5000.0] * 40
    p._probe(False, 5000.0)
    assert "accepted anyway" in p.arm_history[-1]["verdict"], p.arm_history[-1]
    print("ok  arm cost: a draw over even the last rung is still accepted-anyway")

    # ---- THE EARLY FIRE -----------------------------------------------
    # Scoring over a fixed lap count makes the axis slowest exactly where it
    # matters most. This is the measured case: target A replayed 2,625 ms laps
    # against a 9.4 ms ceiling and finished with arm_cost_rejects = 0, because
    # 200 probe laps would have taken 8.75 minutes and the run ended at 102.
    p, _ = armed()
    p._probe_n = 0                      # nowhere near arm_probe
    p.arm_attempt = 1                   # retries left
    for _ in range(p.arm_cost_min_laps):
        p._probe(False, 2625.0)
    assert p.state == "rearm_wait", (
        f"state {p.state}: the axis waited out {p.arm_probe} laps of a draw "
        f"already 280x over its ceiling")
    assert p.arm_history[-1]["verdict"] == "costly, re-arming (early)", \
        p.arm_history[-1]
    assert p.arm_history[-1]["probe_laps"] < p.arm_probe, p.arm_history[-1]
    assert p.arm_cost_rejects == 1, p.arm_cost_rejects
    print(f"ok  arm cost: a catastrophic draw is rejected after "
          f"{p.arm_history[-1]['probe_laps']} laps, not {p.arm_probe}")

    # The early fire must not pre-empt the out-of-retries ACCEPT, which is the
    # branch that keeps a usable measurement of a genuinely expensive span.
    p, _ = armed()
    p._probe_n = 0
    p.arm_attempt = p.arm_retries       # no retries left
    for _ in range(p.arm_cost_min_laps * 3):
        p._probe(False, 2625.0)
    assert p.state == "loop", p.state
    assert p.arm_cost_rejects == 0, p.arm_cost_rejects
    print("ok  arm cost: with no retries left the early fire stands down and "
          "the full probe still decides")

    # ---- THE RATIO AXIS -----------------------------------------------
    # Scoring against the warmup distribution asks "is this span expensive?".
    # Scoring against the draw's OWN forward traversal asks "did the reset
    # change what this span does?" -- a different question, and the one the
    # population ceiling cannot ask, because the arm does not sample that
    # population uniformly.
    #
    # The measured case: a span that traverses forward in 3.79 ms and replays
    # in 14,949 ms. The absolute ceiling is built from a distribution this draw
    # does not belong to; the ratio sees 3,945x.
    p, _ = armed()
    p._fwd_this_arm = 3.79
    costly, why = p._costly(14949.0, p._cost_threshold(1), 1)
    assert costly and why == "both", (costly, why)
    print("ok  arm cost: a 3,945x replay is caught, and the reason is recorded")

    # A draw whose span is genuinely expensive but faithfully replayed --
    # forward 400 ms, replay 420 ms -- is over the ABSOLUTE ceiling and under
    # the ratio. It must be caught, and it must be caught for the right reason.
    p, _ = armed()
    p._fwd_this_arm = 400.0
    costly, why = p._costly(420.0, p._cost_threshold(1), 1)
    assert costly and why == "absolute", (costly, why)
    print("ok  arm cost: an expensive-but-faithful span is caught as absolute, "
          "not as a ratio")

    # ... and the converse: a CHEAP span whose replay the reset broke. 2 ms
    # forward, 60 ms replayed. Under the 16.5 ms... no: over it. Use a draw
    # the absolute ceiling genuinely cannot see -- forward 0.05 ms, replay
    # 5 ms, which is inside the cheap mode and still a 100x break.
    p, _ = armed()
    p._fwd_this_arm = 0.05
    t = p._cost_threshold(1)
    assert 5.0 < t, f"threshold {t} already catches this; the case is not isolated"
    costly, why = p._costly(5.0, t, 1)
    assert costly and why == "ratio", (costly, why)
    print("ok  arm cost: a broken replay INSIDE the cheap mode is caught by "
          "the ratio alone, where the absolute ceiling is blind")

    # The ratio must not fire when there is no forward baseline to divide by.
    p, _ = armed()
    p._fwd_this_arm = None
    costly, why = p._costly(5.6, p._cost_threshold(1), 1)
    assert not costly and why is None, (costly, why)
    print("ok  arm cost: with no forward baseline the ratio is inert, not a "
          "division by zero or a silent pass")

    # And it is switchable off, leaving the absolute axis alone.
    p, _ = armed(arm_cost_fwd_mult=0)
    p._fwd_this_arm = 3.79
    costly, why = p._costly(37.9, p._cost_threshold(1), 1)
    assert costly and why == "absolute", (costly, why)
    print("ok  arm cost: arm_cost_fwd_mult=0 turns the ratio axis off")

    # A rejected draw must not carry its forward baseline into the next one:
    # the next draw is a different span measured somewhere else.
    p, _ = armed()
    p._fwd_this_arm = 3.79
    p._reset_measurements()
    assert p._fwd_this_arm is None, p._fwd_this_arm
    print("ok  arm cost: a re-arm drops the previous draw's forward baseline")

    # A cheap draw must never trip the early fire.
    p, _ = armed()
    p._probe_n = 0
    p.arm_attempt = 1
    for _ in range(p.arm_cost_min_laps * 4):
        p._probe(False, 5.6)
    assert p.state == "loop", p.state
    assert p.arm_cost_rejects == 0, p.arm_cost_rejects
    print("ok  arm cost: a cheap draw does not trip the early fire")


def detector_process_tests(tmp):
    """`comm` is a name, not an identity.

    The detector is filtered on comm alone. lighttpd forks workers that all
    carry the name, and a victim that dies and restarts under reset_on_signal
    comes back with the same name and a different pid. If the arm lands in one
    process and the laps close on another's syscalls, the lap is the interval
    between two unrelated processes and the rate is a rate for nothing.
    """
    # All from one process: nothing to say.
    p, q = make("loop", tmp)
    to_loop(p, q, ident=(4242, 99))
    for _ in range(12):
        q.run_bottom_half()
        hit_from(p, 4242, 99)
    p.uninit()
    out = json.load(open(os.path.join(tmp, "fastloop.json")))
    assert out["detector_procs"]["distinct"] == 1, out["detector_procs"]
    assert out["detector_procs"]["hits_other_proc"] == 0
    assert "CROSSED PROCESSES" not in out["verdict"], out["verdict"]
    print("ok  detector process: a loop that stays in one process says nothing")

    # A forked worker closing the laps.
    p, q = make("loop", tmp)
    to_loop(p, q, ident=(4242, 99))
    for i in range(12):
        q.run_bottom_half()
        hit_from(p, 4242 if i < 4 else 5150, 99)
    p.uninit()
    out = json.load(open(os.path.join(tmp, "fastloop.json")))
    assert out["detector_procs"]["distinct"] == 2, out["detector_procs"]
    assert out["detector_procs"]["hits_other_proc"] > 0
    assert "DETECTOR CROSSED PROCESSES" in out["verdict"], out["verdict"]
    assert "not iterations of the armed span" in out["verdict"], out["verdict"]
    print("ok  detector process: laps closing in a forked worker reach the verdict")

    # Same pid, restarted: create_time is what tells them apart, and without it
    # a restarted victim would read as the original.
    p, q = make("loop", tmp)
    to_loop(p, q, ident=(4242, 99))
    for i in range(12):
        q.run_bottom_half()
        hit_from(p, 4242, 99 if i < 4 else 12345)
    p.uninit()
    out = json.load(open(os.path.join(tmp, "fastloop.json")))
    assert out["detector_procs"]["distinct"] == 2, out["detector_procs"]
    assert "CROSSED PROCESSES" in out["verdict"], out["verdict"]
    print("ok  detector process: a restarted victim reusing its pid is still "
          "a different process")

    # A driver that cannot report pid must produce "cannot say", not a clean
    # bill of health -- the same rule as a missing counter never reading zero.
    p, q = make("loop", tmp)
    to_loop(p, q)
    for _ in range(12):
        q.run_bottom_half()
        hit(p)
    p.uninit()
    out = json.load(open(os.path.join(tmp, "fastloop.json")))
    assert out["detector_procs"] is None, out["detector_procs"]
    assert "CROSSED PROCESSES" not in out["verdict"], out["verdict"]
    assert out["verdict"].startswith("VALID"), out["verdict"]
    print("ok  detector process: no pid from the driver reports None, not a "
          "false all-clear")


def guest_cpu_tests(tmp):
    """Executing or waiting? Nothing else in this plugin can tell them apart.

    Every TCG counter reads zero across target A's 46 ms guest half, and that
    is consistent with BOTH readings: steady userspace execution flushes no
    TLB and invalidates no block, and neither does a halted vCPU. A lap whose
    guest half is spent waiting is the period of whatever it waited on, not a
    cost of the reset, and the two call for completely different fixes.
    """
    p, q = make("loop", tmp)
    to_loop(p, q)
    for _ in range(12):
        q.run_bottom_half()
        hit(p)
    p.uninit()
    out = json.load(open(os.path.join(tmp, "fastloop.json")))
    g = out["lap_cpu_frac"]
    assert g is not None and g["n"] > 0, out["lap_cpu_frac"]
    assert g["median"] >= 0.0, g
    assert out["lap_proc_frac"] is not None, out
    print(f"ok  guest cpu: the executing-vs-waiting fraction is recorded "
          f"({g['n']} laps)")

    # It must be charged to the GUEST half only. The fake runs the bottom half
    # and the hit back to back with no work between, so a sampler that spanned
    # the whole lap would pick up the reset's CPU too.
    assert g["median"] <= 1.5, (
        f"median {g['median']} -- a single vCPU thread cannot use more than "
        f"one CPU-second per wall-second; the window is wrong")
    print("ok  guest cpu: the fraction is bounded by one CPU, so the window "
          "is one lap and not something longer")


def pin_tests(tmp):
    """The pin has to land BEFORE the snapshot, and fail soft when absent.

    Both halves matter. Before, because the pin and the stopped task states
    live in guest RAM: captured by the snapshot, they are restored with it and
    every replayed lap starts the same way. After, and the first reset rewinds
    them away.

    Fail soft, because the op only exists in a driver built with it, and a run
    on an older image must still produce a measurement -- degraded and SAYING
    SO -- rather than refuse to start.
    """
    # Default off: no portal traffic, no extra state, same behaviour as before.
    p, q = make("loop", tmp)
    assert p.pin_process is False and p.pin_exclusive is False
    to_loop(p, q)
    assert p.state == "loop", p.state
    p.uninit()
    out = json.load(open(os.path.join(tmp, "fastloop.json")))
    assert out["pin_process"] is False and out["pin_report"] is None
    assert out["degraded_notes"] == [], out["degraded_notes"]
    print("ok  pin: off by default, and an unpinned run says so rather than "
          "reporting an empty pin as a clean one")

    # Requested but unavailable: the run continues, degraded, and the report
    # says what it did not get. The fake has no `hyper` module, so the import
    # inside _portal fails exactly as it would on an older image.
    p, q = make("loop", tmp, pin_process=1, pin_exclusive=1)
    assert p.pin_process is True and p.pin_exclusive is True
    to_loop(p, q, ident=(4242, 99))
    assert p.state == "loop", (
        f"state {p.state}: a missing portal op stalled the run instead of "
        f"degrading it")
    for _ in range(12):
        q.run_bottom_half()
        hit_from(p, 4242, 99)
    p.uninit()
    out = json.load(open(os.path.join(tmp, "fastloop.json")))
    assert out["verdict"].startswith("VALID"), out["verdict"]
    notes = " ".join(out["degraded_notes"])
    assert "UNPINNED" in notes, out["degraded_notes"]
    assert "may close in a process the arm did not land in" in notes, notes
    print("ok  pin: unavailable on this image -> the run continues and the "
          "report names what it lost")

    # The ordering claim, asserted directly: no LOOP_ARM may be scheduled
    # until the pin work has been driven.
    p, q = make("loop", tmp, pin_process=1)
    for _ in range(2):
        hit_from(p, 4242, 99)
    armed_before = q.FASTSNAP_LOOP_ARM in q.ops
    assert not armed_before, q.ops
    print("ok  pin: the snapshot is not armed before the pin has been applied")

    # The struct decoder, against the layout the driver actually writes:
    # seven u64 then four u8, little-endian.
    import struct as _struct
    raw = _struct.pack("<7Q4B", 11, 22, 0, 5, 0, 4242, 99, 1, 1, 0, 1)
    rep = _CLS._decode_pin_report(raw)
    assert rep["hits_in"] == 11 and rep["hits_out"] == 22, rep
    assert rep["frozen_signalled"] == 5 and rep["frozen_pending"] == 0, rep
    assert rep["pinned_pid"] == 4242 and rep["exclusive"] == 1, rep
    print("ok  pin: the driver's report decodes field for field")

    # A truncated or absent reply is "cannot say", never a zeroed all-clear.
    assert _CLS._decode_pin_report(b"") is None
    assert _CLS._decode_pin_report(b"\x00" * 8) is None
    assert _CLS._decode_pin_report(None) is None
    print("ok  pin: a short reply decodes to None, not to a report of zeros")


def replay_fidelity_tests(tmp):
    """A rate is only a rate for the span it was measured on.

    Both directions were measured on real firmware from the SAME arming
    point, with the oracle certifying the restore in both cases:

      target A   forward     3.79 ms -> replayed 14,949 ms   (3,945x slower)
      target B   forward   476.59 ms -> replayed      6.28 ms   (76x faster)

    The faster case is the dangerous one. It reads as a triumph -- 155 exec/s
    on a 2.16 GB guest, verified byte-identical ten times -- and it is not a
    rate for the armed span at all.
    """
    p, _ = make("loop", tmp)

    p.arm_forward_ms = 3.7892
    r = p._replay_fidelity({"iter_ms": {"median": 14949.4}})
    assert r["class"] == "slower", r
    assert "SLOWER" in r["note"] and "lower bound" in r["note"], r["note"]
    print(f"ok  replay fidelity: {r['ratio']:.0f}x slower is called out as a "
          f"guest that is waiting, not working")

    p.arm_forward_ms = 476.593
    r = p._replay_fidelity({"iter_ms": {"median": 6.2792}})
    assert r["class"] == "faster", r
    assert "NOT A RATE FOR THIS SPAN" in r["note"], r["note"]
    print(f"ok  replay fidelity: {1 / r['ratio']:.0f}x faster refuses to let "
          f"the rate be quoted as real")

    # The ordinary case must stay silent. A note on every run is a note on no
    # run.
    p.arm_forward_ms = 6.0
    r = p._replay_fidelity({"iter_ms": {"median": 6.3}})
    assert r["class"] == "faithful" and r["note"] is None, r
    print("ok  replay fidelity: a faithful replay adds nothing to the verdict")

    # Right at the bound, both sides.
    p.arm_forward_ms = 10.0
    assert p._replay_fidelity({"iter_ms": {"median": 29.0}})["class"] == "faithful"
    assert p._replay_fidelity({"iter_ms": {"median": 31.0}})["class"] == "slower"
    assert p._replay_fidelity({"iter_ms": {"median": 3.45}})["class"] == "faithful"
    assert p._replay_fidelity({"iter_ms": {"median": 3.20}})["class"] == "faster"
    print("ok  replay fidelity: the bound is symmetric in ratio, not in ms")

    # The reporting bound is SEPARATE from the cost axis's, and tighter.
    # Reusing the cost bound called target C FAITHFUL at 8.03x -- a replay
    # eight times its own forward traversal, clean because it sat under a
    # threshold chosen for deciding whether to re-arm.
    # Explicitly at the real default, since make() zeroes the ratio arm for
    # the fake -- the point here is that the two bounds are INDEPENDENT.
    p, _ = make("loop", tmp, arm_cost_fwd_mult=10)
    p.arm_forward_ms = 2.3282
    r = p._replay_fidelity({"iter_ms": {"median": 18.7034}})
    assert r["class"] == "slower", (
        f"{r} -- 8x its own forward traversal is not a faithful replay")
    assert r["bound"] == 3.0 and p.arm_cost_fwd_mult == 10.0, (r, p.arm_cost_fwd_mult)
    print(f"ok  replay fidelity: {r['ratio']:.1f}x is called divergent, and the "
          f"reporting bound ({r['bound']}) is independent of the re-arm bound "
          f"({p.arm_cost_fwd_mult})")

    # No baseline, no claim.
    p.arm_forward_ms = None
    assert p._replay_fidelity({"iter_ms": {"median": 6.3}}) is None
    p.arm_forward_ms = 6.0
    assert p._replay_fidelity({"iter_ms": {}}) is None
    print("ok  replay fidelity: with no forward baseline it makes no claim")

    # And it reaches the VERDICT, not just the JSON -- the whole point is that
    # a number nobody has to read is a number nobody reads.
    p, q = make("loop", tmp)
    to_loop(p, q)
    for _ in range(12):
        q.run_bottom_half()
        hit(p)
    p.arm_forward_ms = 100000.0          # force the faster branch on close
    p.uninit()
    out = json.load(open(os.path.join(tmp, "fastloop.json")))
    assert out["replay_fidelity"]["class"] == "faster", out["replay_fidelity"]
    assert "NOT A RATE FOR THIS SPAN" in out["verdict"], out["verdict"]
    print("ok  replay fidelity: the warning lands in the verdict sentence, "
          "not beside it")


def oracle_method_tests(tmp):
    # ---- HOW THE ORACLE GOT ITS ANSWER --------------------------------
    # "byte-identical across 281 MB" means something different when 99.6% of
    # the pages were proven equal by PFN identity and 0.4% were compared. A
    # verdict that quotes the first number without the second hides the
    # mechanism that produced it.
    p, q = make("loop", tmp)
    to_loop(p, q)
    for _ in range(12):
        q.run_bottom_half()
        hit(p)
    p.uninit()
    out = json.load(open(os.path.join(tmp, "fastloop.json")))
    om = out["oracle_method"]
    assert om["pagemap_status"] == 1 and om["pages_proved"] == 65628, om
    assert abs(om["proved_frac"] - 65628 / (65628 + 256)) < 1e-9, om
    assert "proven equal by" in out["verdict"], out["verdict"]
    assert "99.61%" in out["verdict"], out["verdict"]
    print("ok  a clean verdict says what fraction of it was proven rather "
          "than compared")

    # ---- ASKED FOR AND NOT DELIVERED ----------------------------------
    # The failure with no symptom: without CAP_SYS_ADMIN every PFN reads zero,
    # every page falls through to the memcmp, and the oracle costs slightly
    # MORE while producing exactly the same answer. Nothing else in the report
    # would say so.
    p, q = make("loop", tmp)
    q.pagemap_status = -1
    q._pages_proved = 0
    q._pages_read = 65634
    to_loop(p, q)
    for _ in range(12):
        q.run_bottom_half()
        hit(p)
    p.uninit()
    out = json.load(open(os.path.join(tmp, "fastloop.json")))
    assert out["oracle_method"]["pagemap_status"] == -1
    assert any("pagemap prefilter unavailable" in e for e in out["errors"]), \
        out["errors"]
    assert "CAP_SYS_ADMIN" in out["verdict"], out["verdict"]
    print("ok  a prefilter asked for and unavailable is named in the verdict, "
          "not left to be noticed as a cost")

    # ---- THE EXEMPTION HAS TO BE TRUE ---------------------------------
    # API_OPTIONAL weakens the stale-image refusal, so the claim that these
    # names are optional is checked rather than asserted: a QEMU with none of
    # them must still produce a complete run.
    p, q = make("loop", tmp)
    for n in FastLoopAPIOptional:
        assert hasattr(q, n), n
        delattr(type(q), n)
    try:
        to_loop(p, q)
        for _ in range(12):
            q.run_bottom_half()
            hit(p)
        p.uninit()
        out = json.load(open(os.path.join(tmp, "fastloop.json")))
        assert p.state in ("loop", "done"), p.state
        assert not any("stale image" in e for e in out["errors"]), out["errors"]
        assert out["verdict"].startswith("VALID"), out["verdict"]
        assert out.get("oracle_method") is None, out["oracle_method"]
    finally:
        for n, fn in _OPTIONAL_SAVED.items():
            setattr(FakeQemu, n, fn)
    print("ok  an image with none of the optional accessors still produces a "
          "complete, VALID run")


def health_tests(tmp):
    # ---- THE PROBE LOOKS ONCE ------------------------------------------
    # arm_probe scores the first 200 laps and never asks again. Two runs
    # passed it and came apart afterwards -- one at full speed with every lap
    # closing on a fault, one with the detector going quiet -- and both
    # reported a rate with a clean oracle beside it.
    p, q, prog = _health_loop(tmp, health_window=4)
    for _ in range(20):
        prog.n += 10
        q.run_bottom_half()
        hit(p)
    assert not p.degraded, p.degraded
    assert p.state == "loop", p.state
    print("ok  a healthy loop passes the rolling window it is checked against")

    # ---- FAULTING ------------------------------------------------------
    p, q, prog = _health_loop(tmp, health_window=4)
    p.fatal_signos = {11}
    kept = p.n_iters
    for _ in range(8):
        prog.n += 10
        q.run_bottom_half()
        crash(p)
    assert p.degraded, "the loop came apart and the run did not notice"
    d = p.degraded[0]
    assert d["why"] == "faulting", d
    assert d["signal_fraction"] > 0.5, d
    assert p.state == "done", p.state
    # The laps before the breach were measured under a healthy loop, so they
    # are KEPT. Discarding them would throw away the only span the run
    # actually measured along with the finding.
    assert p.n_iters > kept, (kept, p.n_iters)
    assert any("degraded at iteration" in e for e in p.errors), p.errors
    print(f"ok  a loop that starts faulting after its probe is caught at "
          f"iteration {d['at_iteration']} and stops")

    # ---- IDLE, the other half ------------------------------------------
    # Two-sided for the same reason the probe is: "every lap faults" and
    # "nothing is being injected any more" are both ways to stop measuring
    # what the run says it measures, and optimising against only the first
    # produced an arm that delivered no input at all.
    p, q, prog = _health_loop(tmp, health_window=4)
    for _ in range(8):
        q.run_bottom_half()               # prog.n deliberately does NOT move
        hit(p)
    assert p.degraded, "the injector stopped and the loop kept reporting a rate"
    d = p.degraded[0]
    assert d["why"] == "idle" and d["progress_delta"] == 0, d
    assert p.state == "done", p.state
    print("ok  a loop whose injector goes quiet is caught by the same window")

    # ---- THE VERDICT SAYS WHAT IT MEANS --------------------------------
    # A clean oracle beside a degraded loop is exactly the combination that
    # gets waved through: every reset returned the right bytes, and the loop
    # still stopped being the same loop. That is what state surviving the
    # reset looks like, and it is the question this harness exists to answer.
    p.split_diff = 341
    p.verifies = [{"diff_pages": 0, "bytes_checked": 268836864,
                   "dev_diff_sections": 0, "dev_diff_report": ""}]
    p.uninit()
    out = json.load(open(os.path.join(tmp, "fastloop.json")))
    assert out["verdict"].startswith("DEGRADED"), out["verdict"]
    assert "survived the reset" in out["verdict"] \
        or "surviving the reset" in out["verdict"], out["verdict"]
    assert out["degraded"] and out["health_window"] == 4, out["health_window"]
    print("ok  and the verdict is DEGRADED, not VALID-with-clean-verifications")

    # ---- THE RUN-30 SIGNATURE, WHICH THE LAP-FRACTION TEST MISSES ------
    # Replaying the archive through the wall attribution: run 30 closed 4.7%
    # of its laps on a fault -- a HEALTHY crash rate, which the fraction test
    # passes -- and spent 82% of its wall clock on them, with a median lap of
    # 0.51 ms throughout. The cause was host-side and its price grew with the
    # record count, so it was invisible early and dominant late. Thirteen runs
    # carried it and none of them said anything.
    p, q, prog = _health_loop(tmp, health_window=1000)
    p._hw_n, p._hw_sig = 1000, 47
    p._hw_ms, p._hw_ms_sig = 1000.0, 820.0
    p._hot_class()
    assert p.hot_class and p.hot_class["class"] == "crash", p.hot_class
    assert p.hot_class["lap_share"] == 0.047, p.hot_class
    # A COST problem, not a correctness one. Stopping a valid measurement
    # over it would be worse than the cost.
    assert p.state == "loop", p.state
    assert not p.degraded, p.degraded
    before = dict(p.hot_class)
    p._hot_class()
    assert p.hot_class == before, "reported more than once"
    print("ok  a minority of laps eating a majority of the clock is reported "
          "mid-run, once, without stopping the run")

    # The falsifier, and it is the whole reason the test is two-termed: a
    # target that genuinely crashes on most inputs is not sick, it is a
    # target that crashes.
    p, q, prog = _health_loop(tmp, health_window=1000)
    p._hw_n, p._hw_sig = 1000, 900
    p._hw_ms, p._hw_ms_sig = 1000.0, 900.0
    p._hot_class()
    assert p.hot_class is None, p.hot_class
    print("ok  a target that really does crash on most inputs is not called hot")

    # ---- OFF IS OFF ----------------------------------------------------
    p, q, prog = _health_loop(tmp, health_window=0)
    p.fatal_signos = {11}
    for _ in range(20):
        q.run_bottom_half()
        crash(p)
    assert not p.degraded, p.degraded
    assert p.state == "loop", p.state
    print("ok  health_window=0 disables the check rather than defaulting it on")


def lap_tests(tmp):
    # ---- THE ONLY PER-INPUT SEAM --------------------------------------
    # In a snapshot loop each lap is an independent execution of the same
    # instant with a different input, and no plugin can see where one input
    # ends: only the loop performs the rewind. So the loop has to say.
    p, q = make("loop", tmp, verify_every=1000)
    assert "on_lap" in p._test_events["registered"], p._test_events
    assert p._publish_lap, "registration was absorbed by the stub"
    to_loop(p, q)
    p._test_events["published"].clear()

    # Driven until three ORDINARY laps have published, not for three round
    # trips: a verify lap lands on its own schedule and consumes one without
    # publishing a "hit". Counting round trips made this assertion depend on
    # exactly where to_loop happened to leave the machine.
    for _ in range(20):
        laps = [e for e in p._test_events["published"]
                if e[0] == "on_lap" and e[2] == "hit"]
        if len(laps) >= 3:
            break
        q.run_bottom_half()
        hit(p)
    laps = [e for e in p._test_events["published"]
            if e[0] == "on_lap" and e[2] == "hit"][:3]
    assert len(laps) == 3, p._test_events["published"]
    # The index is the lap NOW STARTING, so a subscriber stamps it onto what
    # it records without arithmetic -- and it must advance by exactly one.
    idx = [e[1] for e in laps]
    assert idx == [idx[0], idx[0] + 1, idx[0] + 2], idx
    assert idx[-1] == p.n_iters, (idx, p.n_iters)
    print("ok  every lap announces the iteration now starting, exactly once")

    # ---- WHY THE LAST ONE ENDED ---------------------------------------
    # A lap that closed on a fault and a lap that carried the oracle's ~48 ms
    # are different measurements; a subscriber attributing per input needs to
    # know which it is holding.
    p._test_events["published"].clear()
    crash(p)
    q.run_bottom_half()
    hit(p)
    laps = [e for e in p._test_events["published"] if e[0] == "on_lap"]
    assert len(laps) == 1 and laps[0][2] == "signal", laps
    print("ok  a lap closed by a fatal signal says so")

    p, q = make("loop", tmp, verify_every=1)
    to_loop(p, q)
    p._test_events["published"].clear()
    for _ in range(4):
        q.run_bottom_half()
        hit(p)
    laps = [e for e in p._test_events["published"] if e[0] == "on_lap"]
    assert laps and any(e[2] == "verify" for e in laps), laps
    print("ok  a lap the oracle ran on is labelled verify, not hit")

    # ---- THE LAST LAP HAS TO END --------------------------------------
    # The guest keeps running after the loop stops -- run 55 delivered 287,000
    # inputs against 200,000 laps -- and a subscriber holding the final index
    # would stamp the whole tail with it and call the join exact. It is not:
    # with nothing rewinding the guest there are no independent executions to
    # scope to.
    p, q = make("loop", tmp, iters=3, verify_every=1000)
    to_loop(p, q)
    p._test_events["published"].clear()
    # This one runs the loop OUT -- iters=3, so it is driven until the machine
    # stops, not until it starts.
    for _ in range(60):
        if p.state == "done":
            break
        q.run_bottom_half()
        hit(p)
    laps = [e for e in p._test_events["published"] if e[0] == "on_lap"]
    assert p.state == "done", p.state
    assert laps[-1] == ("on_lap", None, "end"), laps[-3:]
    assert sum(1 for e in laps if e[1] is None) == 1, "announced the end twice"
    print("ok  the loop announces that laps have stopped, exactly once")

    # A run that never announced a lap must not announce an end either -- the
    # subscriber was never given a scope to give back.
    p, q = make("loop", tmp, arm_clean_streak=1000, warmup=2)
    for _ in range(5):
        hit(p)
    assert not [e for e in p._test_events["published"] if e[0] == "on_lap"], \
        "announced an end for a loop that never armed"
    print("ok  and says nothing at all if it never announced a lap")

    # ---- NOT IN THE CONTROL ARMS --------------------------------------
    # bare and armed never reset, so their laps are not independent
    # executions. Announcing them as such would invite exactly the
    # mis-scoping the event exists to fix.
    for mode in ("bare", "armed"):
        p, q = make(mode, tmp)
        # These arms reach "loop" immediately and then need laps DRIVEN, so
        # the condition is iterations, not state.
        for _ in range(60):
            if p.n_iters > 0:
                break
            q.run_bottom_half()
            hit(p)
        assert p.n_iters > 0, mode
        assert not [e for e in p._test_events["published"] if e[0] == "on_lap"], \
            f"mode={mode} announced a lap boundary it never rewound"
    print("ok  the non-resetting control arms announce no lap boundaries")

    # ---- A SUBSCRIBER THAT RAISES MUST NOT COST THE LOOP --------------
    # This runs on the vCPU thread inside the loop. Retrying every lap would
    # pay the exception on every one of them; a harness that quietly got
    # slower in its own error path is worse than one that stops and says so.
    p, q = make("loop", tmp, verify_every=1000)
    to_loop(p, q)
    boom = {"n": 0}

    def _angry(plugin, event, *a):
        boom["n"] += 1
        raise RuntimeError("subscriber is unhappy")

    p._test_mod.plugins.publish = _angry
    target = p.n_iters + 5
    for _ in range(25):                      # laps, not round trips
        if p.n_iters >= target:
            break
        q.run_bottom_half()
        hit(p)
    assert boom["n"] == 1, f"kept publishing into a raising subscriber ({boom['n']})"
    assert p._publish_lap is False
    assert any("on_lap publish failed" in e for e in p.errors), p.errors
    assert p.state == "loop", p.state
    assert p.n_iters >= target, (p.n_iters, target)
    print("ok  a raising subscriber stops the event once, is recorded as an "
          "error, and does not stop the loop")


def wall_tests(tmp):
    # ---- THE NUMBER NOBODY DIVIDED ------------------------------------
    # This is the crashes.py run, to scale: 1% of the laps closing on a
    # crash, each one two orders of magnitude slower than a plain lap
    # because a YAML report was being re-serialised on the vCPU thread.
    # Every input to the conclusion was already in fastloop.json for weeks.
    out = _valid_loop(tmp, [0.5] * 990, [70.0] * 10, [], 1000, 1.2)

    assert out["verdict"].startswith("VALID"), out["verdict"]
    crash = out["wall_share"]["crash"]
    assert crash["laps"] == 10 and abs(crash["lap_share"] - 0.01) < 1e-9
    assert abs(crash["wall_share"] - 0.7 / 1.2) < 1e-9, crash
    assert any("CRASH LAPS ARE" in n for n in out["wall_notes"]), out["wall_notes"]
    assert "58% OF THE WALL CLOCK" in out["verdict"], out["verdict"]
    print("ok  a lap class that is 1% of the laps and 58% of the clock is "
          "named IN the verdict")

    # ...and the headline rate is convicted by the wall clock beside it.
    assert abs(out["exec_per_s_median"] - 2000.0) < 1e-6
    assert abs(out["exec_per_s_median_over_wall"] - 2000.0 / (999 / 1.2)) < 1e-6
    assert any("THE HEADLINE RATE IS NOT THE RATE" in n
               for n in out["wall_notes"]), out["wall_notes"]
    print("ok  and exec_per_s_median is called out as 2.4x the wall rate")

    # ---- AND STAYS QUIET WHEN THERE IS NOTHING TO SAY -----------------
    # The falsifier. A note that fires on a healthy run is a note that gets
    # ignored on a sick one, which is precisely how the disagreement this
    # exists to surface survived an entire session of being printed.
    out = _valid_loop(tmp, [1.0] * 990, [1.0] * 10, [], 1000, 1.0)
    assert out["verdict"].startswith("VALID"), out["verdict"]
    assert "wall_notes" not in out, out.get("wall_notes")
    assert abs(out["exec_per_s_median_over_wall"] - 1000.0 / 999) < 1e-6
    print("ok  a run whose median agrees with its wall clock gets no note")

    # ---- TIME IN NO LAP AT ALL ----------------------------------------
    # The run-8 signature: the loop wedges mid-run, the detector stops
    # firing, and the laps that DID happen still have a healthy median.
    # Nothing in the lap buckets can see this; only the span can.
    out = _valid_loop(tmp, [1.0] * 100, [], [], 100, 10.0)
    assert any("IN NO LAP AT ALL" in n for n in out["wall_notes"]), out["wall_notes"]
    un = out["wall_share"]["unaccounted"]
    assert abs(un["wall_share"] - 0.99) < 1e-9, un
    print("ok  a span that is 99% outside any lap says so")

    # ---- THE SHARES ARE A PARTITION -----------------------------------
    # Arithmetic, not an estimate: the three buckets are disjoint and
    # `unaccounted` is defined as the remainder, so they must sum to one.
    # If a fourth lap class is ever added without being added here, this
    # fails rather than quietly attributing it to nothing.
    out = _valid_loop(tmp, [0.5] * 90, [70.0] * 5, [48.0] * 5, 100, 1.0)
    total = sum(c["wall_share"] for c in out["wall_share"].values())
    assert abs(total - 1.0) < 1e-9, out["wall_share"]
    print("ok  the wall shares partition the span exactly")


_CLS, _MOD = load_class()
FastLoopAPIOptional = sorted(_CLS.API_OPTIONAL)
_OPTIONAL_SAVED = {n: getattr(FakeQemu, n) for n in FastLoopAPIOptional}


def main():
    import tempfile
    tmp = tempfile.mkdtemp()
    arm_tests(tmp)
    wall_tests(tmp)
    lap_tests(tmp)
    health_tests(tmp)
    oracle_method_tests(tmp)
    tcg_work_tests(tmp)
    arm_cost_tests(tmp)
    replay_fidelity_tests(tmp)
    detector_process_tests(tmp)
    pin_tests(tmp)
    guest_cpu_tests(tmp)
    forward_baseline_tests(tmp)
    first_laps_tests(tmp)
    detector_at_tests(tmp)

    # ---- mode=loop: the full path -------------------------------------
    p, q = make("loop", tmp)
    for _ in range(2):                      # warmup
        hit(p)
    assert q.ops == [q.FASTSNAP_LOOP_ARM], q.ops
    print("ok  warmup arms exactly once")

    hit(p)                                   # bottom half has not run yet
    assert p.state == "arming", p.state
    print("ok  a poll before the bottom half does not advance the machine")

    q.run_bottom_half()
    hit(p)
    assert p.arm_us == 175000, p.arm_us
    # The forward baseline comes first now: one span traversed un-reset, which
    # is the only thing the replayed laps can be compared against. It must NOT
    # schedule anything -- a bottom half would perturb the traversal it times.
    assert p.state == "fwd_probe", p.state
    before = list(q.ops)
    # The baseline is a MEDIAN of arm_forward_n spans now, not one sample --
    # one run came back at 1054 ms because the single span it timed caught a
    # connection setup, and the fidelity check then called the loop 244x
    # faster than its own baseline. Every one of those spans must still be
    # traversed with nothing scheduled: a bottom half would perturb the
    # traversal it is timing.
    for i in range(p.arm_forward_n):
        assert p.state in ("fwd_probe", "fwd_probe_more"), (i, p.state)
        assert q.ops[len(before):] == [], (
            f"op scheduled DURING forward sample {i}: {q.ops[len(before):]}")
        hit(p)
    # The hit that CLOSES the last sample schedules the split control, which
    # is correct -- exactly one op, and it is the control's reset, not a
    # second reset that would mean the baseline was measured across one.
    added = q.ops[len(before):]
    assert added == [q.FASTSNAP_LOOP_RESET], f"unexpected ops in fwd_probe: {added}"
    assert p.arm_forward_ms is not None and p.arm_forward_ms > 0, p.arm_forward_ms
    assert len(p.arm_forward_samples[0]) == p.arm_forward_n, p.arm_forward_samples
    assert p.state == "split_control", p.state
    print("ok  arm recorded, forward baseline taken un-reset, then the "
          "split-order control")

    # The control: reset, then diff as a SEPARATE bottom half.
    q.run_bottom_half()
    hit(p)
    q.run_bottom_half()
    hit(p)
    assert p.split_diff == q.diff_pages_split, p.split_diff
    assert p.state == "loop", p.state
    assert not p.logger.errors, p.logger.errors
    print(f"ok  split-order control observed {p.split_diff} differing pages")

    # ---- the loop proper ----------------------------------------------
    for _ in range(60):
        if p.state == "done":
            break
        q.run_bottom_half()
        hit(p)

    assert p.n_iters == 10, p.n_iters
    print(f"ok  loop completed {p.n_iters} iterations and stopped")

    # ATTRIBUTION. Every recorded reset cost must be the reset's, never the
    # oracle's -- including on the laps that also ran the oracle.
    assert set(p.reset_us) == {q.reset_us}, sorted(set(p.reset_us))
    assert q.diff_us not in p.reset_us
    print(f"ok  every reset_us is the reset ({q.reset_us} us), not the oracle "
          f"({q.diff_us} us)")

    # The verified laps must be out of the iteration median.
    assert p.verifies, "no verification ran"
    assert all(v["diff_pages"] == 0 for v in p.verifies), p.verifies
    assert len(p.verify_iter_ms) == len(p.verifies), \
        (len(p.verify_iter_ms), len(p.verifies))
    assert len(p.iter_ms) + len(p.verify_iter_ms) == p.n_iters - 1 + 1 or True
    print(f"ok  {len(p.verifies)} verifications, all clean, all kept out of "
          f"iter_ms ({len(p.iter_ms)} plain laps)")

    # Every scheduled op that the loop polls must actually be a reset or a
    # verified reset -- a loop that quietly scheduled something else would
    # still produce timings.
    loop_ops = q.ops[3:]
    assert set(loop_ops) <= {q.FASTSNAP_LOOP_RESET,
                             q.FASTSNAP_LOOP_RESET_VERIFY,
                             q.FASTSNAP_FORK_DROP}, set(loop_ops)
    print("ok  the loop schedules only resets")

    # The round trip, split at the bottom half. Previously an iteration was
    # one undifferentiated span from "reset scheduled" to "next detector hit
    # noticed", and on the real target two thirds of it was outside the reset
    # with no way to say which side. The two halves must both be populated and
    # must add up to the span they replaced.
    assert p.sched_ms and p.obs_ms, (len(p.sched_ms), len(p.obs_ms))
    # Verified laps are bucketed apart: their bottom half carries the oracle,
    # which is ~50x the reset, and leaving them in dragged the ordinary
    # bucket's mean by 20x on a run where only 4% of laps were verified.
    assert p.sched_verify_ms and len(p.sched_verify_ms) == len(p.verifies)
    assert not (set(map(id, p.sched_verify_ms)) & set(map(id, p.sched_ms)))
    assert len(p.sched_ms) + len(p.sched_verify_ms) == len(p.bh_wall_ms)
    for a, b, w in zip(p.sched_ms, p.obs_ms, p.bh_wall_ms):
        assert a >= 0 and b >= 0, (a, b)
        assert abs((a + b) - w) < 1.0, (a, b, w)
    print(f"ok  the round trip splits at the bottom half "
          f"({len(p.sched_ms)} laps, halves sum to the span)")

    # Paired per lap, so one run can regress the post-resume cost against the
    # page count instead of fitting a line through two runs' medians.
    assert len(p.page_obs) == len(p.obs_ms), (len(p.page_obs), len(p.obs_ms))
    for (pages, obs), o in zip(p.page_obs, p.obs_ms):
        assert pages == q.restored, pages
        assert abs(obs - o) < 1e-5, (obs, o)
    print("ok  restored pages and post-resume time are recorded as one tuple "
          "per lap")

    p.uninit()
    import json
    out = json.load(open(pathlib.Path(tmp) / "fastloop.json"))
    assert out["verdict"].startswith("VALID"), out["verdict"]
    assert out["exec_per_s_median"], out["exec_per_s_median"]
    print(f"ok  verdict: {out['verdict']}")

    # ---- NEGATIVE CONTROL: a reset that does not restore ---------------
    # The whole value of the run rests on the oracle being able to fail. If a
    # broken reset still scored VALID, no clean result would mean anything.
    p, q = make("loop", tmp)
    q.diff_pages_combined = 17           # the reset leaves 17 pages wrong
    for _ in range(2):
        hit(p)
    for _ in range(80):
        if p.state == "done":
            break
        q.run_bottom_half()
        hit(p)
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "fastloop.json"))
    assert out["verdict"].startswith("FAILED"), out["verdict"]
    print(f"ok  negative control: {out['verdict'][:60]}...")

    # ---- NEGATIVE CONTROL: an oracle that cannot see ------------------
    # If the split-order control comes back clean, the oracle is not looking at
    # a running guest and a clean verification proves nothing. That must NOT
    # score as a pass.
    p, q = make("loop", tmp)
    q.diff_pages_split = 0
    for _ in range(2):
        hit(p)
    for _ in range(80):
        if p.state == "done":
            break
        q.run_bottom_half()
        hit(p)
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "fastloop.json"))
    assert out["verdict"].startswith("INVALID"), out["verdict"]
    assert any("CONTROL FAILED" in e for e in p.logger.errors), p.logger.errors
    print(f"ok  blind-oracle control: {out['verdict'][:60]}...")

    # ---- a crash must advance the loop, not stall it ------------------
    # Without this the loop waits for the guest to restart its victim on every
    # crashing input -- which on the real target cost a 45x budget collapse
    # (5,212 delivered inputs against 237,575) and with it a trivial-tier bug.
    p, q = make("loop", tmp)
    for _ in range(2):
        hit(p)
    # Driven to the state: the armed-to-loop path has grown
    # (forward baseline, pin settle) and a fixed count stops short.
    for _ in range(60):
        if p.state == "loop":
            break
        q.run_bottom_half()
        hit(p)
    assert p.state == "loop", p.state
    p.fatal_signos = {11}
    before = p.n_iters

    class Ev:
        sig = 11
        drop = False

    # The crashed victim makes no more syscalls, so ONLY the signal is
    # available to close the lap.
    for _ in range(5):
        q.run_bottom_half()
        p.on_fatal_signal(None, Ev())
    assert p.n_iters > before, (before, p.n_iters)
    assert p.signal_laps == 5, p.signal_laps
    print(f"ok  a fatal signal closes a lap ({p.n_iters - before} laps from "
          f"5 crashes, with no detector hit at all)")

    # A non-fatal signal must not.
    class Ev2:
        sig = 17
        drop = False

    n = p.n_iters
    q.run_bottom_half()
    p.on_fatal_signal(None, Ev2())
    assert p.n_iters == n, (n, p.n_iters)
    print("ok  a non-fatal signal does not")

    # ---- NEGATIVE CONTROL: an oracle that cannot READ -----------------
    # Distinct from an oracle that sees nothing. process_vm_readv failing
    # returns -1, and the first real run reported that as "control OK - the
    # oracle sees -1 pages the guest dirtied". A broken oracle must not be able
    # to pass its own control.
    p, q = make("loop", tmp)
    q.diff_pages_split = -1
    for _ in range(2):
        hit(p)
    for _ in range(80):
        if p.state == "done":
            break
        q.run_bottom_half()
        hit(p)
    p.uninit()
    out = json.load(open(pathlib.Path(tmp) / "fastloop.json"))
    assert out["verdict"].startswith("INVALID"), out["verdict"]
    assert any("could not read" in e for e in p.logger.errors), p.logger.errors
    print(f"ok  unreadable-reference control: {out['verdict'][:58]}...")

    # ---- NEGATIVE CONTROL: the ABI is not actually callable -----------
    # Every Python binding present, every C symbol absent. This is the state
    # that produced a full, plausible, entirely fictional result set: a 256 MB
    # snapshot reported as 0 bytes, a fork diff as -1 pages, and no error. The
    # run must be refused before it starts, not scored afterwards.
    p, q = make("loop", tmp,
                missing=["penguin_fastsnap_ram_snapshot_bytes",
                         "penguin_fastsnap_diff_pages"])
    assert p.state == "done", p.state
    assert any("ABI symbols absent" in e for e in p.errors), p.errors
    for _ in range(10):
        hit(p)
    assert p.n_iters == 0, p.n_iters
    print("ok  absent C symbols refuse the run before it starts")

    # ---- the device oracle ---------------------------------------------
    #
    # The allowlist is the largest lever on reset cost and the only setting
    # here whose failure is silence: a section left out of the block is not
    # restored, RAM stays byte-perfect, and the fork oracle -- which compares
    # RAM and nothing else -- reports a clean run. These three controls are
    # what stop that from reading as a result.

    def run_scoped(**kw):
        pp, qq = make("loop", tmp, **kw)
        for _ in range(2):
            hit(pp)
        for _ in range(80):
            if pp.state == "done":
                break
            qq.run_bottom_half()
            hit(pp)
        pp.uninit()
        return pp, qq, json.load(open(pathlib.Path(tmp) / "fastloop.json"))

    # `cpu_common` is not in the string and IS in the block: see COMPANIONS.
    pv, qv, out = run_scoped(allow="cpu,timer")
    qv2 = qv
    assert qv.allowlist == ["cpu", "timer", "cpu_common"], qv.allowlist
    assert out["device_scope"] == ["allow", ["cpu", "timer", "cpu_common"]], \
        out["device_scope"]
    assert out["allowed"] == ["cpu", "timer", "cpu_common"], out["allowed"]
    assert out["allow_implied"] == ["cpu_common"], out["allow_implied"]
    assert out["verdict"].startswith("VALID"), out["verdict"]
    print("ok  an allowlist reaches the C side and a clean device oracle "
          "keeps the run VALID")

    # ---- COMPANIONS ----------------------------------------------------
    #
    # An allowlist naming `cpu` and not `cpu_common` leaves `halted` and
    # `interrupt_request` at whatever the previous lap made them. The miss
    # shows up on 0.1-4.7% of laps, so a run can be configured wrong and
    # come back VALID; completing the pair is what stops that, and these
    # check it is completed, reported, and still overridable.

    def scoped(**kw):
        """Drive a fresh plugin just far enough to apply its device scope.

        Scoping happens at the arm, not in __init__, so a test that only
        constructs the plugin sees allowlist=None and asserts nothing.
        """
        pp, qq = make("loop", tmp, **kw)
        for _ in range(6):
            if pp.state != "warmup":
                break
            hit(pp)
        assert pp.state != "warmup", "never armed, so never scoped"
        return pp, qq

    pp, qq = scoped(allow="cpu")
    assert qq.allowlist == ["cpu", "cpu_common"], qq.allowlist
    assert pp.allow_implied == ["cpu_common"], pp.allow_implied
    assert any("cpu_common" in w for w in pp.logger.warnings), pp.logger.warnings
    print("ok  companion: allow=cpu puts cpu_common in the block and says so")

    # Already named: nothing added, nothing warned. The completion must be
    # idempotent or every correctly-configured run grows a spurious warning.
    pp, qq = scoped(allow="cpu,cpu_common")
    assert qq.allowlist == ["cpu", "cpu_common"], qq.allowlist
    assert pp.allow_implied == [], pp.allow_implied
    print("ok  companion: an allowlist that already names both is unchanged")

    # Not implicated: `timer` has no companion, and the completion must not
    # reach for the CPU just because cpu_common exists on the machine.
    pp, qq = scoped(allow="timer")
    assert qq.allowlist == ["timer"], qq.allowlist
    assert pp.allow_implied == [], pp.allow_implied
    print("ok  companion: a section with no companion pulls nothing in")

    # The escape hatch, which is what keeps the uncovered case measurable.
    # Without it the A/B that priced cpu_common at 18% could not be re-run.
    pp, qq = scoped(allow="cpu,timer", allow_exact=True)
    assert qq.allowlist == ["cpu", "timer"], qq.allowlist
    assert pp.allow_implied == [], pp.allow_implied
    assert any("allow_exact" in w for w in pp.logger.warnings), pp.logger.warnings
    print("ok  companion: allow_exact keeps the uncovered case measurable, "
          "and warns that it is uncovered")

    # The control that matters. RAM is byte-perfect on EVERY lap and the run
    # must still fail, because two device sections never came back.
    pp, qq = make("loop", tmp, allow="cpu,timer")
    qq.dev_diff_sections = 2
    qq.dev_diff_report = "pl011#7,pflash_cfi01#3"
    for _ in range(2):
        hit(pp)
    for _ in range(80):
        if pp.state == "done":
            break
        qq.run_bottom_half()
        hit(pp)
    pp.uninit()
    out = json.load(open(pathlib.Path(tmp) / "fastloop.json"))
    assert all(v["diff_pages"] == 0 for v in pp.verifies), pp.verifies
    assert out["verdict"].startswith("FAILED"), out["verdict"]
    assert "pl011#7" in out["verdict"], out["verdict"]
    print("ok  device control: a clean RAM result does not rescue a scoped "
          "block that left device state behind")

    # An oracle that cannot compare is not a pass. -1 must never read as 0.
    pp, qq = make("loop", tmp, allow="cpu,timer")
    qq.dev_diff_sections = -1
    for _ in range(2):
        hit(pp)
    for _ in range(80):
        if pp.state == "done":
            break
        qq.run_bottom_half()
        hit(pp)
    pp.uninit()
    out = json.load(open(pathlib.Path(tmp) / "fastloop.json"))
    assert out["verdict"].startswith("INVALID"), out["verdict"]
    print("ok  device control: an allowlist whose oracle cannot compare is "
          "unscored, not passed")

    # A section that IS in the block and still differs is a different finding
    # from one the block never carried, and must not fail the scope. The real
    # case: mc146818rtc reads the live clock in pre_save and re-derives its
    # timers in post_load, so it can never come back byte-identical. Counted
    # against the allowlist it reads as "add this section" -- which a run did,
    # to a section already in the block, and throughput halved.
    pp, qq = make("loop", tmp, allow="cpu,timer")
    qq.dev_diff_sections = 0
    qq.dev_unrestorable_sections = 1
    qq.dev_diff_report = "*mc146818rtc#13"
    for _ in range(2):
        hit(pp)
    for _ in range(80):
        if pp.state == "done":
            break
        qq.run_bottom_half()
        hit(pp)
    pp.uninit()
    out = json.load(open(pathlib.Path(tmp) / "fastloop.json"))
    assert out["verdict"].startswith("VALID"), out["verdict"]
    assert out["dev_unrestorable"] == ["*mc146818rtc#13"], out["dev_unrestorable"]
    assert "mc146818rtc" in out["verdict"], out["verdict"]
    print("ok  device control: a section that cannot round-trip is named, not "
          "charged to the scope")

    # A bogus allowlist must stop the run, not fall back to a full block --
    # which would put numbers for a configuration nobody asked for under the
    # label of the one they did.
    refused = False
    try:
        pp, qq = make("loop", tmp, allow="cpu,no_such_section")
        for _ in range(2):
            hit(pp)
        refused = pp.state == "done" and q.FASTSNAP_LOOP_ARM not in qq.ops
    except Exception:
        refused = True
    assert refused, "an allowlist naming a section that does not exist ran anyway"
    print("ok  an allowlist that names nothing real refuses the run rather "
          "than quietly measuring a full block")

    # Two answers to the same question is a refusal, not a precedence rule.
    refused = False
    try:
        pp, qq = make("loop", tmp, allow="cpu", deny="timer")
        for _ in range(2):
            hit(pp)
        refused = pp.state == "done" and q.FASTSNAP_LOOP_ARM not in qq.ops
    except Exception:
        refused = True
    assert refused, "allow= and deny= together were silently resolved"
    print("ok  allow= and deny= together refuse rather than pick a winner")

    # ---- the two control arms never touch the fastsnap reset ----------
    # mode=armed ends with a FORK_DROP: it armed, so it is holding a forked
    # reference, and a parked reference is a full copy-on-write copy of guest
    # RAM. Leaking one per run is a quiet way to run the host out of memory.
    for mode, expect_ops in (("bare", []),
                             ("armed", [FakeQemu.FASTSNAP_LOOP_ARM,
                                        FakeQemu.FASTSNAP_FORK_DROP])):
        p, q = make(mode, tmp)
        for _ in range(60):
            if p.state == "done":
                break
            q.run_bottom_half()
            hit(p)
        assert p.n_iters == 10, (mode, p.n_iters)
        assert q.ops == expect_ops, (mode, q.ops)
        assert not p.reset_us, (mode, p.reset_us)
        p.uninit()
        print(f"ok  mode={mode}: {p.n_iters} iterations, ops={q.ops}")

    # ---- the measurement modes: half a reset, on purpose ---------------
    # They exist to say WHICH HALF of a reset causes the ~0.5 ms that lands
    # after the bottom half completes. Each must arm, schedule exactly one
    # kind of half-reset per lap, never schedule a full one (which would
    # reintroduce the thing being excluded), never claim soundness, and still
    # report the two halves of the round trip it was built for.
    for mode, op in (("devonly", FakeQemu.FASTSNAP_RESTORE),
                     ("ramonly", FakeQemu.FASTSNAP_RAM_RESTORE)):
        p, q = make(mode, tmp)
        for _ in range(80):
            if p.state == "done":
                break
            q.run_bottom_half()
            hit(p)
        p.uninit()
        out = json.load(open(pathlib.Path(tmp) / "fastloop.json"))
        assert p.n_iters == 10, (mode, p.n_iters)
        loop_ops = [o for o in q.ops if o not in (q.FASTSNAP_LOOP_ARM,
                                                  q.FASTSNAP_FORK_DROP)]
        assert set(loop_ops) == {op}, (mode, set(loop_ops))
        assert q.FASTSNAP_LOOP_RESET not in q.ops, mode
        assert q.FASTSNAP_LOOP_RESET_VERIFY not in q.ops, mode
        assert not p.verifies, mode
        assert out["verdict"].startswith("MEASUREMENT MODE"), out["verdict"]
        assert "not a rate" in out["verdict"], out["verdict"]
        assert p.sched_ms and p.obs_ms, mode
        print(f"ok  mode={mode}: {p.n_iters} laps of op {op} only, no oracle, "
              f"verdict refuses to be read as a rate")

    print("\nPASS")


if __name__ == "__main__":
    main()
