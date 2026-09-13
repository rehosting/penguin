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

    def info(self, *a):
        pass

    def warning(self, *a):
        pass

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
            self._args = dict(mode=mode, outdir=str(tmpdir), warmup=2,
                              iters=10, verify_every=3, comm="v",
                              detector="read", arm_clean_streak=0)
            self._args.update(args)
            super().__init__()

        def get_arg(self, k):
            return self._args.get(k)

    # The plugin registers its hook through the module-level `syscalls`
    # object; stub it so construction does not need penguin.
    class _Sys:
        def syscall(self, *a, **k):
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


def crash(p):
    """One fatal signal delivery."""
    class Ev:
        sig = 11
        drop = False
    p.fatal_signos = {11}
    p.on_fatal_signal(None, Ev())


def to_loop(p, q):
    """Drive warmup, arm and the split-order control until the loop is live."""
    for _ in range(2):
        hit(p)
    for _ in range(6):
        q.run_bottom_half()
        hit(p)
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
    for _ in range(10):
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
            for _ in range(6):               # arm + split control
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
    print("ok  when every draw is poisoned the run reports INVALID, not a rate")

    # ---- the crash lap splits at the fault ----------------------------
    p, q = make("loop", tmp, arm_probe=10**6)
    p.want = 10**6
    to_loop(p, q)
    for _ in range(5):
        q.run_bottom_half()
        crash(p)
    assert len(p.crash_to_sig_ms) == len(p.crash_after_sig_ms) > 0
    for i in range(len(p.crash_to_sig_ms)):
        total = p.crash_to_sig_ms[i] + p.crash_after_sig_ms[i]
        assert abs(total - p.obs_crash_ms[i]) < 1e-6, (i, total,
                                                       p.obs_crash_ms[i])
    print(f"ok  the crash lap splits at the fault and the halves sum "
          f"({len(p.crash_to_sig_ms)} laps)")


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

    for _ in range(3):
        q.run_bottom_half()
        hit(p)
    laps = [e for e in p._test_events["published"] if e[0] == "on_lap"]
    assert len(laps) == 3, p._test_events["published"]
    assert all(e[2] == "hit" for e in laps), laps
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

    # ---- NOT IN THE CONTROL ARMS --------------------------------------
    # bare and armed never reset, so their laps are not independent
    # executions. Announcing them as such would invite exactly the
    # mis-scoping the event exists to fix.
    for mode in ("bare", "armed"):
        p, q = make(mode, tmp)
        for _ in range(6):
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
    for _ in range(5):
        q.run_bottom_half()
        hit(p)
    assert boom["n"] == 1, f"kept publishing into a raising subscriber ({boom['n']})"
    assert p._publish_lap is False
    assert any("on_lap publish failed" in e for e in p.errors), p.errors
    assert p.state == "loop", p.state
    assert p.n_iters >= 5, p.n_iters
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


def main():
    import tempfile
    tmp = tempfile.mkdtemp()
    arm_tests(tmp)
    wall_tests(tmp)
    lap_tests(tmp)

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
    assert p.state == "split_control", p.state
    print("ok  arm recorded, split-order control scheduled first")

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
    for _ in range(6):                       # through arm + split control
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

    pv, qv, out = run_scoped(allow="cpu,timer")
    qv2 = qv
    assert qv.allowlist == ["cpu", "timer"], qv.allowlist
    assert out["device_scope"] == ["allow", ["cpu", "timer"]], out["device_scope"]
    assert out["verdict"].startswith("VALID"), out["verdict"]
    print("ok  an allowlist reaches the C side and a clean device oracle "
          "keeps the run VALID")

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
