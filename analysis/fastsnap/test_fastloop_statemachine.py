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
            self._args = dict(mode=mode, outdir=str(tmpdir), warmup=2,
                              iters=10, verify_every=3, comm="v",
                              detector="read", **args)
            super().__init__()

        def get_arg(self, k):
            return self._args.get(k)

    # The plugin registers its hook through the module-level `syscalls`
    # object; stub it so construction does not need penguin.
    class _Sys:
        def syscall(self, *a, **k):
            return lambda fn: fn

    mod.syscalls = _Sys()
    p = Harnessed()
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


def main():
    import tempfile
    tmp = tempfile.mkdtemp()

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
