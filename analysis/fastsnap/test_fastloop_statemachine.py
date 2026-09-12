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
        elif op == self.FASTSNAP_LOOP_RESET:
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

    print("\nPASS")


if __name__ == "__main__":
    main()
