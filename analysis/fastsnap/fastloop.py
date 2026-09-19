"""The complete reset, closed into a loop on real firmware -- and what it costs.

This is the measurement the rest of the lane has been arithmetic about. Every
exec/s figure quoted so far (1,760 / 2,390 / 3,200 / 5,525) was a sum of
independently measured parts, and the one time that sum was checked against a
closed loop it was out by 3.7x -- predicted 0.456 ms, measured 1.69 ms. So the
number this plugin produces is not "reset + G"; it is the wall-clock interval
between successive iterations of a guest that is actually being reset.

WHAT AN ITERATION IS HERE. LOOP_ARM takes the device block, snapshots RAM, arms
dirty tracking and forks the oracle reference -- all in one bottom half, at one
instant. Every LOOP_RESET afterwards returns the guest to exactly that instant:
device state from the block, and the pages dirtied since copied back. So the
guest re-executes the SAME span of work every iteration, which is the shape a
snapshot fuzzer runs in. The measured interval is the cost of one lap of that.

THREE ARMS, because a single number for "the loop" is not attributable:

  mode=loop    arm once, reset every iteration                -- the product
  mode=armed   arm once, never reset                          -- isolates what
               holding the snapshot costs. This control is not optional and it
               is not obvious: arming turns on QEMU's global dirty log, and
               every first store to a clean page then traps through
               notdirty_write(). That slows the guest whether or not anything
               is ever restored, and without this arm that slowdown would be
               attributed to the reset.
  mode=bare    neither                                        -- the floor

  loop - armed  = the reset
  armed - bare  = the tracking
  bare          = guest work + the portal round trip

THE ORACLE, and why it needs its own op. A reset that silently restored nothing
produces the same timing as a correct one, and on this target the only channel
that could notice -- crashes.yaml -- is blind to kernel damage by construction
(it hooks userspace fatal signals; a panic is not one). So correctness comes
from the fork oracle: a child forked at the arm instant, read back with
process_vm_readv() and compared page by page. It shares no code with the
restore, which reads an in-process copy.

It has to run in the SAME bottom half as the reset. Scheduled as a separate op
the guest executes in the gap and dirties pages of ordinary kernel work, so a
perfectly correct reset reports hundreds of differing pages. That is not a
hypothetical -- this plugin measures it, as a control: `split_diff` runs the
oracle the wrong way round on purpose, and a run where the split form reports
zero would mean the oracle is not looking at a running guest at all.
"""

import json
import math
import os
import statistics
import time

from penguin import Plugin, plugins

syscalls = plugins.syscalls

FATAL_SIGNALS = ["SIGSEGV", "SIGBUS", "SIGILL", "SIGABRT", "SIGFPE"]


def _stats(v):
    if not v:
        return None
    v = sorted(v)
    return {
        "n": len(v),
        "median": statistics.median(v),
        "mean": statistics.fmean(v),
        "min": v[0],
        "max": v[-1],
        "p10": v[max(0, len(v) // 10)],
        "p90": v[min(len(v) - 1, 9 * len(v) // 10)],
    }


def _sign_test_p(n, pos):
    """Exact two-sided binomial p for `pos` of `n` deltas sharing a sign.

    Written out rather than reached for: scipy is not in the image, and the
    alternative -- a normal approximation -- is wrong in exactly the regime
    this is used in. At n=5 all-positive the approximation gives p=0.025 and
    the exact answer is 0.0625, so it would license a claim from five pairs
    that five pairs cannot support.
    """
    if n <= 0:
        return 1.0
    k = max(pos, n - pos)
    tail = sum(math.comb(n, i) for i in range(k, n + 1))
    return min(1.0, 2.0 * tail / float(2 ** n))


class FastLoop(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.comm = self.get_arg("comm") or "lighttpd"
        self.detector = self.get_arg("detector") or "writev"
        self.mode = (self.get_arg("mode") or "loop").lower()
        self.warmup = int(self.get_arg("warmup") or 40)
        # Wall-clock floor on the arm, on top of the hit count. The first run
        # of this plugin armed after 40 detector hits, which fell 72 s into
        # boot -- in the middle of the guest generating SSH host keys. Every
        # lap then replayed that key generation, and the loop measured 20
        # SECONDS per iteration. Nothing was wrong with the reset; the console
        # shows the same "Creating SSH2 RSA key" line repeating, which is the
        # guest deterministically re-executing the span it was rewound to. The
        # iteration cost is the span from the armed instant to the next
        # detector hit, so WHERE the arm lands is the measurement.
        self.arm_after_s = float(self.get_arg("arm_after_s") or 0)
        self.reset_on_signal = bool(self.get_arg("reset_on_signal"))
        # Registered unconditionally so a subscriber can bind before the
        # first lap; published only in mode=loop. Registration failing is not
        # fatal -- the loop is still a valid measurement without an audience.
        self._publish_lap = True
        self._lap_ever = False
        try:
            plugins.register(self, "on_lap")
        except Exception as e:                              # noqa: BLE001
            self._publish_lap = False
            self.logger.warning(
                f"fastloop: could not register on_lap ({e!r}); per-input "
                f"scoping is unavailable for this run")
        self.signal_laps = 0
        self._closed_by_signal = False
        self.crash_iter_ms = []    # laps a crash ended

        # THE ARM IS A BLIND DRAW, AND SOME DRAWS ARE POISON.
        #
        # An iteration is the span from the armed instant to the next detector
        # hit, so WHERE the arm lands is the measurement -- that is this lane's
        # oldest finding. What was not known until it was looked for is that a
        # bad draw does not merely give a slow lap. It gives a PERMANENTLY
        # CRASHING one: the loop can arm at an instant where the victim is
        # already broken, and then rewind to it several thousand times. Two of
        # five draws did exactly that, at 145 exec/s against 1,879, and the
        # run reported the number without complaint -- every reset correct,
        # every fork-oracle verification byte-identical, because the guest
        # really is being restored perfectly to a broken instant.
        #
        # Nothing else in the harness can see it. The oracles check that the
        # reset is faithful, not that the instant is worth being faithful to.
        #
        # So: probe the first `arm_probe` laps. A healthy draw closes ~1.4% of
        # laps on a fatal signal; a poisoned one closes essentially all of
        # them, so the threshold is nowhere near either population and does not
        # need tuning. On a bad draw, stop resetting (which lets the guest's
        # own restart loop produce a live victim again), wait, and draw again.
        # Measurements from a rejected draw are DISCARDED, not averaged in.
        # `x or default`, the idiom used elsewhere in this file, is wrong for
        # every one of these: 0 is a legitimate value for all four (re-arm
        # immediately, never re-arm, reject any signal at all) and `0 or 3.0`
        # is 3.0. Caught by a test that set arm_backoff_s=0 and waited 3 s.
        # ARM ON EVIDENCE, NOT ON A CLOCK. The probe below is the detective
        # control and it works -- it rejected three draws in a row at 200/200
        # probe laps and refused to report a rate. But rejecting and then
        # waiting a fixed 3 s draws again from the same distribution, and all
        # three draws failed, so detection alone does not get a measurement.
        #
        # The preventive control is to require the victim to have just done
        # `arm_clean_streak` consecutive detector hits with no fatal signal
        # between them. That targets the observed failure exactly: the wedged
        # runs crash on uniformly random opcodes, i.e. on ANY input, and a
        # victim that crashes on any input cannot produce a clean streak. It
        # also rules out arming mid-loader or on a process about to die.
        #
        # It is a filter on the draw, not a guarantee: the arm lands one bottom
        # half after the streak, and nothing here says the next input is
        # survivable. The probe stays as the backstop.
        # AND THE OTHER SIDE OF IT, which cost a run to learn. Requiring a
        # clean streak fixed the wedged draw and immediately produced its
        # mirror image: an arm whose replayed span delivers NO INPUT. That run
        # looked like the best result in the lane -- 200,000 laps, 0.294 ms,
        # 3,396 exec/s, 0 of 200 probe laps on a fatal signal -- and it was a
        # loop resetting a guest that was not being fuzzed. 27 signal laps in
        # 200,000 where 1.3% was expected, and a clean streak of 193,309 reads,
        # which no victim under random input achieves.
        #
        # "The victim did not die" is not "the loop is doing work", and a
        # health check that only looks for death selects for idleness. So the
        # probe also requires PROGRESS, named as `plugin.attribute` (e.g.
        # `bug_bench.n_sent`) rather than hardcoded: fastloop has no business
        # knowing what an injector is called, and any counter that should
        # advance once per lap will do. Unset means the check cannot run, which
        # is reported rather than assumed to be fine.
        self.arm_progress = self.get_arg("arm_progress")
        self.arm_progress_frac = float(self._num("arm_progress_frac", 0.5))
        self._progress0 = None
        self.arm_clean_streak = int(self._num("arm_clean_streak", 64))
        self._clean_streak = 0
        self._best_streak = 0
        self.arm_probe = int(self._num("arm_probe", 200))
        # THE THIRD ARM AXIS: is this draw SLOW?
        #
        # The probe already rejects a draw that FAULTS and a draw that is IDLE.
        # Both ask "is this draw broken". Neither asks what turned out to set
        # the rate.
        #
        # Measured, on two real images: the interval between detector hits is
        # not unimodal. Target B alternates ~5.5 ms (a pipelined response
        # inside a live connection) with ~450 ms (connection turnover -- the
        # client exits, a new one forks and execs, a fresh TCP connect
        # completes). The loop replays ONE of those forever. Same target, same
        # reset, same configuration: 155 exec/s on the cheap phase, about 2 on
        # the expensive one. A 70x swing decided by which hit the arm landed
        # on.
        #
        # Compared against a LOW percentile of the warmup distribution, not the
        # median: on a 50/50 bimodal the median IS the expensive mode, so a
        # median-relative threshold would accept exactly the draw worth
        # rejecting.
        self.arm_cost_mult = float(self._num("arm_cost_mult", 3.0))
        self.arm_cost_pctl = float(self._num("arm_cost_pctl", 25))
        self.arm_cost_min_gaps = int(self._num("arm_cost_min_gaps", 50))
        # Factor the cost ceiling widens by per rejected draw. 1.0 holds it
        # fixed, which is the behaviour that ends on an unselected last draw.
        # Applied to the multiplier, NOT the percentile -- see
        # _cost_threshold() for why the percentile version is a trap.
        self.arm_cost_relax = float(self._num("arm_cost_relax", 1.5))
        # Ceiling on the compounded slack, and it exists because raising
        # arm_retries from 3 to 12 broke the axis without it. The ladder is
        # meant to forgive a draw that is MERELY CLOSE; at 1.5 per attempt it
        # compounds to 86x by attempt 12, and the test suite caught exactly
        # that -- a 455 ms lap sailing through a 1427 ms ceiling and being
        # recorded as "accepted" rather than "accepted anyway". A ceiling that
        # grows faster than the thing it is bounding is not a ceiling.
        #
        # 4x is chosen to sit above the ladder's useful range (three attempts
        # reach 2.25x) and far below the gap between the modes seen on real
        # firmware, which is ~300x. With it, more retries buy more DRAWS --
        # the intended effect -- and not a progressively more forgiving
        # standard for judging them.
        self.arm_cost_relax_cap = float(self._num("arm_cost_relax_cap", 4.0))
        # Probe laps the cost axis needs before it may fire EARLY. A
        # median over this few is noisy, but the axis only ever spends a
        # re-arm on it, and the alternative is waiting out `arm_probe`
        # laps of a draw already known to be catastrophic.
        self.arm_cost_min_laps = int(self._num("arm_cost_min_laps", 5))
        # How far a replayed lap may exceed THIS DRAW'S OWN forward
        # traversal before the draw is dropped. 0 turns the ratio axis
        # off and leaves only the warmup-percentile ceiling. 10x is
        # loose enough that an ordinary span survives and tight enough
        # to catch the measured 3,945x case. See _costly().
        self.arm_cost_fwd_mult = float(self._num("arm_cost_fwd_mult", 10))
        # REJECT A DRAW WHOSE REPLAY IS MUCH FASTER THAN ITS OWN FORWARD
        # TRAVERSAL, which is the one failure neither cost axis can see.
        #
        # Both cost axes reject draws that are too EXPENSIVE. Nothing rejected
        # the opposite, and the opposite is the more dangerous of the two
        # because it produces a large, quotable number:
        #
        #   run 106  armed span traverses forward in 10,189.66 ms and replays
        #            in 3.35 ms. Accepted on attempt 1 -- the absolute axis saw
        #            3.35 against a 7.04 ms ceiling and passed it, and the
        #            ratio axis only fires at lap > forward x 10. Reported
        #            298.9 exec/s for a span that contains a ten-second wait.
        #   run 91   the same shape at 209x.
        #
        # The span still contains the wait; the replay just never pays it,
        # because whatever the forward pass was waiting FOR arrived during the
        # wait and is already there at replay. `replay_fidelity` says so after
        # the fact. This says it while there are still retries left to spend
        # on a draw that does not have the problem -- and on a workload with a
        # cheap mode, such a draw exists: run 106's own warmup gaps have a p10
        # of a few ms.
        #
        # 0 disables it. The ladder and cap are shared with the cost axis, so
        # a run that cannot find a faithful draw still arms rather than
        # spending every retry and refusing.
        self.arm_fidelity_mult = float(self._num("arm_fidelity_mult", 3.0))
        # One extra lap, and it is the only baseline the run can compare
        # its own laps against. On by default for that reason.
        self.arm_forward_probe = bool(self._num("arm_forward_probe", 1))
        # Forward spans to time before the first reset. The baseline every
        # divergence claim is measured against, so not 1 -- see _fwd_finish().
        self.arm_forward_n = max(1, int(self._num("arm_forward_n", 5)))
        # Pin the guest to the process the arm lands in, immediately before
        # the snapshot. See _pin_apply(). Default OFF: it needs a driver new
        # enough to carry the op, and on an older one the loop must still run.
        self.pin_process = bool(self._num("pin_process", 0))
        # ...and take the CPU away from every other userspace task. Only
        # meaningful with an injector: the in-guest load generator is one of
        # the tasks this stops, so without something answering the victim's
        # reads from inside the boundary the victim simply goes idle.
        self.pin_exclusive = bool(self._num("pin_exclusive", 0))
        self.pin_settle_hits = int(self._num("pin_settle_hits", 200))
        # How far a lap may sit from its own forward traversal before the
        # verdict calls the replay divergent. Reporting only -- the cost
        # axis's own bound is arm_cost_fwd_mult. See _replay_fidelity().
        self.fidelity_bound = float(self._num("fidelity_bound", 3.0))
        self.arm_bad_frac = float(self._num("arm_bad_frac", 0.5))
        # Raised from 3 to 12 on measured evidence. Three runs, same config,
        # same image, same target, differing only in which instant the arm
        # caught:
        #
        #   run 88  accepted attempt 1 at    3.30 ms  ->  303.3 exec/s
        #   run 89  3 draws all costly, OUT OF RETRIES,
        #           accepted 1054.58 ms anyway        ->    0.9 exec/s
        #   run 90  2 costly then 4.53 ms accepted    ->  225.7 exec/s
        #
        # A 337x spread, and run 89 is the whole reason for this change: the
        # cost axis identified all three of its draws correctly and then ran
        # out of counter and took the last one regardless. It was not choosing
        # badly, it was being made to stop looking -- on a target whose cheap
        # mode plainly exists, since run 89's own forward samples were
        # [4.19, 1051.93, 4.14], two of three cheap.
        #
        # 3 is the right default for a unimodal target, where a rejected draw
        # means the whole workload is expensive and more looking will not help.
        # It is the wrong default for a bimodal one, where each retry is an
        # independent chance at the cheap mode. At roughly even odds, 3 retries
        # fail outright about 6% of the time and 12 about 0.02%; the observed
        # odds here are worse than even, which makes the gap wider still.
        #
        # A retry is not free -- it costs an arm (~0.6 s) and a probe -- but
        # against a 337x error in the reported rate that is not the trade
        # worth optimising. Runs that arm early still stop early: the count is
        # a bound, not a target, and run 90 used 3 of its 12.
        self.arm_retries = int(self._num("arm_retries", 12))
        self.arm_backoff_s = float(self._num("arm_backoff_s", 3.0))
        # THE PROBE LOOKS ONCE. This looks for the whole run.
        #
        # `arm_probe` scores the first 200 laps and never asks again. Two runs
        # passed it and came apart afterwards -- one at full speed with every
        # lap closing on a fault, one with the detector simply going quiet --
        # and both reported a rate with a clean oracle beside it.
        #
        # 0 disables. `_num`, not `or`, so it can be.
        self.health_window = int(self._num("health_window", 1000))
        self.degraded = []
        # A MINORITY OF LAPS TAKING A MAJORITY OF THE CLOCK is a different
        # failure from a loop that came apart, and it needs a different
        # answer. Reported once and the run continues: it is a cost problem,
        # not a correctness one, and stopping a valid measurement over it
        # would be worse than the cost.
        # EDGE COVERAGE, off by default.
        #
        # This lane's exec/s was a loop rate: reset, feed an input, detect the
        # next boundary. What it could not do was notice that an input reached
        # somewhere new, and every published figure it gets compared to (Nyx,
        # FIRM-AFL) is coverage-GUIDED throughput. Those are different
        # quantities. With this on, they are the same one.
        #
        # Off by default because it is not free and because the numbers
        # already recorded were taken without it -- turning it on silently
        # would make this run incomparable to every earlier one without
        # anything in the result saying so. `coverage_on` goes into the
        # output for exactly that reason.
        self.cov = bool(self._num("coverage", 0))
        # Instrument only blocks in [lo, hi). 0/0 means everything, kernel
        # included. A VIRTUAL range in a full-system emulator, so it cannot
        # separate two processes sharing it; check cov_tbs_instrumented in the
        # result before believing a zero edge count, because "the range names
        # no code" and "the guest reached nothing" produce the same empty map.
        self.cov_lo = int(self._num("cov_filter_lo", 0))
        self.cov_hi = int(self._num("cov_filter_hi", 0))
        # Power of two, before the first arm only. 0 leaves QEMU's default of
        # 65536, which is AFL's MAP_SIZE and what anything downstream assumes.
        self.cov_map_size = int(self._num("cov_map_size", 0))
        self._cov_armed = False
        self.cov_edges = []         # distinct edges, per lap
        # Whether the lap now closing had its coverage summarised. Consumed
        # by _lap_event(); see the append site for why it cannot be assumed.
        self._cov_fresh = False
        # Laps whose reset performed no coverage scan because
        # coverage was disarmed (cov_ab's off phases). Their
        # accessors hold the previous armed lap's numbers.
        self.cov_disarmed_laps = 0
        self.cov_new = []           # edges never seen before, per lap
        self.cov_new_buckets = []   # new hit-count buckets -- the AFL signal
        # Block executions per lap. Recorded because it is the DENOMINATOR the
        # emission cost needs: the per-block cost is eight TCG ops, and
        # "coverage costs X us a lap" is uninterpretable without knowing how
        # many blocks a lap runs. Saturates at 255 per edge, so on a lap with
        # a hot loop this is a floor, not an exact count.
        self.cov_hits = []
        self.cov_scan_us = []       # what summarising cost, per lap
        # ---- THE IN-RUN A/B, which exists because the cross-run one failed.
        #
        # Measuring coverage's cost by running a control run and a coverage
        # run and subtracting does not work here, and the failure is on the
        # record: two controls taken back to back differed by 23% in the guest
        # half, because each run draws its own span to loop over and the spans
        # are not equally expensive. A 23% instrument cannot resolve a 5%
        # effect. Both coverage runs even landed BELOW both controls -- the
        # wrong sign -- which is what a draw-dominated comparison looks like
        # when it is asked a question it cannot answer.
        #
        # So the comparison has to happen INSIDE one run, on ONE draw, against
        # ONE snapshot: arm coverage, run N laps, disarm, run N laps. The
        # snapshot is identical across the phases by construction, so whatever
        # made this draw expensive is a constant that subtracts out.
        #
        # ALTERNATING, not one switch. A single changeover confounds the phase
        # with position in the run: if the guest drifts at all over 2000 laps
        # (a log file growing, an allocator warming), all of that drift lands
        # on whichever phase came second. Alternating on..off..on..off leaves
        # each phase spread evenly across the run, so a linear drift cancels
        # instead of being attributed to coverage.
        #
        # This measures the WHOLE cost -- emission plus the reset-side scan --
        # because disarm stops both. That is the number worth having, and the
        # scan half is separately known from cov_scan_us, so the emission half
        # comes out by subtraction rather than having to be isolated directly.
        self.cov_ab = int(self._num("cov_ab", 0))
        # Laps after each toggle that belong to NEITHER steady state. Both arm
        # and disarm queue a tb_flush, so the laps just after a toggle pay to
        # re-translate every block the guest touches -- a real cost, but the
        # toggle's, not the phase's. Recorded in its own bucket rather than
        # dropped, so "the settle window is short" stays checkable.
        self.cov_ab_settle = int(self._num("cov_ab_settle", 0))
        if self.cov_ab and self.cov_ab_settle <= 0:
            self.cov_ab_settle = max(20, self.cov_ab // 8)
        self._ab_phase = "on"       # coverage is armed first, at warmup
        self._ab_lap = 0            # plain laps since the last toggle
        self._ab_switches = 0
        self._ab_wait_seq = None    # see _ab_toggle on why this is awaited
        self._ab_tbi = 0            # tbs_instrumented, summed over arms
        # tbs_FILTERED, summed the same way. Carrying one and not the other
        # is worse than carrying neither: the two are only meaningful as a
        # RATIO -- "what fraction of blocks did the filter reject" -- and a
        # sum divided by a single sample is a number that looks like a
        # fraction and is not one. That produced a reported 1.6% where the
        # answer was 58.7%, which is the difference between "the filter does
        # nothing" and "the filter removes most of the working set".
        self._ab_tbf = 0
        # Three buckets per quantity, and the same split the run already makes
        # between the reset half and the guest half. The whole point is to see
        # WHERE the cost lands, so a single lap-time table would waste the
        # experiment.
        self.ab_ms = {"on": [], "off": [], "settle": []}
        self.ab_sched = {"on": [], "off": [], "settle": []}
        self.ab_obs = {"on": [], "off": [], "settle": []}
        # PER-BLOCK medians as well as pooled ones, because pooling throws
        # away the only thing that makes this design trustworthy. Alternating
        # gives a sequence on,off,on,off,... of blocks run minutes apart; the
        # medians of those blocks are a PAIRED sample, and a consistent sign
        # across every pair is evidence no pooled median can offer. Pooled,
        # one unusually expensive stretch of guest time is indistinguishable
        # from a real effect. Paired, it shows up as one pair disagreeing.
        self.ab_blocks = []
        self._ab_cur = {"ms": [], "sched": [], "obs": []}
        self.health_time_frac = float(self._num("health_time_frac", 0.5))
        self.hot_class = None
        self._hw_n = self._hw_sig = 0
        self._hw_ms = self._hw_ms_sig = 0.0
        self._hw_progress0 = None
        self.arm_attempt = 0
        self.arm_history = []      # one row per draw, accepted or rejected
        self._probe_n = 0
        self._probe_sig = 0
        self._probe_done = False
        self._probe_laps_ms = []    # this draw's replayed laps, for the cost axis
        self.warm_gaps_ms = []      # forward intervals seen during warmup
        self._warm_prev = None
        self.arm_cost_rejects = 0
        # THE BASELINE, measured inside the run that uses it.
        #
        # The right comparison for "what does a reset cost the guest" is the
        # SAME span traversed normally versus replayed -- not a replayed span
        # against an average of forward spans, which is what produced a "the
        # reset costs 60 ms" reading that a second target then inverted into
        # "the reset makes the guest 36x faster".
        #
        # It has to be taken here and nowhere else. `bare` never arms, so it
        # samples every span rather than this one. `armed` arms and so already
        # pays for the dirty log -- every first store to a page takes the
        # TLB_NOTDIRTY path -- and is a different run besides, which on a
        # bimodal distribution lands on a different span as a coin flip.
        #
        # So: after the arm and BEFORE the first reset of any kind, let the
        # guest run forward exactly one span and time it. Costs one lap.
        self.arm_forward_ms = None      # the FIRST arm's, for reporting
        self.arm_forward_ms_all = []    # every arm's median, in order
        self.arm_forward_samples = []   # ...and the raw samples behind each
        self._fwd_samples = []
        self._fwd_this_arm = None       # this arm's, the cost reference
        self._fwd1_this_arm = None      # sample 1, the fidelity reference
        self._rearm_at = None
        self.arm_gave_up = False
        if (self.get_arg("mode") or "loop").lower() != "loop":
            # bare/armed do no resets to rewind INTO a bad instant, and the two
            # measurement modes are known-broken by construction -- probing
            # them would reject every draw and refuse a run whose whole purpose
            # is to time half a reset.
            self._probe_done = True
        self.t_sched = None
        self.t_sched_mono = None
        # Wall time from scheduling a reset to first SEEING it finished.
        #
        # READ IT AS A COMPOSITE, not as bottom-half latency. The observation
        # point is the next detector hit, so this is
        #     max(time for the bottom half to run, time to the next detector)
        # and which term dominates depends on the target. Where the detector
        # fires thousands of times a second it approximates the first, and the
        # throttling experiment on bugbench used it that way: removing host-side
        # YAML writes from the signal callback dropped crash-lap latency 309 ms
        # -> 57 ms, which only the bottom-half term can explain. On a target
        # whose detector fires twelve times a second it is the second term, and
        # says nothing about the reset.
        #
        # The in-QEMU `reset_us` measures neither -- its clock starts when the
        # bottom half is already running.
        self.bh_wall_ms = []
        self.bh_wall_crash_ms = []
        # The two halves of bh_wall, which it could not previously separate.
        # sched_ms is scheduling to the bottom half completing (main-loop
        # latency plus the reset); obs_ms is that completion to the next
        # detector hit noticing (guest execution plus this plugin's own cost).
        # "The reset is slow" and "the round trip is slow" have opposite fixes
        # and bh_wall alone cannot tell them apart.
        self.sched_ms = []
        self.obs_ms = []
        self.sched_crash_ms = []
        self.obs_crash_ms = []
        # THE CRASH LAP, SPLIT AT THE SIGNAL. bh_to_observed_crash is 99.86% of
        # a crash lap (69.85 ms of 69.91 ms), so the reset is not in it -- but
        # "after the bottom half" still covers two entirely different spans
        # with opposite fixes:
        #   reset done -> the guest faults        (guest work: parse, fault,
        #                                          kernel signal delivery)
        #   the fault seen -> the lap closes      (host work: the signal
        #                                          subscribers, then another
        #                                          reset and resume)
        # Removing the injector's YAML dump from the signal callback took it
        # from 12.5 ms to 0.33 ms and did NOT move the crash lap, which is how
        # I know one number for the whole span is not enough to aim at.
        self.crash_to_sig_ms = []
        self.crash_after_sig_ms = []
        self.t_signal_mono = None
        self.sched_verify_ms = []
        self.obs_verify_ms = []
        # PAIRED, per lap. The two-run comparison that raised this question
        # fitted a line through exactly two points, which any two points admit,
        # and the line it gave (23.9 us per restored page) was wrong: the two
        # runs differed in device scope as well as page count. Within one run
        # over 3,785 laps the slope is 0.81 us/page against a 631 us fixed
        # term. Keep the pairs -- they are what refuted it.
        self.page_obs = []
        self.page_obs_max = 20000
        self._have_bh_clock = True
        self.t0 = time.perf_counter()
        self.want = int(self.get_arg("iters") or 200)
        self.verify_every = int(self.get_arg("verify_every") or 50)
        self.tag = self.get_arg("tag") or "fastloop"

        # bare   : no arm, no reset. The floor -- guest work plus the
        #          detector round trip.
        # armed   : arm, never reset. Prices what arming costs on its own.
        # loop    : the real thing, device block + dirty RAM every lap.
        # devonly : arm, then restore ONLY the device block each lap.
        # ramonly : arm, then restore ONLY the dirty RAM pages each lap.
        #
        # The last two are MEASUREMENT MODES and are unsound by construction.
        # A device-only restore rewinds the CPU's page-table base into RAM that
        # was never rewound; a RAM-only restore leaves device state drifting.
        # Neither is a configuration anyone should run a campaign in, and the
        # verdict says so rather than reporting a rate that looks quotable.
        #
        # They exist because an ordinary lap costs 0.782 ms of which the reset
        # is 0.071 ms, and 0.638 ms lands AFTER the bottom half completes --
        # against 0.111 ms for a bare lap. That ~0.5 ms is fixed per lap
        # (measured: 0.81 us per restored page over 3,785 laps, so not
        # per-page work) and appears only when a reset happened. These two
        # modes are the cheapest cut that says which HALF of the reset causes
        # it, and they need no new ABI: RESTORE and RAM_RESTORE already exist.
        self.MEASUREMENT_MODES = ("devonly", "ramonly")
        if self.mode not in ("loop", "armed", "bare") + self.MEASUREMENT_MODES:
            raise ValueError(f"fastloop: unknown mode {self.mode!r}")
        if self.mode in self.MEASUREMENT_MODES:
            self.logger.warning(
                f"fastloop: mode={self.mode} is a MEASUREMENT MODE. It "
                f"restores half a machine on purpose, so the guest is wrong "
                f"by construction and the only numbers worth reading are the "
                f"timings. Do not quote its exec/s as a rate.")

        # Keep ONLY these device sections in the block. The largest single
        # lever on reset cost -- measured, 17 sections restore in 0.752 ms and
        # {cpu, timer} in 0.043 ms -- and the only setting here whose failure
        # mode is silence rather than an error. Paired with dev_diff below;
        # see _apply_scoping().
        self.allow = self.get_arg("allow")
        self.deny = self.get_arg("deny")
        if self.allow and self.deny:
            # Refused here, in __init__, so it costs nothing: the two are
            # answers to the same question and the C side takes exactly one.
            # A precedence rule would make the block's scope depend on
            # argument order, which nothing downstream reports.
            raise ValueError(
                f"fastloop: allow={self.allow!r} and deny={self.deny!r} are "
                f"mutually exclusive")
        if self.deny is None and not self.allow:
            # The default, and it is a correctness default rather than a
            # tuning one -- see _apply_scoping(). An explicit allowlist is
            # already narrower than any denylist, so it does not get one
            # layered underneath it.
            self.deny = "auto"
        extra = self.get_arg("deny_extra")
        self.deny_extra = ([x.strip() for x in extra.split(",") if x.strip()]
                           if extra else [])
        # Take the allowlist literally, adding no companion section (see
        # COMPANIONS in _apply_scoping). This exists so the A/B that measured
        # what the companion costs can still be run -- an auto-completion no
        # experiment can turn off makes the uncovered case unmeasurable, and
        # the uncovered case is what justifies the completion.
        self.allow_exact = bool(self.get_arg("allow_exact"))
        self.allow_implied = []

        self.loadavg0 = list(os.getloadavg())
        if self.loadavg0[0] > 2.0:
            self.logger.warning(
                f"fastloop: host load average is {self.loadavg0[0]:.2f} at "
                f"start. Timings from a contended host are not comparable "
                f"with timings from an idle one, and the failure mode is not "
                f"subtle: it looks like the guest crashing on every lap.")
        self.state = "warmup"
        self.hits = 0
        self.errors = []
        self.n_iters = 0
        self.all_sections = []
        self.denied = []
        self.arm_us = None
        self.t_arm_s = None
        self._arm_ident = None   # (pid, create_time) the arm landed in
        self._pending_portal = None   # generator for on_hit to drive
        self._pin_n = 0               # settle polls spent
        self.pin_report = None        # what the driver said, for the record
        self.degraded_notes = []      # things the run did NOT get, in words
        self._cpu_prev = None
        self._cpu_prev_t = None
        self.lap_cpu_frac = []        # vCPU-thread CPU / wall, per lap
        self.lap_proc_frac = []       # whole-process CPU / wall, per lap
        self._last_ident = None
        self.hit_procs = {}      # identity -> hits, across the whole run
        self.hits_other_proc = 0
        self.arm_digest = None
        self.snapshot_bytes = None

        self.reset_us = []          # from inside QEMU, per reset
        self.iter_ms = []           # host wall clock, per iteration
        # The first laps RAW, not summarised, and the reason is one specific
        # question that the summary cannot answer.
        #
        # The loop replays the span starting at the armed instant. In `armed`
        # mode nothing is replayed -- but the FIRST lap after the arm is that
        # same span, traversed forward exactly once. So lap 0 of an armed run
        # and the median lap of a loop run are the same span measured two ways,
        # and the difference between them is what replay costs.
        #
        # Without this the comparison is impossible: `iter_ms` is a median over
        # thousands of DIFFERENT forward gaps, which is what the earlier
        # "8.73 ms vs 69.54 ms, so the reset costs 60 ms" reading compared, and
        # it was comparing an average of all spans against one specific span.
        self.first_laps_ms = []
        self.first_laps_max = 32

        # Reset cost in WORK. The timings say a real-firmware lap is 69 ms of
        # which the reset is 0.5 ms; they cannot say what the other 68.5 ms is
        # DOING, and three hypotheses about that were wrong. These are TCG's
        # own counters, sampled at the same two boundaries the timings split
        # at -- lap close and bottom-half done -- so the work divides into
        # "caused by the reset" and "done by the guest afterwards" exactly as
        # sched_to_bh and bh_to_observed do.
        self._tcg_prev = None       # sample at the previous lap close
        self._tcg_at_bh = None      # sample when the bottom half finished
        self.tcg_reset = {k: [] for k, _ in self.TCG_COUNTERS}
        self.tcg_guest = {k: [] for k, _ in self.TCG_COUNTERS}
        self._tcg_any = False       # did ANY counter ever move?
        self.verify_iter_ms = []    # laps that also ran the oracle
        self.restored = []          # dirty pages copied back, per reset
        self.verifies = []          # {iter, diff_pages, bytes, diff_us, dev_*}
        self.allowed = None
        self.split_diff = None      # the deliberately-wrong-order control
        self.t_iter = None
        self.seq_at_sched = None
        self.t_loop0 = None
        self.t_loopN = None
        self.pending_reset = False
        self._pending_verify = None

        # ASKED FOR AND ABSENT HAS TO STOP THE RUN.
        #
        # The coverage symbols are deliberately not in FASTSNAP_SYMBOLS, so an
        # image whose QEMU predates them still runs every measurement that
        # does not want coverage. But a run that asked for it and cannot have
        # it must not proceed: every accessor would answer zero, which reads
        # exactly like a guest that reached nothing, for thousands of laps.
        if self.cov:
            # Python attributes first, C symbols second -- the same two
            # questions the general preflight asks below, and for the same
            # reason: a binding can be present and still uncallable because
            # the generated cffi header never declared the symbol.
            absent_py = sorted(
                (self._api_names_used() & self.API_COVERAGE)
                - set(dir(self.panda)))
            missing = absent_py or (
                self.panda.fastsnap_cov_missing_symbols()
                if hasattr(self.panda, "fastsnap_cov_missing_symbols")
                else ["<no fastsnap_cov_* API at all>"])
            if missing:
                self.logger.error(
                    f"fastloop: coverage was requested and this QEMU build "
                    f"does not expose {missing}. Every coverage number would "
                    f"be a zero indistinguishable from a real one, so the run "
                    f"is refused. Rebuild penguin-qemu from this tree.")
                self.errors.append(f"coverage ABI absent: {missing}")
                self.state = "done"
            else:
                if self.cov_map_size and not self.panda.fastsnap_cov_set_map_size(
                        self.cov_map_size):
                    self.errors.append(
                        f"cov_map_size {self.cov_map_size} rejected")
                self.panda.fastsnap_cov_set_filter(self.cov_lo, self.cov_hi)
                # The reset summarises and clears; see the ABI comment. An
                # extra scheduled op per lap would cost more than the scan.
                self.panda.fastsnap_cov_set_clear_on_reset(True)

        self.have_api = bool(getattr(self.panda, "fastsnap_available", None)
                             and self.panda.fastsnap_available())
        if not self.have_api:
            self.logger.error(
                "fastloop: this QEMU build does not export the fastsnap ABI. "
                "Build penguin with --override-input penguin-qemu <qemu_builder>.")
            self.state = "done"

        # The image's Python bindings and the QEMU library are versioned
        # independently, and an image built before a binding was added answers
        # fastsnap_available() True and then raises AttributeError several
        # minutes later inside a vCPU callback, after a boot and a warmup.
        # Three runs were lost to exactly that in this lane. Check the names
        # this class actually reaches for, read out of its own bytecode rather
        # than from a hand-kept list -- a list that has to be updated in
        # lockstep with the code it guards will fall out of lockstep.
        need = self._api_names_used() - self.API_OPTIONAL
        if not need:
            self.logger.error("fastloop: the API preflight found no fastsnap "
                              "names -- it is inert and will not catch a stale "
                              "image")
            self.errors.append("api preflight inert")
        absent = sorted(need - set(dir(self.panda)))
        if absent and self.state != "done":
            self.logger.error(
                f"fastloop: the image's QemuCompat is missing {absent} -- it "
                f"predates these bindings. Rebuild the image from this tree.")
            self.errors.append(f"stale image, missing: {absent}")
            self.state = "done"

        # AND ask the LIBRARY, which is a different question. The check above
        # is about Python attributes; a binding can exist as a method and still
        # be uncallable because the generated cffi header never declared the C
        # symbol. That is not hypothetical -- it is what the first run of this
        # plugin did: every fastsnap accessor was present in Python, none of
        # the new ones was declared to cffi, and the run reported a 256 MB RAM
        # snapshot as "0 bytes" and a fork diff as "-1 pages" without raising
        # anything. It produced a complete, plausible, entirely fictional
        # result set. An absent symbol has to stop the run, not decorate it.
        if self.state != "done" and hasattr(self.panda, "fastsnap_missing_symbols"):
            missing = self.panda.fastsnap_missing_symbols()
            if missing:
                self.logger.error(
                    f"fastloop: this QEMU build does not expose {missing}. "
                    f"Every accessor behind those would return a made-up "
                    f"number, so the run is refused rather than reported.")
                self.errors.append(f"ABI symbols absent: {missing}")
                self.state = "done"
        elif self.state != "done":
            self.logger.error(
                "fastloop: the image's QemuCompat has no "
                "fastsnap_missing_symbols(), so the C-symbol preflight cannot "
                "run and a silently incomplete ABI would not be caught. "
                "Rebuild the image from this tree.")
            self.errors.append("no symbol-level preflight available")
            self.state = "done"

        # ENTER OR RETURN, and it is worth a knob because it is worth a
        # syscall boundary.
        #
        # The injector hooks `on_sys_read_return` and this hooked
        # `on_sys_read_enter`, so a lap that is ONE guest read paid for TWO
        # trap-and-dispatch round trips. This lane already priced that
        # boundary on another target: 133 us for the cheapest syscall, 208 us
        # for `read`, against a lap that is 528 us here. Collapsing both
        # callbacks onto one trap is therefore the largest host-side lever
        # left, larger than everything in the injector's own cost table.
        #
        # It is a knob and not a change because it MOVES THE ARMING POINT. An
        # iteration is the span from the armed instant to the next detector
        # hit, so arming at read-return instead of read-enter rewinds the guest
        # to a different instant -- one where the kernel has already filled the
        # buffer. That is a different measurement, not a faster one, and the
        # controls have to say whether it is still the right one: the fork
        # oracle for the reset, `arm_progress` for the injection, and the crash
        # rate for whether the victim is still being fuzzed the same way.
        at = (self.get_arg("detector_at") or "enter").lower()
        if at not in ("enter", "return"):
            self.logger.error(
                f"fastloop: detector_at={at!r} is not 'enter' or 'return'; "
                f"refusing rather than silently picking one")
            self.errors.append(f"bad detector_at: {at!r}")
            self.state = "done"
            at = "enter"
        self.detector_at = at
        # pin_filter only MATTERS once a pin is set, and a pin is set at arm
        # time -- but the hook is registered here, long before. Asking for it
        # up front is safe because an unset pin matches every task; asking for
        # it conditionally is what keeps an older driver working, since the
        # field is only sent when requested.
        syscalls.syscall(f"on_sys_{self.detector}_{at}",
                         comm_filter=self.comm,
                         pin_filter=self.pin_process)(self.on_hit)

        # A fatal signal is an iteration boundary too. Registered here rather
        # than left to the detector because a crashed victim makes no more
        # syscalls: see on_fatal_signal.
        self.fatal_signos = set()
        if self.reset_on_signal and self.state != "done":
            try:
                for name in FATAL_SIGNALS:
                    num = plugins.signals.signal_name_to_num(name)
                    if num is not None:
                        self.fatal_signos.add(int(num))
                plugins.subscribe(plugins.signal_monitor, "signal_deliver",
                                  self.on_fatal_signal)
                for num in self.fatal_signos:
                    plugins.signal_monitor.register_hook(sig=num)
            except Exception as e:                          # noqa: BLE001
                # Not a warning. The caller asked for crash-driven laps, and a
                # loop that silently waits for the guest to restart its victim
                # would still produce a rate -- a much worse one -- with no
                # sign that the thing being measured was not what was asked
                # for.
                self.logger.error(
                    f"fastloop: reset_on_signal was requested and could not be "
                    f"armed ({e!r}); refusing to report a rate for a loop that "
                    f"is not the one asked for")
                self.errors.append(f"signal hook: {e!r}")
                self.state = "done"
        if not self.reset_on_signal:
            self.logger.info(
                "fastloop: reset_on_signal is OFF -- a crashing input will "
                "stall the loop until the guest restarts the victim, which is "
                "the cost this design exists to remove. Correct for a pure "
                "rate measurement with no injector; wrong with one.")
        self.logger.info(
            f"fastloop: mode={self.mode} comm={self.comm} "
            f"detector={self.detector} warmup={self.warmup} iters={self.want} "
            f"verify_every={self.verify_every}")

    # REPORTING-ONLY ACCESSORS, exempt from the stale-image refusal.
    #
    # The preflight reads the names this class reaches for out of its own
    # bytecode, deliberately, because a hand-kept list of required names falls
    # out of lockstep with the code it guards. An EXCLUSION list has the
    # opposite failure mode -- it can only weaken the check, and only for names
    # written down here -- which is why it is three entries long and why the
    # rule for adding one is narrow:
    #
    #   a name belongs here only if the run is a valid measurement without it.
    #
    # These three say HOW the fork oracle reached its answer (pages proven
    # equal by PFN identity versus pages read back). An image that predates
    # them measures exactly the same reset at exactly the same rate; all that
    # is lost is the method breakdown. Refusing such a run would make a
    # reporting improvement retroactively invalidate every older image, which
    # is a worse failure than a missing field.
    #
    # `test_optional_api_names_really_are_optional` drives the plugin with a
    # QEMU that has none of them and asserts a complete run, so the claim above
    # is checked rather than asserted.
    # Names the general preflight must NOT require, because the class reaches
    # for them only under a condition the preflight cannot evaluate.
    #
    # The coverage group is exempt CONDITIONALLY, not permanently, and the
    # distinction matters: an image without them is a fine image for every run
    # that does not ask for coverage, and a bad one for every run that does.
    # The general check therefore skips them and the `if self.cov:` block in
    # __init__ requires the whole group -- Python attributes and C symbols
    # both -- when coverage is actually on. Exempting them outright would put
    # back exactly the failure this preflight exists to catch, just narrowed
    # to the runs that care.
    API_COVERAGE = frozenset({
        "FASTSNAP_COV_ARM",
        # Only the in-run A/B disarms, but it comes from the same build as
        # the arm, so requiring the pair together costs nothing and keeps the
        # group a group rather than a list with a conditional hole in it.
        "FASTSNAP_COV_DISARM",
        "fastsnap_cov_missing_symbols",
        "fastsnap_cov_set_filter",
        "fastsnap_cov_set_map_size",
        "fastsnap_cov_set_clear_on_reset",
        # Read every lap, to tell a lap that scanned from one that did not.
        # Without it the accessors below are indistinguishable between "this
        # lap found nothing new" and "no scan ran, so these are the previous
        # armed lap's numbers".
        "fastsnap_cov_armed",
        "fastsnap_cov_edges",
        "fastsnap_cov_new_edges",
        "fastsnap_cov_new_buckets",
        "fastsnap_cov_hits",
        "fastsnap_cov_total_edges",
        "fastsnap_cov_tbs_instrumented",
        "fastsnap_cov_tbs_filtered",
        "fastsnap_cov_scan_us",
        "fastsnap_cov_map_size",
    })

    API_OPTIONAL = frozenset({
        "fastsnap_diff_pages_proved",
        "fastsnap_diff_pages_read",
        "fastsnap_diff_pagemap_status",
    }) | API_COVERAGE

    def _num(self, name, default):
        """get_arg with a default that survives a legitimate zero."""
        v = self.get_arg(name)
        return default if v is None else v

    @classmethod
    def _api_names_used(cls):
        import re
        import types
        pat = re.compile(r"^(FASTSNAP_\w+|fastsnap_\w+)$")
        seen, out = set(), set()

        def walk(code):
            if id(code) in seen:
                return
            seen.add(id(code))
            out.update(n for n in code.co_names if pat.match(n))
            for c in code.co_consts:
                if isinstance(c, types.CodeType):
                    walk(c)

        # The MRO, not just vars(cls): a subclass -- which is how the host-side
        # test drives this -- has only its own overrides in vars(), so walking
        # one class found nothing and the preflight reported itself inert.
        # That is the exact failure this check exists to prevent, one level up.
        for klass in cls.__mro__:
            for v in vars(klass).values():
                fn = getattr(v, "__func__", v)
                code = getattr(fn, "__code__", None)
                if code is not None:
                    walk(code)
        return out

    # ---- plumbing ---------------------------------------------------------

    def _fwd_finish(self, now):
        """Close the forward baseline: the MEDIAN of the samples, not one.

        One sample was defensible while it was reproducible -- three arms on
        target A returned 4.15, 4.15 and 4.22 ms. It stopped being defensible
        the moment a run came back at 1054 ms because the single span it
        happened to time caught a connection setup, and the fidelity check
        then reported the loop as 244x FASTER than its own baseline. The
        baseline is the thing every divergence claim is measured against, so
        it is the last number that should rest on n=1.

        The samples are still consecutive spans of the same draw, taken before
        any reset, so the median costs a few more milliseconds of forward
        execution and nothing else.
        """
        self._fwd_this_arm = statistics.median(self._fwd_samples)
        # Sample 1 alone: the armed span's own traversal, and the only one
        # that starts where the replayed laps start. Kept separately because
        # the two axes want different things -- the cost axis wants a robust
        # local estimate, the fidelity axis wants THIS span.
        self._fwd1_this_arm = self._fwd_samples[0]
        self.arm_forward_ms_all.append(round(self._fwd_this_arm, 4))
        self.arm_forward_samples.append([round(x, 4) for x in self._fwd_samples])
        # Unconditional: this is the reported baseline and it must describe
        # the draw the loop ended up on. Guarded with `is None` it froze on
        # the first attempt, so a run that re-armed reported the forward cost
        # of a span it had explicitly rejected. The cost axis is unaffected --
        # it uses `_fwd_this_arm`, which is per-attempt by construction.
        self.arm_forward_ms = self._fwd_this_arm
        spread = (max(self._fwd_samples) / min(self._fwd_samples)
                  if min(self._fwd_samples) > 0 else None)
        # The wording matters here and used to be wrong: this said "the armed
        # span traverses FORWARD in <median> ms (median of 5)", which reads as
        # five measurements of one span. They are five CONSECUTIVE DIFFERENT
        # spans -- the armed instant to the first hit, that hit to the next,
        # and so on. Only the first starts where the replayed laps start, so
        # only the first is the armed span's own cost; the median is a local
        # estimate used by the cost axis, and a ratio against it on a bimodal
        # workload compares the loop to a span it never runs.
        self.logger.info(
            f"fastloop: baseline -- the ARMED SPAN traverses forward in "
            f"{self._fwd_samples[0]:.3f} ms, un-reset. Every lap below "
            f"replays that same span, so the two are comparable and the "
            f"difference is what the reset costs the guest. The next "
            f"{len(self._fwd_samples) - 1} spans after it took "
            f"{[round(x, 2) for x in self._fwd_samples[1:]]} ms (median of "
            f"all {len(self._fwd_samples)}: {self._fwd_this_arm:.3f} ms, "
            f"which is the COST AXIS's reference, not the fidelity one)."
            + ("" if spread is None or spread < 4 else
               f" NOTE: those samples span {spread:.0f}x, so the workload "
               f"around this draw alternates between two costs; which one the "
               f"arm landed on is what the first number says."))
        self.state = "split_control"
        self._sched(self.panda.FASTSNAP_LOOP_RESET)

    def _cpu_sample(self):
        """CPU time consumed, against the wall clock it was consumed in.

        The one measurement that separates "the guest is computing" from "the
        guest is waiting", and nothing in this plugin had it. Every TCG
        counter reads zero across a 46 ms guest half on target A, which is
        consistent with BOTH -- steady userspace execution flushes no TLB and
        invalidates no block, and so does a halted vCPU.

        This plugin runs in QEMU's own process, on the vCPU thread, so
        thread_time() is that vCPU's CPU time: it advances while the guest
        executes and stands still while the vCPU sleeps on a halt. A lap with
        cpu/wall near 1 is doing work; near 0 it is waiting for something, and
        the "rate" is the period of whatever it is waiting on.
        """
        try:
            return (time.process_time(), time.thread_time())
        except Exception:                                   # noqa: BLE001
            return None

    def _tcg_sample(self):
        """Read every TCG counter, or None if this image exposes none.

        Returns None rather than zeros when the accessors are absent, because
        a dict of zeros is indistinguishable from a reset that caused no work
        -- which is precisely the reading being tested.
        """
        out = {}
        for key, fn in self.TCG_COUNTERS:
            f = getattr(self.panda, fn, None)
            if f is None:
                return None
            try:
                out[key] = int(f())
            except Exception:                               # noqa: BLE001
                return None
        return out

    def _tcg_record(self, into, a, b):
        if a is None or b is None:
            return
        for k in into:
            d = b.get(k, 0) - a.get(k, 0)
            if d:
                self._tcg_any = True
            into[k].append(d)

    def _sched(self, op):
        self.seq_at_sched = self.panda.fastsnap_seq()
        self.t_sched = time.perf_counter()
        self.t_sched_mono = time.clock_gettime(time.CLOCK_MONOTONIC)
        self.panda.fastsnap_schedule(op)

    def _bh_done(self):
        """Has the scheduled bottom half run yet? This runs on a vCPU thread
        and the bottom half is on the main loop, so blocking would deadlock;
        the state machine re-checks on the next detector hit instead."""
        return self.panda.fastsnap_seq() > self.seq_at_sched

    # One device, two vmstate sections, and an allowlist that names one of
    # them and not the other is a scope miss rather than a choice.
    #
    # The only entry is the CPU, and it is not a special case of this target:
    # `cpu` is the arch's legacy vmsd -- target/*/machine.c, `.name = "cpu"`
    # on every target in the tree, mips included -- and `cpu_common` is
    # vmstate_cpu_common, which cpu_vmstate_register() (hw/core/cpu-system.c)
    # registers for the SAME CPUState alongside it. The split is about where
    # the fields live, CPUState versus the arch struct, not about what a reset
    # should cover. cpu_common carries `halted` and `interrupt_request` (plus
    # exception_index and crash_occurred as subsections); everything else is
    # in `cpu`.
    #
    # Why complete it rather than warn: the symptom of the miss is rare and
    # therefore reads as health. Measured on bugbench/mipsel, an uncovered
    # cpu_common diverged on 0.1-4.7% of verifications, so a 1000-lap run
    # decided its own verdict by whether an interrupt happened to land -- run
    # 58 FAILED on 1/1000 and run 61 returned VALID on 0/1000 from the same
    # configuration. With it covered: 0 in 1000, twice.
    #
    # It is not free, and the price is worth stating because it looks like
    # overhead and mostly is not: +127 us on a 528 us lap, 18% of throughput
    # (1,760 -> 1,441 exec/s), of which 22.6 us is the larger reset and
    # 102.6 us is the GUEST running differently -- resuming from the interrupt
    # state the arm captured instead of whatever the previous lap left behind.
    # That second part is the thing being bought.
    #
    # The standing claim before this was measured was that covering cpu_common
    # cost 4x the lap. It did not; the two runs that produced that number had
    # crash rates of 0.00% and 0.01% against 1.33% everywhere else -- they
    # armed on an idle guest and were measuring nothing. See SCOPE-AB.md.
    COMPANIONS = {
        "cpu": ("cpu_common",),
    }

    TCG_COUNTERS = (
        ("tb_invalidate", "fastsnap_tb_invalidate_count"),
        ("tb_flush", "fastsnap_tb_flush_count"),
        ("tlb_full_flush", "fastsnap_tlb_full_flush_count"),
        ("tlb_part_flush", "fastsnap_tlb_part_flush_count"),
        ("pages_unchanged", "fastsnap_ram_pages_unchanged"),
        ("pages_invalidated", "fastsnap_ram_pages_invalidated"),
        ("pages_skipped_nocode", "fastsnap_ram_pages_skipped_nocode"),
    )

    def _companions(self, wanted, names):
        """Sections implied by the ones asked for, present on this machine.

        Order-preserving, deduplicated, and filtered against `names`, so a
        machine whose CPU carries a qdev vmsd (and therefore registers no
        cpu_common at all -- see cpu_vmstate_register) adds nothing.
        """
        out = []
        for w in wanted:
            for c in self.COMPANIONS.get(w, ()):
                if c in names and c not in wanted and c not in out:
                    out.append(c)
        return out

    def _apply_scoping(self):
        """Choose which device sections the block covers.

        An allowlist and a denylist answer the same question two ways and the
        C side takes exactly one, so naming both is refused here rather than
        silently resolved -- a precedence rule would make the scoping depend on
        argument order in a way nothing reports.
        """
        try:
            names = self.panda.fastsnap_section_names()
            self.all_sections = names
            self.logger.info(f"fastloop: device sections on this machine: "
                             f"{names}")
            if self.allow and self.deny:
                raise ValueError(
                    "fastloop: allow= and deny= are mutually exclusive; they "
                    "are two answers to 'is this section in the block' and "
                    "only one can be in force")
            if self.allow:
                wanted = [x.strip() for x in self.allow.split(",") if x.strip()]
                unknown = [w for w in wanted if w not in names]
                if unknown:
                    # Not a warning. An allowlist of names that match nothing
                    # produces an empty block that restores nothing, very
                    # quickly, and every number from the run would be a
                    # measurement of doing no work.
                    raise ValueError(
                        f"fastloop: allow= names {unknown}, which are not "
                        f"sections on this machine. Available: {names}")
                implied = self._companions(wanted, names)
                if implied and self.allow_exact:
                    # Asked for literally, so honour it -- but say what is
                    # being left out, because the symptom is rare enough to
                    # be mistaken for a clean run.
                    self.logger.warning(
                        f"fastloop: allow_exact=True, so {implied} stays "
                        f"OUT of the block even though the allowlist names "
                        f"its other half. The device oracle will report it "
                        f"unrestored on the fraction of laps where it "
                        f"happened to change.")
                elif implied:
                    wanted = wanted + implied
                    self.allow_implied = implied
                    self.logger.warning(
                        f"fastloop: adding {implied} to the allowlist. These "
                        f"are the other half of a section you named -- see "
                        f"COMPANIONS. Pass allow_exact=True to measure "
                        f"without them.")
                self.allowed = wanted
                self.panda.fastsnap_set_allowlist(wanted)
                self.logger.info(
                    f"fastloop: {len(names)} sections, allowing "
                    f"{len(wanted)}: {wanted}")
                return
            if self.deny == "auto":
                # Every virtio device, by section id. A virtio device's state
                # is split between the model and a vring in GUEST RAM. The RAM
                # half IS restored now, but virtio_load() validates against
                # indices the host-side backend has moved on from, and the
                # backend is not part of the guest, so the block still cannot
                # carry it.
                chosen = [n for n in names if "virtio" in n.lower()]
            elif self.deny:
                chosen = [x.strip() for x in self.deny.split(",") if x.strip()]
            else:
                chosen = []
            chosen += [n for n in self.deny_extra
                       if n in names and n not in chosen]
            self.denied = chosen
            if chosen:
                self.panda.fastsnap_set_denylist(chosen)
            self.logger.info(f"fastloop: {len(names)} sections, denying "
                             f"{len(chosen)}: {chosen}")
        except Exception as e:                              # noqa: BLE001
            # FATAL, where this used to warn and carry on. The scope of the
            # block is not a detail of the run, it IS what the run measures: a
            # failed allowlist silently falls back to a full block, and the
            # resulting numbers describe a configuration nobody asked for while
            # carrying the label of the one they did. Better no result.
            self.errors.append(f"scoping: {e!r}")
            self.logger.error(
                f"fastloop: REFUSING THE RUN - could not apply the requested "
                f"device scope ({e!r}). Falling back to a different scope "
                f"would produce numbers for a configuration you did not ask "
                f"for.")
            raise

    # ---- the loop ---------------------------------------------------------

    def _portal(self, op_name, pid=0, addr=0, size=0):
        """Issue one portal op; yields the command, returns what came back.

        The imports are INSIDE the function on purpose. A driver that predates
        these ops has no such enumerator, and an image built before them has
        no such module path -- in both cases the loop must degrade to "no pin"
        and still produce a measurement, rather than refuse to start. That is
        the same rule the TCG counters follow.
        """
        try:
            from hyper.portal import PortalCmd
            from hyper.consts import HYPER_OP as hop
            op = getattr(hop, op_name)
        except Exception as e:                              # noqa: BLE001
            self._pin_unavailable(op_name, e)
            return None
        return (yield PortalCmd(op, addr=addr, size=size, pid=pid))

    def _pin_unavailable(self, op_name, err):
        if self.pin_process and "pin" not in " ".join(self.degraded_notes):
            self.degraded_notes.append(
                f"pin requested but {op_name} is not available on this image "
                f"({err!r}); the run continues UNPINNED and its laps may close "
                f"in a process the arm did not land in")
            self.logger.warning(f"fastloop: {self.degraded_notes[-1]}")

    def _pin_settle_step(self):
        """One poll of the freeze, and the arm once it has landed."""
        done = yield from self._pin_poll()
        if done:
            self.state = "arming"
            self._sched(self.panda.FASTSNAP_LOOP_ARM)

    def _pin_apply(self):
        """Pin the guest to the arming process, before the snapshot is taken.

        BEFORE, and that is the whole design. The pin and the stopped task
        states live in driver memory and task_struct -- guest RAM -- so the
        snapshot captures them and every replayed lap begins with the same pin
        and the same tasks stopped. Applied after the snapshot, the first reset
        would rewind it away.
        """
        ident = self._last_ident
        if ident is None:
            self._pin_unavailable("SET_FUZZ_PIN", "driver reports no pid")
            return
        flags = 1 | (2 if self.pin_exclusive else 0)   # F_CHILDREN | F_EXCLUSIVE
        r = yield from self._portal("HYPER_OP_SET_FUZZ_PIN",
                                    pid=int(ident[0]), addr=int(ident[1]),
                                    size=flags)
        self.logger.info(
            f"fastloop: pinned the guest to pid {ident[0]} "
            f"(create_time {ident[1]}), children included"
            + (", EXCLUSIVE -- every other userspace task stopped"
               if self.pin_exclusive else "")
            + f"; portal returned {r!r}")

    def _pin_poll(self):
        """Has the freeze actually taken effect yet?

        SIGSTOP is asynchronous: a task stops at its next signal check, not at
        the call. Arming the snapshot before that has happened would capture a
        half-frozen guest and every replayed lap would inherit it, so this
        polls until the driver reports nothing pending. It CANNOT block waiting
        -- the tasks being stopped need the guest to run in order to receive
        the signal -- which is why it is driven one detector hit at a time.
        """
        self._pin_n += 1
        raw = yield from self._portal("HYPER_OP_GET_FUZZ_PIN_STATS")
        rep = self._decode_pin_report(raw)
        self.pin_report = rep
        if rep is None:
            return True          # cannot ask; do not stall the run on it
        if rep.get("frozen_pending", 0) == 0:
            self.logger.info(
                f"fastloop: pin settled after {self._pin_n} polls -- "
                f"{rep.get('frozen_signalled')} tasks stopped, "
                f"{rep.get('hits_in')} hook firings inside the subtree, "
                f"{rep.get('hits_out')} suppressed outside it")
            return True
        if self._pin_n >= self.pin_settle_hits:
            self.degraded_notes.append(
                f"pin did not settle: {rep.get('frozen_pending')} of "
                f"{rep.get('frozen_signalled')} tasks were still not stopped "
                f"after {self._pin_n} polls. The snapshot below captures a "
                f"HALF-FROZEN guest and every lap replays it")
            self.logger.warning(f"fastloop: {self.degraded_notes[-1]}")
            return True
        return False

    @staticmethod
    def _decode_pin_report(raw):
        """struct igloo_fuzz_pin_report: five u64s then four u8s, LE."""
        if not raw or len(raw) < 5 * 8 + 4:
            return None
        import struct
        f = struct.unpack_from("<7Q4B", raw, 0)
        return {"hits_in": f[0], "hits_out": f[1], "walk_truncated": f[2],
                "frozen_signalled": f[3], "frozen_pending": f[4],
                "pinned_pid": f[5], "pinned_start_time": f[6],
                "active": f[7], "pinned_alive": f[8],
                "frozen_overflow": f[9], "exclusive": f[10]}

    def _hit_identity(self, args):
        """(pid, create_time) of the process this hit came from, or None.

        None means the DRIVER does not report it, which is a different finding
        from "a different process" and must never be coerced into one. Read
        positionally off whichever argument carries it, because the hook
        signature differs per syscall.
        """
        for a in args:
            pid = getattr(a, "pid", None)
            if pid is None:
                continue
            try:
                return (int(pid), int(getattr(a, "create_time", 0) or 0))
            except Exception:                               # noqa: BLE001
                return None
        return None

    def on_hit(self, *args, **kwargs):
        """The syscall hook. penguin's machinery drives this with `yield from`,
        so it must stay a generator even though nothing in it yields."""
        # WHICH PROCESS. The detector is filtered on `comm` alone, and a comm
        # is not an identity: lighttpd forks workers that all carry the name,
        # and a victim that dies and restarts under reset_on_signal comes back
        # with the same name and a different pid. If the armed instant is in
        # one process and the next hit is in another, the "span" being replayed
        # is not one process's work and the lap is not an iteration of
        # anything. create_time is part of the key because a restarted victim
        # can reuse a pid.
        ident = self._hit_identity(args)
        self._last_ident = ident
        if ident is not None:
            self.hit_procs[ident] = self.hit_procs.get(ident, 0) + 1
            if self._arm_ident is not None and ident != self._arm_ident:
                self.hits_other_proc += 1
        self.hits += 1
        self._clean_streak += 1
        if self._clean_streak > self._best_streak:
            self._best_streak = self._clean_streak
        self._step(time.perf_counter())
        # _step cannot yield -- it is also called from the signal handler,
        # which has no portal context -- so anything needing the portal is
        # queued here and driven from the hook, which does.
        g, self._pending_portal = self._pending_portal, None
        if g is not None:
            yield from g

    def on_fatal_signal(self, cpu, event):
        """A crash also ends an iteration -- and this is the whole point.

        Without it the loop stalls exactly when fuzzing gets interesting. The
        detector is the victim's next read(), and a victim that just took a
        SIGSEGV never makes one: the loop waits for the guest's own restart
        machinery, which is the per-execution process teardown and setup that
        snapshot fuzzing exists to delete. Measured on this very target, that
        cost is not a rounding error -- under random input the victim died
        almost every restart and the run delivered 5,212 inputs where the
        crash-free oracle run delivered 237,575, a 45x collapse that cost the
        run a trivial-tier bug it should have found.

        So a fatal signal is an iteration boundary like any other. The reset
        rewinds past the crash to a live victim, and the next input goes in
        without a process ever being created.
        """
        if self.mode == "bare":
            return
        try:
            if int(event.sig) not in self.fatal_signos or event.drop:
                return
        except Exception:                                   # noqa: BLE001
            return
        # BEFORE the state check, which is the point. The streak gates arming,
        # and arming happens in warmup and rearm_wait -- the two states an
        # early `state != "loop"` return would have skipped, leaving the streak
        # to grow through a victim that was dying repeatedly.
        self._clean_streak = 0
        if self.state != "loop":
            return
        self.signal_laps += 1
        # The FIRST fault of this lap. _step can return without closing (the
        # bottom half may not have run yet), so a later fault must not
        # overwrite the instant the guest actually broke.
        if self.t_signal_mono is None:
            self.t_signal_mono = time.clock_gettime(time.CLOCK_MONOTONIC)
        self._closed_by_signal = True
        self._step(time.perf_counter())

    def _step(self, now):
        try:
            if self.state == "warmup":
                # COVERAGE IS ARMED HERE, AT THE TOP OF WARMUP, and the
                # placement is load-bearing rather than tidy.
                #
                # Instrumentation is emitted at TRANSLATION time, and arming
                # queues a tb_flush so everything already cached is
                # re-translated with it. Do that later -- after the forward
                # probe, say -- and the replayed laps would carry
                # instrumentation while the forward traversal they are scored
                # against did not. `_replay_fidelity` divides one by the
                # other, so the ratio would move for a reason that has nothing
                # to do with the reset, and the verdict it drives would move
                # with it. Arming before anything is measured keeps both sides
                # of every ratio on the same footing.
                #
                # Scheduled directly rather than through _sched(): that helper
                # records seq_at_sched/t_sched for the reset accounting, and
                # this op is not a reset. Nothing awaits it -- warmup is
                # thousands of hits long and the bottom half runs immediately.
                if self.cov and not self._cov_armed:
                    self._cov_armed = True
                    self.panda.fastsnap_schedule(self.panda.FASTSNAP_COV_ARM)

                # The FORWARD distribution, recorded before anything is armed.
                # This is the baseline the cost axis scores a draw against, and
                # nothing was capturing it: warmup counted hits and discarded
                # the intervals between them, which is the one thing that would
                # have shown the bimodality immediately.
                if self._warm_prev is not None:
                    g = (now - self._warm_prev) * 1000.0
                    if len(self.warm_gaps_ms) < 20000:
                        self.warm_gaps_ms.append(g)
                self._warm_prev = now
                if (self.hits >= self.warmup
                        and (now - self.t0) >= self.arm_after_s
                        and (self.mode != "loop"
                             or self._clean_streak >= self.arm_clean_streak)):
                    if self.mode == "bare":
                        self.state = "loop"
                        self.t_iter = now
                        self.t_loop0 = now
                    else:
                        self._apply_scoping()
                        self.arm_attempt = 1
                        if self.pin_process:
                            # Pin BEFORE the snapshot, then wait for the
                            # freeze to actually take effect. Both steps have
                            # to happen while the guest is still running
                            # freely: a stopped task needs to be scheduled to
                            # receive its SIGSTOP, so this cannot be a busy
                            # wait inside one hook.
                            self._pin_n = 0
                            self.state = "pin_settle"
                            self._pending_portal = self._pin_apply()
                        else:
                            self.state = "arming"
                            self._sched(self.panda.FASTSNAP_LOOP_ARM)

            elif self.state == "pin_settle":
                self._pending_portal = self._pin_settle_step()

            elif self.state == "arming":
                if not self._bh_done():
                    return
                if self.panda.fastsnap_last_rc() != 0:
                    self.errors.append("LOOP_ARM returned rc != 0")
                    self.state = "done"
                    return
                self.arm_us = self.panda.fastsnap_last_us()
                self.t_arm_s = round(now - self.t0, 1)
                self._arm_ident = self._last_ident
                self.arm_digest = self.panda.fastsnap_last_digest()
                self.snapshot_bytes = self.panda.fastsnap_ram_snapshot_bytes()
                self.logger.info(
                    f"fastloop: armed in {self.arm_us} us, "
                    f"{self.snapshot_bytes} bytes of RAM snapshotted")
                # Split the hook budget at the armed instant. Boot swamps a
                # whole-run total -- the first real budget was 5,791 ioctl
                # firings, nearly all of them bringing the system up -- while
                # the question a loop asks is what a LAP costs. Marking here
                # (and again on each re-arm, which moves the boundary to the
                # draw actually kept) makes the per-lap figure readable
                # instead of inferred. No-op unless hook_budget is on.
                try:
                    plugins.syscalls.hook_budget_mark("armed")
                except Exception:                            # noqa: BLE001
                    # An older penguin has no such method. The budget is
                    # diagnostics; never let it break an arm.
                    pass
                if self.mode == "armed" or self.mode in self.MEASUREMENT_MODES:
                    # The split-order control validates the ORACLE, and these
                    # modes make no soundness claim for it to validate. Running
                    # it would also mean one full LOOP_RESET in a run whose
                    # whole point is that no full reset happens.
                    self.state = "loop"
                    self.t_iter = now
                    self.t_loop0 = now
                elif self._fwd_this_arm is None and self.arm_forward_probe:
                    # One span forward, un-reset, before anything rewinds the
                    # guest. This is the only point in the run where the armed
                    # instant has been reached and no restore has happened yet.
                    #
                    # Measured on EVERY arm, not just the first, because it is
                    # the cost axis's reference: a draw is scored against its
                    # own forward traversal, and a re-armed draw is a different
                    # span with a different one.
                    self.state = "fwd_probe"
                    self._t_fwd0 = now
                else:
                    # THE CONTROL FIRST. Run the oracle the wrong way round --
                    # as its own bottom half, with the guest free to run in
                    # between -- before trusting any zero from the right way
                    # round. If this reports zero too, the oracle is not
                    # looking at a running guest and every later zero is
                    # worthless.
                    self.state = "split_control"
                    self._sched(self.panda.FASTSNAP_LOOP_RESET)

            elif self.state == "fwd_probe_more":
                # Another forward span, un-reset, for the same draw.
                self._fwd_samples.append((now - self._t_fwd0) * 1000.0)
                if len(self._fwd_samples) < self.arm_forward_n:
                    self._t_fwd0 = now
                    return
                self._fwd_finish(now)

            elif self.state == "fwd_probe":
                # The next detector hit closes the forward span. Nothing is
                # scheduled here on purpose: any bottom half would perturb the
                # very traversal being timed.
                self._fwd_samples = [(now - self._t_fwd0) * 1000.0]
                if self.arm_forward_n > 1:
                    self._t_fwd0 = now
                    self.state = "fwd_probe_more"
                    return
                self._fwd_finish(now)

            elif self.state == "split_control":
                if not self._bh_done():
                    return
                self.state = "split_control_diff"
                self._sched(self.panda.FASTSNAP_FORK_DIFF)

            elif self.state == "split_control_diff":
                if not self._bh_done():
                    return
                self.split_diff = self.panda.fastsnap_diff_pages()
                # <= 0, not == 0. A negative value means the comparison itself
                # failed -- process_vm_readv could not read the child -- and
                # the first run of this plugin reported exactly that as
                # "control OK - the oracle sees -1 pages the guest dirtied".
                # A broken oracle passing its own control is the precise shape
                # of failure the control exists to prevent.
                if self.split_diff <= 0:
                    why = ("could not read the forked reference at all"
                           if self.split_diff < 0 else
                           "reports zero differing pages")
                    self.logger.error(
                        f"fastloop: CONTROL FAILED - the oracle run as a "
                        f"separate bottom half {why}. On a running guest it "
                        f"should see the pages written between the two bottom "
                        f"halves, so a zero from the combined op would prove "
                        f"nothing.")
                    self.errors.append(
                        f"split-order control failed (diff_pages="
                        f"{self.split_diff})")
                else:
                    self.logger.info(
                        f"fastloop: control OK - split-order oracle sees "
                        f"{self.split_diff} pages the guest dirtied between "
                        f"the reset and the diff; the combined op has "
                        f"something to be right about")
                self.state = "loop"
                self.t_iter = now
                self.t_loop0 = now

            elif self.state == "rearm_wait":
                # No reset outstanding: the guest is running forward under its
                # own restart loop, which is what produces a live victim to
                # arm on. Every detector hit just checks the clock.
                if (now < self._rearm_at
                        or self._clean_streak < self.arm_clean_streak):
                    return
                self.arm_attempt += 1
                self._probe_n = self._probe_sig = 0
                self._probe_done = False
                self._probe_laps_ms = []
                self.state = "arming"
                self._sched(self.panda.FASTSNAP_LOOP_ARM)

            elif self.state == "loop":
                if self.mode in ("bare", "armed"):
                    # No reset outstanding, so every detector hit closes an
                    # iteration directly. These arms exist to price what the
                    # loop arm carries BESIDES the reset, so they must take
                    # their interval from the same event.
                    self._mark(now)
                    return

                if self.pending_reset:
                    if not self._bh_done():
                        return          # bottom half has not run yet
                    if self.panda.fastsnap_last_rc() != 0:
                        self.errors.append("reset returned rc != 0")
                        self.state = "done"
                        return
                    # Read the reset's own clock BEFORE _mark, which consumes
                    # the verification bookkeeping from the same op.
                    if self.t_sched is not None:
                        w = (now - self.t_sched) * 1000.0
                        (self.bh_wall_crash_ms if self._closed_by_signal
                         else self.bh_wall_ms).append(w)
                        self._split_wall(now)
                    self._tcg_at_bh = self._tcg_sample()
                    self._tcg_record(self.tcg_reset, self._tcg_prev,
                                     self._tcg_at_bh)
                    self.reset_us.append(self.panda.fastsnap_last_us())
                    pages = self.panda.fastsnap_ram_restored_pages()
                    self.restored.append(pages)
                    # The lap the reset just closed, summarised inside the
                    # same bottom half. Four accessor reads, no scheduled op:
                    # clear_on_reset means the scan already happened as part
                    # of the reset, which is the only reason coverage can be
                    # per-lap here at all -- an op per lap would cost more
                    # than the scan it asked for.
                    # A DISARMED LAP HAS NOTHING TO REPORT, AND THE
                    # ACCESSORS DO NOT SAY SO.
                    #
                    # fastsnap_cov_clear_on_reset() is
                    # (clear_on_reset && armed), so while coverage is
                    # disarmed the reset performs NO SCAN and every accessor
                    # keeps whatever the last ARMED lap left in it. Appending
                    # them anyway re-counts that lap's novelty once per
                    # disarmed lap -- and new_edges_total is a sum over this
                    # list, so a single lap that found 50 edges is worth 50 x
                    # cov_ab of them.
                    #
                    # MEASURED, because this shipped and was published from.
                    # Runs 122 and 123 differ only in cov_ab, same session,
                    # same everything else: new_edges_total 416 against 1904,
                    # new_edges_per_s 10.2 against 49.9 -- while total_edges,
                    # a cumulative counter inside QEMU that no host-side sum
                    # can distort, moved 21,121 to 22,788. The code reached
                    # was the same. The counting was not.
                    if self.cov and self.panda.fastsnap_cov_armed():
                        self.cov_edges.append(self.panda.fastsnap_cov_edges())
                        self.cov_new.append(
                            self.panda.fastsnap_cov_new_edges())
                        # This lap, and only this lap, has fresh coverage to
                        # announce. Not every _mark() arrives here -- the
                        # first lap has no outstanding reset to read -- and a
                        # subscriber handed the PREVIOUS lap's novelty would
                        # credit it to the wrong input, silently and forever.
                        self._cov_fresh = True
                        self.cov_new_buckets.append(
                            self.panda.fastsnap_cov_new_buckets())
                        self.cov_hits.append(self.panda.fastsnap_cov_hits())
                        self.cov_scan_us.append(
                            self.panda.fastsnap_cov_scan_us())
                    elif self.cov:
                        # Counted, not silently dropped: a coverage block
                        # whose lap count is below the run's lap count needs
                        # to say why, or it reads as laps going missing.
                        self.cov_disarmed_laps += 1
                    self.pending_reset = False
                    self._mark(now)
                    if self.state != "loop":
                        return
                else:
                    # First lap: nothing outstanding, just start the clock so
                    # the first interval is a real one rather than the gap
                    # since the control finished.
                    self.t_iter = now
                    # ONCE. This branch is not only the first lap: it is every
                    # lap that arrives with no reset outstanding, which
                    # includes the lap after each cov_ab toggle barrier. Run
                    # 123 re-stamped t_loop0 thirty-five times and reported
                    # loop_wall_s = 1.12 s for a loop whose own per-lap sum was
                    # 113.8 s -- and exec_per_s_wall_incl_oracle = 10,703/s,
                    # which is not a number this machine can produce.
                    #
                    # It did not go unnoticed for lack of a check. wall_share
                    # put `unaccounted` at -100.5% of the span, and a negative
                    # share of a positive span is arithmetically impossible.
                    # The check fired on the run and nobody read it, which is
                    # why the report now refuses the span outright rather than
                    # printing an impossible share next to it.
                    if self.t_loop0 is None:
                        self.t_loop0 = now

                # Nothing may be scheduled while an A/B toggle is in flight;
                # see _ab_step on what a premature _bh_done() would record.
                if self._ab_blocked():
                    return

                # Verify on a schedule, not every lap: the oracle reads all of
                # guest RAM back through process_vm_readv() and costs ~80x the
                # reset, so verifying every lap would report the oracle's rate
                # as the loop's.
                if self.mode in self.MEASUREMENT_MODES:
                    # No verification here, and not an oversight. The oracle is
                    # only meaningful in the combined reset+diff op, which
                    # exists for a COMPLETE reset and not for half of one --
                    # and split across two bottom halves the guest runs in the
                    # gap, so the diff reports ordinary kernel work and means
                    # nothing. A half-reset is known-wrong anyway; asking an
                    # oracle to confirm it would be theatre.
                    self._pending_verify = None
                    self._sched(self.panda.FASTSNAP_RESTORE
                                if self.mode == "devonly"
                                else self.panda.FASTSNAP_RAM_RESTORE)
                elif (self.verify_every
                        and self.n_iters % self.verify_every == 0):
                    self._pending_verify = self.n_iters
                    self._sched(self.panda.FASTSNAP_LOOP_RESET_VERIFY)
                else:
                    self._pending_verify = None
                    self._sched(self.panda.FASTSNAP_LOOP_RESET)
                self.pending_reset = True
        except Exception as e:                              # noqa: BLE001
            if len(self.errors) < 5:
                # The repr alone names the type and loses the line, and this
                # handler swallows every state-machine bug in the plugin --
                # which is precisely the class of failure that reports a
                # number instead of an error. Keep the traceback.
                import traceback
                self.errors.append(
                    f"{e!r} @ {traceback.format_exc().strip().splitlines()[-2].strip()}")
            self.state = "done"

    @staticmethod
    def _self_sha256():
        try:
            import hashlib
            return hashlib.sha256(
                open(__file__, "rb").read()).hexdigest()[:16]
        except Exception:                                   # noqa: BLE001
            return None

    # ---- the in-run A/B -------------------------------------------------

    def _ab_bucket(self):
        """Which phase the lap now closing belongs to, or None if not A/B-ing.

        A lap inside the settle window after a toggle is named `settle` rather
        than dropped: a discarded sample cannot be checked, and the claim that
        re-translation is over within the window is exactly the claim a reader
        should not have to take on faith.
        """
        if not (self.cov and self.cov_ab):
            return None
        if self._ab_lap < self.cov_ab_settle:
            return "settle"
        return self._ab_phase

    def _ab_step(self, now):
        """Count a plain lap toward the current phase and toggle when due.

        Called at lap close, which is the only safe moment: nothing is
        outstanding, and in particular the reset for the next lap has not been
        scheduled yet.
        """
        if not (self.cov and self.cov_ab):
            return
        self._ab_lap += 1
        if self._ab_lap < self.cov_ab + self.cov_ab_settle:
            return
        # Carry the instrumented-block count forward before it is lost. ARM
        # zeroes cov_tbs_instrumented, so without this the final report would
        # describe only the last armed phase and quietly understate how much
        # of the guest was covered across the run.
        if self._ab_phase == "on":
            try:
                self._ab_tbi += self.panda.fastsnap_cov_tbs_instrumented()
                self._ab_tbf += self.panda.fastsnap_cov_tbs_filtered()
            except Exception:                               # noqa: BLE001
                pass
        self._ab_flush_block()
        self._ab_phase = "off" if self._ab_phase == "on" else "on"
        self._ab_lap = 0
        self._ab_switches += 1
        # AWAITED, and this is not optional. Every fastsnap op bumps the one
        # global fastsnap_seq, and _bh_done() is `seq() > seq_at_sched`. Let a
        # reset be scheduled while this toggle's bottom half is still queued
        # and the toggle's own bump satisfies the reset's completion test --
        # the lap would then read last_us() and ram_restored_pages() left over
        # from the PREVIOUS reset and record them as this one's. That is a
        # wrong number, not a missing one, so the state machine stalls on the
        # next detector hits until the toggle is observed instead.
        self._ab_wait_seq = self.panda.fastsnap_seq()
        self.panda.fastsnap_schedule(
            self.panda.FASTSNAP_COV_ARM if self._ab_phase == "on"
            else self.panda.FASTSNAP_COV_DISARM)

    def _ab_flush_block(self):
        """Close the steady-state block just finished, as three medians."""
        cur, self._ab_cur = self._ab_cur, {"ms": [], "sched": [], "obs": []}
        if not cur["ms"]:
            return
        row = {"phase": self._ab_phase, "i": self._ab_switches,
               "laps": len(cur["ms"]),
               "iter_ms": round(statistics.median(cur["ms"]), 4)}
        for k, name in (("sched", "sched_to_bh_ms"), ("obs", "bh_to_observed_ms")):
            if cur[k]:
                row[name] = round(statistics.median(cur[k]), 4)
        self.ab_blocks.append(row)

    @staticmethod
    def _cov_exposure(per_lap):
        """How uneven the per-lap coverage was, because total_edges depends on
        it and nothing else in the report says so.

        THE MISTAKE THIS PREVENTS, which was made rather than anticipated.
        Two runs of this target were compared on cumulative `total_edges` --
        31,920 at 64 KiB against 42,249 at 1 MiB -- and the jump was
        attributed to map size. It could not be. This workload's laps are
        BIMODAL: most replay a pipelined request in ~3.5 ms, and a few replay
        a CONNECTION BOUNDARY, which is a guest fork+exec and sees up to
        29,285 edges against a 5,011 median. One run drew one of those and the
        other drew four, so they had different EXPOSURE, and a cumulative
        count over different exposure is not a comparison.

        Per-lap medians are immune (a median cannot be moved by four laps in
        two thousand) and that is where the real comparison ended up. But
        nothing in the result made the exposure difference visible, so the
        confounded number was the one to hand. This counts the outlier laps so
        it is not.
        """
        if not per_lap:
            return None
        v = sorted(per_lap)
        med = v[len(v) // 2]
        if med <= 0:
            return {"laps": len(v), "median_edges": med, "outlier_laps": 0}
        hi = [x for x in v if x > 2 * med]
        out = {"laps": len(v), "median_edges": med,
               "outlier_laps": len(hi),
               "outlier_threshold": 2 * med,
               "max_edges": v[-1]}
        if hi:
            out["outlier_edge_share"] = round(sum(hi) / float(sum(v)), 4)
            out["errors"] = (
                f"{len(hi)} of {len(v)} laps saw more than twice the median "
                f"edge count (up to {v[-1]}), so this run's exposure is "
                f"uneven. total_edges is CUMULATIVE over that exposure and is "
                f"not comparable to another run's unless the outlier count "
                f"matches -- compare the per-lap median instead.")
        return out

    @staticmethod
    def _cov_occupancy(total_edges, map_size):
        """How much of the map is used, and how much coverage it is hiding.

        WHY THIS IS NOT JUST A PERCENTAGE. An AFL map is a hash table with no
        collision handling: two distinct edges landing in the same byte are
        one edge forever. So a full map does not report "full", it reports a
        LOWER edge count than the guest actually produced -- coverage loss
        that looks exactly like a target with less coverage. There is nothing
        in the map that distinguishes them, which is why the estimate has to
        come from the occupancy itself.

        Under a uniform hash, n distinct edges fill an expected
        m * (1 - e^(-n/m)) buckets. Observing a fraction f = buckets/m used,
        that inverts to n ~= -m * ln(1 - f), and the shortfall between that
        and what was observed is what the map is swallowing. The block index
        is a splitmix64 finalizer, so uniformity is a fair assumption here --
        it would NOT be for a plain `pc & mask`, which is why the selftest
        checks the spread of 4096 page-aligned PCs against the birthday bound
        rather than assuming it.
        """
        if not map_size or total_edges is None:
            return None
        f = total_edges / float(map_size)
        out = {"distinct_edges": total_edges, "map_size": map_size,
               "used_frac": round(f, 4)}
        if total_edges <= 0:
            return out
        if f >= 1.0:
            # Saturated: the estimator's log diverges and every further edge
            # is invisible. Say so rather than returning a huge number.
            out["saturated"] = True
            out["errors"] = "the map is completely full; edge counts are meaningless"
            return out
        est = -map_size * math.log(1.0 - f)
        out["est_true_edges"] = int(round(est))
        out["est_edges_lost"] = int(round(est - total_edges))
        out["est_loss_frac"] = round(1.0 - total_edges / est, 4)
        # A THRESHOLD, because the number alone gets read as "fine".
        #
        # 5% is where raising cov_map_size is clearly worth what it charges,
        # and what it charges turned out to be much less than expected. This
        # comment previously said the scan is O(map) so doubling the map
        # doubles the scan. MEASURED, THAT IS WRONG: 64 KiB -> 1 MiB, a 16x
        # map, moved the scan from 163 us to 268 us -- 1.64x, not 16x. The
        # zero-word skip is why. A sparse map is skimmed 8 bytes at a time
        # (~0.5 ns per word) and only the non-zero words are examined byte by
        # byte (~5 ns per set byte), so cost tracks the number of EDGES SET
        # PER LAP far more than the map's size. Per-lap occupancy at 64 KiB
        # was only 7.4% -- it is the cumulative virgin map that fills up, and
        # the virgin map is not what the scan is dominated by.
        if out["est_loss_frac"] >= 0.05:
            out["verdict"] = (
                f"{out['est_loss_frac'] * 100:.1f}% of distinct edges are "
                f"being lost to hash collisions ({out['est_edges_lost']} of "
                f"an estimated {out['est_true_edges']}). This UNDERSTATES "
                f"coverage and is indistinguishable from a target that "
                f"reaches less code. Raise cov_map_size -- measured, a 16x "
                f"map cost 1.64x the scan, not 16x, because the zero-word "
                f"skip makes cost track edges-per-lap rather than map size "
                f"-- or narrow cov_filter_lo/hi to the victim's text.")
        else:
            out["verdict"] = (
                f"map is {f * 100:.1f}% full; estimated collision loss "
                f"{out['est_loss_frac'] * 100:.1f}%, low enough that the "
                f"edge count can be read at face value")
        return out

    def _ab_report(self):
        """What coverage cost, measured against itself inside this one run."""
        self._ab_flush_block()      # the last block never sees a toggle
        out = {
            "laps_per_phase": self.cov_ab,
            "settle_laps": self.cov_ab_settle,
            "switches": self._ab_switches,
            "tbs_instrumented_all_arms": self._ab_tbi,
            "blocks": self.ab_blocks,
        }
        for name, d in (("iter_ms", self.ab_ms),
                        ("sched_to_bh_ms", self.ab_sched),
                        ("bh_to_observed_ms", self.ab_obs)):
            out[name] = {k: _stats(v) for k, v in d.items()}

        # THE PAIRED COMPARISON. Adjacent blocks differ in phase and are
        # minutes apart, so each adjacent pair is one before/after measurement
        # of the same guest under the same snapshot. The sign agreement across
        # pairs is the statistic that matters: a pooled difference of the
        # right size with two pairs disagreeing is not a measurement of
        # anything.
        pairs = {}
        for key in ("iter_ms", "sched_to_bh_ms", "bh_to_observed_ms"):
            deltas = []
            for x, y in zip(self.ab_blocks, self.ab_blocks[1:]):
                if x["phase"] == y["phase"]:
                    continue
                if key not in x or key not in y:
                    continue
                on, off = ((x, y) if x["phase"] == "on" else (y, x))
                deltas.append(round(on[key] - off[key], 4))
            if not deltas:
                continue
            n = len(deltas)
            pos = sum(1 for d in deltas if d > 0)
            row = {
                "deltas_on_minus_off": deltas,
                "n_pairs": n,
                "median_delta_ms": round(statistics.median(deltas), 4),
                "mean_delta_ms": round(statistics.fmean(deltas), 4),
                "pairs_positive": pos,
                "sign_consistent": pos == n or pos == 0,
            }
            # TWO TESTS, AND BOTH MUST PASS, because each covers the other's
            # blind spot.
            #
            # The SIGN TEST is distribution-free: under no effect each pair is
            # a coin flip, so an exact two-sided binomial on the split is the
            # weakest assumption that says anything. It cannot be fooled by
            # one enormous pair, and it does not care what the lap-time
            # distribution looks like -- which matters, because this one is
            # heavy-tailed and nothing here should assume otherwise.
            #
            # The T-RATIO covers what the sign test cannot see: a perfectly
            # consistent effect that is trivially small. Thirty pairs all
            # leaning the same way by a microsecond would give an impressive
            # p and mean nothing.
            #
            # Requiring only "every pair agrees" was the first version and it
            # was wrong in the direction that loses information: with 30-odd
            # pairs and a real 2-3 sigma effect, one or two pairs will
            # disagree by chance, and an all-or-nothing rule would report a
            # thoroughly resolved measurement as a bound.
            row["sign_test_p"] = float(f"{_sign_test_p(n, pos):.3g}")
            if n >= 2:
                sd = statistics.stdev(deltas)
                row["sd_delta_ms"] = round(sd, 4)
                row["t_stat"] = (round(abs(row["mean_delta_ms"])
                                       / (sd / math.sqrt(n)), 3)
                                 if sd > 0 else None)
            # A SYMMETRIC 10% TRIM, and the t-ratio judged on it.
            #
            # Not to make a marginal result significant -- the sign test is
            # trim-free and already gave p = 3.5e-6 for the guest half on the
            # first real run. The trim fixes something else: the t-ratio's
            # sensitivity to a handful of blocks that measure the GUEST being
            # expensive rather than coverage being expensive.
            #
            # That first run showed exactly this. Of 18 disarmed blocks, 16
            # landed in 3.130-3.247 ms and all 18 armed blocks in
            # 3.394-3.606 -- fully DISJOINT -- while two disarmed blocks came
            # in at 3.565 and 3.662. Each of those sits between two armed
            # blocks, so two bad blocks produce exactly the four negative
            # pairs observed. On the GUEST HALF -- the quantity the whole
            # experiment was built to resolve, and the smallest of the three
            # -- those two blocks dragged t from 9.7 down to 2.9, i.e. from
            # settled to under the bar. (The lap total, being larger, only
            # fell from 15.4 to 8.5 and would have passed either way.) The
            # same trim is applied to every quantity at the same
            # rate, decided by rule rather than by which points are
            # inconvenient, and both figures are reported so a reader can see
            # what it changed.
            if n >= 5:
                k = max(1, n // 10)
                tr = sorted(deltas)[k:-k]
                if len(tr) >= 2:
                    tsd = statistics.stdev(tr)
                    row["trim_frac"] = round(k / float(n), 3)
                    row["trimmed_mean_delta_ms"] = round(
                        statistics.fmean(tr), 4)
                    row["t_trimmed"] = (
                        round(abs(statistics.fmean(tr))
                              / (tsd / math.sqrt(len(tr))), 3)
                        if tsd > 0 else None)
            t_use = row.get("t_trimmed", row.get("t_stat"))
            row["resolved"] = bool(
                row["sign_test_p"] <= 0.05
                and (t_use is None or t_use >= 3.0))
            pairs[key] = row
        out["paired"] = pairs

        # The arithmetic the whole experiment was built to do: total cost
        # minus the part already measured directly, leaving the part that
        # could not be. Stated as a subtraction so a reader can see which
        # term is measured twice and which only once.
        # The MEDIAN of the pair deltas, not the mean, for the same reason
        # the trim exists: two expensive guest blocks move a mean of 35 and
        # move a median of 35 by nothing.
        # THE ACCOUNTING, and it closes three ways rather than one.
        #
        # The lap total and its two halves are each measured independently by
        # the same paired design, so `reset + guest == total` is a check the
        # experiment has to pass rather than an identity it defines. On the
        # first real run it closed to 1 us out of 261.
        #
        # Within the reset half there is a fourth, independent instrument:
        # QEMU's own clock around the map walk. It does NOT have to agree with
        # the A/B's reset half, and the gap between them is reported as
        # unattributed rather than quietly assigned to the scan -- the scan
        # clock covers the walk and the virgin-map fold, and whatever else the
        # armed bottom half costs (a call, and a 128 KiB working set walked
        # past the reset's own) is real and is not in it.
        def med(key):
            return pairs.get(key, {}).get("median_delta_ms")

        tot, rst, gst = med("iter_ms"), med("sched_to_bh_ms"), \
            med("bh_to_observed_ms")
        scan = (_stats(self.cov_scan_us) or {}).get("median")
        if tot is None:
            return out
        att = {"total_cost_ms_per_lap": round(tot, 4)}
        if rst is not None:
            att["reset_half_ms_per_lap"] = round(rst, 4)
        if gst is not None:
            att["guest_half_ms_per_lap"] = round(gst, 4)
        if rst is not None and gst is not None:
            att["halves_minus_total_ms"] = round(rst + gst - tot, 4)
            att["closes"] = abs(rst + gst - tot) <= max(0.02, 0.1 * abs(tot))
        if scan is not None:
            att["scan_own_clock_ms_per_lap"] = round(scan / 1000.0, 4)
            if rst is not None:
                att["reset_half_unattributed_ms"] = round(
                    rst - scan / 1000.0, 4)
        att["note"] = (
            "total, reset half and guest half are three independent paired "
            "measurements; reset+guest==total is therefore a check, not an "
            "identity. The scan's own clock is a fourth instrument inside the "
            "reset half, and the difference is left unattributed.")
        out["attribution"] = att
        if not pairs.get("iter_ms", {}).get("resolved"):
            pr = pairs.get("iter_ms", {})
            att["caveat"] = (
                f"the paired deltas do not separate the phases "
                f"(sign-test p={pr.get('sign_test_p')}, "
                f"t={pr.get('t_stat')}, t_trimmed={pr.get('t_trimmed')}, "
                f"{pr.get('pairs_positive')} of {pr.get('n_pairs')} "
                f"positive), so read this as a bound, not a value")
        for k, lbl in (("bh_to_observed_ms", "guest_half_unresolved"),
                       ("sched_to_bh_ms", "reset_half_unresolved")):
            if k in pairs and not pairs[k].get("resolved"):
                att[lbl] = (
                    f"p={pairs[k].get('sign_test_p')}, "
                    f"t_trimmed={pairs[k].get('t_trimmed')}")
        return out

    def _ab_blocked(self):
        """True while a toggle's bottom half has not been observed yet."""
        if self._ab_wait_seq is None:
            return False
        if self.panda.fastsnap_seq() > self._ab_wait_seq:
            self._ab_wait_seq = None
            return False
        return True

    def _split_wall(self, now):
        """Split the schedule-to-observed span at the bottom half.

        CLOCK_MONOTONIC on both sides, taken explicitly rather than through
        perf_counter(): both are that clock on Linux, but only the explicit
        form is documented to be, and a mismatched epoch would arrive as a
        plausible latency rather than as an error. A build without the
        timestamp is recorded as absent, never as zero.
        """
        if not self._have_bh_clock or self.t_sched_mono is None:
            return
        try:
            bh = self.panda.fastsnap_bh_done_us() / 1e6
        except Exception:                                   # noqa: BLE001
            self._have_bh_clock = False
            return
        now_mono = time.clock_gettime(time.CLOCK_MONOTONIC)
        sched = (bh - self.t_sched_mono) * 1000.0
        obs = (now_mono - bh) * 1000.0
        # A negative half means the two clocks are not the same clock. Dropping
        # the sample is right: a negative latency reported as a small positive
        # one is exactly the kind of number that gets quoted.
        if sched < 0 or obs < 0:
            self._have_bh_clock = False
            self.errors.append(
                f"bh clock mismatch (sched={sched:.3f} ms, obs={obs:.3f} ms); "
                f"the split is unavailable for this run")
            return
        if (not self._closed_by_signal and self._pending_verify is None
                and len(self.page_obs) < self.page_obs_max):
            # Capped. These are the raw pairs behind the per-page regression,
            # and 20,000 of them settle a slope of 0.81 us/page as well as
            # 250,000 would -- while a long run with no cap writes tuples into
            # the report until the report is the largest artifact of the run.
            self.page_obs.append((self.restored[-1] if self.restored else -1,
                                  round(obs, 6)))
        if self._closed_by_signal:
            self.sched_crash_ms.append(sched)
            self.obs_crash_ms.append(obs)
            if self.t_signal_mono is not None:
                to_sig = (self.t_signal_mono - bh) * 1000.0
                after = (now_mono - self.t_signal_mono) * 1000.0
                # Dropped rather than clamped if either is negative: the fault
                # can predate the bottom half when the signal arrived while a
                # reset was still outstanding, and a negative span reported as
                # a small positive one is exactly the kind of number that gets
                # quoted.
                if to_sig >= 0 and after >= 0:
                    self.crash_to_sig_ms.append(to_sig)
                    self.crash_after_sig_ms.append(after)
        elif self._pending_verify is not None:
            # A verified lap's bottom half carries the oracle's ~50 ms, which
            # lands wholly inside sched_to_bh. Left in the ordinary bucket it
            # moved that bucket's MEAN from 0.12 ms to 2.54 ms on a run where
            # 4% of laps were verified -- the median survived, so the number
            # was quotable and the number beside it was not. Same separation
            # iter_ms already makes, one level down.
            self.sched_verify_ms.append(sched)
            self.obs_verify_ms.append(obs)
        else:
            self.sched_ms.append(sched)
            self.obs_ms.append(obs)
            # The same two halves again, bucketed by A/B phase. Appended here
            # rather than recomputed later because this is the only place the
            # split exists, and a second derivation would be a second thing
            # that can disagree.
            b = self._ab_bucket()
            if b is not None:
                self.ab_sched[b].append(sched)
                self.ab_obs[b].append(obs)
                if b != "settle":
                    self._ab_cur["sched"].append(sched)
                    self._ab_cur["obs"].append(obs)

    def _mark(self, now):
        """Close one iteration."""
        _tcg_now = self._tcg_sample()
        # Work between the bottom half finishing and this lap closing is the
        # GUEST's, not the reset's.
        self._tcg_record(self.tcg_guest, self._tcg_at_bh, _tcg_now)
        self._tcg_prev = _tcg_now
        self._tcg_at_bh = None
        # ...and how much of the LAP was spent EXECUTING rather than waiting.
        #
        # Per lap, not per guest half, and the difference is not cosmetic: the
        # plugin only learns the bottom half finished when it next polls, which
        # is at lap close, so a bh-to-close window would always be zero. The
        # reset is ~0.6 ms of a 46 ms lap, so it dilutes this by about one
        # percent -- small enough to read, and named `lap_` so nobody reads it
        # as the guest half it is not.
        c = self._cpu_sample()
        if c is not None and self._cpu_prev is not None:
            wall = now - self._cpu_prev_t
            if wall > 0:
                self.lap_cpu_frac.append((c[1] - self._cpu_prev[1]) / wall)
                self.lap_proc_frac.append((c[0] - self._cpu_prev[0]) / wall)
        self._cpu_prev = c
        self._cpu_prev_t = now
        was_crash = self._closed_by_signal
        self._closed_by_signal = False
        was_verify = self._pending_verify is not None
        if was_verify:
            d = self.panda.fastsnap_diff_pages()
            # The device oracle, read in the same breath as the RAM one. They
            # answer different questions and a scoped block needs both: the
            # fork reference cannot see a device section that was never
            # restored, only the guest damage it eventually causes -- which is
            # a slower, weaker and much later signal.
            try:
                dev_n = self.panda.fastsnap_dev_diff_sections()
                dev_unres = self.panda.fastsnap_dev_unrestorable_sections()
                dev_report = self.panda.fastsnap_dev_diff_report()
            except Exception as e:                          # noqa: BLE001
                dev_n, dev_unres, dev_report = -1, -1, repr(e)
            # HOW the oracle reached its answer, not only what it was. Pages
            # proven equal by PFN identity were never read; a clean result over
            # 281 MB means something different depending on the split, and a
            # verdict quoting bytes_checked alone hides it.
            try:
                proved = self.panda.fastsnap_diff_pages_proved()
                pmread = self.panda.fastsnap_diff_pages_read()
                pmstat = self.panda.fastsnap_diff_pagemap_status()
            except Exception:                               # noqa: BLE001
                proved, pmread, pmstat = 0, 0, None
            self.verifies.append({
                "iter": self._pending_verify,
                "diff_pages": d,
                "bytes_checked": self.panda.fastsnap_diff_bytes_checked(),
                "diff_us": self.panda.fastsnap_diff_us(),
                "pages_proved": proved,
                "pages_read": pmread,
                "pagemap_status": pmstat,
                "report": self.panda.fastsnap_diff_report() if d else "",
                "dev_diff_sections": dev_n,
                "dev_unrestorable_sections": dev_unres,
                "dev_diff_report": dev_report if (dev_n or dev_unres) else "",
            })
            if dev_n > 0:
                self.logger.error(
                    f"fastloop: DEVICE SCOPE TOO NARROW - iteration "
                    f"{self._pending_verify} left {dev_n} device sections "
                    f"outside the block and unrestored ({dev_report}). "
                    f"RAM can be byte-perfect and this still be wrong.")
            if dev_unres > 0:
                # Reported once per run, not per lap: it is a property of the
                # devices on this machine, not of the iteration, and it does
                # not change. Logging it every verification buried the scope
                # answer, which does.
                if not getattr(self, "_said_unrestorable", False):
                    self._said_unrestorable = True
                    self.logger.warning(
                        f"fastloop: {dev_unres} device sections are IN the "
                        f"block, are restored from it, and still do not "
                        f"serialise identically ({dev_report}). Widening the "
                        f"allowlist cannot fix this -- either the device's "
                        f"save reads state the restore does not own (a live "
                        f"clock, say), or its restore is broken. Not counted "
                        f"against the scope.")
            elif dev_n < 0:
                self.logger.warning(
                    f"fastloop: the device oracle could not compare at "
                    f"iteration {self._pending_verify}; a scoped block is "
                    f"unscored for this lap")
            if d < 0:
                self.logger.error(
                    f"fastloop: THE ORACLE IS BLIND - iteration "
                    f"{self._pending_verify} could not read the forked "
                    f"reference. Nothing about the reset follows from this "
                    f"lap, in either direction.")
            elif d > 0:
                self.logger.error(
                    f"fastloop: RESET IS NOT SOUND - iteration "
                    f"{self._pending_verify} left {d} pages differing from the "
                    f"forked reference (at {self.panda.fastsnap_diff_report()})")
            self._pending_verify = None

        dt = None    # None on the first lap: there is no interval yet
        if self.t_iter is not None:
            dt = (now - self.t_iter) * 1000.0
            # A verified lap carries the oracle's ~48 ms as well as the reset,
            # so it belongs in its own bucket. Folding it into iter_ms would
            # drag the median toward the cost of the instrument -- the same
            # mistake, one level up, that keeping diff_us out of last_us()
            # avoids inside QEMU.
            if was_verify:
                self.verify_iter_ms.append(dt)
            elif was_crash:
                # Separated because a crash-closed lap is a DIFFERENT
                # measurement, not an outlier to be smoothed away. Measured on
                # the first combined run: median lap 1.15 ms, mean 5.64 ms,
                # max 784 ms, and 533 crash-closed laps of 38,858 accounted for
                # very nearly all 220 s of wall clock. A single iter_ms bucket
                # hides that behind a healthy-looking median, and the median is
                # the number that gets quoted.
                self.crash_iter_ms.append(dt)
            else:
                self.iter_ms.append(dt)
                b = self._ab_bucket()
                if b is not None:
                    self.ab_ms[b].append(dt)
                    if b != "settle":
                        self._ab_cur["ms"].append(dt)
            # Every class, in order, including the verified and crash-closed
            # ones: which class lap 0 fell into is part of what is being asked.
            if len(self.first_laps_ms) < self.first_laps_max:
                self.first_laps_ms.append(
                    {"i": self.n_iters, "ms": round(dt, 4),
                     "class": ("verify" if was_verify
                               else "crash" if was_crash else "plain")})
        self.t_iter = now
        self.t_signal_mono = None
        self.n_iters += 1
        # AFTER the lap has been bucketed, so the lap that triggers a toggle
        # is still attributed to the phase it actually ran under.
        if not was_verify and not was_crash:
            self._ab_step(now)
        self.t_loopN = now
        if self._publish_lap and self.mode == "loop":
            self._lap_event(was_crash, was_verify)
        if not self._probe_done:
            self._probe(was_crash, dt)
        elif self.health_window and self.mode == "loop":
            self._health(was_crash, dt)
        if self.state != "loop":
            return
        if self.n_iters >= self.want:
            self.state = "done"
            self._lap_end()
            self.logger.info(f"fastloop: finished {self.n_iters} iterations")
            if self.mode != "bare":
                self.panda.fastsnap_schedule(self.panda.FASTSNAP_FORK_DROP)

    def _read_progress(self):
        """Sample the named counter, or None if it cannot be read.

        None is propagated, never coerced to 0: "the injector has not moved"
        and "I cannot see the injector" are different findings and only the
        first is evidence about the draw.
        """
        if not self.arm_progress:
            return None
        try:
            name, attr = self.arm_progress.split(".", 1)
            return int(getattr(getattr(plugins, name), attr))
        except Exception as e:                              # noqa: BLE001
            if "progress" not in " ".join(self.errors):
                self.errors.append(f"arm_progress {self.arm_progress!r}: {e!r}")
            return None

    def _cost_threshold(self, attempt=1):
        """What a draw's replayed lap may cost, from the forward distribution.

        Relative to a LOW percentile, because the distribution is not unimodal.
        On a 50/50 bimodal the median is the expensive mode, so scoring against
        the median would accept exactly the draw worth rejecting; p25 lands on
        the cheap mode whenever one exists.

        The ceiling RELAXES as the retry budget burns, by `arm_cost_relax` per
        attempt. This is not a nicety: an arming point is a moment in guest
        time, and a declined draw is gone -- there is no going back to it. So
        the axis is an online stopping problem, not a best-of-N. Held at a
        fixed ceiling, every attempt fails with the same probability and the
        run ends on whatever the LAST draw happens to be, which is a fresh
        random draw rather than a selected one.

        The widening is applied to the MULTIPLIER and deliberately not to the
        percentile, which is the obvious alternative and is wrong. On the
        measured bimodal, walking p25 -> p50 -> p75 steps straight across the
        gap between the modes: p50 x 3 is 683 ms and p75 x 3 is 1350 ms,
        either of which accepts the 450 ms mode outright. One attempt in and
        the axis would have given up while still reporting a ceiling. Widening
        the multiplier instead gives 16.5 -> 24.8 -> 37.1 -> 55.7 ms, which
        forgives a draw that is merely close and still refuses the expensive
        mode at every rung.

        None when there is not enough warmup data to say -- and None means the
        axis does not fire, never that the draw passed.
        """
        if (self.arm_cost_mult <= 0
                or len(self.warm_gaps_ms) < self.arm_cost_min_gaps):
            return None
        try:
            base = statistics.quantiles(self.warm_gaps_ms, n=100)[
                max(0, min(98, int(self.arm_cost_pctl) - 1))]
        except Exception:                                   # noqa: BLE001
            return None
        slack = min(self.arm_cost_relax ** max(0, attempt - 1),
                    self.arm_cost_relax_cap)
        return base * self.arm_cost_mult * slack

    def _costly(self, lap_med, thresh, attempt):
        """Is this draw too expensive to keep? Two independent reasons.

        Returns (costly, reason) -- reason is None, "absolute", "ratio", or
        "both", and it is recorded so a rejection can be read back.

        ABSOLUTE: the replayed lap against a ceiling built from the warmup
        distribution. Answers "is this span expensive?".

        RATIO: the replayed lap against THIS DRAW'S OWN forward traversal.
        Answers "did the reset change what this span does?" -- which is a
        different question, and the one the warmup ceiling cannot ask.

        The ratio axis exists because the population baseline turned out to be
        the wrong reference class twice over:

          - The arm does not sample the forward distribution uniformly. Target
            B armed twice, once with the cost axis off entirely, and both times
            replayed at ~6.2 ms against a forward MEDIAN of 182.8 ms -- landing
            on the p10 both times. Arming stops the vCPU for ~250 ms, so the
            first span after resume is a request that queued up while the guest
            was paused, not a fresh one.

          - The catastrophic case is invisible to an absolute ceiling built
            from a distribution the draw does not belong to. Target A armed on
            a span that traverses FORWARD in 3.79 ms and then replayed it in
            14,949 ms -- flat to 0.3% across sixteen laps, which is a timeout
            firing and not a workload. A per-draw ratio sees 3,945x. The
            population ceiling saw a lap in a run it had no reference for.

        Same span, same arm, same guest state, one traversal each way: the
        ratio is the only form of this comparison not confounded by comparing
        two different spans.
        """
        if lap_med is None:
            return False, None
        absolute = thresh is not None and lap_med > thresh
        ratio = (self.arm_cost_fwd_mult > 0
                 and self._fwd_this_arm is not None
                 and self._fwd_this_arm > 0
                 and lap_med > self._fwd_this_arm * self.arm_cost_fwd_mult
                 * min(self.arm_cost_relax ** max(0, attempt - 1),
                       self.arm_cost_relax_cap))
        why = ("both" if absolute and ratio
               else "absolute" if absolute
               else "ratio" if ratio else None)
        return (absolute or ratio), why

    def _unfaithful(self, lap_med, attempt):
        """Does this draw replay far FASTER than the span it armed on?

        The mirror of the cost axis's ratio test, against sample 1 rather than
        the median -- sample 1 is the armed span's own traversal and the only
        one that starts where the replayed laps start.

        A replay that beats its forward pass by more than `arm_fidelity_mult`
        is not a fast span; it is a span whose wait has already been waited.
        Rejecting it costs one draw. Keeping it costs a headline number that
        means nothing, which is the more expensive of the two and the harder
        to notice later.

        Relaxes on the same ladder as the cost axis so the search terminates.
        """
        if (self.arm_fidelity_mult <= 0 or lap_med is None or lap_med <= 0
                or self._fwd1_this_arm is None or self._fwd1_this_arm <= 0):
            return False
        slack = min(self.arm_cost_relax ** max(0, attempt - 1),
                    self.arm_cost_relax_cap)
        return lap_med * self.arm_fidelity_mult * slack < self._fwd1_this_arm

    def _cost_rearm(self, lap_med, thresh, n_laps, early):
        """Drop this draw and go back for another, on the cost axis.

        Shared by the two places the axis fires: the full probe, and the
        early short-circuit in _probe() that does not wait for it.

        Deliberately does NOT touch arm_cost_rejects. That counter means
        "draws seen over the ceiling" -- the full path increments it before it
        knows whether it will re-arm or accept out of retries -- so counting
        here too would double every rejection.
        """
        over = (f"{lap_med / thresh:.0f}x over" if thresh else "over")
        when = (f"after {n_laps} of {self.arm_probe} probe laps -- the draw is "
                f"already {over} and waiting out the probe would cost "
                f"{(self.arm_probe - n_laps) * lap_med / 1000:.0f} s"
                if early else f"over {n_laps} probe laps")
        # thresh is None when the axis fired on the RATIO alone, which needs no
        # warmup distribution at all.
        against = (f"a {thresh:.2f} ms ceiling ("
                   f"{self.arm_cost_mult * self.arm_cost_relax ** (self.arm_attempt - 1):.1f}x "
                   f"the {self.arm_cost_pctl:.0f}th percentile of "
                   f"{len(self.warm_gaps_ms)} forward gaps)"
                   if thresh is not None else
                   f"its own forward traversal of "
                   f"{self._fwd_this_arm:.2f} ms (no warmup ceiling yet)")
        self.logger.warning(
            f"fastloop: arm {self.arm_attempt} REJECTED on COST {when} -- the "
            f"probe replays a {lap_med:.2f} ms span, against {against}. The "
            f"span is chosen by WHERE the arm landed, and on a real image "
            f"the cheap and expensive modes differ by a factor of eighty. "
            f"Drawing again, against a ceiling widened by "
            f"{self.arm_cost_relax}x.")
        self._reset_measurements()
        self._rearm_at = time.perf_counter() + self.arm_backoff_s
        self.state = "rearm_wait"
        self.pending_reset = False
        self._pending_verify = None
        self._closed_by_signal = False

    def _probe(self, was_crash, dt=None):
        """Score the draw over its first `arm_probe` laps.

        Three axes now. The first two -- faulting and idle -- ask whether the
        draw is BROKEN, and a run that only has broken draws is not worth
        reporting, so they refuse. The third asks whether it is SLOW, and a
        slow draw is perfectly valid: it just replays an expensive span. That
        difference is why exhausting the retries on cost ACCEPTS rather than
        refusing the run.

        What it accepts is the LAST draw, not the cheapest one seen. It cannot
        be the cheapest: an arming point is a moment in guest time and a
        declined draw is gone. The ceiling relaxes per attempt precisely
        because of that -- see _cost_threshold().
        """
        if self._probe_n == 0:
            self._progress0 = self._read_progress()
        self._probe_n += 1
        if was_crash:
            self._probe_sig += 1
        if dt is not None:
            self._probe_laps_ms.append(dt)
        if self._probe_n < self.arm_probe:
            # The cost axis on a TIME budget rather than a lap count. Scoring
            # over a fixed `arm_probe` laps makes the axis slowest exactly
            # where it matters most: a 6 ms draw is judged in 1.2 s, while a
            # 2,625 ms draw needs 200 laps = 8.75 MINUTES to reach the same
            # verdict -- and a run that ends before then reports the
            # catastrophic draw with the axis never having fired at all.
            #
            # That is measured, not hypothetical. Target A's first cost=on arm
            # replayed 2,625 ms laps against a 9.4 ms ceiling and finished with
            # arm_cost_rejects = 0, because it only ever completed 102 of the
            # 200 laps the axis was waiting for.
            #
            # A draw this far over needs no further evidence, and a rejected
            # draw costs nothing but a re-arm. So fire early -- but only with a
            # retry left to spend, because the out-of-retries branch ACCEPTS
            # and the other two axes still deserve their full sample before a
            # draw is kept.
            if (self.arm_attempt < self.arm_retries
                    and len(self._probe_laps_ms) >= self.arm_cost_min_laps):
                thresh = self._cost_threshold(self.arm_attempt)
                lap_med = statistics.median(self._probe_laps_ms)
                early_costly, why = self._costly(lap_med, thresh,
                                                 self.arm_attempt)
                if early_costly:
                    self.arm_history.append(
                        {"attempt": self.arm_attempt, "armed_at_s": self.t_arm_s,
                         "probe_laps": self._probe_n,
                         "probe_signal_laps": self._probe_sig,
                         "probe_lap_median_ms": round(lap_med, 4),
                         # None when the axis fired on the RATIO alone: the
                         # absolute ceiling needs arm_cost_min_gaps of warmup
                         # and the ratio needs none, so "costly" does not
                         # imply a ceiling exists. Rounding it unguarded threw
                         # TypeError straight into the handler that swallows
                         # state-machine bugs and ends the run.
                         "cost_threshold_ms": (None if thresh is None
                                               else round(thresh, 4)),
                         "warmup_gaps": len(self.warm_gaps_ms),
                         "forward_ms": (None if self._fwd_this_arm is None
                                        else round(self._fwd_this_arm, 4)),
                         "cost_reason": why,
                         "verdict": "costly, re-arming (early)"})
                    self.arm_cost_rejects += 1
                    self._cost_rearm(lap_med, thresh, self._probe_n, early=True)
            return
        self._probe_done = True
        frac = self._probe_sig / self._probe_n
        now_p = self._read_progress()
        delta = (None if (now_p is None or self._progress0 is None)
                 else now_p - self._progress0)
        need = self.arm_progress_frac * self._probe_n
        row = {"attempt": self.arm_attempt, "armed_at_s": self.t_arm_s,
               "probe_laps": self._probe_n, "probe_signal_laps": self._probe_sig,
               "signal_fraction": round(frac, 4),
               "progress_counter": self.arm_progress,
               "progress_delta": delta, "progress_needed": need}
        idle = delta is not None and delta < need
        # The cost axis. Median, not mean: a draw whose replayed span is cheap
        # can still show the occasional long lap, and one outlier must not
        # reject a good draw.
        lap_med = (statistics.median(self._probe_laps_ms)
                   if self._probe_laps_ms else None)
        thresh = self._cost_threshold(self.arm_attempt)
        costly, why = self._costly(lap_med, thresh, self.arm_attempt)
        unfaithful = self._unfaithful(lap_med, self.arm_attempt)
        row["cost_reason"] = why
        row["probe_lap_median_ms"] = (round(lap_med, 4)
                                      if lap_med is not None else None)
        row["cost_threshold_ms"] = round(thresh, 4) if thresh is not None else None
        row["warmup_gaps"] = len(self.warm_gaps_ms)
        row["forward_ms"] = (None if self._fwd_this_arm is None
                             else round(self._fwd_this_arm, 4))
        if idle:
            self.logger.warning(
                f"fastloop: arm {self.arm_attempt} made no work -- "
                f"{self.arm_progress} advanced by {delta} over "
                f"{self._probe_n} probe laps, needing {need:.0f}. The span "
                f"this draw replays does not reach the injector, so the loop "
                f"would reset a guest that is not being fuzzed and report an "
                f"excellent rate for it.")
        elif delta is None and self.arm_progress:
            # FATAL, where this warned. The caller asked for the progress
            # check, and a run that quietly proceeds without it is exactly the
            # run this whole mechanism exists to prevent -- an idle draw
            # reporting 3,396 exec/s with nothing being injected. An inert
            # check is worse than no check, because it reads as one.
            #
            # (It was inert on its first run: the registry key is the plugin's
            # FILE name, so `bug_bench.n_sent` -- the logger's name for the
            # class -- resolved to nothing and the draw was scored on the
            # signal fraction alone.)
            self.logger.error(
                f"fastloop: REFUSING THE RUN - arm_progress "
                f"{self.arm_progress!r} could not be read, so a draw that "
                f"delivers no input would pass the probe. Name it as "
                f"<plugin-file-name>.<attribute>.")
            self.errors.append(f"arm_progress unreadable: {self.arm_progress!r}")
            row["verdict"] = "refused, progress counter unreadable"
            self.arm_history.append(row)
            self._reset_measurements()
            self.state = "done"
            return
        if frac <= self.arm_bad_frac and not idle and not costly and unfaithful:
            row["verdict"] = ("unfaithful, out of retries -- accepted anyway"
                              if self.arm_attempt >= self.arm_retries
                              else "unfaithful, re-arming")
            row["fwd1_ms"] = round(self._fwd1_this_arm, 4)
            self.arm_history.append(row)
            if self.arm_attempt >= self.arm_retries:
                self.logger.warning(
                    f"fastloop: arm {self.arm_attempt} replays in "
                    f"{lap_med:.2f} ms a span that traverses FORWARD in "
                    f"{self._fwd1_this_arm:.2f} ms -- "
                    f"{self._fwd1_this_arm / lap_med:.0f}x faster -- and there "
                    f"are no retries left. Accepting it, because refusing "
                    f"would throw away a working reset over a badly chosen "
                    f"instant, but the rate below is NOT a rate for this span: "
                    f"whatever the forward pass waited for had already arrived "
                    f"by the time it was replayed. See replay_fidelity.")
                return
            self.logger.warning(
                f"fastloop: arm {self.arm_attempt} REJECTED on FIDELITY -- the "
                f"draw replays in {lap_med:.2f} ms a span that traverses "
                f"forward in {self._fwd1_this_arm:.2f} ms, "
                f"{self._fwd1_this_arm / lap_med:.0f}x faster. The span "
                f"contains a wait the replay never pays, so its rate would be "
                f"a number for a span nobody ran. Drawing again.")
            self._reset_measurements()
            self._rearm_at = time.perf_counter() + self.arm_backoff_s
            self.state = "rearm_wait"
            return
        if frac <= self.arm_bad_frac and not idle and not costly:
            row["verdict"] = "accepted"
            self.arm_history.append(row)
            self.logger.info(
                f"fastloop: arm {self.arm_attempt} accepted -- "
                f"{self._probe_sig}/{self._probe_n} probe laps closed on a "
                f"fatal signal ({frac:.1%})"
                + ("" if lap_med is None or thresh is None else
                   f", probe lap {lap_med:.2f} ms against a "
                   f"{thresh:.2f} ms ceiling"))
            return

        # A COSTLY-ONLY draw is not a broken one, and the difference decides
        # what happens when the retries run out. A faulting or idle draw makes
        # the run's numbers meaningless, so those refuse. A costly draw is
        # perfectly valid -- it replays an expensive span and reports an honest,
        # low rate -- so running out of retries here keeps the draw rather than
        # throwing away a usable measurement.
        if costly and frac <= self.arm_bad_frac and not idle:
            self.arm_cost_rejects += 1
            if self.arm_attempt >= self.arm_retries:
                row["verdict"] = "costly, out of retries -- accepted anyway"
                self.arm_history.append(row)
                self.logger.warning(
                    f"fastloop: arm {self.arm_attempt} replays a "
                    f"{lap_med:.2f} ms span against a {thresh:.2f} ms ceiling, "
                    f"and there are no retries left. ACCEPTING it: a costly "
                    f"draw is a valid measurement of an expensive span, not a "
                    f"broken one. The rate below is real and low. Note this is "
                    f"the LAST draw, not the cheapest of the "
                    f"{self.arm_attempt} -- a declined arming point cannot be "
                    f"returned to -- so read it as an unselected sample.")
                return
            row["verdict"] = "costly, re-arming"
            self.arm_history.append(row)
            self._cost_rearm(lap_med, thresh, self._probe_n, early=False)
            return
        if self.arm_attempt >= self.arm_retries:
            row["verdict"] = ("idle, out of retries" if idle
                              else "rejected, out of retries")
            self.arm_history.append(row)
            self.arm_gave_up = True
            # Discarded here too, and for a sharper reason than on a retry: a
            # refused run that still carries an exec_per_s_median is one grep
            # away from being quoted, and the verdict beside it will not
            # travel with the number.
            self._reset_measurements()
            self.logger.error(
                f"fastloop: {self.arm_attempt} draws in a row were "
                f"unusable (last: {frac:.1%} of probe laps on a fatal signal, "
                f"progress {delta}). Not reporting a rate for this: the reset "
                f"is fine and the instant it restores is not.")
            self.errors.append(
                f"every arm ({self.arm_attempt}) landed on a broken victim")
            self.state = "done"
            return
        row["verdict"] = "idle, re-arming" if idle else "rejected, re-arming"
        self.arm_history.append(row)
        self.logger.warning(
            f"fastloop: arm {self.arm_attempt} REJECTED -- "
            + (f"the draw is idle (progress {delta} < {need:.0f})."
               if idle else
               f"{self._probe_sig} of {self._probe_n} probe laps closed on a "
               f"fatal signal ({frac:.1%}). This draw armed on a victim that "
               f"was already broken, so every lap rewinds to it.")
            + f" Backing off "
            f"{self.arm_backoff_s}s to let the guest restart it, then drawing "
            f"again. Everything measured from this draw is discarded.")
        self._reset_measurements()
        self._rearm_at = time.perf_counter() + self.arm_backoff_s
        self.state = "rearm_wait"
        self.pending_reset = False
        self._pending_verify = None
        self._closed_by_signal = False

    def _health(self, was_crash, dt=None):
        """Re-ask the probe's question on a rolling window, for the whole run.

        WHAT A MID-RUN CHANGE MEANS, and it is not what a bad draw means.
        Every lap rewinds to the same instant, so lap 100,000 has to behave
        like lap 1. If it does not, something survived the reset -- state that
        accumulated across laps and was never rewound. A degradation that only
        appears after a long run is therefore evidence about the SCOPE of the
        restore, which is the one question this harness exists to answer, and
        it is precisely the evidence a first-200-laps probe cannot collect.
        (`cpu_common` is a known real scope miss on this target; this is the
        instrument that would find the next one.)

        Both halves of the probe's two-sided test, for the same reason it is
        two-sided: "every lap faults" and "nothing is being injected any more"
        are both ways for the loop to stop measuring what it says it measures,
        and optimising against only the first produced an arm that delivered
        no input at all.

        On a breach the run STOPS and says where. Re-arming would discard the
        finding along with the laps; continuing would average the degraded
        span into the rate. The laps before it are kept: they were measured
        while the window was still under threshold.
        """
        if self._hw_n == 0:
            self._hw_progress0 = self._read_progress()
        self._hw_n += 1
        if was_crash:
            self._hw_sig += 1
        if dt is not None:
            self._hw_ms += dt
            if was_crash:
                self._hw_ms_sig += dt
        if self._hw_n < self.health_window:
            return
        self._hot_class()
        frac = self._hw_sig / self._hw_n
        now_p = self._read_progress()
        delta = (None if (now_p is None or self._hw_progress0 is None)
                 else now_p - self._hw_progress0)
        need = self.arm_progress_frac * self._hw_n
        idle = delta is not None and delta < need
        if frac <= self.arm_bad_frac and not idle:
            self._hw_n = self._hw_sig = 0
            self._hw_ms = self._hw_ms_sig = 0.0
            self._hw_progress0 = None
            return
        self.degraded.append({
            "at_iteration": self.n_iters,
            "window": self._hw_n,
            "signal_laps": self._hw_sig,
            "signal_fraction": round(frac, 4),
            "progress_delta": delta,
            "progress_needed": need,
            "why": "idle" if idle else "faulting",
        })
        self.logger.error(
            f"fastloop: THE LOOP DEGRADED AT ITERATION {self.n_iters}, having "
            f"passed its arming probe. Over the last {self._hw_n} laps "
            + (f"{self.arm_progress} advanced by {delta}, needing "
               f"{need:.0f}: the injector has stopped being reached."
               if idle else
               f"{self._hw_sig} ({frac:.1%}) closed on a fatal signal.")
            + " Every lap rewinds to the same instant, so a lap that behaves "
              "differently from lap 1 means something survived the reset. "
              "Stopping here: the laps before this were measured under a "
              "healthy loop and are kept, the rest of the run would not have "
              "been.")
        self.errors.append(
            f"degraded at iteration {self.n_iters} "
            f"({'idle' if idle else f'{frac:.1%} faulting'})")
        self.state = "done"
        self._lap_end()

    def _hot_class(self):
        """Say it mid-run when crash laps are eating the clock. Once.

        THE SIGNATURE THIS IS FOR. Replaying the archive through the wall
        attribution: run 30 closed 4.7% of its laps on a fault and spent 82%
        of its wall clock on them, and every run in the 39-52 population spent
        51-77%. The cause was host-side -- crashes.py re-serialising a growing
        YAML report inside the vCPU thread -- and its cost grew with the
        record count, so it was invisible early and dominant late. None of
        those runs said anything: the lap-fraction test passes (4.7% is a
        HEALTHY crash rate) and the median lap was 0.51 ms throughout.

        So the test is on time, not on count, and it requires the class to be
        a MINORITY of the laps -- a target that genuinely crashes on most
        inputs is not sick, it is a target that crashes.
        """
        if self.hot_class is not None or self._hw_ms <= 0:
            return
        ms_share = self._hw_ms_sig / self._hw_ms
        lap_share = self._hw_sig / self._hw_n
        if ms_share < self.health_time_frac or lap_share > ms_share / 2.0:
            return
        self.hot_class = {"class": "crash", "at_iteration": self.n_iters,
                          "window": self._hw_n, "wall_share": round(ms_share, 4),
                          "lap_share": round(lap_share, 4)}
        self.logger.warning(
            f"fastloop: crash laps are {lap_share:.1%} of the last "
            f"{self._hw_n} laps and {ms_share:.0%} of their wall clock "
            f"(iteration {self.n_iters}). A cost that concentrates like that "
            f"scales with something other than the loop -- host-side work "
            f"whose price grows with the run, done on the vCPU thread. The "
            f"resets are unaffected and the run continues; the rate it "
            f"reports is not the loop's.")

    def _reset_measurements(self):
        """Throw away everything the rejected draw measured.

        Not optional and not tidiness: a rejected draw contributes thousands of
        laps at 5-7 ms, and left in the buckets they would drag the median of
        the accepted draw toward a configuration that was explicitly refused.
        The history row keeps the fact that it happened.
        """
        for name in ("iter_ms", "crash_iter_ms", "verify_iter_ms",
                     "bh_wall_ms", "bh_wall_crash_ms", "sched_ms", "obs_ms",
                     "sched_crash_ms", "obs_crash_ms", "sched_verify_ms",
                     "obs_verify_ms", "crash_to_sig_ms", "crash_after_sig_ms",
                     "reset_us", "restored", "verifies", "page_obs",
                     "degraded"):
            getattr(self, name).clear()
        self.n_iters = 0
        self.signal_laps = 0
        self._hw_n = self._hw_sig = 0
        self._hw_ms = self._hw_ms_sig = 0.0
        self._hw_progress0 = None
        self.t_iter = None
        self.t_loop0 = None
        self.t_loopN = None
        self.t_signal_mono = None
        self.split_diff = None
        # The next draw is a different span and needs its own forward
        # traversal. Keeping the rejected draw's would score the new one
        # against a baseline measured somewhere else entirely.
        self._fwd_this_arm = None
        self._fwd_samples = []
        # The next draw arms in its own process; counting this draw's
        # cross-process hits against it would describe the wrong span.
        self.hits_other_proc = 0
        self._arm_ident = None

    def _lap_event(self, was_crash, was_verify):
        """Announce the iteration boundary, which is the only per-input seam.

        THE SCOPE PROBLEM THIS EXISTS FOR. In a normal run a plugin's state is
        run-scoped and that is correct: there is one execution and everything
        accumulates into it. A snapshot loop is not that. Each lap is an
        INDEPENDENT execution of the same instant with a different input, so
        state a plugin would naturally accumulate -- a crash table, a counter,
        a file map -- belongs to one input, and no plugin can tell where one
        input ends and the next begins. Only the loop knows, because only the
        loop performs the rewind.

        `lap` is the index of the iteration NOW STARTING, deliberately, so a
        subscriber can stamp it onto whatever it records without arithmetic.
        `closed_by` says why the previous one ended: "signal" (the victim
        faulted), "verify" (the oracle ran, so the lap carries ~48 ms that is
        the instrument's and not the guest's), or "hit".

        NOT `reset_state()`, and the difference is the point. plugin_manager
        documents that hook for restore-many and crashes.py implements it as a
        rewind, on the reasoning that repeated restores would "accumulate
        across iterations that the guest never actually executed". That is
        true of a replay, where every lap is the same execution. It is false
        here: every lap really does execute, with a different input, so a
        count of 4,343 is 4,343 inputs reaching one crash site and rewinding
        it would destroy the campaign's only real result. What this mode needs
        is not a rewind but an attribution, and attribution needs a boundary.

        Published in mode=loop only. bare and armed never reset, so their laps
        are not independent executions and announcing them as such would
        invite exactly the mis-scoping this is meant to fix.
        """
        # The lap's coverage, or (None, None) when there is none to give.
        # THE NONE IS LOAD-BEARING. A subscriber building a corpus needs to
        # tell "coverage is on and this input found nothing" from "coverage
        # is off, so nothing here can ever be new" -- the two produce an
        # identical empty corpus, and only the second is a misconfiguration.
        # Reporting 0 for both would make that indistinguishable.
        new_edges = lap_edges = None
        if self._cov_fresh:
            new_edges = self.cov_new[-1] if self.cov_new else None
            lap_edges = self.cov_edges[-1] if self.cov_edges else None
            self._cov_fresh = False
        try:
            plugins.publish(self, "on_lap", self.n_iters,
                            "signal" if was_crash
                            else ("verify" if was_verify else "hit"),
                            new_edges, lap_edges)
            self._lap_ever = True
        except Exception as e:                              # noqa: BLE001
            # Disabled after the first failure rather than retried. This runs
            # on the vCPU thread inside the loop: a subscriber that raises
            # every lap would pay the exception on every one of them, and a
            # measurement harness that quietly got slower in its own error
            # path is worse than one that stops publishing and says so.
            self._publish_lap = False
            self.logger.error(
                f"fastloop: on_lap publish failed ({e!r}); no further lap "
                f"boundaries will be announced. Anything scoping itself per "
                f"input is now silently run-scoped.")
            self.errors.append(f"on_lap publish failed: {e!r}")

    def _lap_end(self):
        """Announce that there are no more laps.

        WITHOUT THIS THE LAST LAP NEVER ENDS. The guest keeps running after the
        loop stops -- run 55 delivered 287,000 inputs against 200,000 laps --
        and a subscriber holding the final lap index would go on stamping the
        tail with it and calling the join exact. It would not be exact: with
        nothing rewinding the guest there are no independent executions left to
        scope to, so the honest answer for the tail is the same `None` the
        subscriber started with, which sends it back to whatever join it uses
        when no loop is present.

        Published once, and only if the loop actually announced laps.
        """
        if not self._publish_lap or self.mode != "loop" or not self._lap_ever:
            return
        self._publish_lap = False
        try:
            plugins.publish(self, "on_lap", None, "end", None, None)
        except Exception as e:                              # noqa: BLE001
            self.logger.warning(f"fastloop: on_lap end publish failed ({e!r})")

    def _wall_attribution(self, span):
        """Where the wall clock went, by lap class, as a share of the span.

        The three lap buckets are disjoint, so this is arithmetic rather than
        an estimate, and it is here because the two numbers needed to see the
        largest win of this lane were both already in this report and neither
        was read. `exec_per_s_median` said 1,876 for a run whose loop really
        turned over 543 times a second. The comment on `crash_iter_ms` said,
        in this file, that crash laps "accounted for very nearly all 220 s of
        wall clock". The verdict went on quoting the median for weeks.

        A share is not a new measurement -- it is the division nobody was
        going to do by hand. `unaccounted` is the part of the span that is in
        no bucket at all: the arming draws, the gaps where the detector never
        fired, and anything that happened between laps.
        """
        if not span or span <= 0:
            return None
        classes = {
            "plain": self.iter_ms,
            "crash": self.crash_iter_ms,
            "verify": self.verify_iter_ms,
        }
        out = {}
        total_ms = 0.0
        for name, bucket in classes.items():
            ms = float(sum(bucket))
            total_ms += ms
            out[name] = {
                "laps": len(bucket),
                "lap_share": (len(bucket) / self.n_iters) if self.n_iters else None,
                "wall_s": ms / 1000.0,
                "wall_share": ms / 1000.0 / span,
            }
        out["unaccounted"] = {
            "laps": None,
            "lap_share": None,
            "wall_s": span - total_ms / 1000.0,
            "wall_share": (span - total_ms / 1000.0) / span,
        }
        return out

    def _proc_note(self, out):
        """Did the loop stay in the process it armed in?

        The detector is filtered on `comm`, and a comm is not an identity.
        lighttpd forks workers that all carry the name; a victim that dies and
        restarts under reset_on_signal comes back with the same name and a new
        pid. If the armed instant is in one process and the hits that close the
        laps are in another, the lap is not an iteration of the armed span --
        it is the interval between two unrelated processes' syscalls, and the
        rate computed from it is not a rate for anything.

        Silent when the driver does not report pid: "cannot say" is not
        "clean", but it is also not a finding, and inventing one here would be
        the same mistake as reading a missing counter as a zero.
        """
        if not self.hit_procs:
            return None
        n = self.n_iters or 1
        other = self.hits_other_proc
        if other == 0:
            return None
        frac = other / n
        ids = sorted(self.hit_procs.items(), key=lambda kv: -kv[1])[:3]
        shown = ", ".join(f"pid {k[0]}x{v}" for k, v in ids)
        return (
            f"DETECTOR CROSSED PROCESSES: {other} of {n} laps "
            f"({frac:.1%}) closed on a hit from a process other than the one "
            f"the arm landed in ({len(self.hit_procs)} distinct: {shown}). "
            f"`comm` is a name, not an identity -- a forked worker or a "
            f"restarted victim carries the same one. Those laps are the "
            f"interval between two processes' syscalls, not iterations of the "
            f"armed span.")

    def _replay_fidelity(self, out):
        """Does the loop replay the span it armed on, or a different one?

        The oracle proves the guest STATE is restored byte for byte. It cannot
        prove the guest's WORLD is: the host-side socket, the virtio queue and
        anything else the guest talks to sit outside the snapshot and are not
        rewound. So a replay can diverge from the forward traversal in either
        direction, and both were measured on real firmware:

          target A   forward     3.79 ms -> replayed 14,949 ms   (3,945x SLOWER)
          target B   forward   476.59 ms -> replayed      6.28 ms   (76x FASTER)

        Same arming point in each case, same run, and the oracle certified the
        restore in both -- target B's across 2.16 GB, byte-identical, ten
        times. That is precisely why the divergence has to come from outside
        the guest state. The leading account is that A's input was consumed
        and is never redelivered, so the guest waits on a timer for data that
        will not arrive again, while B's arrived DURING the forward traversal
        and is still queued at replay, so the guest never waits at all.

        The two directions need different handling, which is why this is a
        report rather than another re-arm:

          SLOWER  a different draw may not depend on fresh input, so the cost
                  axis re-arms on it.
          FASTER  re-arming cannot help, because the mechanism is structural --
                  every draw on target B replays at ~6.2 ms. What it can do is
                  refuse to let the rate be quoted as if it were real.

        A rate taken from a faster-than-forward replay is the same failure the
        idle axis exists to prevent -- an excellent number for a guest that is
        not doing the work -- arriving through a different door.
        """
        # THE ARMED SPAN'S OWN FORWARD TRAVERSAL IS SAMPLE ONE, and only
        # sample one.
        #
        # `arm_forward_samples` are five CONSECUTIVE, DIFFERENT spans, not
        # five measurements of one: `fwd_probe` starts its clock at the armed
        # instant and the next detector hit closes sample 1; sample 2 is that
        # hit to the next, and so on. Only sample 1 begins where every
        # replayed lap begins, so only sample 1 is the controlled comparison
        # -- same starting state, one traversal without a reset against many
        # with one. Samples 2-5 start from states the loop never visits.
        #
        # Scoring against their MEDIAN was wrong in a way that mattered. On a
        # workload that alternates between serving a pipelined request (~3 ms)
        # and waiting out a connection boundary (~1050 ms), a draw that armed
        # on the cheap mode reads:
        #
        #   run 88  sample 1 2.39 ms, lap 3.30 ms  -- ratio 1.38 FAITHFUL
        #           median 1051.94 ms              -- ratio 0.003 "diverged"
        #
        # and the median verdict was used, in this lane's own notes, to
        # retract a rate that was real. It does not uniformly flatter either:
        # run 91's sample 1 is 1052.01 ms against a 4.97 ms lap, which is a
        # genuine 209x divergence by both references.
        #
        # The median stays as `forward_ms` because the COST axis wants a
        # robust local estimate for its ceiling, and rejecting a draw is an
        # action with a cost. Reporting is not, so reporting uses the span
        # the run actually replays.
        # ...and it is the LAST arm's sample 1, not the first arm's.
        #
        # `arm_forward_samples` gets one entry per ARM ATTEMPT, and only the
        # final attempt is the one the loop actually ran on. Indexing [0] reads
        # the span of a draw that was measured and then thrown away. Run 107
        # is the demonstration: attempt 1 was rejected on fidelity at 10186.84
        # ms, attempt 2 accepted at 2.5746 ms, and the lap was 3.4518 ms.
        # Against the accepted draw that is 1.341, faithful. Against the
        # rejected one it is 0.0003, and the run was labelled NOT A RATE --
        # by the very check that had correctly rejected the draw it was then
        # scoring against.
        #
        # `arm_forward_ms` had the same shape and predates this: it was
        # assigned `if self.arm_forward_ms is None`, so it froze on attempt 1
        # for the life of the run. Every multi-attempt run has been reporting
        # a forward baseline from a draw it did not use.
        samples = (self.arm_forward_samples[-1]
                   if self.arm_forward_samples else None)
        fwd = samples[0] if samples else self.arm_forward_ms
        it = out.get("iter_ms") or {}
        lap = it.get("median")
        if not fwd or not lap or fwd <= 0 or lap <= 0:
            return None
        # WHICH forward cost is this lap supposed to match?
        #
        # The baseline is the median of the draw's forward samples, and on a
        # bimodal workload the median is a value the span never actually
        # takes. Target A, one draw, five samples:
        #
        #   [10189.65, 2.36, 10214.19, 3.31, 10225.93]
        #
        # The victim alternates between serving a request on a live
        # connection (2-3 ms) and waiting out a dead one (10.2 s). The median
        # picks the waiting mode; a replayed lap of 3.32 ms then scores 0.0003
        # and is called a 3,000x divergence, when it is an exact match for the
        # serving mode sitting in the same list. Both the "divergence" and the
        # size of it would be artifacts of summarising two behaviours as one.
        #
        # So when the samples are clearly bimodal -- a gap of `spread_bound`
        # or more between adjacent sorted samples -- score against the mode
        # the lap actually matches, and SAY which one and what the other was.
        # The alternative readings stay visible; what changes is that the
        # number is quoted against a cost the span is observed to have.
        #
        # This is not licence to shop for a flattering baseline. It applies
        # only to a genuine gap, it reports both modes and the matched one
        # every time, and with unimodal samples nothing changes at all.
        modes = self._forward_modes()
        matched = None
        if modes:
            lo, hi = modes
            # Closest by RATIO, not by difference: a difference would say so
            # only by accident of scale. max(a/b, b/a) is the symmetric ratio
            # distance -- the same ordering abs(log(a/b)) gives, without
            # importing math for it. (penguin's loader admits a fixed set of
            # imports and drops the rest silently, so a new one is a
            # NameError that surfaces only under test.)
            fold = lambda a, b: a / b if a > b else b / a       # noqa: E731
            matched = "low" if fold(lap, lo) <= fold(lap, hi) else "high"
        # THE CLASS IS STILL SCORED AGAINST THE MEDIAN, deliberately.
        #
        # It is tempting to score against the matched mode instead: on a
        # bimodal draw the median is a cost the span never actually takes, and
        # a lap that sits on the low mode then reads as a 3,000x divergence
        # when it is an exact match for a value in the same list.
        #
        # The reason not to is that the two explanations are observationally
        # identical here. A cheap forward sample can mean the workload really
        # has a cheap mode -- or it can be the arming pause: the vCPU is
        # stopped for ~250 ms, so the first span after resume serves a request
        # that queued up during the stop rather than a fresh one. Run 88's
        # samples were [2.39, 1073.13, 1047.99, 1051.94, 1054.88], cheap
        # sample FIRST, which is exactly that signature. Scoring against the
        # low mode would have called that run faithful and quietly restored
        # the 303 exec/s this lane has already retracted once.
        #
        # So: report the modes, report which one the lap matches, keep the
        # conservative class, and name the measurement that WOULD separate
        # them -- the warmup gap distribution, which is sampled with no
        # arming pause anywhere near it. If the matched mode agrees with the
        # warmup gaps, the cheap mode is the workload; if only the arming
        # samples are ever cheap, it is the pause.
        ratio = lap / fwd
        # How stable was the baseline this ratio is quoted against? Target A
        # returned forward samples of [1062, 2.8, 2.3, 1047, 1072] within a
        # SINGLE draw -- a 470x spread. The median of that is the right
        # summary and is still not a stable quantity, so a ratio against it
        # deserves to be read with that attached rather than to three decimal
        # places.
        spread = None
        if self.arm_forward_samples and self.arm_forward_samples[0]:
            lo = min(self.arm_forward_samples[0])
            hi = max(self.arm_forward_samples[0])
            if lo > 0:
                spread = hi / lo
        # A SEPARATE bound from the cost axis's, and deliberately tighter.
        #
        # Reusing arm_cost_fwd_mult (10x) called target C's run FAITHFUL at
        # 8.03x -- a replay eight times its own forward traversal, reported as
        # clean because it sat under a threshold chosen for a different job.
        # Rejecting a draw is an action with a cost, so that one stays
        # conservative; SAYING a replay diverged costs nothing but ink, so it
        # fires where the evidence does. One forward sample against a median
        # of many laps can carry a factor of two or so honestly; it cannot
        # carry eight.
        k = self.fidelity_bound
        row = {"forward_ms": round(fwd, 4),
               "forward_ms_note": ("the armed span's own traversal (sample 1);"
                                   " samples 2-5 start from states the loop "
                                   "never visits"),
               "forward_median_ms": (round(self.arm_forward_ms, 4)
                                     if self.arm_forward_ms else None),
               "lap_ms": round(lap, 4),
               "ratio": round(ratio, 6), "bound": k,
               "forward_spread": (None if spread is None else round(spread, 1)),
               "forward_modes": ([round(modes[0], 4), round(modes[1], 4)]
                                 if modes else None),
               "matched_mode": matched,
               "matched_mode_ms": (round(modes[0 if matched == "low" else 1],
                                         4) if modes else None),
               "ratio_vs_matched": (
                   round(lap / modes[0 if matched == "low" else 1], 6)
                   if modes else None),
               "warm_gaps_p10_ms": self._warm_p10()}
        if modes:
            wp10 = self._warm_p10()
            m_ms = modes[0 if matched == "low" else 1]
            agrees = (wp10 is not None and m_ms > 0
                      and max(wp10 / m_ms, m_ms / wp10) < k)
            caveat_mode = (
                f" The forward samples are BIMODAL at {modes[0]:.2f} ms and "
                f"{modes[1]:.2f} ms ({self.arm_forward_samples[0]}), and the "
                f"replayed lap matches the {matched} mode "
                f"({m_ms:.2f} ms, ratio {lap / m_ms:.3f}). The ratio above "
                f"is quoted against sample 1 -- the armed span's own forward "
                f"traversal, the only one that starts where the replayed laps "
                f"start. Read the modes as what the workload alternates "
                f"between, not as a menu of baselines.")
            if wp10 is not None:
                caveat_mode += (
                    f" The warmup gaps, sampled with no arming pause near "
                    f"them, have p10 {wp10:.2f} ms -- "
                    + (f"consistent with that mode, so the cheap mode looks "
                       f"like the workload."
                       if agrees else
                       f"NOT consistent with it, so the cheap mode looks like "
                       f"the pause rather than the workload."))
        else:
            caveat_mode = ""
        caveat = ("" if spread is None or spread < 4 else
                  f" NOTE: the forward samples behind that baseline span "
                  f"{spread:.0f}x ({self.arm_forward_samples[0]}), so the "
                  f"armed span's forward cost is bimodal and this ratio is a "
                  f"summary of two different behaviours, not one measurement.")
        caveat += caveat_mode
        if ratio > k:
            row["class"] = "slower"
            row["note"] = (
                f"REPLAY DIVERGES: the armed span traverses forward in "
                f"{fwd:.2f} ms and replays in {lap:.2f} ms -- {ratio:.0f}x "
                f"SLOWER. The oracle certifies the guest state; it cannot "
                f"certify the host-side input, which is not rewound. Read the "
                f"rate as a lower bound on a guest that is waiting, not "
                f"working." + caveat)
        elif ratio < 1.0 / k:
            row["class"] = "faster"
            row["note"] = (
                f"REPLAY DIVERGES: the armed span traverses forward in "
                f"{fwd:.2f} ms and replays in {lap:.2f} ms -- {1 / ratio:.0f}x "
                f"FASTER. The guest state is restored byte for byte, so the "
                f"speedup is not in the guest: it is input that arrived during "
                f"the forward traversal and is still queued at replay, so the "
                f"wait the forward span paid for never happens again. THE RATE "
                f"ABOVE IS NOT A RATE FOR THIS SPAN -- it is the rate for a "
                f"span whose input was already there." + caveat)
        else:
            row["class"] = "faithful"
            # A faithful verdict reached by picking a mode owes the reader
            # the same sentence a diverged one does: the run is faithful to
            # ONE of two behaviours the span was seen to have, and which one
            # is the whole of what it means.
            row["note"] = (caveat_mode.strip() or None) if modes else None
        return row

    def _warm_p10(self):
        """A low percentile of the warmup gaps, as an independent reference.

        The forward samples are taken around the arm, which stops the vCPU;
        the warmup gaps are not. So they answer the question the forward
        samples cannot: does this workload have a cheap mode at all, or is
        every cheap span a consequence of having been paused?
        """
        if len(self.warm_gaps_ms) < 10:
            return None
        try:
            return statistics.quantiles(self.warm_gaps_ms, n=100)[9]
        except Exception:                                   # noqa: BLE001
            return None

    def _forward_modes(self):
        """The two clusters of this draw's forward samples, or None.

        Splits at the largest RATIO gap between adjacent sorted samples and
        returns (low median, high median) when that gap is at least the
        fidelity bound. Ratio rather than difference: these samples span
        milliseconds to seconds, and a gap of "10 seconds" means something
        different at each end while "3000x" does not.

        None whenever the samples are unimodal, too few to split, or carry a
        non-positive value -- in which case the caller keeps the median and
        behaves exactly as before.
        """
        samples = (self.arm_forward_samples[0]
                   if self.arm_forward_samples else None)
        if not samples or len(samples) < 4 or any(x <= 0 for x in samples):
            return None
        xs = sorted(samples)
        gaps = [(xs[i + 1] / xs[i], i) for i in range(len(xs) - 1)]
        best, at = max(gaps)
        if best < self.fidelity_bound:
            return None
        lo, hi = xs[:at + 1], xs[at + 1:]
        if not lo or not hi:
            return None
        return statistics.median(lo), statistics.median(hi)

    def _wall_notes(self, out):
        """Sentences the verdict owes the reader about where the time went.

        Two questions, both of which went unasked for an entire session:

        1. Does the headline rate agree with the wall clock? fastloop has
           computed both since the first loop run, with a comment saying a
           disagreement means the median is hiding a tail. It disagreed by
           3.4x and the comment was the only thing that noticed.
        2. Is a minority of the laps eating a majority of the clock? Crash
           laps were 1.4% of the laps and most of the run. That is the
           signature of a cost that scales with something other than the
           loop, which is what a YAML report rewritten per crash was.
        """
        notes = []
        med = out.get("exec_per_s_median")
        wall = out.get("exec_per_s_wall_incl_oracle")
        share = out.get("wall_share")
        if med and wall and wall > 0:
            ratio = med / wall
            out["exec_per_s_median_over_wall"] = ratio
            # 1.5x is well past what the oracle can explain: verify laps are
            # ~1 in `verify_every` and cost ~48 ms, which at the configured
            # rates is tens of percent, not multiples.
            if ratio >= 1.5:
                notes.append(
                    f"THE HEADLINE RATE IS NOT THE RATE: exec_per_s_median "
                    f"{med:.0f} is {ratio:.1f}x the wall-clock rate "
                    f"{wall:.0f}. The median is hiding a tail; read "
                    f"wall_share before quoting either number.")
        if share:
            for name in ("plain", "crash", "verify"):
                c = share.get(name) or {}
                ws, ls = c.get("wall_share"), c.get("lap_share")
                if ws is None or ls is None or not c.get("laps"):
                    continue
                if ws >= 0.25 and ls > 0 and ws >= 2.0 * ls:
                    notes.append(
                        f"{name.upper()} LAPS ARE {ws:.0%} OF THE WALL CLOCK "
                        f"AND {ls:.1%} OF THE LAPS. A cost that concentrates "
                        f"like that scales with something other than the loop.")
            un = (share.get("unaccounted") or {}).get("wall_share")
            if un is not None and un >= 0.25:
                notes.append(
                    f"{un:.0%} OF THE SPAN IS IN NO LAP AT ALL. Arming draws, "
                    f"a detector that stopped firing, or time between laps -- "
                    f"whichever it is, the lap medians do not describe this "
                    f"run.")
        return notes

    # ---- report -----------------------------------------------------------

    def uninit(self) -> None:
        it = _stats(self.iter_ms)
        out = {
            "mode": self.mode,
            "comm": self.comm,
            "detector": self.detector,
            "detector_at": getattr(self, "detector_at", "enter"),
            "state": self.state,
            "hits": self.hits,
            "iterations": self.n_iters,
            "signal_laps": self.signal_laps,
            "reset_on_signal": self.reset_on_signal,
            "arm_us": self.arm_us,
            "arm_after_s": self.arm_after_s,
            "armed_at_s": self.t_arm_s,
            "ram_snapshot_bytes": self.snapshot_bytes,
            "sections_on_machine": len(self.all_sections),
            # The names, not just the count. Choosing an allowlist requires
            # knowing what is on the machine, and a run that recorded only a
            # count made the next run's configuration a guess.
            "sections": list(self.all_sections),
            # This plugin's own source hash. The project directories hold
            # COPIES of fastloop.py (the container cannot see the analysis
            # tree), so a run can silently measure a version older than the one
            # in git. Recording the hash makes a result traceable to a source
            # rather than to a filename.
            "plugin_sha256": self._self_sha256(),
            "denied": self.denied,
            # The scope AS APPLIED, which until now the report did not carry
            # at all: an allowlisted run recorded `denied: []` and the section
            # list, and nothing said which sections were actually in the
            # block. `allowed` is None for a denylist run; `allow_implied`
            # names what _companions() added, so a result whose scope is
            # wider than its configuration says so in the artifact rather
            # than only in the log.
            "allowed": self.allowed,
            "allow_implied": self.allow_implied,
            "allow_exact": self.allow_exact,
            "iter_ms": it,
            "first_laps_ms": self.first_laps_ms,
            # None, not zeros, when the image has no such counters: a
            # report of zeros reads as "the reset caused no translation work",
            # which is the conclusion under test.
            "tcg_work": ({
                "note": ("per-lap deltas; `reset` is lap-close to bottom-half "
                         "done, `guest` is bottom-half done to the next lap "
                         "close -- the same split as sched_to_bh and "
                         "bh_to_observed"),
                "reset": {k: _stats(v) for k, v in self.tcg_reset.items()},
                "guest": {k: _stats(v) for k, v in self.tcg_guest.items()},
            } if self._tcg_any else None),
            "verify_iter_ms": _stats(self.verify_iter_ms),
            "crash_iter_ms": _stats(self.crash_iter_ms),
            "bh_wall_ms": _stats(self.bh_wall_ms),
            "bh_wall_crash_ms": _stats(self.bh_wall_crash_ms),
            "sched_to_bh_ms": _stats(self.sched_ms),
            "bh_to_observed_ms": _stats(self.obs_ms),
            "sched_to_bh_crash_ms": _stats(self.sched_crash_ms),
            "bh_to_observed_crash_ms": _stats(self.obs_crash_ms),
            # The crash lap, split at the fault. Same reason the round trip is
            # split at the bottom half: "the guest is slow to crash" and "the
            # harness is slow to notice" have opposite fixes and one number
            # cannot tell them apart.
            "crash_bh_to_signal_ms": _stats(self.crash_to_sig_ms),
            "crash_signal_to_close_ms": _stats(self.crash_after_sig_ms),
            "arm_attempts": self.arm_attempt,
            "arm_clean_streak_required": self.arm_clean_streak,
            # The FORWARD distribution, which nothing was recording and
            # which turned out to be what sets the rate. Reported as stats
            # rather than raw: what matters is the shape -- a mean far above
            # the median means the cheap and expensive modes are far apart,
            # and the draw decides which one the loop replays forever.
            "warm_gaps_ms": _stats(self.warm_gaps_ms),
            # The ceiling the ACCEPTED draw actually faced, which is not the
            # opening one once the ladder has relaxed. `arm_cost_ladder_ms`
            # carries every rung so a reader can see how far it had to widen.
            "arm_cost_threshold_ms": (
                round(self._cost_threshold(self.arm_attempt), 4)
                if self._cost_threshold(self.arm_attempt) is not None else None),
            "arm_cost_ladder_ms": [
                (None if self._cost_threshold(a) is None
                 else round(self._cost_threshold(a), 4))
                for a in range(1, self.arm_retries + 2)],
            "arm_cost_relax": self.arm_cost_relax,
            "arm_cost_rejects": self.arm_cost_rejects,
            # The same span, un-reset, timed once before any restore. The
            # ratio against iter_ms is the reset's cost TO THE GUEST, and it
            # is the only form of that number not confounded by comparing two
            # different spans.
            "arm_forward_ms": (round(self.arm_forward_ms, 4)
                               if self.arm_forward_ms is not None else None),
            # One per arm, in order. With re-arms this is how far the draws
            # differed from each other, and the ratio axis scored each lap
            # against its OWN entry rather than against the first.
            "arm_forward_ms_all": self.arm_forward_ms_all,
            "arm_forward_samples": self.arm_forward_samples,
            "arm_cost_fwd_mult": self.arm_cost_fwd_mult,
            "pin_process": self.pin_process,
            "pin_exclusive": self.pin_exclusive,
            # What the DRIVER reported, not what was asked for. hits_out is
            # the number this whole mechanism exists to drive to zero: hook
            # firings from outside the pinned subtree, which without the pin
            # would have been counted as laps.
            # Near 1: the guest spent its half EXECUTING. Near 0: it spent it
            # WAITING, and the lap is the period of whatever it waited on
            # rather than a cost of the reset. Every TCG counter reads zero in
            # both cases, which is why this exists.
            "lap_cpu_frac": _stats(self.lap_cpu_frac),
            "lap_proc_frac": _stats(self.lap_proc_frac),
            # READ hits_in/hits_out AS PER-LAP, NOT PER-RUN. The counters live
            # in driver memory, which is guest RAM, which the snapshot captures
            # and every reset RESTORES -- so they are rewound along with
            # everything else. A run that fed 303,315 inputs reported
            # hits_in=1: not a broken pin, but the single hook firing between
            # setting the pin and taking the snapshot, replayed forever after.
            #
            # This is the property that makes the pin work at all -- captured
            # by the snapshot, so every lap begins pinned -- turned against its
            # own statistics. A non-zero hits_out still means something real
            # (some lap fired a hook outside the armed subtree); it just cannot
            # be totalled over a run.
            "pin_report": self.pin_report,
            "pin_report_note": (
                None if not self.pin_report else
                "hits_in/hits_out are rewound by every reset because they live "
                "in guest RAM; read them as this lap's counts, not the run's"),
            "degraded_notes": self.degraded_notes,
            # WHICH PROCESS the detector fired in. `comm` is a name, not an
            # identity. None throughout means the driver does not report pid,
            # which is "cannot say", not "all one process".
            "detector_procs": (
                None if not self.hit_procs else
                {"distinct": len(self.hit_procs),
                 "top": sorted(({"pid": k[0], "create_time": k[1], "hits": v}
                                for k, v in self.hit_procs.items()),
                               key=lambda r: -r["hits"])[:5],
                 "armed_in": (None if self._arm_ident is None else
                              {"pid": self._arm_ident[0],
                               "create_time": self._arm_ident[1]}),
                 "hits_other_proc": self.hits_other_proc}),
            "arm_progress_counter": self.arm_progress,
            "longest_clean_streak": self._best_streak,
            "arm_history": self.arm_history,
            "health_window": self.health_window,
            "degraded": self.degraded,
            "hot_class": self.hot_class,
            # HOST LOAD, at the start and end of the run. Not decoration.
            # Two runs of this harness were read as a QEMU regression -- nearly
            # every lap closing on a fatal signal, inputs delivered down 5.6x --
            # and they were a busy machine. The same signature was used to
            # convict a code change, on a run that followed a 50-minute build.
            # A timing harness that does not record the load it ran under
            # cannot tell those apart afterwards, and afterwards is when you
            # ask.
            "loadavg_start": self.loadavg0,
            "loadavg_end": list(os.getloadavg()),
            "page_obs": self.page_obs,
            "sched_to_bh_verify_ms": _stats(self.sched_verify_ms),
            "bh_to_observed_verify_ms": _stats(self.obs_verify_ms),
            "reset_us": _stats(self.reset_us),
            "restored_pages": _stats(self.restored),
            "verifies": self.verifies,
            "split_order_control_diff_pages": self.split_diff,
            "errors": self.errors,
        }
        # exec/s from the MEDIAN interval, not from total/elapsed: the tail
        # includes whatever the guest does when the driver pauses, and a mean
        # over that reports the driver's duty cycle rather than the loop's rate.
        out["exec_per_s_median"] = (1000.0 / it["median"]) if it else None
        # `is not None`, not truthiness. perf_counter()'s origin is unspecified
        # and a zero timestamp is a legal reading; `x and y` would silently drop
        # the whole wall-clock cross-check on it. Same falsy-zero shape as the
        # `arm_backoff_s: 0` bug that waited three seconds anyway.
        if (self.t_loop0 is not None and self.t_loopN is not None
                and self.n_iters > 1):
            # Includes the verified laps, so it is BELOW the loop's rate by
            # however much the oracle cost. Reported as a cross-check on the
            # median rather than as the headline: if the two disagree by more
            # than the verify laps can account for, the median is hiding a tail.
            span = self.t_loopN - self.t_loop0
            out["exec_per_s_wall_incl_oracle"] = (
                (self.n_iters - 1) / span if span else None)
            out["loop_wall_s"] = span
            out["wall_share"] = self._wall_attribution(span)
            # A negative unaccounted share means the laps took longer than the
            # span that is supposed to contain them, i.e. the span is wrong --
            # not that the accounting is. Say so on the report rather than
            # leaving an impossible percentage for a reader to notice.
            wa = out["wall_share"]
            if wa and (wa["unaccounted"]["wall_s"] < 0):
                out["loop_wall_s_invalid"] = (
                    f"loop_wall_s ({span:.2f} s) is SHORTER than the sum of "
                    f"the laps it contains "
                    f"({-wa['unaccounted']['wall_s'] + span:.2f} s), so the "
                    f"loop clock was restarted mid-run and this span, "
                    f"exec_per_s_wall_incl_oracle and every wall_share below "
                    f"are meaningless. Use the lap-class sum instead.")

        # A negative diff means the oracle could not look. That is neither a
        # pass nor an ordinary failure, and lumping it in with "pages differ"
        # would report a broken instrument as a broken reset.
        blind = [v for v in self.verifies if v["diff_pages"] < 0]
        bad = [v for v in self.verifies if v["diff_pages"] > 0]
        dev_bad = [v for v in self.verifies
                   if v.get("dev_diff_sections", 0) > 0]
        dev_unres = sorted({n for v in self.verifies
                            for n in v.get("dev_diff_report", "").split(",")
                            if n.startswith("*") or n.startswith("!*")})
        out["dev_unrestorable"] = dev_unres
        # THE ORACLE'S OWN COST AND METHOD. It was 34-35% of the wall clock on
        # every run this lane has measured, so how it reached its answer is a
        # first-class part of the result rather than a footnote.
        pm_stats = [v for v in self.verifies if v.get("pagemap_status") is not None]
        if pm_stats:
            last = pm_stats[-1]
            tot = (last.get("pages_proved", 0) or 0) + (last.get("pages_read", 0) or 0)
            out["oracle_method"] = {
                "pagemap_status": last["pagemap_status"],
                "pages_proved": last.get("pages_proved"),
                "pages_read": last.get("pages_read"),
                "proved_frac": ((last.get("pages_proved", 0) or 0) / tot) if tot else None,
            }
            if last["pagemap_status"] == -1:
                # LOUDLY. The filter asked for and not delivered costs MORE and
                # changes no answer, so nothing else in this report would say
                # so. That is the shape of instrument failure this lane keeps
                # writing checks against.
                self.errors.append(
                    "pagemap prefilter unavailable (PFNs read as zero without "
                    "CAP_SYS_ADMIN); the oracle read all of RAM and paid for "
                    "the pagemap on top")
        # ---- coverage ----
        #
        # `coverage_on` is present whether or not coverage ran, because its
        # absence is the thing a reader needs to know. Every rate this lane
        # has recorded so far was measured WITHOUT coverage, and comparing one
        # of those to a coverage-guided figure from the literature is
        # comparing two different quantities. A result that does not say which
        # one it is invites exactly that.
        out["coverage_on"] = bool(self.cov)
        if self.cov and self._cov_armed:
            tbi = self.panda.fastsnap_cov_tbs_instrumented()
            tbf = self.panda.fastsnap_cov_tbs_filtered()
            # ARM ZEROES THIS COUNTER, so under the A/B `tbi` describes only
            # the LAST armed phase -- run 113 reported 28,524 where the whole
            # run translated 392,075. Left alone that is a number a reader
            # would compare against a single-arm run and conclude the guest
            # had shrunk. _ab_step carries the total forward across arms; use
            # it where it exists, and keep the per-arm figure under its own
            # name rather than silently replacing it.
            if self.cov_ab and self._ab_tbi:
                tbi_arm, tbi = tbi, self._ab_tbi + tbi
                tbf_arm, tbf = tbf, self._ab_tbf + tbf
            cov = {
                "map_size": self.panda.fastsnap_cov_map_size(),
                "filter": [self.cov_lo, self.cov_hi],
                "tbs_instrumented": tbi,
                "tbs_filtered": tbf,
                "total_edges": self.panda.fastsnap_cov_total_edges(),
                "laps": len(self.cov_edges),
                "disarmed_laps": self.cov_disarmed_laps,
                "edges": _stats(self.cov_edges),
                "new_edges_total": sum(self.cov_new),
                "new_buckets_total": sum(self.cov_new_buckets),
                "hits": _stats(self.cov_hits),
                "laps_with_new_buckets": sum(1 for n in self.cov_new_buckets
                                             if n),
                "scan_us": _stats(self.cov_scan_us),
            }
            if self.cov_ab and self._ab_tbi:
                cov["tbs_instrumented_last_arm"] = tbi_arm
                cov["tbs_filtered_last_arm"] = tbf_arm
                # The ratio, computed here rather than left to a reader to
                # form out of two fields whose scopes differ. THE FIRST ARM
                # DISTORTS THE SUM: it translates the whole boot plus the
                # workload (~200,000 blocks) while every later arm
                # re-translates only the replayed span's working set (a few
                # thousand). So the steady-state ratio is the LAST arm's, and
                # the summed ratio is reported beside it rather than instead.
                if tbi_arm + tbf_arm:
                    cov["filtered_frac_last_arm"] = round(
                        tbf_arm / float(tbi_arm + tbf_arm), 4)
                if tbi + tbf:
                    cov["filtered_frac_all_arms"] = round(
                        tbf / float(tbi + tbf), 4)
                cov["tbs_instrumented_note"] = (
                    "tbs_instrumented is summed over every arm; each toggle "
                    "flushes the TB cache and re-translates, so it counts "
                    "translations rather than distinct blocks")
            if self.cov_ab:
                cov["ab"] = self._ab_report()
            cov["occupancy"] = self._cov_occupancy(
                cov["total_edges"], cov["map_size"])
            cov["exposure"] = self._cov_exposure(self.cov_edges)
            # THE ZERO THAT MEANS TWO THINGS. An empty map is produced both by
            # a guest that reached nothing and by a filter naming a range that
            # holds no code, and nothing in the map separates them. The tbs
            # counters do, so the verdict says which rather than leaving a
            # plausible zero in the report.
            if tbi == 0:
                cov["blind"] = (
                    f"no block was instrumented ({tbf} filtered out), so "
                    f"every coverage number here is the absence of a "
                    f"measurement, not a measurement of absence")
                self.errors.append(
                    f"coverage instrumented 0 blocks (filter "
                    f"{hex(self.cov_lo)}..{hex(self.cov_hi)}); the range names "
                    f"no code this guest executes")
            elif not cov["total_edges"]:
                cov["blind"] = (
                    f"{tbi} blocks were instrumented and no edge was ever "
                    f"logged, so the emitted ops are not reaching the map")
                self.errors.append(
                    "coverage instrumented blocks but logged no edges")
            # THE FIGURE OF MERIT, which was missing and cost a wrong
            # recommendation.
            #
            # Nothing in this report said what coverage is FOR, so every
            # comparison between configurations got made on the numbers that
            # were here: overhead per lap and exec/s. Both are costs. On
            # those, a 256 KiB map beat a 1 MiB one outright -- 163 us a lap
            # against 255, and 309.6 exec/s against 296.5 -- and it was the
            # worse configuration, because its 4.3% collision loss cost 34%
            # of the novelty rate.
            #
            # Novelty is a MARGINAL quantity and that is why it reacts so
            # much harder than the edge count. An edge that collides with a
            # known one is never new; the slot stays blinded for the rest of
            # the run; so a small static loss compounds. A fuzzer's output is
            # novel executions per second, and nothing else here is.
            #
            # Stated so the next comparison is made on it rather than on
            # whichever cost happened to be printed.
            if cov["laps"]:
                nov = cov["laps_with_new_buckets"] / float(cov["laps"])
                rate = out.get("exec_per_s_median")
                # NEW EDGES PER SECOND IS THE METRIC. Buckets are reported
                # beside it and are NOT the one to compare on.
                #
                # A new EDGE is a map slot never set before: code the loop had
                # not reached. A new BUCKET can be the same path at a
                # different iteration count, so it tracks loop trip counts and
                # moves with the input rather than with discovery.
                #
                # THE TWO DISAGREE, and picking the wrong one flips the
                # answer. Three runs, kernel filtered, only the map differing:
                #
                #   map      collision loss   new edges   bucket-novel rate
                #   256 KiB       4.32%         (2,134)        6.54%
                #   1 MiB         1.20%         (4,179)       10.04%
                #   4 MiB         0.30%         (4,228)        6.74%
                #
                # THE NEW-EDGE COLUMN IS WITHDRAWN -- runs 116/117/118 all ran
                # with cov_ab on, and a disarmed lap re-reported the previous
                # armed lap's new_edges for this sum to add again. Kept in
                # parentheses only because the argument below is about which
                # KIND of number to compare on, and that argument survives its
                # data: a new EDGE is code never reached, a new BUCKET is the
                # same path at a different trip count. Do not quote the
                # figures. See CORRECTIONS entry 14 and PREDICTION-mapsize.md.
                #
                # On buckets, a 16x change in map size and a 14x change in
                # collision loss move nothing, and the middle size is
                # inexplicably the best. That is noise wearing a mechanism's
                # clothes, and it was reported here as the figure of merit
                # until run 118 contradicted it.
                # THE DENOMINATOR, and it was wrong until run 123.
                #
                # This used to be `iterations / exec_per_s_median` -- the time
                # the run WOULD have taken if every lap had cost the median.
                # It is not the time the run took, and on this target the two
                # diverge in the one direction that flatters:
                #
                #   run 122   modelled 41.0 s   measured  54.5 s   7 outliers
                #   run 123   modelled 38.2 s   measured 113.8 s  23 outliers
                #
                # A boundary lap replays a guest fork+exec, costs ~10 s, and
                # is where nearly all the new edges are found. The modelled
                # denominator prices those laps at the median -- so it counts
                # a boundary lap's discoveries in the numerator while
                # pretending it took 3 ms. The more expensive a run's tail,
                # the more the rate is overstated: run 123's by 3.0x.
                #
                # Measured time is the sum over the lap classes, not
                # `loop_wall_s`. The lap sum is immune to the clock being
                # re-stamped mid-run (see t_loop0 above) and is exactly the
                # time the loop spent looping.
                lap_secs = None
                wa = out.get("wall_share")
                if isinstance(wa, dict):
                    lap_secs = sum(wa[k]["wall_s"] for k in
                                   ("plain", "crash", "verify") if k in wa)
                    if lap_secs <= 0:
                        lap_secs = None
                model_secs = ((out.get("iterations") or 0) / rate) if rate else None
                secs = lap_secs or model_secs
                eps = (cov["new_edges_total"] / secs
                       if secs else None)
                cov["throughput"] = {
                    "new_edges_per_s": round(eps, 3) if eps else None,
                    "new_edges_denominator": ("measured lap-time sum"
                                              if lap_secs else
                                              "MODELLED iters/median -- "
                                              "overstates the rate on a run "
                                              "with expensive tail laps"),
                    "seconds_measured": (round(lap_secs, 2)
                                         if lap_secs else None),
                    "seconds_modelled": (round(model_secs, 2)
                                         if model_secs else None),
                    "new_edges_total": cov["new_edges_total"],
                    "exec_per_s_median": rate,
                    "bucket_novelty_rate": round(nov, 5),
                    "novel_laps_per_s": (round(rate * nov, 3)
                                         if rate is not None else None),
                    "note": ("COMPARE CONFIGURATIONS ON new_edges_per_s. "
                             "Overhead and exec/s are costs, and a "
                             "configuration can win on both and still find "
                             "less code. bucket_novelty_rate is reported for "
                             "completeness and is the noisier measure -- it "
                             "moves with loop trip counts rather than with "
                             "discovery."),
                    # Said HERE because this is the number that gets carried
                    # into a comparison, and the caveat has to travel with it.
                    "cross_run_caveat": (
                        "new_edges_total is cumulative over this run's "
                        "exposure. A few laps per thousand replay a "
                        "connection boundary (a guest fork+exec) worth ~10x "
                        "the median lap's edges, and nearly all discovery "
                        "happens there -- so two runs of the SAME config "
                        "differing in exposure.outlier_laps differ in "
                        "new_edges_total for that reason alone. Runs 122 and "
                        "123 differ 4.6x in new_edges_total and also 3.3x in "
                        "outlier_laps (7 against 23); that pair cannot "
                        "separate the two causes and should not be quoted as "
                        "if it could. Check outlier_laps on BOTH runs before "
                        "attributing a difference to configuration."),
                }
                # The trap, named where the number is. Collision loss is
                # reported by `occupancy` as a percentage of EDGES, which
                # reads as small; its effect on novelty is several times
                # larger and is what actually matters.
                occ = cov.get("occupancy") or {}
                if occ.get("est_loss_frac", 0) >= 0.02:
                    cov["throughput"]["warning"] = (
                        f"the map is losing an estimated "
                        f"{occ['est_loss_frac'] * 100:.1f}% of edges to "
                        f"collisions, and DISCOVERY loss is expected to "
                        f"compound well beyond that, because a blinded slot "
                        f"stays blinded for the rest of the run. That "
                        f"compounding is a MECHANISM, not a measurement: the "
                        f"figure that used to appear here (4.3% static loss "
                        f"costing 49% of discoveries) came off cov_ab runs "
                        f"and is withdrawn. A cheaper, faster configuration "
                        f"with a smaller map may still be a WORSE one; check "
                        f"new_edges_per_s, and check that the runs being "
                        f"compared have similar exposure.outlier_laps before "
                        f"believing the difference")
            out["coverage"] = cov

        dev_blind = [v for v in self.verifies
                     if v.get("dev_diff_sections", 0) < 0]
        out["device_scope"] = ("allow", self.allowed) if self.allowed else (
            ("deny", self.denied) if self.denied else ("all", []))
        out["dev_diff_clean"] = len(self.verifies) - len(dev_bad) - len(dev_blind)
        if self.mode in self.MEASUREMENT_MODES:
            out["verdict"] = (
                f"MEASUREMENT MODE ({self.mode}): half a reset, on purpose. "
                f"The guest is wrong by construction -- a device-only restore "
                f"rewinds the page-table base into RAM that was never rewound, "
                f"a RAM-only restore leaves devices drifting -- so no "
                f"correctness claim is made or implied and the rate is not a "
                f"rate. Read sched_to_bh_ms and bh_to_observed_ms only.")
            self.logger.info(f"fastloop: {out['verdict']}")
        elif self.mode == "loop":
            if any(r["verdict"].startswith("refused")
                   for r in self.arm_history):
                out["verdict"] = (
                    f"INVALID: the arm_progress counter "
                    f"{self.arm_progress!r} could not be read, so a draw that "
                    f"delivered no input would have passed the probe. Name it "
                    f"as <plugin-file-name>.<attribute>.")
            elif self.arm_gave_up:
                # SAY WHICH AXIS REFUSED. This asserted a crashing victim
                # unconditionally, and reported exactly that for a run whose
                # arm_history read "costly, costly, IDLE" with zero signal laps
                # -- sending the investigation after crashes that had never
                # happened, when the finding was that nothing was being
                # injected into the span being measured.
                why = [r.get("verdict", "?") for r in self.arm_history]
                last = (self.arm_history[-1].get("verdict", "")
                        if self.arm_history else "")
                if "idle" in last:
                    cause = ("the last draw made NO PROGRESS -- the injector's "
                             "counter did not advance over the probe, so the "
                             "span being replayed does not reach it. The rate "
                             "such a run would report is the rate of a guest "
                             "nothing is being injected into")
                elif "costly" in last:
                    cause = ("every draw replayed a span more expensive than "
                             "the ceiling allowed, and the retries ran out")
                else:
                    cause = ("every draw landed on a victim that was already "
                             "broken, so every lap rewound to a crash")
                out["verdict"] = (
                    f"INVALID: {self.arm_attempt} arming draws in a row were "
                    f"refused ({', '.join(why)}). {cause}. The resets were "
                    f"correct and the instant they restored was not; there is "
                    f"no rate here to report. See arm_history.")
            elif not self.verifies:
                out["verdict"] = ("UNVERIFIED: the loop ran but the oracle "
                                  "never did, so nothing here says the reset "
                                  "was correct")
            elif self.split_diff is None or self.split_diff <= 0:
                out["verdict"] = (
                    f"INVALID: the split-order control returned "
                    f"{self.split_diff}, so the oracle either cannot see a "
                    f"running guest or cannot read the reference at all; a "
                    f"clean verify would prove nothing about the reset")
            elif blind:
                out["verdict"] = (
                    f"INVALID: {len(blind)} of {len(self.verifies)} "
                    f"verifications could not read the forked reference. This "
                    f"is a broken oracle, not a broken reset, and the run says "
                    f"nothing either way.")
            elif bad:
                out["verdict"] = (f"FAILED: {len(bad)} of {len(self.verifies)} "
                                  f"verifications found the guest differing "
                                  f"from the reference after a reset")
            elif dev_bad:
                # Reported as a failure of the RUN, not a caveat on it. A
                # scoped block that leaves device state behind is the exact
                # thing the allowlist was supposed to be checked for, and a
                # clean RAM result sitting next to it is what would make this
                # easy to wave through.
                names = sorted({n for v in dev_bad
                                for n in v["dev_diff_report"].split(",") if n})
                out["verdict"] = (
                    f"FAILED: RAM came back clean on all "
                    f"{len(self.verifies)} verifications, but {len(dev_bad)} "
                    f"of them left device sections unrestored ({names}). The "
                    f"device scope in force does not cover what this workload "
                    f"touches.")
            elif self.degraded:
                d = self.degraded[0]
                out["verdict"] = (
                    f"DEGRADED: the loop passed its arming probe and then came "
                    f"apart at iteration {d['at_iteration']} "
                    f"({d['why']}: {d['signal_fraction']:.1%} of the last "
                    f"{d['window']} laps closed on a fatal signal, progress "
                    f"{d['progress_delta']} of {d['progress_needed']:.0f}). "
                    f"The {len(self.verifies)} verifications before that point "
                    f"were clean, so this is not a reset that returns the "
                    f"wrong bytes -- it is a loop that stopped being the same "
                    f"loop, which is what state surviving the reset looks "
                    f"like. The rate covers only the laps up to that "
                    f"iteration.")
            elif self.allowed and dev_blind and not out.get("dev_diff_clean"):
                out["verdict"] = (
                    f"INVALID: an allowlist was in force and the device "
                    f"oracle could not compare on any of "
                    f"{len(self.verifies)} verifications, so nothing scored "
                    f"the sections it dropped")
            else:
                out["verdict"] = (
                    f"VALID: {len(self.verifies)} verifications, every one "
                    f"byte-identical to an independently forked reference "
                    f"across {self.verifies[0]['bytes_checked']} bytes, with "
                    f"{out['dev_diff_clean']} of them also finding every "
                    f"device section in scope back where the arm left it"
                    + (f". {len(dev_unres)} sections on this machine never "
                       f"serialise identically and are excluded by name: "
                       f"{dev_unres}" if dev_unres else ""))
            rejected = [r for r in self.arm_history
                        if r["verdict"].startswith("rejected")]
            if rejected and not self.arm_gave_up:
                out["verdict"] += (
                    f" Reached on draw {self.arm_attempt} of "
                    f"{len(self.arm_history)}: {len(rejected)} earlier "
                    f"draw(s) armed on a broken victim and were discarded.")
            # Appended to the VERDICT, not filed beside it. The whole lesson
            # of the crashes.py fix is that a number nobody has to read is a
            # number nobody reads; putting this anywhere but in the sentence
            # that gets quoted would reproduce the failure it exists to catch.
            om = out.get("oracle_method")
            if om and om.get("proved_frac") is not None:
                if om["pagemap_status"] == 1:
                    out["verdict"] += (
                        f" Of the bytes that verdict covers, "
                        f"{om['proved_frac']:.2%} of pages were proven equal by "
                        f"PFN identity rather than read back -- a kernel "
                        f"guarantee, not a shortcut, and the remaining "
                        f"{om['pages_read']} pages were compared byte for byte.")
                elif om["pagemap_status"] == -1:
                    out["verdict"] += (
                        " The PFN prefilter was unavailable (no CAP_SYS_ADMIN),"
                        " so every page was read back and the oracle paid for"
                        " the pagemap on top. Pass"
                        " --extra_docker_args \"--cap-add=SYS_ADMIN\".")
            pn = self._proc_note(out)
            if pn:
                out["verdict"] += " " + pn
            fid = self._replay_fidelity(out)
            if fid:
                out["replay_fidelity"] = fid
                # WHETHER THE RATE IS A RATE, as a field rather than as prose
                # buried in a paragraph. The note below has always been
                # correct and has always been in the wrong place: run 88's
                # verdict opens "VALID: 20 verifications, every one
                # byte-identical..." and says REPLAY DIVERGES four sentences
                # and 400 characters later, after an aside about
                # CAP_SYS_ADMIN. "VALID" there is a statement about the RAM
                # oracle and nothing else, but it is the first word, and the
                # run it introduced was quoted at 303 exec/s -- by me, in this
                # lane's own notes -- for a span that replays 319x faster than
                # it traverses. A reader who stops at the first word gets the
                # opposite of the finding.
                #
                # So: lead with it, and give tooling something to branch on
                # that is not a substring search.
                out["exec_per_s_valid"] = (fid.get("class") == "faithful")
                if fid["note"]:
                    # ONLY in front of a verdict that currently opens with
                    # good news. A verdict already leading with DEGRADED,
                    # INVALID, REFUSED or FAILED is not lulling anybody, and
                    # displacing one of those with a rate caveat would repeat
                    # the mistake in the other direction -- the first assert
                    # this change broke was a run that came apart at iteration
                    # 6 and had its DEGRADED headline pushed to second place.
                    # "VALID" is the only opener that invites the rate to be
                    # read as sound, so it is the only one that gets a prefix.
                    if (not out["exec_per_s_valid"]
                            and out["verdict"].startswith("VALID")):
                        out["verdict"] = (
                            f"RATE IS NOT A RATE ({fid['class']}, replay/"
                            f"forward {fid['ratio']:.4f}) -- "
                            + out["verdict"])
                    out["verdict"] += " " + fid["note"]
            notes = self._wall_notes(out)
            if notes:
                out["wall_notes"] = notes
                out["verdict"] += " " + " ".join(notes)
            self.logger.info(f"fastloop: {out['verdict']}")

        path = os.path.join(self.outdir, "fastloop.json")
        with open(path, "w") as fh:
            json.dump(out, fh, indent=2)
        self.logger.info(
            f"fastloop: RESULTS mode={self.mode} iters={self.n_iters} "
            f"iter_median_ms={it['median'] if it else None} "
            f"exec_per_s={out['exec_per_s_median']}"
            f"{'' if out.get('exec_per_s_valid', True) else ' (NOT A RATE: replay diverged from forward traversal -- see replay_fidelity)'} "
            f"exec_per_s_wall={out.get('exec_per_s_wall_incl_oracle')} "
            f"reset_us_median="
            f"{out['reset_us']['median'] if out['reset_us'] else None} "
            f"restored_pages_median="
            f"{out['restored_pages']['median'] if out['restored_pages'] else None}"
        )
