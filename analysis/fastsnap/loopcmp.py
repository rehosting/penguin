#!/usr/bin/env python3
"""Compare fastsnap loop runs side by side.

Every run of the real-firmware loop drops three JSON files into its results
directory -- fastloop.json, snapfeed.json, hook_budget.json -- and for most of
this lane's history a comparison meant opening all three by hand, for each run,
and remembering which number lived where. That is how run 102's stall came to
be blamed on dirty pages: the reset numbers were in front of me
(949 pages/1364 us, both genuinely up) and snapfeed's feed_wall_s, which said
the guest had stopped being fed a tenth of the way in, was in a file I did not
open. The dirty-page reading was not contradicted by anything on screen.

So this prints the columns that discriminate, together, with the derived ratios
the raw files leave implicit:

  exec_s        exec/s from the MEDIAN lap -- the per-lap rate.
  wall_s        exec/s over the loop's wall clock, oracle laps included.
                THIS is the number a fuzzer gets. The two differ by whatever
                the loop spends not looping: run 106 reports 298.9 from the
                median and 33.5 over the wall, because the guest driver's
                connection dies and takes about two seconds to come back, and
                a median over laps cannot see time when there were no laps.
                A tail that big is worth more attention than the headline.
  med/wall      their ratio, and a direct read on how much of the run was
                spent outside a lap.
  lap_ms        median plain lap
  fwd_ms        THE ARMED SPAN's own forward traversal -- sample 1 of the
                draw's five, the only one that starts where every replayed
                lap starts. The other four are the spans that followed it and
                begin from states the loop never visits, so their median is a
                local cost estimate for the arming axis and not a fidelity
                reference. Reading the median as "the armed span's cost"
                retracted a real rate in this lane once already: run 88's
                sample 1 is 2.39 ms against a 3.30 ms lap (faithful, 1.38),
                while their median is 1051.94 (an apparent 319x divergence).
  fid1          lap_ms / fwd_ms -- the fidelity ratio that matters. Near 1 the
                loop replays what it armed on. Taken from the LAST arm
                attempt's samples: there is one set per attempt and only the
                final one is the draw the loop ran on. Run 107 rejected a
                10186.84 ms draw, accepted a 2.5746 ms one, and lapped at
                3.4518 -- 1.341 against the draw it used, 0.0003 against the
                draw it threw away.
  reset_us      cost of the reset itself
  pages         pages restored per lap
  reset_frac    reset_us / lap_ms -- how much of the lap the mechanism under
                study actually accounts for. On this target it has never once
                been the big term, which is the single most useful fact here.
  fidel         fastloop's own replay_fidelity verdict, as class and
                lap_ms/forward_ms. THIS IS THE ACCEPTANCE TEST, not exec/s.
                A ratio far below 1 means the loop replays a span whose input
                had already arrived during the forward traversal, so the wait
                the span was supposed to contain never happens again and the
                rate is not a rate for that span. fastloop says so in its own
                note; runs 88 and 91 carry it, and reading their 303 and 201
                exec/s as throughput -- as I did -- ignores it.
  spread        max/min of the five forward samples behind the arming draw.
                Near 1 the span costs what it costs. Large (448x on run 88)
                the span is bimodal and its "cost" is a summary of two
                different behaviours, which is also the signature of the
                queued-input divergence above.
  acc/lap       accepts per lap. snapfeed feeds accepted fds and cannot
                synthesise accept(), so anything above ~0 means the replayed
                span contains a wait only the guest can satisfy.
  fed/lap       feeds per lap -- the victim's actual request rate.
  hook_ms_lap   estimated syscall-hook cost per lap, at the measured
                95.880 us/firing. Compare against lap_ms, not against zero.

                Counted from the ARMED MARK onwards where the run has one:
                hook_budget's total covers the whole run, and boot fires
                thousands of hooks no lap is responsible for. Run 107 fired
                34,461 in total, 12,003 of them before it armed, leaving
                22,458 across 2,000 laps -- 11.23 firings and 1.077 ms per
                lap against a 3.452 ms lap, or 31.2% of it.

                `marks.armed.firings` is already the POST-arm count (each
                row's `firings_since` is `n - snapshot`, and the mark's total
                is their sum), so it is used directly. An earlier version
                subtracted it from the total and reported the boot half
                instead, which halved this column and made hooks look like a
                seventh of the lap rather than a third.

                Runs with no armed mark are flagged: their number includes
                boot and is an upper bound, not comparable with a marked run.

Usage:  python3 loopcmp.py <results_dir> [<results_dir> ...]
        python3 loopcmp.py work/stride/proj/results/{88,99,102}
"""

import json
import os
import statistics
import sys

US_PER_HOOK_FIRING = 95.880      # analysis/fastsnap/result_speedscheme.json


def load(d, name):
    p = os.path.join(d, name)
    try:
        with open(p) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def med(stat):
    """fastloop writes {n, median, mean, ...} or None for an empty sample."""
    if isinstance(stat, dict):
        return stat.get("median")
    return None


def forward_modes(samples, bound=3.0):
    """Split a draw's forward samples at their largest ratio gap.

    Returns (low median, high median) when the gap is at least `bound`, else
    None. Mirrors fastloop's own `_forward_modes` so a run recorded before
    that existed can still be read this way.
    """
    if not samples or len(samples) < 4 or any(x <= 0 for x in samples):
        return None
    xs = sorted(samples)
    best, at = max((xs[i + 1] / xs[i], i) for i in range(len(xs) - 1))
    if best < bound:
        return None
    return statistics.median(xs[:at + 1]), statistics.median(xs[at + 1:])


def cheap_mode_verdict(fl):
    """Is the cheap forward mode the workload, or the arming pause?

    The forward samples are taken around the arm, which stops the vCPU for
    ~250 ms -- so the first span after resume serves a request that queued
    during the stop rather than a fresh one, and reads cheap for a reason
    that has nothing to do with the workload. The warmup gaps are sampled
    with no arming pause near them, so they answer what the forward samples
    cannot.

    Returns None (not bimodal), "workload" (the warmup gaps sit on the same
    cheap mode), or "pause" (they do not).
    """
    samples = (fl.get("arm_forward_samples") or [[]])[-1]
    modes = forward_modes(samples)
    if not modes:
        return None
    p10 = (fl.get("warm_gaps_ms") or {}).get("p10")
    if not p10 or p10 <= 0:
        return None
    lo = modes[0]
    return "workload" if max(p10 / lo, lo / p10) < 3.0 else "pause"


def lap_time_sum(fl):
    """Seconds the loop spent in laps, from the disjoint lap classes.

    The honest denominator for a discovery rate. See the note at the `new/s`
    computation in main() for why neither `loop_wall_s` nor
    `iterations / exec_per_s_median` can be used instead.
    """
    wa = fl.get("wall_share")
    if not isinstance(wa, dict):
        return None
    t = sum(wa[k]["wall_s"] for k in ("plain", "crash", "verify") if k in wa)
    return t or None


def row(d):
    fl, sf, hb = (load(d, "fastloop.json"), load(d, "snapfeed.json"),
                  load(d, "hook_budget.json"))
    lap = med(fl.get("iter_ms"))
    # Fall back to the verify laps when there are no plain ones. A run with
    # only verify laps is a run that made one pass, and reporting a blank
    # there would hide exactly the case worth seeing.
    lap_src = "plain"
    if lap is None:
        lap, lap_src = med(fl.get("verify_iter_ms")), "verify-only"
    reset = med(fl.get("reset_us"))
    pages = med(fl.get("restored_pages"))
    iters = fl.get("iterations")
    wall = fl.get("loop_wall_s")
    feed = sf.get("feed_wall_s")

    firings = hb.get("total_firings")
    # `marks.armed.firings` is ALREADY the post-arm count, not a snapshot
    # taken at the arm: syscalls.py computes each row's `firings_since` as
    # `n - snap` and the mark's total is the sum of those. Subtracting it from
    # the total therefore yields the BOOT half -- the opposite of what is
    # wanted. Checked both ways round on run 107: total 34,461, mark 22,458,
    # and the per-hook `firings_since` values sum to exactly 22,458.
    post_arm = ((hb.get("marks") or {}).get("armed") or {}).get("firings")
    if post_arm is not None:
        firings, marked = post_arm, True
    else:
        marked = False
    hook_ms = (firings * US_PER_HOOK_FIRING / 1000.0 / iters
               if firings and iters else None)

    rf = fl.get("replay_fidelity") or {}
    epw = sf.get("epoll_pass_why") or {}
    disjoint = epw.get("disjoint")
    n_epoll_pass = sf.get("n_epoll_pass")

    samples = (fl.get("arm_forward_samples") or [[]])[-1]
    modes = forward_modes(samples)
    s1 = samples[0] if samples else None
    return {
        "fwd1_ms": s1,
        "fid1": (lap / s1) if (s1 and lap) else None,
        "run": os.path.basename(os.path.normpath(d)),
        "fwd_lo": modes[0] if modes else None,
        "cheap": cheap_mode_verdict(fl),
        "exec_s": fl.get("exec_per_s_median"),
        "wall_s": fl.get("exec_per_s_wall_incl_oracle"),
        "med/wall": fl.get("exec_per_s_median_over_wall"),
        "iters": iters,
        "lap_ms": lap,
        "lap_src": lap_src,
        "fwd_ms": fl.get("arm_forward_ms"),
        "reset_us": reset,
        "pages": pages,
        "reset_frac": (reset / 1000.0 / lap) if (reset and lap) else None,
        "attempts": fl.get("arm_attempts"),
        "fidel": (f"{rf.get('class')} {rf.get('ratio'):.3f}"
                  if rf.get("ratio") is not None else None),
        "faithful": rf.get("class") == "faithful",
        "spread": rf.get("forward_spread"),
        "acc/lap": (sf.get("n_accept") / iters
                    if sf.get("n_accept") is not None and iters else None),
        "fed/lap": (sf.get("n_sent") / iters
                    if sf.get("n_sent") is not None and iters else None),
        "feed_wall": feed,
        "loop_wall": wall,
        "lap_secs": lap_time_sum(fl),
        "disjoint": (disjoint / n_epoll_pass
                     if disjoint and n_epoll_pass else None),
        "hook_ms_lap": hook_ms,
        "hook_marked": marked,
        "verdict": (fl.get("verdict") or "")[:40],
        **_cov(fl),
    }


def _cov(fl):
    """The coverage columns, and a `cov` flag that is never blank.

    Coverage arrived after most of these runs were recorded, and a run taken
    without it is not comparable to one taken with it -- the instrumentation
    is real work inside the lap. So `cov` reads "off" rather than empty: a
    blank column invites the reader to assume the two rows differ only in the
    numbers they do show.

    `cov_edges` is the median distinct edges per lap and `cov_new` the total
    edges never seen before across the run. new == 0 over thousands of laps
    is the interesting reading: the inputs are not reaching anywhere the
    corpus has not already been.
    """
    if not fl.get("coverage_on"):
        return {"cov": "off", "cov_edges": None, "cov_new": None}
    c = fl.get("coverage") or {}
    if c.get("blind"):
        # Instrumented nothing, or instrumented and logged nothing. Either
        # way the numbers below are the absence of a measurement, and a row
        # that printed them as zeros would read as a result.
        return {"cov": "BLIND", "cov_edges": None, "cov_new": None}
    map_size = c.get("map_size")
    return {
        "cov": "on",
        "cov_edges": (c.get("edges") or {}).get("median"),
        "cov_new": c.get("new_edges_total"),
        "map_KiB": (map_size // 1024) if map_size else None,
        # Carried so the caller can refuse to report a discovery rate off a
        # run that spent laps disarmed. See the warning in main().
        "disarmed": c.get("disarmed_laps"),
        # Boundary laps. A few per thousand replay a guest fork+exec and carry
        # ~10x the median lap's edges, and nearly all discovery happens there
        # -- so two runs of the SAME config with different outlier counts have
        # different new_edges_total for that reason alone. This column exists
        # so that a table of runs cannot be read without it in view.
        "outliers": (c.get("exposure") or {}).get("outlier_laps"),
    }


COLS = [
    ("run", "{}", 6), ("exec_s", "{:.2f}", 8), ("wall_s", "{:.2f}", 8),
    ("med/wall", "{:.1f}x", 9), ("iters", "{}", 6),
    ("lap_ms", "{:.3f}", 10), ("fwd_ms", "{:.2f}", 9),
    ("reset_us", "{:.0f}", 9), ("pages", "{:.0f}", 6),
    ("reset_frac", "{:.4%}", 11), ("attempts", "{}", 5),
    ("acc/lap", "{:.2f}", 8), ("fed/lap", "{:.2f}", 8),
    ("disjoint", "{:.0%}", 9), ("hook_ms_lap", "{:.3f}", 12),
    ("spread", "{:.1f}x", 8), ("fwd1_ms", "{:.2f}", 10),
    ("fid1", "{:.3f}", 8), ("cheap", "{}", 10),
    ("cov", "{}", 6), ("map_KiB", "{}", 8),
    ("cov_edges", "{:.0f}", 10),
    ("cov_new", "{:.0f}", 9), ("new/s", "{:.2f}", 8),
    ("outliers", "{}", 9),
]


def main(dirs):
    rows = [row(d) for d in dirs]
    for r in rows:
        # The figure of merit, computed here rather than by hand. Doing it by
        # hand each time is part of how an inflated version of this number
        # stayed in COVERAGE.md across three runs.
        #
        # NOT loop_wall_s. That is `t_loopN - t_loop0`, and t_loop0 was
        # re-stamped by every cov_ab toggle barrier -- run 123 reports 1.12 s
        # for a loop whose laps sum to 113.8 s. NOT iterations/median either:
        # that is the time the run would have taken if no lap hit a connection
        # boundary, which prices the expensive laps at the median while
        # counting their discoveries. The lap-class sum is the time the loop
        # actually spent looping and is immune to both.
        n, w = r.get("cov_new"), r.get("lap_secs")
        r["new/s"] = (n / w) if (n is not None and w) else None
    head = "".join(f"{name:>{w}}" for name, _, w in COLS)
    print(head)
    print("-" * len(head))
    for r in rows:
        line = ""
        for name, fmt, w in COLS:
            v = r.get(name)
            line += f"{(fmt.format(v) if v is not None else '-'):>{w}}"
        print(line)
    print()
    for r in rows:
        if r.get("hook_ms_lap") is not None and not r.get("hook_marked"):
            print(f"  run {r['run']}: hook_ms_lap {r['hook_ms_lap']:.3f} "
                  f"includes BOOT firings -- no armed mark in this run, so it "
                  f"is an upper bound, not a per-lap cost")
        if r["lap_src"] != "plain":
            print(f"  run {r['run']}: no plain laps -- lap_ms is from the "
                  f"verify sample ({r['iters']} iteration(s) total)")
        f1 = r.get("fid1")
        if f1 is not None and not (1 / 3.0 <= f1 <= 3.0):
            print(f"  run {r['run']}: lap/armed-span {f1:.4f} -- exec_s is "
                  f"NOT a rate for the armed span")
        if (r["feed_wall"] and r["loop_wall"]
                and r["feed_wall"] < 0.5 * r["loop_wall"]):
            print(f"  run {r['run']}: fed for {r['feed_wall']:.0f}s of a "
                  f"{r['loop_wall']:.0f}s loop -- the guest starved")
        # A cov_ab run alternates armed and disarmed laps. An edge first
        # reached while disarmed is never logged, so cov_new UNDERCOUNTS by an
        # unknown amount -- and before 34b05d58 the same laps re-reported the
        # last armed lap's new_edges, so it OVERCOUNTED by 4.6x instead. Either
        # way it is not a discovery measurement, which is the whole content of
        # CORRECTIONS entry 14. Say so on the row rather than trusting a
        # comment in a config file to be read.
        if r.get("lap_secs") and r.get("loop_wall") and (
                r["loop_wall"] < 0.9 * r["lap_secs"]):
            print(f"  run {r['run']}: loop_wall_s {r['loop_wall']:.2f}s is "
                  f"shorter than its own laps ({r['lap_secs']:.2f}s) -- the "
                  f"loop clock was restarted mid-run; wall_s here is "
                  f"meaningless and new/s uses the lap sum instead")
        if r.get("disarmed"):
            print(f"  run {r['run']}: {r['disarmed']} of {r['iters']} laps ran "
                  f"DISARMED (cov_ab) -- cov_new and new/s are not a discovery "
                  f"rate for this run, at best a lower bound over the armed "
                  f"laps. cov_ab prices coverage; it cannot measure it.")
        if r["verdict"].startswith("FAILED"):
            print(f"  run {r['run']}: {r['verdict']}")
    # THE CROSS-RUN REFUSAL. Discovery concentrates in boundary laps, so a
    # spread in outlier counts is a competing explanation for any spread in
    # cov_new -- one that has nothing to do with whatever config key the runs
    # were meant to differ in. This is the exact confound that produced the
    # withdrawn map-size ranking, so it refuses here rather than being left as
    # a judgement call after the numbers are in view.
    ol = [r["outliers"] for r in rows if r.get("outliers")]
    if len(ol) > 1 and max(ol) > 2 * min(ol):
        print(f"\n  REFUSED: outlier (boundary) laps span {min(ol)}-{max(ol)}, "
              f"more than 2x across these runs. A boundary lap replays a guest "
              f"fork+exec worth ~10x the median lap's edges and is where "
              f"nearly all discovery happens, so these runs differ in EXPOSURE "
              f"as well as in configuration. Any difference in cov_new or "
              f"new/s is confounded and must not be attributed to the config.")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
