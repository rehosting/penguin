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

  exec/s        the outcome
  lap_ms        median plain lap
  fwd_ms        forward traversal measured at the arming draw. When this is
                close to lap_ms the replay is faithful; when lap_ms is much
                larger than fwd_ms the loop is replaying something the arming
                draw did not sample.
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

Usage:  python3 loopcmp.py <results_dir> [<results_dir> ...]
        python3 loopcmp.py work/stride/proj/results/{88,99,102}
"""

import json
import os
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
    hook_ms = (firings * US_PER_HOOK_FIRING / 1000.0 / iters
               if firings and iters else None)

    rf = fl.get("replay_fidelity") or {}
    epw = sf.get("epoll_pass_why") or {}
    disjoint = epw.get("disjoint")
    n_epoll_pass = sf.get("n_epoll_pass")

    return {
        "run": os.path.basename(os.path.normpath(d)),
        "exec_s": fl.get("exec_per_s_median"),
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
        "disjoint": (disjoint / n_epoll_pass
                     if disjoint and n_epoll_pass else None),
        "hook_ms_lap": hook_ms,
        "verdict": (fl.get("verdict") or "")[:40],
    }


COLS = [
    ("run", "{}", 6), ("exec_s", "{:.2f}", 8), ("iters", "{}", 6),
    ("lap_ms", "{:.3f}", 10), ("fwd_ms", "{:.2f}", 9),
    ("reset_us", "{:.0f}", 9), ("pages", "{:.0f}", 6),
    ("reset_frac", "{:.4%}", 11), ("attempts", "{}", 5),
    ("acc/lap", "{:.2f}", 8), ("fed/lap", "{:.2f}", 8),
    ("disjoint", "{:.0%}", 9), ("hook_ms_lap", "{:.3f}", 12),
    ("spread", "{:.1f}x", 8), ("fidel", "{}", 18),
]


def main(dirs):
    rows = [row(d) for d in dirs]
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
        if r["lap_src"] != "plain":
            print(f"  run {r['run']}: no plain laps -- lap_ms is from the "
                  f"verify sample ({r['iters']} iteration(s) total)")
        if r["fidel"] and not r["faithful"]:
            print(f"  run {r['run']}: replay {r['fidel']} -- exec_s is NOT a "
                  f"rate for the armed span")
        if (r["feed_wall"] and r["loop_wall"]
                and r["feed_wall"] < 0.5 * r["loop_wall"]):
            print(f"  run {r['run']}: fed for {r['feed_wall']:.0f}s of a "
                  f"{r['loop_wall']:.0f}s loop -- the guest starved")
        if r["verdict"].startswith("FAILED"):
            print(f"  run {r['run']}: {r['verdict']}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    sys.exit(main(sys.argv[1:]))
