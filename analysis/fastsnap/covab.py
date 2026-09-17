#!/usr/bin/env python3
"""Read the in-run coverage A/B out of one or more fastloop.json results.

Prints the three buckets, the paired deltas, the attribution, and the map
occupancy estimate. Exists so the numbers are read the same way every time --
the cross-run comparison this replaced went wrong partly because each
comparison was assembled by hand.
"""
import json
import math
import statistics
import sys


def sign_test_p(n, pos):
    """Exact two-sided binomial. Recomputed here from the raw deltas rather
    than read from the result, so a result written by an older plugin (which
    only recorded whether every pair agreed) can still be judged properly."""
    if n <= 0:
        return 1.0
    k = max(pos, n - pos)
    return min(1.0, 2.0 * sum(math.comb(n, i) for i in range(k, n + 1)) / 2 ** n)


def fmt(st, key="median"):
    return "--" if not st else f"{st[key]:.4f}"


def one(path):
    d = json.load(open(path))
    print(f"\n{'=' * 72}\n{path}\n{'=' * 72}")
    print(f"verdict: {d.get('verdict', '?')}")
    print(f"coverage_on={d.get('coverage_on')}  "
          f"laps={d.get('n_iters')}  "
          f"exec/s={d.get('exec_per_s', {}).get('median', '?')}")
    cov = d.get("coverage")
    if not cov:
        print("no coverage block")
        return
    if cov.get("blind"):
        print(f"BLIND: {cov['blind']}")
    print(f"map_size={cov['map_size']}  tbs_instrumented={cov['tbs_instrumented']}  "
          f"total_edges={cov['total_edges']}")
    print(f"edges/lap median={fmt(cov['edges'])}  hits/lap median={fmt(cov['hits'])}  "
          f"scan_us median={fmt(cov['scan_us'])}")
    print(f"new_edges_total={cov['new_edges_total']}  "
          f"new_buckets_total={cov['new_buckets_total']}  "
          f"laps_with_new_buckets={cov['laps_with_new_buckets']}")

    occ = cov.get("occupancy")
    if occ:
        print(f"\n-- map occupancy --")
        print(f"used {occ['used_frac'] * 100:.1f}%  "
              f"est true edges {occ.get('est_true_edges', '--')}  "
              f"est lost {occ.get('est_edges_lost', '--')} "
              f"({occ.get('est_loss_frac', 0) * 100:.1f}%)")
        print(f"  {occ.get('verdict', occ.get('errors', ''))}")

    ab = cov.get("ab")
    if not ab:
        print("\n(no in-run A/B: cov_ab was 0)")
        return
    print(f"\n-- in-run A/B: {ab['laps_per_phase']} laps per phase, "
          f"{ab['settle_laps']} settle, {ab['switches']} switches --")
    hdr = f"{'':<20}{'ARMED':>12}{'DISARMED':>12}{'SETTLE':>12}{'delta':>12}"
    print(hdr)
    for name in ("iter_ms", "sched_to_bh_ms", "bh_to_observed_ms"):
        b = ab[name]
        on, off = b["on"], b["off"]
        delta = (f"{on['median'] - off['median']:+.4f}"
                 if on and off else "--")
        print(f"{name:<20}{fmt(on):>12}{fmt(off):>12}{fmt(b['settle']):>12}"
              f"{delta:>12}")

    print(f"\n-- paired (adjacent blocks, so the draw and any drift cancel) --")
    for name, pr in ab.get("paired", {}).items():
        ds = pr["deltas_on_minus_off"]
        n, pos = len(ds), sum(1 for d in ds if d > 0)
        pv = sign_test_p(n, pos)
        sd = statistics.stdev(ds) if n > 1 else 0.0
        t = abs(statistics.fmean(ds)) / (sd / math.sqrt(n)) if sd > 0 else float("inf")
        flag = "RESOLVED" if (pv <= 0.05 and t >= 3.0) else "NOT RESOLVED"
        print(f"{name:<20} median {pr['median_delta_ms']:+.4f} ms  "
              f"mean {pr['mean_delta_ms']:+.4f}  "
              f"{pos}/{n} positive  p={pv:.3g}  t={t:.2f}  {flag}")
        print(f"{'':<20} deltas: {' '.join(f'{x:+.3f}' for x in ds[:14])}"
              f"{' ...' if len(ds) > 14 else ''}")

    att = ab.get("attribution")
    if att:
        print(f"\n-- attribution, per lap --")
        print(f"  total (paired iter_ms)  {att['total_cost_ms_per_lap'] * 1000:8.1f} us")
        print(f"  reset-side scan         {att['scan_ms_per_lap'] * 1000:8.1f} us  "
              f"(QEMU's own clock)")
        print(f"  guest-side emission     {att['emission_ms_per_lap'] * 1000:8.1f} us  "
              f"(remainder)")
        if "caveat" in att:
            print(f"  CAVEAT: {att['caveat']}")
        # An UPPER BOUND on per-block cost, and labelled as one. cov_hits
        # saturates at 255 per edge, so on a lap with a hot loop it is a
        # floor on executions -- dividing by a floor gives a ceiling on the
        # per-block cost, which is the honest direction to state it in.
        h = cov["hits"]
        if h and att["emission_ms_per_lap"] > 0:
            ns = att["emission_ms_per_lap"] * 1e6 / h["median"]
            print(f"  => at most {ns:.1f} ns per block execution "
                  f"({h['median']:.0f} hits/lap, itself a floor: the map "
                  f"saturates at 255 per edge)")

    blocks = ab.get("blocks", [])
    if blocks:
        for ph in ("on", "off"):
            v = [b["iter_ms"] for b in blocks if b["phase"] == ph]
            if v:
                print(f"  {ph:>4} blocks n={len(v)} "
                      f"median-of-medians {statistics.median(v):.4f} ms "
                      f"(spread {min(v):.4f}..{max(v):.4f})")


if __name__ == "__main__":
    for p in sys.argv[1:]:
        one(p)
