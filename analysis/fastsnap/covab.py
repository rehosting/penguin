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
          f"laps={d.get('iterations')}  "
          f"exec/s median={d.get('exec_per_s_median')}  "
          f"valid={d.get('exec_per_s_valid')}")
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
        # The trimmed t is the one the verdict rests on; see fastloop's
        # _ab_report on why. Recomputed here so a result from an older
        # plugin is judged the same way as a fresh one.
        k = max(1, n // 10)
        tr = sorted(ds)[k:-k] if n >= 5 else ds
        tsd = statistics.stdev(tr) if len(tr) > 1 else 0.0
        tt = (abs(statistics.fmean(tr)) / (tsd / math.sqrt(len(tr)))
              if tsd > 0 else float("inf"))
        flag = "RESOLVED" if (pv <= 0.05 and tt >= 3.0) else "NOT RESOLVED"
        print(f"{name:<20} median {pr['median_delta_ms']:+.4f} ms  "
              f"trimmed mean {statistics.fmean(tr):+.4f}  "
              f"{pos}/{n} positive  p={pv:.3g}  t={t:.2f} "
              f"t_trim={tt:.2f}  {flag}")
        print(f"{'':<20} deltas: {' '.join(f'{x:+.3f}' for x in ds[:14])}"
              f"{' ...' if len(ds) > 14 else ''}")

    # RECOMPUTED from the paired medians, not read from the result. A run
    # written by an older plugin carries a different attribution shape (and,
    # for run 113, a caveat produced by the superseded unanimity rule that
    # the sign test contradicts). Deriving it here keeps every run readable
    # the same way.
    def med(k):
        pr = ab.get("paired", {}).get(k)
        return pr["median_delta_ms"] if pr else None

    tot, rst, gst = med("iter_ms"), med("sched_to_bh_ms"), med("bh_to_observed_ms")
    scan = cov["scan_us"]["median"] / 1000.0 if cov.get("scan_us") else None
    if tot is not None:
        print(f"\n-- attribution, per lap (three independent paired measurements) --")
        print(f"  lap total                 {tot * 1000:8.1f} us")
        if rst is not None:
            print(f"    reset half              {rst * 1000:8.1f} us")
            if scan is not None:
                print(f"      scan, QEMU's clock    {scan * 1000:8.1f} us")
                print(f"      unattributed          {(rst - scan) * 1000:8.1f} us")
        if gst is not None:
            print(f"    guest half (emission)   {gst * 1000:8.1f} us")
        if rst is not None and gst is not None:
            resid = rst + gst - tot
            print(f"  CHECK  reset+guest-total  {resid * 1000:+8.1f} us  "
                  f"({'closes' if abs(resid) <= 0.02 else 'DOES NOT CLOSE'})")
        h = cov.get("hits")
        if h and gst:
            print(f"  => {gst * 1e6 / h['median']:.1f} ns per block execution at "
                  f"most ({h['median']:.0f} hits/lap, a floor: the map "
                  f"saturates at 255/edge)")
        on = [b["iter_ms"] for b in ab["blocks"] if b["phase"] == "on"]
        off = [b["iter_ms"] for b in ab["blocks"] if b["phase"] == "off"]
        if on and off:
            r_on, r_off = 1000 / statistics.median(on), 1000 / statistics.median(off)
            print(f"  rate: armed {r_on:.1f} exec/s, disarmed {r_off:.1f} "
                  f"exec/s -- coverage costs {100 * (1 - r_on / r_off):.1f}% "
                  f"of the rate")
    stale = ab.get("attribution", {}).get("caveat")
    if stale and all(ab["paired"][k].get("sign_consistent") is not None
                     for k in ab.get("paired", {})):
        pr = ab["paired"].get("iter_ms", {})
        ds = pr.get("deltas_on_minus_off", [])
        if ds and sign_test_p(len(ds), sum(1 for x in ds if x > 0)) <= 0.05:
            print(f"\n  (the result file carries a caveat written by the "
                  f"superseded unanimity rule; the sign test above "
                  f"contradicts it)")

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
