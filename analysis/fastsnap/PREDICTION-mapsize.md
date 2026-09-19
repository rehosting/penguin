# Prediction: the map-size ranking, re-measured with `cov_ab: 0`

Written before runs 126/127/128 are launched, so it can fail.

## Why the ranking is being re-measured

`COVERAGE.md` and the comment above `cov_map_size:` in
`work/stride/proj/patch_zzz_fastloop.yaml` both carry this table:

    map       cost/lap   exec/s   collision loss   NEW EDGES/s
    256 KiB    163.0 us   309.6       4.32%            55.1
    1 MiB      255.5 us   296.5       1.20%           103.2
    4 MiB      464.6 us   286.0       0.30%           100.8

Those are runs 116, 117 and 118, and **all three were `cov_ab`-on runs**.
`cov_ab` disarms coverage for half the run; a disarmed lap runs no scan, so
`fastsnap_cov_new_edges()` returns the *previous* armed lap's value, and
`fastloop` summed that stale read once per disarmed lap. `new_edges_total` —
and therefore the whole `NEW EDGES/s` column — is inflated by a factor that
depends on how many disarmed laps happened to follow a high-novelty lap.
That is close to random per run, so it is not even a constant offset that
might cancel in a ratio.

Size of the effect, from the one controlled pair available (runs 122 and 123,
identical but for `cov_ab`):

    run 122  cov_ab 0    416 new edges    10.2 new edges/s    21,121 total
    run 123  cov_ab 300 1904 new edges    49.9 new edges/s    22,788 total

4.6x on the headline number. Fixed in `34b05d58` (the per-lap append is now
guarded by `fastsnap_cov_armed()`), and these three runs are the first
map-size measurements taken with the fix in place.

## The predictions

**P1 — magnitude.** The 1 MiB arm lands near run 122's 10.2 new edges/s, an
order of magnitude below the published 103.2. Say 7-15 new edges/s. If it
comes back near 100 then the stale-read diagnosis is wrong, or `cov_ab: 0`
does not do what I think it does, and everything downstream needs re-opening.

**P2 — direction.** Rank order survives: 1 MiB >= 4 MiB > 256 KiB. The
mechanism behind it — a collided slot stays blinded for the rest of the run,
so static edge loss compounds into lost discoveries — is independent of the
stale-read bug and should still hold.

**P3 — the gap narrows.** The published data has 256 KiB discovering at 53%
of 1 MiB's rate. Both sides of that ratio were inflated and the inflation is
not guaranteed symmetric, so I expect the honest gap to be *smaller*: 256 KiB
at 60-90% of the 1 MiB rate.

**P4 — cost per lap is unaffected.** `cost/lap` and `exec/s` were never
touched by the bug (they come from the scan's own clock and the lap timer,
not from the coverage accessors), so those columns should reproduce within
normal run-to-run variance.

## What this experiment CANNOT decide, stated in advance

One run per arm. Draw-to-draw variance on this target has historically been
~20-25% on quantities far more stable than discovery rate (runs 109-112
differed by 23% in the guest half on *identical* configs, purely from which
span the arm landed on). Three single runs can resolve a factor, not a
percentage.

**The readability threshold is ~1.5x.** The published 1.9x (103 vs 55) would
be readable at this sample size. A 1.2x would not be.

So: if the three arms come back within 1.5x of each other, the honest
conclusion is **"map size does not measurably change discovery rate over
256 KiB - 4 MiB on this target"**, and the 1 MiB choice should be justified on
its *modelled* collision loss (1.20% vs 4.32%) while saying plainly that the
justification is a model and not a measurement. It is not licence to keep the
ranking because the ordering happened to come out the way it used to.

**The falsifier for the current default:** if 256 KiB comes back at or above
the 1 MiB rate, the 1 MiB choice is unsupported and the default should change
to the cheaper map.

## Configuration

Identical to the resting configuration in every respect but `cov_map_size`:
mutation on, corpus off, kernel filtered `[0, 0xC0000000)`, `cov_ab: 0`,
12,000 iters, `arm_after_s: 150`, `arm_retries: 12`, seed 1337.

    run 126    262144   (256 KiB)
    run 127   1048576   (1 MiB)
    run 128   4194304   (4 MiB)

Run 125 was this sweep's first 256 KiB arm and was **aborted two thirds of
the way through, deliberately**. Mid-run I found the two denominator faults
recorded in the addendum below, and fixing them also produced a third thing
the old plugin does not emit: `coverage.discovery`, which splits novelty by
whether the lap was a boundary lap. Without it, a sweep whose arms draw
different numbers of boundary laps has no comparison it is allowed to make
and has to be re-run anyway. Given the 7-against-23 spread on the last pair
that looked more likely than not, so the twenty minutes already spent were
cheaper to abandon than the hour they would probably have cost. `results/125`
holds no `fastloop.json`; it stopped before writing one.

---

## Addendum, written while runs 126-128 were in flight

**No prediction above is changed.** This records two instrument faults found
after launch, and how they affect reading the results.

**1. The rate denominator was modelled, not measured.** `new_edges_per_s` in
`fastloop.json` divides by `iterations / exec_per_s_median` — the time the run
would have taken if every lap cost the median. Measured time is the lap-class
sum in `wall_share`. The two diverge with the tail: run 122 modelled 41.0 s
against 54.5 s measured; run 123, 38.2 s against 113.8 s.

Run 125 carried the unfixed plugin and was abandoned for it. Runs 126/127/128
carry the fix, so `throughput.new_edges_per_s` in their JSON is already on the
measured denominator and `new_edges_denominator` says so. Under that
denominator P1's reference point (run 122, recomputed by hand) is **7.6**
rather than 10.2 — still inside P1's stated 7-15 band, so P1 stands as
written.

**2. The 4.6× attributed to the `cov_ab` stale read is not supportable.** Runs
122 and 123 also differ 3.3× in `exposure.outlier_laps` (7 against 23). The
stale-read mechanism is established by reading the code; its magnitude is not
established by that pair. Nothing above depended on the 4.6×.

## The additional check these two faults force

`exposure.outlier_laps` must be reported for all three arms, and a difference
in it is a competing explanation for any difference in `new_edges_total` — one
that has nothing to do with map size.

**Pre-registered refusal:** if the three arms' `outlier_laps` counts span more
than 2×, the discovery comparison is abandoned and reported as confounded,
whatever ordering the numbers happen to show. The arms would then differ in how
often they replayed a connection boundary, and that alone moves discovery more
than any map size in this range plausibly does.

This is the specific trap that produced the withdrawn ranking, so it gets a
rule written before the data rather than a judgement call after it.

## Amendment to the refusal, made before any arm produced data

The refusal above ("if the arms' `outlier_laps` span more than 2×, abandon the
discovery comparison") was written when I had no exposure-free number to fall
back on. Fixing the denominators produced one, so the rule changes — and
because changing a pre-registered rule mid-experiment is exactly the move that
pre-registration exists to catch, here is the change stated in full, with the
timing: **no arm of this sweep had produced a `fastloop.json` when this was
written.** Run 125 was aborted before writing one; runs 126/127/128 had not
started.

`coverage.discovery` now splits novelty by lap class and reports
**`new_edges_per_1k_typical_laps`** — new edges per thousand non-boundary
laps. It is per-lap, so it does not grow with run length, and it excludes the
outliers, so it does not move with how many boundary laps an arm happened to
draw. That is the confound, removed by construction rather than by refusing to
look.

**The primary comparison for this sweep is `new_edges_per_1k_typical_laps`.**
`new_edges_total` and `new_edges_per_s` are reported beside it and are
secondary, because both are cumulative over exposure.

The refusal survives in weaker form, and it is not weaker in what counts as
evidence: if the arms' `outlier_laps` span more than 2×, then
`new_edges_total` and `new_edges_per_s` are confounded for those arms and
**may not be quoted or ranked**, while `new_edges_per_1k_typical_laps` may.
The readability threshold of ~1.5× from draw variance still applies to the
primary metric, and it applies to the *typical* laps' variance, which is not
yet characterised — so if the three arms land inside 1.5× on the primary
metric, the answer is still "no measurable difference", not a ranking.

`outlier_discovery_share` is reported for each arm as a side finding: if
boundary laps turn out to carry most of the discovery on every arm, that is a
more important fact about this fuzzing loop than any map size, and it argues
for a driver that produces boundaries deliberately rather than by accident.

---

# RESULT — runs 126/127/128

| | 256 KiB | 1 MiB | 4 MiB |
|---|---|---|---|
| **`new_edges_per_1k_typical_laps`** (primary) | **22.06** | **23.61** | **22.55** |
| `new_edges_total` | 553 | 527 | 517 |
| `new_edges_per_s` (measured denom.) | 5.50 | 7.34 | 6.06 |
| `outlier_laps` | 12 | 9 | 10 |
| `outlier_discovery_share` | 0.514 | 0.454 | 0.468 |
| `cov_scan_us` median | 75 | 134 | 372 |
| `exec_per_s_median` | 310.7 | 296.3 | 275.8 |
| occupancy | 8.02% | 2.04% | 0.73% |
| est. collision loss | 4.06% | 1.02% | 0.36% |

`outlier_laps` spans 9–12, inside 2×, so the pre-registered confound refusal
does not fire and all the columns above may be read.

## The predictions, scored

**P1 (magnitude) — HELD.** The 1 MiB arm came in at 7.34 new edges/s against a
predicted 7–15, an order of magnitude below the published 103.2. The
stale-read diagnosis is confirmed by a run that does not depend on it.

**P2 (direction) — FAILED.** Predicted `1 MiB >= 4 MiB > 256 KiB`. On the
primary metric the three arms are **22.06 / 23.61 / 22.55 — a 7% spread across
a 16× change in map size**, which is not an ordering. On cumulative new edges
the nominal order is *reversed* (256 KiB highest). The collision-compounding
mechanism I predicted would survive the bug is not observable here.

**P3 (the gap narrows) — FAILED, in the direction of there being no gap.**
Predicted 256 KiB at 60–90% of the 1 MiB rate. Measured 93% on the primary
metric. The published gap was 53%; the honest gap is **indistinguishable from
zero**.

**P4 (cost unaffected) — HELD.** Cost ordering reproduces cleanly and is the
one real effect in the table: scan 75 / 134 / 372 µs, exec/s 310.7 / 296.3 /
275.8.

## The finding

**The map-size ranking does not exist.** A 1.9× difference was published
(55.1 against 103.2 new edges/s); the measured difference on an
exposure-corrected, correctly-denominated metric is **1.07×**, with the sign
unstable across metrics. Cost is real, benefit is not.

## Why no version of this design could have answered it

This is the part worth keeping, and it was not visible until `novel_laps`
existed:

* **Only ~69 laps in 12,000 discover anything at all** — 69, 69, 68 across the
  three arms. Twelve thousand laps is a sample size of sixty-nine.
* **Two laps carry ~43% of each run's discovery.** The two largest single-lap
  contributions are 128+97=225 of 553, 135+89=224 of 527, and 121+108=229 of
  517. Nearly half of each run's headline number rests on two events, and all
  three arms got almost exactly the same two-lap contribution — these are
  structural events, not configuration responding.
* **The arms did not execute the same code.** `tbs_instrumented` is 20,330 /
  20,311 / **26,959** — run 128's guest translated 33% more blocks, which is
  also why its `total_edges` reads 30,488 against ~21,000. That is guest
  behaviour varying run to run, not a map-size effect, and it is a second
  reason cumulative counts cannot be compared across these runs.

So the effective sample is ~69 events dominated by 2, not 12,000 laps and not
553 edges. **No single-run-per-arm design can resolve anything about map size**,
and the 1.5× readability threshold written at the top of this document was far
too generous. The published ranking was noise that happened to look like a
mechanism, and the mechanism was available to explain it.

## What follows for the configuration

`cov_map_size: 1048576` **stays**, and the reason changes completely.

It is not that 1 MiB discovers more — measured, it does not. It is that 256 KiB
is already 8.0% full at 12,000 laps with an estimated 4.1% collision loss, and
that loss compounds with run length because a blinded slot stays blinded. A
campaign 100× longer would put 256 KiB near 38% occupancy and ~21% loss, and
1 MiB near 9.5% and ~5%. **That is a model, not a measurement, and this lane
has never run at that length.** The premium is ~5% of throughput (296.3 against
310.7 exec/s) and ~59 µs of a 3,375 µs lap. Cheap insurance against a regime we
have not measured, which is the honest description of it.

4 MiB is **out**: 11% slower than 1 MiB for collision headroom that is already
negligible at 1 MiB.

## The finding that matters more than the map size

`outlier_discovery_share` is 0.51 / 0.45 / 0.47. **About half of all discovery
happens in 9–12 laps out of 12,000** — 0.08% of laps carrying ~48% of new code.
Those are the connection-boundary laps that replay a guest fork+exec.

Two consequences, one reassuring and one not:

**The held-open-connection driver is still right, and now for a measured
reason.** A boundary lap yields ~24 new edges in ~10 s (2.7–3.4 edges/s); a
typical lap yields 0.023 in 3.4 ms (6.6 edges/s). Boundary laps are ~2× *less*
efficient per second, so the driver that avoids them is not trading discovery
for throughput. That was adopted on throughput grounds alone and could have
been an expensive mistake; it was not.

**But half the discovery is not in the target.** The code a boundary lap
reaches is the guest's fork+exec path, not lighttpd's request handling. So the
effective discovery rate *against the thing being fuzzed* is roughly half the
headline — call it 11–12 new edges per 1,000 typical laps — and the headline
figure is measuring the driver as much as the victim. That is a sharper limit
on "~296 exec/s coverage-guided, ~7.6 new edges/s" than any of the three
already recorded next to it.
