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
