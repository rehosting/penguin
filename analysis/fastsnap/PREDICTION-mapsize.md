# Prediction: the map-size ranking, re-measured with `cov_ab: 0`

Written before runs 125/126/127 are launched, so it can fail.

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

    run 125    262144   (256 KiB)
    run 126   1048576   (1 MiB)
    run 127   4194304   (4 MiB)
