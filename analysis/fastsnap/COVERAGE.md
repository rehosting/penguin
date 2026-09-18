# Edge coverage: what it is, why it is in QEMU, and what it does not yet tell us

## Why it exists

Before this, the loop could reset a real armel guest 248 times a second and
feed each lap a mutated request. What it could not do was notice that an input
had reached somewhere new.

That gap is not a missing feature so much as a missing *unit*. The published
figures this lane gets compared against are all **coverage-guided** fuzzing
throughput:

| system | rate | what it is |
|---|---|---|
| Nyx / kAFL | ~17,000 exec/s | x86-64 only, KVM + Intel PT, coverage-guided |
| FIRM-AFL (b) | our architecture | full-system + dirty-page snapshot, coverage-guided |
| Muench et al. | "did not exceed 15 test cases per second" | full-system, the reference for the category |
| **this lane, run 88** | **248.10 exec/s wall** | reset + feed + crash detect, **no coverage** |

248 against 15 is a real difference and the reset half is genuinely good. But
until now the left column and the bottom row were not measuring the same thing,
and saying "we are at the strong end of the category" while quietly comparing a
loop rate to fuzzing rates is the kind of claim that reads as health right up
until someone runs a campaign. With `coverage: 1` they are the same quantity.

## Where it lives, and why not a TCG plugin

In QEMU, in-tree: `qemu_builder/src/fastsnap/coverage.c` plus one hook in
`accel/tcg/translator.c` (series patch 0018). Not a `-plugin` shared object,
and the first reason I wrote down for that was wrong, so it is worth stating
the corrected version.

**Wrong:** "plugins are not built here." They are. QEMU's `configure` enables
them whenever a C++ compiler is present, so the shipped
`libqemu-system-armel.so` exports 89 `qemu_plugin_*` symbols even though
`configs/default.json` never passes `--enable-plugins`.

**The two reasons that survive checking:**

1. **A plugin cannot see the reset.** The map has to be summarised and cleared
   in the *same bottom half* that rewinds guest RAM, or every lap's map carries
   a tail of the previous lap. Penguin embeds QEMU as a library and drives it
   over the CFFI ABI; a plugin is loaded by QEMU and has no channel back to the
   embedding process.

2. **The plugin API cannot express an edge.** Its inline ops are exactly
   `QEMU_PLUGIN_INLINE_ADD_U64` and `QEMU_PLUGIN_INLINE_STORE_U64` against a
   fixed scoreboard entry — no indexed addressing. So `map[prev ^ cur]++` is
   not expressible inline and must become a per-block *callback* through the
   plugin dispatch: an indirect call per translated block, against eight inline
   TCG ops here.

It also could not have gone in `cpu_tb_exec()`, which is the other obvious
place. Chained blocks jump straight to each other and never return through it,
so a counter there sees the first block of a chain and nothing else.

## What is emitted

AFL's classic edge hash, per translated block, ahead of the first instruction:

```
idx        = prev ^ cur        cur is a translate-time CONSTANT
map[idx]  += 1                 one byte, wrapping
prev       = cur >> 1
```

`cur` is fixed when the block is translated and blocks are cached, so per
execution this is a load, an xor, a pointer extend and add, a byte load, an
add, a byte store and a store — eight TCG ops before optimisation, counted
from the source rather than estimated. No call, no branch, no lookup. The map is 64 KiB by default because that
is AFL's `MAP_SIZE` and what anything downstream assumes.

Novelty is judged on AFL's power-of-two hit-count buckets, not on edge presence.
`new_buckets` is the signal to drive corpus decisions from: an edge that ran
three times instead of once is how a loop bound gets found, and an
edge-presence count cannot see it.

## The three ways this reads as a healthy zero

Each has a negative control in the selftest, because a coverage map is the
easiest thing in this lane to fake — it is a buffer of bytes, and any nonzero
byte in it looks like working instrumentation.

**1. Instrumentation is baked in at translation time.** A block already in the
cache will never acquire any. So arming queues a `tb_flush`. It *queues* rather
than calls, and that is not a style choice:
`tb_flush__exclusive_or_serial()` asserts
`!runstate_is_running() || (current_cpu && cpu_in_serial_context(...))`, and
neither holds at an arm — `fastsnap_bh()` deliberately pauses vCPUs *without* a
runstate change (that is the whole point of the fast path), and the bottom half
runs on the main loop where `current_cpu` is NULL. Calling it directly aborts
QEMU.

**2. The map pointer is baked in too.** It is materialised as a TCG constant
inside every instrumented block, so freeing or resizing the map while any block
references it is a use-after-free in generated code. The map is allocated once
and never freed. Resizing needs a restart — a constraint worth having over a
lifetime rule nobody can check.

**3. The filter is a virtual address range.** In a full-system emulator it
cannot separate two processes sharing a range, and an empty map means *either*
"the guest found nothing" *or* "that range holds no code". Only
`tbs_instrumented` / `tbs_filtered` separate those. fastloop puts the
distinction in `coverage.blind` and in `errors`, and loopcmp prints `BLIND`
rather than a zero.

## Cost, measured on real firmware (runs 109–113)

Four runs on the armel target, same driver and same arming axis: two controls
(109, 111) and two with coverage on (110, 112).

### The reset side is resolvable and it is the bigger half

`clear_on_reset` folds the summarise-and-clear into `LOOP_RESET`, in the same
bottom half, after the reset's own clock stops. `sched_to_bh_ms` — schedule to
bottom-half completion, measured from Python — isolates it:

| | control 109 | control 111 | coverage 110 | coverage 112 |
|---|---|---|---|---|
| `sched_to_bh_ms` | 0.3543 | 0.3696 | **0.5229** | **0.5295** |
| `cov_scan_us` (C side) | — | — | **160** | **163** |

**+164 µs per lap**, and two independent instruments agree: the Python-side
delta (+164 µs) and QEMU's own clock around the scan (160–163 µs). On a 3.4 ms
lap that is **~4.8%**.

Superseded in magnitude by the paired measurement below, which puts the reset
half at **+178.5 µs** with 35 of 35 pairs agreeing. The cross-run figure was
not wrong so much as imprecise: it differenced four runs with different draws.
The paired number is the one to quote.

**This is five times what the selftest guest suggested, and the earlier
estimate of 25–31 µs in this document was wrong to extrapolate.** The scan is
a skim with a zero-word skip, and the skip is what collapses: the toy guest
sets 151 bytes so almost every 64-bit word is zero, while real firmware sets
4,849 per lap spread across the map, leaving about half the words non-zero.
Scan cost is a function of EDGES SET PER LAP, not of the guest and — as run
114 later showed — not of the map size either.

### The guest side, resolved by an in-run A/B (run 113)

The cross-run comparison could not see this at all, and the earlier text here
said so: the two controls differ by **23%** in the guest half because each run
draws its own span, both coverage runs landed *below* both controls, and the
report was that per-block emission was **not resolved**. That was the right
thing to say and the wrong place to stop.

What resolves it is not more runs, it is a different experiment: alternate
armed and disarmed **inside one run**, on one draw against one snapshot, so
whatever made that draw expensive is a constant that subtracts out. `cov_ab: n`
toggles every `n` plain laps; disarm flushes the TB cache so blocks
re-translate uninstrumented.

Run 113 — 12,000 laps, 300 per phase, 40-lap settle window, **35 switches**:

| | armed | disarmed | paired delta | pairs + | sign-test p | t (trimmed) |
|---|---|---|---|---|---|---|
| `iter_ms` | 3.4599 | 3.1990 | **+0.2612** | 31/35 | 3.5e-06 | 15.4 |
| `sched_to_bh_ms` | 0.5359 | 0.3563 | **+0.1785** | 35/35 | 5.8e-11 | 244 |
| `bh_to_observed_ms` | 2.8677 | 2.7927 | **+0.0817** | 31/35 | 3.5e-06 | 9.7 |

```
lap total                261.2 us
  reset half             178.5 us
    scan, QEMU's clock   165.0 us
    unattributed          13.5 us
  guest half (emission)   81.7 us
CHECK  reset + guest - total   -1.0 us
```

**Emission is 81.7 µs per lap**, measured two independent ways that agree to
1 µs: directly as the paired guest half, and as the paired lap total minus the
paired reset half (261.2 − 178.5 = 82.7). At 13,674 block executions per lap
that is **at most 6.0 ns per block** — roughly 18 cycles for eight TCG ops,
about two cycles an op. That is the first number in this exercise that can be
checked against physics rather than against another measurement.

The close is a **check, not an identity**: the total and the two halves are
three separate paired measurements of the same run. They closed to 1 µs in 261.

The reset half deserves its own line. Armed blocks span 0.5294–0.5436 ms and
disarmed 0.3524–0.3634 across all 36 blocks — **completely disjoint**, 35 of 35
pairs positive. It also runs **13.5 µs larger than the scan's own clock**, and
that gap is reported as *unattributed* rather than folded into the scan: the
scan clock already covers the walk and the virgin-map fold, so whatever else an
armed bottom half costs (a call, and 128 KiB of working set walked past the
reset's own) is real and is not in it.

### Why the statistic is a sign test, and why it is trimmed

Two design decisions here were wrong first and are worth recording as such.

**Unanimity was the wrong bar.** The first version called a result resolved
only when every pair agreed in sign. That is right at five pairs and wrong at
thirty-five: with a real effect, a couple of pairs disagree by chance, so
unanimity would have discarded a thoroughly resolved measurement. Replaced by
an exact two-sided binomial sign test (distribution-free, which matters because
lap times are heavy-tailed) **and** a t-ratio, both of which must pass — the
sign test cannot see a consistent effect that is trivially small, and the
t-ratio cannot resist one enormous pair.

**The four negative pairs are two blocks, not noise in the effect.** Of 18
disarmed blocks, 16 landed in 3.130–3.247 ms and every armed block in
3.394–3.606 — disjoint — while two disarmed blocks came in at 3.565 and 3.662.
Each sits between two armed blocks, so two bad blocks produce exactly the four
negative pairs observed. On the guest half, the smallest of the three
quantities and the one the experiment exists for, those two dragged t from 9.7
to **2.9** — from settled to under the bar. Hence a fixed symmetric 10% trim,
applied to every quantity alike and reported alongside the untrimmed figure.
The sign test never needed it.

### What the settle window is for

Both arm and disarm queue a `tb_flush`, so the laps just after a toggle pay to
re-translate every block the guest touches. This is not small: the run log shows
200 laps taking 11 s right after a toggle against 400 laps in 2 s in steady
state. Those laps go in their own bucket rather than being dropped, so "the
flush is over within the window" stays a claim a reader can check — run 113's
settle median is 3.5464 ms against an armed 3.4742.

### Net effect on the rate

From the same run, so this is one draw rather than four:

| | exec/s | lap ms |
|---|---|---|
| armed | **289.0** | 3.4599 |
| disarmed | **312.6** | 3.1990 |

**Coverage costs 7.5% of the rate.** The earlier cross-run table is kept below
for the record, and its lesson stands: four runs could not see a 5% effect in
exec/s, because the draw dominates.

| run | coverage | exec/s median | lap ms |
|---|---|---|---|
| 109 | off | 293.51 | 3.4070 |
| 111 | off | 242.57 | 4.1226 |
| 110 | **on** | 291.05 | 3.4358 |
| 112 | **on** | 287.59 | 3.4772 |

Asking for the scan as its own op instead would cost a scheduled op per lap,
and on this lane an op is far the more expensive of the two — a hooked syscall
is 95.880 µs against 1.161 µs unhooked, and 98.8% of that is portal round trip.

## What the coverage itself looks like on real firmware

From run 112, 2,200 laps, no address filter (kernel included):

| | |
|---|---|
| blocks instrumented | 49,694 |
| edges per lap | **4,849** median (p10 4,145, p90 5,166, max 23,188) |
| block executions per lap | 13,366 median — 2.76 per edge |
| distinct edges, whole run | **31,920** |
| **map occupancy** | **48.7% of 65,536** |
| new edges over 2,200 laps | 157 |
| laps that found a new bucket | 25 of 2,200 |

## The map size, and a prediction that was tested (run 114)

"48.7% full" reads as comfortable. It is not, and the reason is that an AFL
map is a hash table **with no collision handling**: two distinct edges landing
in the same byte are one edge forever. A filling map does not report "filling",
it reports *fewer edges than the guest produced* — and under-reported coverage
is indistinguishable from a target that reaches less code.

Under a uniform hash, *n* distinct edges fill an expected `m(1 − e^(−n/m))`
buckets, which inverts to `n ≈ −m·ln(1 − f)`. At *f* = 0.487 that put the true
count near **43,750**, i.e. **27% of distinct edges being swallowed** — not
"marginal". (The block index is a splitmix64 finalizer, so uniformity is fair
here. It would not be for a plain `pc & mask`, which is why the selftest checks
the spread of 4,096 page-aligned PCs against the birthday bound rather than
assuming it.)

That is a falsifiable claim, so it was written into the run config *before* the
run and then tested: same driver, same arm axis, same 2,200 laps, `cov_ab: 0`,
one variable changed — a 16x map.

| | run 112 (64 KiB) | run 114 (1 MiB) | predicted |
|---|---|---|---|
| blocks instrumented | 49,694 | 49,995 | (control — same workload) |
| edges per lap | 4,849 | **5,011** | ~5,040 |
| distinct edges, whole run | 31,920 | **42,249** | ~43,700 |
| map occupancy | 48.7% | **4.0%** | ~4.2% |
| estimated collision loss | 27% | **2.0%** | ~2% |
| `cov_scan_us` | 163 | **268** | "higher, roughly linearly" |

**First, the comparison that does *not* work, because it would have been the
headline.** Predicted 43,752 cumulative true edges; the 16x map measured
42,249, which corrected for its own 2.0% residual loss is 43,124 — 1.5% from
the prediction. That looks decisive and **it is confounded.** Run 112 had ~1.1
laps in the expensive 10.2 s mode and run 114 had ~4.1, and an expensive lap is
a *connection boundary*: it replays a guest fork+exec and sees up to 29,285
edges against a 5,011 median. Three extra of those contribute real distinct
edges to the cumulative virgin map, so `total_edges` 31,920 → 42,249 cannot be
attributed to map size alone. The agreement is probably mostly real and it is
not evidence.

**The comparison that does work** is the per-lap edge count, which is immune to
this: it is a per-lap quantity *and* a median, so a handful of boundary laps
cannot move it. Three points, all unconfounded:

| | 64 KiB observed | → predicts | 1 MiB observed | → corrected | apart |
|---|---|---|---|---|---|
| median edges/lap | 4,849 (7.40% full) | 5,038 | 5,011 (0.48%) | 5,023 | **0.29%** |
| p90 edges/lap | 5,166 (7.88%) | 5,381 | 5,342 (0.51%) | 5,356 | **0.47%** |
| max edges/lap | 23,188 (35.38%) | 28,618 | 29,285 (2.79%) | 29,702 | **3.65%** |

The max row is one boundary lap, and it is the one that matters most: at 35%
occupancy it exercises the estimator where the correction is large (23,188
observed against 28,618 predicted — a 19% shortfall) and it still lands within
3.65%. `tbs_instrumented` came back within 0.6% across the two runs, so it was
the same workload.

So the **estimator is validated as a function**, at three occupancies from 0.5%
to 35%. The 27% cumulative loss at 48.7% then follows from applying a validated
function, rather than from the confounded direct comparison.

**The linearity half of the prediction was wrong.** A 16x map cost **1.64x**
the scan, not 16x. The zero-word skip is why: a sparse map is skimmed eight
bytes at a time (~0.5 ns per word) and only non-zero words are examined byte by
byte (~5 ns per set byte), so cost tracks **edges set per lap** far more than
map size. The thing that fills up is the *cumulative virgin* map, and that is
not what the scan is dominated by. Per-lap occupancy at 64 KiB was only 7.4%.

So the trade is **+105 µs per lap** against an estimated **27% of cumulative
edges recovered** — the 32% raw increase in `total_edges` is an overstatement
for the reason above. On these numbers it is worth taking: the 1 MiB map's
total coverage cost is ~366 µs against ~261 µs, still under 11% of a lap.

**157 new edges in 2,200 laps was the expected reading, not a disappointment.**
Those runs had `mutate: 0` — the inputs barely vary, so there is little reason
for coverage to grow, and the number establishes that the mechanism responds
and then settles, which is what a saturated corpus looks like. Run 114 saw 517
new edges over the same 2,200 laps with the bigger map — but it also drew three
more boundary laps, so that figure carries the same confound and is not a clean
"collisions removed" number either. What mutation does to that is measured separately
(run 115), because it is a different question.

## What the scan actually costs, as a model (runs 112, 114, 115)

The map-size comparison forced a correction — cost is not linear in map size —
and the replacement is specific enough to be testable. The scan skims the map
eight bytes at a time and only drops into byte-wise work on words that are not
all zero, so a single set byte drags its whole 8-byte word in with it:

> cost ≈ 0.5 ns × (map/8 words skimmed) + 5.1 ns × (bytes in non-zero words)

Fitted on runs 112 and 114. **Run 115 was not used to fit it** — same 1 MiB map
as 114, different edges per lap — so it is a test:

| run | map | edges/lap | words | bytes examined | scan µs | ⇒ ns/byte |
|---|---|---|---|---|---|---|
| 112 | 64 KiB | 4,849 | 8,192 | 30,103 | 163 | 5.28 |
| 114 | 1 MiB | 5,011 | 131,072 | 39,424 | 268 | 5.14 |
| 115 | 1 MiB | 4,586 | 131,072 | 36,127 | 247 | **5.02** |

The per-byte constant lands in 5.02–5.28 ns — **5.1% spread across two map
sizes**. The practical consequence is the one the earlier "O(map size)" claim
got backwards: **scan cost tracks edges set per lap**, and the map's size only
buys the cheap skim. Run 115 is the cleanest demonstration — it *lowered* the
scan cost (268 → 247 µs) by finding *fewer* edges per lap on the same map.

## Coverage growth under mutation (run 115)

Run 114's config with `mutate: 1` and `complete_request: 1`, so mutation is the
only variable: same 1 MiB map, same 2,200 laps, same driver, same arm axis.
`tbs_instrumented` came back within 0.4%, so it was the same workload.

| | mutate: 0 | mutate: 1 | |
|---|---|---|---|
| **laps that found a new bucket** | 30 / 2,405 = **1.25%** | 239 / 2,610 = **9.16%** | **7.3×** |
| new edges, whole run | 517 | 1,548 | 3.0× |
| new buckets, whole run | 40,613 | 73,146 | 1.8× |
| distinct edges, cumulative | 42,249 | 49,151 | +16% |
| edges per lap (median) | 5,011 | 4,586 | **−8%** |
| block executions per lap | 13,605 | 11,560 | **−15%** |
| exec/s median | 272.2 | 272.6 | — |

**The headline is the novelty rate**, and it is the one figure here immune to
the exposure confound described above: it is a per-lap fraction, so a handful of
boundary laps cannot move it. With mutation on, **one lap in eleven finds
something new** against one in eighty. That is the number that makes this a
coverage-*guided* rate rather than a loop rate.

**Each lap covers less, and the union covers more.** Edges per lap fall 8% and
block executions 15% — mutated requests get rejected earlier, so an individual
lap runs a shorter path. Meanwhile the cumulative set grows 16%. Narrower laps,
wider union, is exactly the shape a working fuzzer should have.

**The +16% cumulative figure is a floor, not an estimate.** Run 115 drew
*fewer* boundary laps than run 114 (~3.0 against ~4.1), and boundary laps are
the richest single source of distinct edges. The confound therefore works
*against* the mutation effect here, which is the one direction in which a
confounded number is still usable.

**Mutation is free in rate terms** (272.2 → 272.6 exec/s) and the pathology
that destroyed run 105 did not recur: the verdict is VALID with 22 of 22
verifications byte-identical, device sections included. `complete_request: 1`
is what makes that true — a truncated request is one lighttpd cannot answer, so
`one_outstanding` withholds the next feed and the held-open connection sits
until the read-idle timeout. Completing the payload without making it valid (a
400 is a perfectly good fuzzing outcome) is the property the alternation
depends on.

## Tuning it: the kernel filter and the map size (runs 116–118)

Four runs, all `mutate: 1` with the in-run A/B, changing one thing at a time.

### Excluding the kernel: yes, and it costs nothing in signal

`cov_filter_hi: 0xC0000000` is ARM's `PAGE_OFFSET`, so `[0, 0xC0000000)` is
userspace. This is **more target-agnostic than this document previously
claimed** — filtering to *lighttpd's text* would need the range read off the
guest, but the user/kernel split is an arch constant of the kernel penguin
itself builds. One number per architecture, no guest introspection.

Measured, the kernel is **58.7% of the replayed span's working set** and ~49%
of block executions — a small, very hot set, which is what a syscall path
looks like.

| | unfiltered | kernel filtered |
|---|---|---|
| edges/lap | 4,586 | 1,438 |
| block execs/lap | 11,560 | 5,902 |
| `cov_scan_us` | 247 | **147** |
| exec/s median | 272.6 | **296.5** |

Kernel blocks execute on every lap and are novel exactly once. Dropping them
cost nothing in discovery.

### The map size: 1 MiB, and the two wrong turns on the way

| map | cost/lap | exec/s | collision loss | **new edges/s** |
|---|---|---|---|---|
| 256 KiB | 163.0 µs | 309.6 | 4.32% | **55.1** |
| **1 MiB** | **255.5 µs** | 296.5 | 1.20% | **103.2** |
| 4 MiB | 464.6 µs | 286.0 | 0.30% | **100.8** |

**1 MiB is the smallest map that does not lose discoveries.** 4 MiB finds code
at the same rate (2% apart) and pays 82% more per lap for it; 256 KiB is
cheaper *and* faster and finds half as much, because a 4.3% static edge loss
compounds into a 49% loss of discoveries — a blinded slot stays blinded.

Two things went wrong reaching that, both worth keeping.

**The cost model had no term for the map's cache footprint.** Emission came
out at 6.0 ns/block on a 64 KiB map and 17.2 ns/block on a 1 MiB one, and
eight fixed TCG ops cannot do that. Every instrumented block writes one byte
at a *hashed* offset, so the accesses are scattered by construction: a small
map is L2-resident and a large one is not. The model priced the map purely
through the scan, which is why "the 1 MiB map costs +105 µs" was too low.

**The figure of merit was noise for one commit.** Bucket novelty rate was made
primary, and it ranks these runs 6.54 / 10.04 / 6.74 % — a 16× change in map
size and a 14× change in collision loss moving the number by 0.2 points, with
the middle size inexplicably best. No mechanism produces that. A new *bucket*
can be the same path at a different iteration count, so it tracks loop trip
counts; a new *edge* is code never reached. On edges the same runs are clean
and the collision mechanism is supported. The result now reports
`new_edges_per_s` as primary and names the bucket rate as the noisier measure.

The general lesson is the one this lane keeps relearning: **overhead and exec/s
are costs.** A configuration can win on both and find less code. 256 KiB is the
worked example.

## What this still does not close

- ~~Per-block cost on real firmware is unmeasured.~~ **Closed by run 113**:
  81.7 µs per lap, at most 6.0 ns per block execution. Note that the remedy
  named here — "one run `coverage: 0`, one `coverage: 1`, same driver, same arm
  axis" — is *exactly what runs 109–112 did*, and it did not work. Two runs
  with the same config still draw different spans. The comparison had to move
  inside a single run before it could resolve anything, which is the part this
  entry had wrong.
- **The filter aliases across processes.** Fine for a pinned single workload,
  wrong the moment the target forks something that shares the range.
- **`prev` is a host global**, as in AFL's QEMU mode. Two vCPUs interleave
  their edge history and produce noise. It cannot go out of bounds — `cur` is
  masked at translation time and `prev` is only ever written as `cur >> 1`, so
  `prev ^ cur` stays inside a power-of-two map whatever order the writes land
  in — but it is noise, and penguin firmware being usually 1 vCPU is the reason
  it is tolerable rather than an argument that it is correct.
- **Nothing consumes the map yet.** `fastsnap_cov_map_bytes()` hands out an
  AFL-layout buffer; no scheduler, corpus or mutation feedback loop reads it.
  Coverage is now *measured*, not yet *guiding*.
- ~~A 64 KiB map is losing about a quarter of the edges.~~ **Measured and
  closed by run 114**: the estimator is validated on unconfounded per-lap
  quantities at occupancies from 0.5% to 35% (0.29%, 0.47% and 3.65% from
  prediction), so the 27% cumulative loss at 48.7% follows. A 16x map costs
  +105 µs a lap. `cov_map_size: 1048576` is the right default here.
- ~~Coverage growth under mutation is unmeasured.~~ **Closed by run 115**:
  the novelty rate goes from 1.25% to 9.16% of laps, 7.3x, at no cost in
  exec/s.
- ~~The remaining lever is the address filter.~~ **Closed by run 116**: the
  kernel is 58.7% of the working set, and excluding it with an arch-constant
  `PAGE_OFFSET` needs no guest introspection. It cut the scan 40% and cost
  nothing in discovery.
- **The scan still skims the whole map.** At 1 MiB that is 65.5 µs a lap of
  pure waste — per-lap occupancy is 0.44%, so 99.5% of the skim reads words
  that were never going to be set. A `ctz` pass over set bytes instead of all
  eight of every non-zero word would cut the *other* term (~134 µs on the
  pre-filter numbers, less now). Neither has been tried; both need a QEMU
  rebuild, and after the filter landed the scan is no longer the dominant
  cost, so the priority is lower than it looked.
- **The emission cache term is measured but not modelled.** 6.0 ns/block at
  64 KiB, 12.2 at 256 KiB, 17.2 at 1 MiB, 13.0 at 4 MiB — not monotonic, so
  the simple "bigger map misses more" story is incomplete. It does not change
  the map-size answer, which rests on discoveries per second, but the cost
  model cannot yet predict emission across map sizes.

## What can now be claimed

Before this work the lane had a **loop rate**: reset, feed, detect the next
boundary. Every published figure it gets compared to — Nyx, FIRM-AFL — is a
**coverage-guided** rate, and those are different quantities. The gap was not
an accuracy problem, it was a category problem.

What can be said now, with the cost of saying it measured rather than assumed:

> **~296 exec/s coverage-guided** on real armel firmware, full-system, with no
> in-guest instrumentation, discovering **~103 new edges per second**. Edge
> coverage costs **255 µs per lap, 6.9% of the rate** — measured inside a
> single run by a paired A/B whose three independent halves close to 1 µs.
> Best configuration: 1 MiB map, kernel excluded by an arch-constant address
> filter, mutation on.

Three honest limits on that sentence. The map should be 1 MiB, not AFL's
default 64 KiB, or roughly a quarter of the cumulative edges go unreported.
Nothing *consumes* the map yet — there is no corpus, scheduler or mutation
feedback reading it, so coverage is measured and not yet guiding. And the rate
itself is a median over a bimodal workload: a few laps per thousand replay a
connection boundary at ~10 s, so `exec_per_s_median` runs 5-6x the wall-clock
rate and `wall_share` is the field to read before quoting either.

## Reading a result

```
out["coverage_on"]                 present whether or not coverage ran
out["coverage"]["tbs_instrumented"]  READ FIRST. Zero means the range is wrong.
out["coverage"]["edges"]           per-lap distinct edges, _stats
out["coverage"]["new_edges_total"] edges never seen before, whole run
out["coverage"]["new_buckets_total"]  the AFL "interesting" signal
out["coverage"]["total_edges"]     distinct edges since the first arm
out["coverage"]["scan_us"]         what summarising cost, per lap
out["coverage"]["blind"]           present only when the numbers mean nothing
```

`loopcmp.py` prints `cov`, `cov_edges` and `cov_new`. A run recorded before
coverage existed reads `off`, never blank: a blank column invites the reader to
assume two rows differ only in the numbers they do show, and a run with
instrumentation in its lap is not comparable to one without.
