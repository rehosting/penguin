# The loop on real firmware

> ## READ THIS FIRST -- most of this document has been superseded by its own later sections
>
> This file was written forward, in the order the measurements arrived, and it
> reverses itself several times. Every reversal is recorded in place rather
> than edited away, because the wrong turns are the useful part -- but that
> means **earlier sections read as current and are not**. The state as of
> 2026-09-14 04:00:
>
> | claim, in the order it was made | status |
> |---|---|
> | "the reset costs 124x its own clock" (the original title) | **DEAD.** An artifact of comparing one replayed span to an average of many forward ones. |
> | "the ARMING POINT sets the rate" | **incomplete.** True, but the deeper problem was that the loop was not replaying the armed span at all. |
> | "replay costs 1.13x" | **DEAD.** Derived from a cross-construct comparison. The direct measurement gives 3,945x / 76x / 97x on the three targets. |
> | "the arm lands cheap by construction" | **DEAD.** The RESTORE lands cheap; the arm does not. |
> | "feeding from inside the boundary is the whole win, 10.8x" | **DEAD.** It was `swallow_writes`, and only in the closed-loop shape. |
> | "target B blocks in select()" | **DEAD.** Its select handler never fired once. C does block there; B does not. |
> | the reset is a 0.46-0.55 ms constant across three architectures | **STANDS.** Measured directly as `sched_to_bh`. |
> | tb_invalidate / tb_flush / tlb_full_flush are 0 per reset | **STANDS.** Translation is not the cost. |
> | the loop did not replay the span it armed on, on 3/3 targets | **STANDS.** This is the finding. |
> | bugbench's ~1,400 exec/s | **STANDS.** Re-measured faithful (1.18 ms forward, 0.63 ms lap); its injector owns the read. |
>
> **Rates currently believed:** target B **27.9 exec/s** faithful (client-driven);
> target A **not established** -- 231.6 and 0.95 from nominally the same config,
> under investigation; target C **not yet measured**.

# Appendix: the document as written, including the parts now known wrong

## The loop on real firmware: the reset costs 124x its own clock

`REALFW.md` established that a device-only restore destroys a booted guest and
that the RAM half is not optional. This is the complete loop -- device block
plus dirty RAM, verified against a forked reference -- run on a booted vendor
image with a real web server under load, on the current build.

Target A: armel, `-M virt`, 20 device sections, 403 MB of RAM tracked, vendor
userspace, **lighttpd** serving a keep-alive HTTP load generated inside the
guest. A lap is one `writev` to the next: one real request/response, not a
synthetic read.

## The three arms

Same image, same project, same arming point (`arm_after_s: 150`), one at a
time on an idle 96-core host. 2,000 laps each.

| arm | what it does | lap | exec/s |
|---|---|---|---|
| `bare` | no arm, no reset -- guest + detector only | **8.68 ms** | **115.2** |
| `armed` | snapshot taken, dirty log armed, never reset | **8.73 ms** | **114.6** |
| `loop` | the real thing: device block + dirty RAM every lap | **69.54 ms** | **14.4** |

`loop` returned **VALID**: 20 verifications, every one byte-identical to an
independently forked reference across 403,054,592 bytes, with all 20 also
finding every device section in scope back where the arm left it. Zero errors,
zero degraded windows.

## The reset is 0.7% of the lap it costs 60 ms

The lap splits at the bottom half:

| | median | share of lap |
|---|---|---|
| `sched_to_bh` -- schedule to bottom half complete, i.e. THE RESET | **0.546 ms** | **0.8%** |
| `bh_to_observed` -- guest running to the next detector hit | **68.96 ms** | **99.2%** |

The reset's own clock, measured inside QEMU, is **490 us** for **227 pages**.

So against `armed`, resetting adds **60.8 ms of guest time while spending
0.49 ms doing it** -- a factor of **124 between what the reset costs and what
it causes**. Restoring makes the same span of guest execution run eight times
slower.

## It is not the arming point, and it is not noise

Both of the usual explanations are ruled out by the data rather than argued
away.

**Not the arming point, and not the arm's own cost.** `armed` uses the
identical arm -- same 150 s, same snapshot, same dirty log -- and gets 8.73 ms.
`bare` neither arms nor resets and gets 8.68 ms. Arming is free to within 0.6%;
the only difference that costs anything is whether the restore happens.

**Not noise, and not host load.** 1,980 laps:

```
iter_ms          min 68.41   p10 69.18   median 69.54   p90 70.36   max 111.70
bh_to_observed   min 67.84   p10 68.62   median 68.96   p90 69.70
reset_us         min 426     p10 458     median 490     p90 557
restored_pages   min 224     p10 226     median 227     p90 229
```

p10 to p90 spans **1.7%**. This is a deterministic replay of one fixed span of
guest execution, 1,980 times over, and the expensive part of it is reproducible
to within a couple of percent. That matters: a 60 ms cost that varied would be
contention, and this lane has twice mistaken a loaded host for a code
regression. A 60 ms cost that repeats to 1.7% is mechanism.

## Predictions for the split, written before the runs

`devonly` restores the device block and not the RAM; `ramonly` the reverse.
Both are MEASUREMENT MODES -- each leaves the guest wrong by construction and
fastloop's verdict refuses to quote their exec/s as a rate -- but they are the
only cut that says which half of the reset causes the 60 ms, and they need no
new ABI.

- **P0 -- the halves are not both innocent.** At least one of `devonly` and
  `ramonly` has a lap above 40 ms. If BOTH come back near `armed`'s 8.73 ms,
  the cost is in something only the combined op does, and every hypothesis
  below is wrong.
- **P1 -- the device half is the one.** `devonly` lands above 40 ms and
  `ramonly` below 20 ms. Mechanism: the `cpu` section's `post_load`
  (`target/arm/machine.c:cpu_post_load`) runs `write_list_to_cpustate()` over
  every CP15 register and then `arm_rebuild_hflags()`. A CP15 write that is not
  raw invalidates the softmmu TLB, and a cold TLB makes every subsequent guest
  memory access take a full page-table walk in C. An 8x slowdown on a span that
  touches a real userspace working set is the right order for that.
- **P2 -- TB invalidation is NOT it.** `ramonly` stays under 20 ms, AND the
  `tbskip` arm (the full loop with `FASTSNAP_TB_SKIP_NOCODE=1`) lands within
  5% of the plain loop's 69.54 ms.

  Two caches get conflated here and they are not the same one. The TB cache
  holds translated blocks and is invalidated when the memory they were
  translated from changes; the softmmu TLB holds guest-virtual to host-address
  mappings and is flushed when the MMU's own registers change. P1 is about the
  second. P2 is about the first.

  The restored pages ARE modified -- by the restore, from the host side -- and
  TCG cannot tell a host write to guest RAM from self-modifying code, so
  `fastsnap_ram_restore()` invalidates each page it copies back. But the
  restored set is the pages the GUEST wrote since the arm: stack, heap, data.
  The web server's `.text`, libc and kernel text are read-only and file-backed,
  never written, never dirty, never restored. Genuine self-modifying code in
  this workload is approximately none, so almost every one of those
  invalidations should already be finding nothing to invalidate.

  That is not a new argument; it is the one that held on the synthetic target,
  where four interleaved arms measured the skip's upside at exactly zero --
  reset 59.0 to 58.5 us, lap unmoved (`TB-SKIP-AB.md`). The `tbskip` arm is
  here to check that it transfers to a real image with a real code working set
  rather than to assume it does.
- **P3 -- neither half alone reaches 69 ms.** `devonly` + `ramonly` laps sum to
  less than the loop's 69.54 ms, because the restores share fixed costs.
- **P4 -- the device half's own clock stays small.** `devonly`'s `reset_us`
  stays under 300 us. If the device block's own measured cost jumps, then the
  60 ms is in the restore rather than in what the restore does to the guest,
  and P1's mechanism is wrong even if its number is right.

P1 and P2 are the ones that can be wrong in an interesting way. P2 is a
prediction against the cheaper fix: if `ramonly` is the expensive half, the
lever is TB invalidation after all, and `FASTSNAP_TB_SKIP_NOCODE` -- currently
default-off with an open safety question -- becomes worth settling properly.

## Caveat on the later arms

The `bare`, `devonly` and `ramonly` arms overlapped a capped firmware extraction
(`--cpus=6`, `nice -19`) on a 96-core host at load 1.2. That is 6% of the box
against arms that use about two cores, and the effect being measured is a
factor of eight. Recorded because it happened, not because it is believed to
matter. `loop` and `armed` -- the two arms the headline numbers come from --
ran on a quiet host with nothing else on it.

# Results: P1 is falsified, and the device half is not the cost

## `devonly` -- the device block, and no guest RAM at all

| | `bare` | `armed` | **`devonly`** | `loop` |
|---|---|---|---|---|
| lap | 8.68 ms | 8.73 ms | **8.66 ms** | 69.54 ms |
| `bh_to_observed` | - | - | **8.34 ms** | 68.96 ms |
| reset's own clock | - | - | 254 us | 490 us |
| pages restored | - | - | **0** | 227 |

**P1 predicted `devonly` above 40 ms. It came back at 8.66 ms.** Falsified.

### What this arm does and does not license

It ran 46 laps in 0.40 s and then the guest emitted no further detector hit for
the remaining 4.5 minutes -- destroyed, which is `REALFW.md`'s documented result
for a device-only restore and the reason that document exists.

So it does NOT show "the device half is cheap in a real replay". Nothing was
replayed: RAM was never rewound, so the guest simply ran forward with clobbered
CPU state until the clobbering caught up with it. Its 8.66 ms is close to
`bare`'s for an uninteresting reason.

What it does license is narrower and still decisive for P1. The hypothesis was
that the `cpu` section's `post_load` -- `write_list_to_cpustate()` over every
CP15 register, then `arm_rebuild_hflags()` -- flushes the softmmu TLB, and that
a cold TLB is what makes the guest eight times slower. **That flush would show
up in these 46 laps whether or not RAM was rewound.** It does not. The
mechanism is wrong on its own terms, independently of the mode being unsound.

That leaves the RAM half holding all 60 ms, and the RAM half is the one that
invalidates translated blocks. `ramonly` is the arm that genuinely replays --
memory IS rewound there -- so it is the one that decides, with `tbskip` to say
whether invalidation or the copy itself is the cost.

## `ramonly` -- the dirty RAM, and no device state at all

| | `devonly` | **`ramonly`** | `loop` |
|---|---|---|---|
| pages restored | 0 | **194** | 227 |
| lap | 8.66 ms | **78.88 ms** | 69.54 ms |
| `bh_to_observed` | 8.34 ms | **78.61 ms** | 68.96 ms |
| reset's own clock | 254 us | 204 us | 490 us |

**The RAM half carries all 60 ms, and the device half carries none of it.**

Two predictions die here.

- **P1 falsified** (device half above 40 ms): it is 8.66 ms.
- **P3 falsified** (the halves sum to less than the loop): 8.66 + 78.88 = 87.5 ms
  against 69.54 ms. The halves do not compose, which is a warning about reading
  either mode as a fraction of the real thing rather than as an attribution.

And a third fact that neither prediction anticipated: **194 pages cost 78.9 ms
where 227 pages cost 69.5 ms.** More pages, less time. Whatever the 60 ms is, it
is not linear in the number of pages restored, which is evidence against the
`memcpy` itself -- 33 extra pages of copying cannot be negative -- and for
something with a cliff in it. What the restore does per page besides copying is
invalidate translated code.

Both arms died early, 46 and 69 laps, which is `REALFW.md`'s documented result
for half a restore on a booted guest and the reason these modes carry a verdict
that refuses to be read as a rate. The timings are what they are for.

## `tbskip` -- and a hole in it worth naming

The full loop with `FASTSNAP_TB_SKIP_NOCODE=1`, confirmed active in the log:

| | `loop` | `tbskip` | `ramonly` |
|---|---|---|---|
| pages restored | 227 | 214 | 194 |
| lap | 69.54 ms | **75.74 ms** | 78.88 ms |

Skipping the invalidation did not help; it came back 6 ms SLOWER. Removing work
cannot slow anything down, so that 6 ms is draw-to-draw variation between runs
-- which is itself a result: **the noise floor between arming draws is about
+-10%, and this design cannot see an effect smaller than that.**

**P2 confirmed at that resolution: TB invalidation is not the 60 ms.**

The hole: **nothing counts how many invalidations were actually skipped.** "No
change" is ambiguous between *invalidation is cheap* and *the skip skipped
nothing*, and this file's own source comment says the `DIRTY_MEMORY_CODE`
predicate may not mean what it looks like with the vCPUs stopped and
`tlb_reset_dirty_range_all()` freshly swept. A measurement whose null result has
two readings is not a measurement yet. What rescues the conclusion is not this
arm but the non-linearity: 194 pages costing more than 227 rules out
page-proportional work of ANY kind, invalidation included.

# The correction: it IS the arming point, and the earlier dismissal was wrong

This document said, above: "Not the arming point -- `armed` uses the identical
arm and gets 8.73 ms." **That reasoning is wrong and the conclusion with it.**

`armed` never replays. Its laps are consecutive FORWARD gaps between detector
hits, averaged over 2,000 of them. The loop replays ONE gap, forever. Those are
different quantities, and the forward distribution is heavy-tailed:

| | n | median | mean | p90 | max |
|---|---|---|---|---|---|
| `bare` | 2000 | 8.68 ms | **11.37 ms** | 14.19 ms | **122.92 ms** |
| `armed` | 2000 | 8.73 ms | 11.31 ms | 14.37 ms | 82.08 ms |

The mean sits 31% above the median. Most gaps are cheap pipelined responses; a
few are connection turnover, where the next hit needs the client to exit, a new
one to fork and exec, and a fresh connect. **The loop's 69.54 ms sits far out in
that tail.**

So the headline number is not a property of the reset at all. It is a property
of which instant the arm happened to land on. A draw at the median would be
8.7 + 0.5 = **9.2 ms, about 109 exec/s instead of 14** -- 7.5x, from choosing
where to arm and changing no code.

## But draw luck alone does not explain it

Laps of 69 ms or more are roughly the top 1-2% of that distribution, and THREE
of three reset-family runs landed there: 69.54, 75.74, 78.88. Independent draws
would do that about once in 10^5. So one of these is true:

1. the draws are correlated -- every one arms near 150 s, at a similar phase of
   a periodic workload, so they are one draw sampled three times; or
2. replaying a span genuinely costs more than running it forward, and the tail
   is a coincidence on top of that; or
3. both.

`phase 4` decides it: four loop arms, identical but for `arm_after_s`
(158/171/189/206). Spread wide, with some laps near 9 ms, and the draw sets the
rate -- the fix is then to SCORE the draw, which the arm health check already
has the machinery for (it checks faulting and progress; lap cost would be the
natural third axis). All four near 70 ms, and replay is intrinsically expensive
and the mechanism is still unidentified.

**The lesson for this lane is the older one restated.** `LEAN-LAP.md` already
says the arming point sets the rate, not the reset. It was dismissed here by
comparing against a number that measured something else, and three device- and
cache-level hypotheses were built and killed before the distribution was
plotted. Plot the distribution first.

## What the arm check would need, if phase 4 says it is the draw

The two-sided arm probe already rejects a draw on two axes, and records them per
attempt in `arm_history`: the fraction of probe laps closing on a fatal signal
(`signal_fraction`), and whether the replayed span reaches the injector at all
(`progress_delta`). Both ask "is this draw BROKEN".

Neither asks "is this draw SLOW", and the data for it is not merely unscored --
it is not captured. The probe runs `arm_probe` laps and times none of them, and
warmup counts detector hits without recording the intervals between them.

The missing axis is the cheapest of the three to add, because the loop is
already doing the work:

1. during warmup, record the interval between detector hits -- that is the
   forward distribution, the thing that turned out to be heavy-tailed and that
   nobody had plotted;
2. during the arm probe, record the median probe lap -- that is what THIS draw
   costs, replayed;
3. reject a draw whose probe median sits above a percentile of the warmup
   distribution, and re-arm, exactly as a faulting or idle draw is rejected
   today.

It stays host-side and target-agnostic, which is the standing constraint: no
guest instrumentation, works on any image. And it would have caught this run --
a 69.5 ms replayed lap against a warmup median of 8.7 ms is not a marginal call.

Worth stating what this does NOT do: it cannot make a target fast whose every
draw is expensive. If phase 4 comes back flat -- all four draws near 70 ms --
then there is no cheap draw to find, the mechanism is still unidentified, and
this axis would only be rejecting draws it cannot improve on.

# A second real target settles it: the reset is a 0.5 ms constant

Target B: mips (big-endian), `malta`, 37 device sections, **2.16 GB** of RAM
tracked, a different vendor's userspace, **lighttpd** again so the software
under test is held constant while the architecture is not.

| | target A (armel) | **target B (mips-BE)** |
|---|---|---|
| **exec/s, wall** | **14.4** | **155.4** |
| lap, median | 69.54 ms | **6.21 ms** |
| **reset (`sched_to_bh`)** | **0.546 ms** | **0.544 ms** |
| the reset's own clock | 490 us | 496 us |
| pages restored | 227 | **281** |
| RAM tracked | 403 MB | **2.16 GB** |
| guest span (`bh_to_observed`) | 68.96 ms | **5.64 ms** |
| verdict | VALID | VALID |

**The reset costs the same 0.5 ms on both, to within 0.4%** -- while the
eleven-times-faster target restores 24% MORE pages across 5.4x MORE RAM.

That is the whole argument, and it is a stronger form of the one `phase 4` was
built to make. Phase 4 varies the draw on one target; this varies the target,
the architecture, the vendor userspace, the RAM size and the page count at once,
and the reset does not move. **The reset is a ~0.5 ms constant. Everything else
in a lap is the span the arm chose to replay.**

It also disposes of the last page-proportional hypothesis by a second route:
281 pages restored in 496 us on target B against 227 in 490 us on target A. More
pages, same cost, eleven times the throughput.

## Two things that worked without being asked

**The PFN prefilter scales to a multi-gigabyte guest.** 526,791 of 534,727 pages
-- **98.52%** -- proven equal by PFN identity, leaving 7,936 to compare byte for
byte. The verified lap is 23.2 ms for 2.16 GB. Before the prefilter existed the
oracle cost 85 ms on a 403 MB guest; it now costs a quarter of that on a guest
five times larger.

**The unrestorable-section handling fired on its own.** Target B lands on the
same `malta` model, and the run excluded `*mc146818rtc#13` by name without being
configured to -- returning VALID rather than FAILED on a section that cannot
round-trip because its `pre_save` reads the live clock. That path was built for
target-independent reasons and this is the first time it earned its keep on a
target nobody wrote it for.

## The lap is deterministic on both

| | n | p10 | median | p90 | spread |
|---|---|---|---|---|---|
| target A | 1980 | 69.18 | 69.54 | 70.36 | 1.7% |
| target B | 990 | 6.13 | 6.21 | 6.38 | 4.0% |

`restored_pages` on target B is 281 at p10, median AND p90. The loop is
replaying one fixed span, exactly as on target A -- it is simply a cheap span
this time.

# Settled, on target B, from one run: the draw sets the rate

The `armed` arm now records its first laps raw (`first_laps_ms`), because lap 0
of an armed run traverses FORWARD the span a loop run replays. Target B's first
twelve forward laps:

```
0:454.5  1:5.68  2:464.3  3:7.79  4:479.3  5:5.51
6:450.9  7:5.54  8:448.4  9:5.68  10:448.5  11:5.44
```

**Strongly bimodal, alternating ~450 ms and ~5.5 ms** -- and the loop on that
target replays at 6.21 ms. Forward 5.5 ms, replayed 6.21 ms: **replay costs
1.13x. It is nearly free.**

The two modes are the workload: ~5.5 ms is a pipelined response inside a live
connection, ~450 ms is connection turnover -- the client exits, the shell forks
and execs a new one, a fresh TCP connect completes.

## Why this is the reading that stands, after two that did not

This document has now said "not the arming point", then "the arming point",
then "replay is intrinsically 16x", and now "the arming point" again. The last
of those was argued from target A's armed lap 0 (4.31 ms) against target A's
loop lap (69.54 ms) -- **two different runs**. On a distribution where adjacent
laps differ by eighty-fold, two runs arming 0.1 s apart land on different phases
as a coin flip, so that comparison was never valid.

Target B needs no cross-run comparison. Its bimodality is visible WITHIN one
run, and its loop lap sits on the cheap mode of its own forward distribution.
Same target, same reset, same configuration: a draw on the 450 ms phase gives
about 2 exec/s and a draw on the 5.5 ms phase gives 155. **A 70x swing from the
draw alone**, with everything else held fixed.

That also re-explains target A without needing a mechanism: 69.5 ms is inside
its own forward range (max 122.9 ms). It is a tail draw, not a slow replay.

## What this makes the highest-value change in the lane

| | forward gaps | loop replays at | exec/s |
|---|---|---|---|
| target A (armel) | 2.8-122.9 ms, heavy tail | 69.5 ms -- tail draw | 14.4 |
| target B (mips-BE) | bimodal 5.5 / 450 ms | 6.21 ms -- cheap draw | 155.4 |
| target C (mipsel) | -- | 0.837 ms median, 536 ms tail | 41.5 |

The arm health check rejects a draw that FAULTS and a draw that is IDLE. It does
not reject a draw that is SLOW, and it does not record the data that would let
it: the probe times no laps, and warmup counts hits without recording intervals.
Both are one line each to capture, and the rejection then works exactly like the
other two axes.

The measured stake is 70x on target B and roughly 16x on target A -- against the
2.8x this whole session bought by every other means combined.

## The reductio: on target B the same comparison says the reset makes the guest 36x FASTER

Target B's armed run has an `iter_ms` median of **222.8 ms** -- the midpoint of a
50/50 bimodal split between 5.5 ms and 450 ms. Its loop replays at 6.21 ms.

| | armed median | loop lap | the loop "looks" |
|---|---|---|---|
| target A | 8.73 ms | 69.54 ms | **8x worse** |
| target B | **222.8 ms** | **6.21 ms** | **36x better** |

Same reset, same code, opposite verdicts. The armed-vs-loop comparison was never
measuring the reset in either direction; it was measuring which span the arm
landed on, against an average over all spans.

**This document's opening claim -- "the reset adds 60.8 ms of guest time while
spending 0.49 ms doing it, a factor of 124" -- is an artifact of that
comparison.** Target B is the reductio: taken at face value the same arithmetic
says the reset makes the guest thirty-six times faster.

What survives, and it is the part worth keeping:

- the reset is a **0.46-0.55 ms constant** across three architectures, 38-281
  pages and 403 MB-2.16 GB. That is measured directly as `sched_to_bh`, not
  inferred from a difference, and it is the same on all three targets.
- everything else in a lap is the span, and the span is chosen by the arm.

## The TCG counters: the reset discards zero translated blocks

The translation hypothesis had survived only by not being measured. `tbskip`
tested it by *removing* work and found no speedup, which is weak evidence: it
cannot distinguish "the work was cheap" from "the work was never happening".

QEMU already maintains the counters that settle it -- `tb_ctx.tb_flush_count`,
`tb_ctx.tb_phys_invalidate_count`, and `cpu->neg.tlb.c.{full,part,elide}_flush_count`.
Exporting them through the fastsnap ABI and sampling at bottom-half-done and at
lap close gives the work each reset does and the work the guest then does,
separately. `FASTSNAP_COUNT_UNCHANGED=1` additionally memcmps each restored page
against the live one before overwriting it, counting dirty-but-identical pages
without changing behaviour.

Both targets, cost axis off, `penguin:fstcg`:

| per reset | target A (armel) | target B (mips-BE) |
|---|---|---|
| pages restored | 177 | 282 |
| `sched_to_bh` | 386 us | 556 us |
| **`tb_phys_invalidate`** | **0** | **0** |
| **`tb_flush`** | **0** | **0** |
| **`tlb_full_flush`** | **0** | **0** |
| pages dirty-but-identical | 23 (13.0%) | 25 (8.9%) |

**The reset discards no translated block on either target**, despite calling
`tb_invalidate_phys_range()` once per restored page. Every one of those calls
finds nothing, because the restored set is pure data -- stack, heap, buffers. A
code page is never written, so it is never dirty, so it is never restored.

Three things follow, all now measured rather than argued:

- **Translation is not the cost.** With `tb_invalidate` and `tb_flush` both zero
  the guest resumes with a fully warm TB cache and re-translates nothing. This
  is the direct form of the evidence `tbskip` only gestured at -- and it
  retroactively explains why `tbskip` changed nothing: there was nothing to skip.
- **The softmmu TLB is not the cost either.** `tlb_full_flush` = 0 replaces the
  indirect `devonly` argument with a count.
- **The over-invalidation instinct was half right, and now has a number.** No
  live translation is being killed, but 23 of 177 (13.0%) and 25 of 282 (8.9%)
  pages were copied and invalidated while already byte-identical. Skipping those
  saves ~10% of the copy -- on the order of 40-50 us of a 386-556 us reset -- and
  nothing in invalidation, since invalidation finds nothing either way.

### The caution these runs also carry

The target A arm here came out at **27.35 ms / 177 pages**; the earlier arm of
the same config came out at **69.54 ms / 227 pages**. Same target, same plugin,
cost axis off in both. A 2.5x swing between draws is one more measurement of the
same finding -- the draw dominates -- and a standing caution that any
single-arm lap number in this document carries that much variance.

### What these counters cannot answer

They measure work the reset does and work the guest does, both after the
snapshot. They do not compare against the guest *before* any reset, which is the
comparison the replay-cost question needs. `arm_forward_probe` adds that: one
forward traversal of the span, timed at the same arming point, before the first
reset runs.

### Decision on the skip-if-identical change: measured, and not worth making

The obvious follow-on is to act on the count -- skip the copy and the
invalidate when the memcmp says the bytes already match. The counters argue
against it:

- the saving is ~10% of the copy, so **40-50 us of a 386-556 us reset**;
- the reset is 0.5 ms of a 6-70 ms lap on targets A and B, so the saving is
  **under 1% of an iteration**;
- it is not free. The memcmp is a 4 KB read per page in the identical case and
  a wasted partial read in the other 87-91%, so a chunk of the 10% is spent
  earning it back.

It stays **counted and not acted on**. The one regime where it could matter is
target C -- 38 pages, 0.461 ms reset against a 0.837 ms lap, where the reset is
**55% of the iteration** rather than under 1%. If the lane ever optimises for
that regime, re-measure the overbreadth fraction there first: it is not
measured on target C, and 13% on a 177-page restore does not predict it.

## A prediction, written before the forward-baseline runs report

Target B has now armed twice, independently, in runs whose only configured
difference was the cost axis:

| | forward gaps during warmup | loop replays at | ceiling | verdict |
|---|---|---|---|---|
| cost=off | n=10844 (target A), median 5.30, p10 2.31, p90 16.05, max 502 | 27.35 ms | -- | -- |
| target B cost=off | -- | 6.216 ms | -- | -- |
| target B cost=on | n=218, **median 182.8**, p10 5.53, p90 464.3, max 1334 | 6.258 ms | 16.89 ms | arm 1 accepted, 0 rejects |

Target B's forward distribution has a **median of 182.8 ms** and a p10 of
5.53 ms. Its loop replays at **6.26 ms** -- sitting essentially ON the p10.
And the previous run, with the axis off entirely and therefore no selection
pressure at all, landed at **6.216 ms**: the same place.

Twice, from a distribution where roughly ninety percent of forward gaps are
above 16.9 ms. That is not a draw landing lucky twice. It is structural, and
it means the "the arm draws uniformly from the forward distribution" framing
this document has been using is at best incomplete.

The obvious mechanism: arming stops the vCPU for ~250 ms. Whatever the client
had in flight queues up, so the first span after resume is a request already
waiting -- the cheap, pipelined mode -- rather than a fresh connection.

**Prediction, recorded before `arm_forward_ms` reports.** If arming
systematically lands on the cheap mode, the single forward traversal timed at
the arming point will come back near **6 ms on target B, not near 182 ms**,
and the replay cost `iter_ms / arm_forward_ms` will be close to 1. If instead
it comes back near the forward median, the reset really does change which span
follows, and the cheap replay is an artifact of the restore rather than of the
arm.

The two readings are opposite and the measurement distinguishes them, which is
the only reason this is worth writing down in advance.

### What it would mean for the cost axis either way

If arming lands cheap by construction, the cost axis is worth much less than
the 70x headline: it would be selecting among draws that are already good, and
target B's two accepted arms -- 6.216 and 6.258 ms, with and without the axis
-- are the evidence. The axis's remaining value is then as a GUARD, catching
the target A case where the arm landed in virtio-blk I/O at 2,625 ms, rather
than as a source of speedup. That is still worth having; it is just a different
claim, and a much smaller one.

## The prediction was wrong, and the way it was wrong is the finding

The prediction recorded above said: if arming systematically lands on the cheap
mode, target B's forward traversal comes back near **6 ms**.

It came back at **476.59 ms** -- the p90 of its own forward distribution, the
expensive mode. The prediction is falsified. The alternative named alongside it
is what happened: *the reset really does change which span follows, and the
cheap replay is an artifact of the restore rather than of the arm.*

Both targets now have the same measurement, from the same arming point, within
a single run, with the oracle certifying the restore in both cases:

| | forward traversal | replayed lap | ratio | oracle |
|---|---|---|---|---|
| target A (armel) | **3.79 ms** | **14,949 ms** | **3,945x SLOWER** | VALID, 403 MB |
| target B (mips-BE) | **476.59 ms** | **6.28 ms** | **76x FASTER** | VALID, 2.16 GB, 10 verifications |

Opposite directions, same cause. And the oracle is what makes the argument
airtight rather than suggestive: it proves the guest state is restored byte for
byte -- 2.16 GB of it on target B, ten times over -- so **the divergence cannot
be in the guest state**. It has to come from outside.

### What is outside the snapshot

The host-side socket, the virtio queue, and everything else the guest talks to.
The reset rewinds the guest; it does not rewind the world.

- **Target A**: the input was consumed during the armed span and is never
  redelivered. The guest replays into a `read()` that will not complete, and
  waits on a timer. The lap sequence is the signature: 4.1 s, 8.5 s, 14.9 s,
  then flat to **0.3% across sixteen laps**. Fifteen seconds with that little
  variance is a timeout firing, not a workload running.
- **Target B**: the input arrived DURING the 476 ms forward traversal and is
  still queued when the replay starts. The guest never waits. Every draw on
  target B replays at ~6.2 ms for this reason -- which is why its two earlier
  arms, one with the cost axis off entirely and therefore under no selection
  pressure, both landed at ~6.2 ms. That was read as "the arm lands cheap by
  construction". It is not. The RESTORE lands cheap by construction.

### What this costs the numbers in this document

The faster direction is the dangerous one, because it reads as success. Target
B's 155 exec/s is a verified, byte-identical, ten-times-certified measurement
of **a span whose input was already there** -- not of the span that was armed.
The same applies to any rate in this lane taken from a replay that outruns its
own forward traversal, and that includes the headline the lane opened with.

This is the same failure the idle axis exists to prevent -- an excellent number
for a guest that is not doing the work -- arriving through a different door, and
past an oracle that is working perfectly and is simply not looking at the world.

### Handling: the two directions are not symmetric

- **SLOWER** -> the cost axis re-arms. A different draw may not depend on input
  that is gone.
- **FASTER** -> re-arming cannot help, because the mechanism is structural.
  Every draw shows it. What the run can do is refuse to let the rate be quoted
  as if it were real, and `_replay_fidelity()` now puts that refusal in the
  VERDICT SENTENCE rather than beside it.

### The open question this leaves

Whether a faithful loop is reachable at all without rewinding host-side I/O --
and if it is not, whether the right move is to drive input from inside the
snapshot boundary so there is no host-side state to rewind. That is a design
question for the lane, not a measurement, and nothing here answers it.

## Three targets, three divergences: none of them replays its armed span

Target C closed the set. Every target that rehosts cleanly enough to fuzz has
now had one forward traversal timed at its arming point and compared against
the laps that replay the same span:

| | forward | replayed | ratio | lap flatness | oracle |
|---|---|---|---|---|---|
| target A (armel) | 3.79 ms | 14,949 ms | **3,945x slower** | 0.3% over 16 laps | VALID, 403 MB |
| target B (mips-BE) | 476.59 ms | 6.28 ms | **76x faster** | -- | VALID, 2.16 GB x10 |
| target C (mipsel) | 1.64 ms | 160.02 ms | **97x slower** | **0.09% over 5 laps** | VALID, 2.16 GB |

**Three for three. Not one replays faithfully**, and every restore was certified
byte-identical against an independently forked reference. Two architectures
diverge slow, one diverges fast, and the two slow ones both show the timeout
signature rather than a workload: target C's laps are 159.91, 160.06, 159.98 ms
-- **flat to 0.09%**. Nothing a guest computes is that repeatable; a timer is.

This is no longer a per-target quirk or a bad draw. It is a property of
resetting a guest whose work is driven by I/O that lives outside the snapshot.

### The rates in this document, restated

Every exec/s figure in this lane was measured on a replayed span. Three of them
can now be read against the span they claimed to be measuring:

| | reported | what the forward traversal says |
|---|---|---|
| target A | 14.4 exec/s | measured a guest waiting on a timeout |
| target B | 155.4 exec/s | measured a span whose input had already arrived |
| target C | 41.5 / 1,195 exec/s | measured a guest waiting on a timeout |

The arithmetic in each run is correct and the oracle is correct. What was wrong
is the referent: "iterations per second" was being read as "iterations of the
armed span per second", and the two are not the same quantity once the world
outside the snapshot stops matching.

### What the cost axis can and cannot do about it

The ratio axis rejects a divergent draw and re-arms. Whether that helps is an
open empirical question and the instrumented runs now in flight are the test:
if the divergence is structural -- as target B's every-draw-is-6.2 ms behaviour
suggests -- then all four attempts will diverge on all three targets, re-arming
is futile, and the only honest output is the refusal `_replay_fidelity()` writes
into the verdict.

That would make the fix a design change at the I/O boundary rather than a
scoring change at the arm, and this document should not pre-empt which.

## The payoff test, against an axis that can fire

All three targets, cost axis on, with the early fire, the relaxing ladder and
the ratio axis in place:

| | arms | forward traversals | accepted lap | fidelity | exec/s wall | exec/s median |
|---|---|---|---|---|---|---|
| A (armel) | 3 (2 rejected early) | 3.77 / 4.99 / 3.92 ms | 44.27 ms | **slower 11.7x** | 22.4 | 22.6 |
| B (mips-BE) | 1 (accepted) | 467.08 ms | 6.24 ms | **faster 75x** | 154.7 | 160.3 |
| C (mipsel) | 3 (2 rejected early) | 2.21 / 2.19 / 2.11 ms | 1.70 ms | **faithful 0.77x** | 82.6 | **589.6** |

**The earlier conclusion that re-arming is futile was drawn from target A alone
and does not generalise.** Target C is the counterexample: the axis rejected a
180 ms draw and a 20 ms draw, and the run it kept has a lap median of 1.70 ms
against a 2.21 ms forward traversal -- a ratio of 0.77, the first **faithful**
replay this lane has measured on real firmware.

Against target C's own forward-baseline run, which drew without the axis:

| target C | lap median | exec/s wall | exec/s median | fidelity |
|---|---|---|---|---|
| cost axis off | 160.02 ms | 4.9 | 6.2 | 97x slower |
| cost axis on | **1.70 ms** | **82.6** | **589.6** | **faithful** |

A 94x improvement in median rate, and -- more to the point -- the difference
between a number that measures a timeout and a number that measures the span
it claims to. Two different runs and therefore two different draws, so part of
that gap is luck; the fidelity ratio is the part that is not.

So the three targets land in three different places, and the axis is doing
something different in each:
- **A**: every draw diverges slow, consistently ~11.5x. Re-arming does not
  help. The refusal in the verdict is the whole value.
- **B**: diverges fast, structurally, on every draw. Re-arming cannot help by
  construction, the axis correctly does not try, and the refusal is again the
  whole value.
- **C**: the divergence is per-draw, and re-arming FOUND a faithful one.

### The limit of the early fire, stated rather than hidden

Target C's probe medians were 180.1, 20.3 and 19.5 ms, and the run it accepted
has an overall median of 1.70 ms. The first 200 laps of the accepted draw sat
flat at ~19.5 ms and the eventual distribution is bimodal -- p10 0.85 ms, p90
20.1 ms. **The probe is not a stationary sample of the run it is scoring.**

That cuts directly at the early fire, which decides on five laps. Those five
were flat to under 1% in every case here, so they estimated the early laps
well -- but a draw rejected at lap 5 might have transitioned the way the
accepted one did, and having rejected it there is no way to know. The honest
statement is that the early fire is a decision made on the first five laps of a
distribution that is demonstrably not stationary, and that it bought a real
result on C anyway.

The test that would settle it: re-run C with `arm_cost_min_laps` raised past
the transition, and see whether the 180 ms draw is still 180 ms at lap 500.
Not run here.

## Cornering target A: seven hypotheses, six dead

Target A replays its armed span consistently 11x slower than it traverses it
forward. Each of these was a live explanation at some point in this lane, and
each is now closed by a measurement rather than by an argument:

| hypothesis | verdict | the measurement that closed it |
|---|---|---|
| TB invalidation | dead | `tb_phys_invalidate` = **0** per reset |
| cold translation after flush | dead | `tb_flush` = **0** |
| softmmu TLB flush | dead | `tlb_full_flush` = **0** |
| memcpy overbreadth | dead | 13% dirty-but-identical, ~40 us of a 500 us reset |
| the detector / epoll idle | dead | `writev` **11.06x** against `read`'s **11.73x** |
| laps closing in another process | dead | 1 distinct pid, **0** hits outside the armed one |
| an unlucky draw | dead | 3 draws, all ~11x, forward tight at 4.15 / 4.15 / 4.22 ms |

The fifth is worth a note: target A's own config comment predicted exactly the
failure we measured -- *"a snapshot armed while it idles in epoll_wait would
resume every reset into a blocking wait, and the measured interval would be the
idle timeout rather than the loop"* -- and the detector had been switched to
`read` anyway. Switching it back changes nothing, so the comment was right
about the risk and wrong about this being it.

Target C agrees at **8.03x** (2.33 ms forward, 18.70 ms replayed), same
process, same zero counters. Two architectures, one shape.

### What the counters cannot say, and the measurement that can

Every TCG counter reads zero across the 46 ms guest half. That is consistent
with BOTH readings and distinguishes neither: steady userspace execution
flushes no TLB and invalidates no translated block, and neither does a halted
vCPU. The two call for completely different fixes -- a lap spent waiting is the
period of whatever it waited on, not a cost of the reset.

`lap_cpu_frac` closes that gap. The plugin runs in QEMU's process on the vCPU
thread, so `thread_time()` is that vCPU's CPU time: it advances while the guest
executes and stands still while the vCPU sleeps on a halt. Near 1 is work; near
0 is waiting.

### The three-arm discriminator

Each arm removes one more thing, so whichever one moves the number is the
answer rather than the next guess:

| arm | what it removes |
|---|---|
| `feed` | the host-side socket -- snapfeed answers reads from inside the boundary |
| `pin` | + hooks confined to the arming process and its children |
| `exclusive` | + every other userspace task STOPPED before the snapshot |

Baseline, same target and detector: forward 4.15 ms, lap 46.63 ms, **11.06x**,
21.4 exec/s.

If all three stay at ~11x it is none of them, and the remaining suspect is the
clock -- which is not rewound, and which `mc146818rtc` is already excluded from
the device scope for failing to round-trip.

## The answer: feed the guest from inside the boundary

Three arms on target A, each removing one more thing, against a baseline of
forward 4.15 ms / lap 46.63 ms / 11.06x slower / 21.4 exec/s:

| arm | lap | exec/s | oracle | outcome |
|---|---|---|---|---|
| `feed` | **4.32 ms** | **231.6** | VALID, 403 MB, 20 verifications | **10.8x** |
| `pin` | 1048 ms | 0.95 | FAILED (virtio unrestored) | a bad draw, and an inert pin |
| `exclusive` | -- | -- | UNVERIFIED, no laps | starved the workload |

**Feeding is the whole win.** The replayed lap lands at 4.32 ms against the
baseline run's un-reset forward traversal of 4.15 ms: the divergence did not
shrink, it is gone. The loop now replays its armed span at the cost of
traversing it.

And `lap_cpu_frac` = **0.916** says what the TCG counters could not. The guest
is now EXECUTING. Which settles what the baseline's 46 ms was: roughly 42 ms of
waiting and 4 ms of work.

That restores the hypothesis this document abandoned. On finding the load
generator was in-guest, the host-side-I/O account looked wrong; it was not. It
does not matter which side of the snapshot boundary the peer sits on -- only
that the victim had to WAIT for one at all. snapfeed answers the read before it
reaches any peer, so there is nothing left in the iteration to wait for.

### Why the other two arms did not help

**Exclusive mode worked and starved the run.** The driver did exactly what it
was built to do -- 17 userspace tasks signalled, `frozen_pending` 0, so every
one of them actually stopped, and the asynchronous-SIGSTOP settle poll held.
But the in-guest load generator is one of those 17. With it stopped no new
connections arrive, snapfeed can only feed fds it already learned from
`accept`, and the loop managed 115 hits and never completed a verification.

The pairing that would fix it is to learn the fds BEFORE freezing and keep
feeding them, which is what already happens -- the shortfall is that a
keep-alive connection eventually closes and there is no client left to open
another. A feeder that could synthesise `accept` as well as `read` would close
that gap. Not built.

**The pin was inert.** It reported `active=1` with a resolved pid and
`hits_in=0, hits_out=0`: the pin was set and no hook ever consulted it, because
nothing set `pin_filter_enabled`. A pin that nothing consults is
indistinguishable from a working one if the only thing checked is that it was
set -- which is why `hits_in`/`hits_out` are in the report at all.

### What the pin is actually for

Not speed. On target A the detector fired 22,143 times from a single pid with
zero outside it, so there was nothing for it to exclude. It is a correctness
guard for the case that measurement cannot rule out in advance: a forked worker
or a restarted victim carrying the same `comm`. Whether it ever fires on these
targets is now measurable rather than assumed.

## CORRECTION: it was not the feeding, and the win does not have one setting

The section above -- *"feeding from inside the boundary is the whole win,
10.8x"* -- is wrong, and wrong in the way this lane keeps being wrong: one arm
changed two things and the conclusion took the credit for the wrong one.

The `feed` arm had `swallow_writes` ON. Isolating it on target A:

| target A | swallow | pin | lap | exec/s |
|---|---|---|---|---|
| `feed` | on | off | **4.32 ms** | **231.6** |
| `pin` | off | on | 118.96 ms | 8.41 |
| `Ans` | off | off | 122.30 ms | 8.18 |

The pin is worth nothing for speed -- 118.96 against 122.30 is noise.
**`swallow_writes` was the entire 28x.** Feeding reads alone gives ~8 exec/s.

And on target B the same switch has the OPPOSITE sign:

| target B | lap | exec/s | fidelity |
|---|---|---|---|
| no snapfeed (the lane's old number) | 6.24 ms | 160 | **75x faster -- fictional** |
| snapfeed, swallow ON | 1038 ms | 0.96 | faithful 1.001 |
| snapfeed, swallow OFF | **35.86 ms** | **27.9** | **faithful 1.685** |

### Two loop shapes, not one setting

That is not a contradiction. There are two ways to run this loop and they want
opposite configurations:

**Client-driven** (B with swallow off). The real client receives the response,
sends the next pipelined request, `select` reports readable, and snapfeed only
substitutes the payload bytes. The client is the engine, so swallowing the
response stops the engine.

**Closed loop** (A with swallow on). No client in the iteration at all: `read`
is answered from guest RAM, `write` is discarded, and the victim spins on
parse. Faster, and the better fuzzing mode -- the iteration is one parse of one
mutated input, with nothing outside the snapshot in it. But it only works if
the victim's event loop REACHES `read()` without a client.

That last clause is why A won and B did not. A gets to `read()`. B blocks in
`select()` first, so snapfeed was feeding perfectly into a victim that was not
listening. Both vendor httpds in this lane import exactly
`accept read recv select`.

### The honest rates so far

| | before | after | what changed |
|---|---|---|---|
| target A | 21.4 exec/s (11x divergent) | **231.6**, closed loop | both ends synthesised |
| target B | 160 exec/s (75x FASTER, fictional) | **27.9**, faithful 1.685 | fed, client-driven |
| target C | 41.5 / 1,195 (8-97x divergent) | not yet measured | crashes; needs reset_on_signal |

Target B's number went DOWN, and that is the point. 160 exec/s was a verified,
byte-identical, ten-times-certified measurement of a span whose input had
already arrived. 27.9 is a measurement of the span that was armed.

## The census answers what three hypotheses could not

Fifteen counting hooks, no intervention. Target A, one run:

```
close 3181, epoll_wait 2848, accept 1331 (=accept4 1331, one call under two
names), shutdown 304, recvmsg 6, poll 5, sendto 4, futex 2
```

**`epoll_wait`, 2848 calls.** That is what lighttpd blocks in. Not `select` --
which is why target B's select handler, correctly registered and enabled, fired
exactly zero times. The hypothesis had the right shape (the victim waits before
it reaches `read`) and the wrong syscall, and no amount of reasoning was going
to fix that; one census run did.

Target C's census says something different and equally decisive:

```
close 733, accept 542 (=accept4 542), recvfrom 6
```

**A connection-per-request server.** 542 accepts, 733 closes, one fed read each,
and `recvfrom` appearing six times in five minutes. Its request boundary is
`accept()`, and every C run in this document armed on `read` -- which for C is
usually a FILE read. That is why `snapfeed.n_sent` never advanced across 200
probe laps and the idle axis refused the run: correctly, and for a reason no
other axis would have caught.

### Two ways this data was misread, both here

- **`recvfrom: 6` was read as "C reads its sockets with recvfrom."** Six calls
  in five minutes is never; 675 of C's 681 feeds came through `read()`. A whole
  run was queued against a detector the victim barely calls before the
  magnitude was checked. A name being present is not a mechanism.
- **`accept` and `accept4` at identical counts were nearly added together.**
  One syscall under two names, 542 and not 1,084.

Both are now flagged in the output (`census_aliases`, `census_top`). Having the
instrument is not the same as reading it.

### What a closed loop on B would take, and why it is not built here

`epoll_wait` would have to be answered the way `select` now is. That is a
bigger change than it sounds and should not be written at the end of a long
session:

- `epoll_ctl` has to be tracked to learn which fds are registered against which
  epfd -- `epoll_wait` names neither.
- The reply is an array of `struct epoll_event`, whose layout is
  arch-dependent: packed to 12 bytes on x86-64, 16 bytes on 32-bit ARM where
  the `u64` member forces alignment. Writing the wrong stride into guest memory
  corrupts the victim rather than accelerating it, and would do so silently.

The evidence for doing it is strong and specific. The evidence that it must be
done carefully is the rest of this document.

### Neither target needs it to be measured

Target B already has an honest rate in the client-driven shape -- **27.9
exec/s**, fidelity 1.685, VALID across 2.16 GB. The closed loop is an
optimisation on top of a working measurement, not a prerequisite for one.

## Target C: five misconfigurations deep, and still not measured

C was configured throughout by analogy to A and B, and it is a different kind
of server. Each assumption was invisible until a control refused to report a
number:

| # | assumption | reality | caught by |
|---|---|---|---|
| 1 | answers with `writev` | answers with `write` | empty response tally -> false "wedged victim" |
| 2 | reads with `read` | **675 of 681 feeds came via `read`; `recvfrom` appears 6 times** | `FED NOTHING`, 556 accepts / 8 reads |
| 3 | request boundary is a read | connection-per-request; boundary is `accept` | `idle, out of retries` x3 -- laps were closing on FILE reads |
| 4 | keep-alive client | closes after one request, so the 20-request pipeline wasted 19 and `nc -w 3` sat out its timeout | accept-to-accept = **1042 ms** |
| 5 | `swallow_writes` helps | C is client-driven like B; the response IS the engine | (queued, not yet reported) |

**Not one of those produced a wrong rate.** Four runs were refused, each naming
a different reason. The alternative -- a loop reporting 41.5 exec/s and letting
a reader believe it -- is what this lane had before the arm axes and the
fidelity check existed.

### The unresolved part, stated rather than guessed at

After rewriting the load generator to four parallel connection-per-request
loops, the run came back with a census **identical to the digit** to the run
before it -- `accept 949/949, close 732, recvfrom 6`, `n_sent 684` -- despite a
different drive script. The new script is present in that run's merged
`core_config.yaml`, and the guest console shows
`[IGLOO] user init dispatched /igloo/init.d/zz_fastsnap_drive` and
`FASTSNAP_DRIVE_START ... waited=4s`, so something ran. Two readings fit:

- the guest received the OLD script (a `static_files` write to
  `/igloo/init.d/` that does not take effect without re-initialising the
  project), and the identical census is simply the same workload twice;
- or the ~2.26 accepts/sec being counted are the firmware's own internal
  traffic and the drive script's connections never reach the hooked `httpd` at
  all.

The first is testable by diffing the file inside the guest; the second by
attributing accepts to a peer. Neither was run. **C's rate is unknown, and
nothing in this document should be read as measuring it.**

### Why stop here

A and B have honest rates. C has five fixed misconfigurations and a sixth
question that wants a different kind of investigation than "queue another
run" -- which is what the previous five each cost. Handing it over as a named
open question is worth more than a sixth guess at 5am.

# The replay penalty looks like a TIMEOUT, not a cost

Measured 2026-09-15 from `results/86`, a later run than everything above, on
the same target A project. It is the sharpest evidence this lane has produced
about the 60 ms, and it points somewhere none of the three killed hypotheses
did.

| attempt | forward traversal | replayed probe lap | ratio |
|---|---|---|---|
| 1 | **2.59 ms** | 1054.99 ms | **407x** |
| 2 | 1050.17 ms | 1054.78 ms | 1.0 |
| 3 | 1051.98 ms | 1054.80 ms | 1.0 |

Two facts here, and the second is the one nothing above anticipated.

**The replayed laps are flat to 0.02%.** 1054.99, 1054.78, 1054.80 across three
independent arms at three different instants (152.2 s, 167.3 s, 183.4 s), and
the accepted arm then ran 215 laps with a median of 1053.68 ms. A workload does
not do that. A timer does. This file already used exactly that reasoning to
classify target A's 14,949 ms case -- "flat to 0.3% across sixteen laps, which
is a timeout firing and not a workload" -- and the same test applied here gives
the same answer with a tighter tolerance. ~1.05 s is a plausible round number
for a poll or connect timeout.

**The slowdown PERSISTS past the reset.** Attempt 1 measures the forward span
at 2.59 ms. After that arm is taken and rejected, attempts 2 and 3 measure the
FORWARD span -- no replay involved -- at 1050 and 1052 ms. The first
arm/restore left the guest in a state where ordinary forward traversal is 400x
slower, and it stayed there. That is not a property of replaying; it is damage
that outlives the restore.

This matters for the arm-cost axis, which is built on the assumption that
draws are independent samples of a fixed forward distribution. They are not:
the act of arming changes the distribution the next attempt samples. The
ladder widened 11.9 -> 17.8 -> 26.8 ms chasing a population that had already
moved to 1050 ms, rejected all three, and accepted the last one anyway -- which
is the documented and correct behaviour for a costly draw, but it means the
axis cannot help on this target. It is not choosing badly among good draws; by
attempt 2 there are no good draws left to choose from.

**What this predicts, and how to falsify it.** If it is a timeout, the lap
length is set by a constant in the victim or the driver script and not by any
amount of emulation, so: (a) it will not move when the reset is made cheaper,
(b) it will not scale with pages restored -- which is already observed, 194
pages costing MORE than 227 -- and (c) it should be visible as a single
blocking syscall consuming ~1.05 s of every lap. (c) is the discriminating
test and it is now cheap to run: `hook_budget: 1` on the syscalls API counts
hook firings per syscall, and `snapfeed`'s census names blocking calls. A lap
that spends 1.05 s in one `poll`/`select`/`connect` is a timeout; a lap that
spreads it across thousands of ordinary syscalls is emulation.

Worth stating plainly: **the 69.54 ms figure this document is built on and the
1053 ms here are probably the same phenomenon at different timeout values**,
not two different regimes. Neither was ever traced to a blocking call, because
nothing counted blocking calls until now.

## The arming draw is the whole rate, and the default was making it worse

Four runs, 2026-09-15, same project, same image, same target, differing only
in which instant the arm caught and (from run 90) `arm_retries`:

| run | `arm_retries` | attempts | accepted lap | exec/s | armed span fwd | lap/fwd |
|---|---|---|---|---|---|---|
| 88 | 3 | 1 | 3.30 ms | **303.3** | 2.39 ms | 1.377 faithful |
| 89 | 3 | 3, all costly -> **accepted anyway** | 1054.58 ms | **0.9** | ~1052 ms | ~1.0 faithful |
| 90 | 12 | 3 (2 costly, 3rd cheap) | 4.43 ms | **225.7** | 3.67 ms | 1.207 faithful |
| 91 | 12 | **4 (3 costly, 4th cheap)** | 4.97 ms | ~~201.1~~ | 1052.01 ms | **0.005 -- not a rate** |

> **CORRECTION, 2026-09-16, twice.** This table was first written quoting all
> four exec/s numbers as throughput. It was then rewritten striking three of
> them as "not rates". The second version was wrong for two of the three, and
> this is the third and, I believe, correct reading.
>
> What settles it is what `arm_forward_samples` actually contains. The five
> samples behind a draw are five **consecutive, different spans** -- the
> `fwd_probe` state clocks the armed instant to the next detector hit, then
> that hit to the next, and so on. They are not five measurements of one span.
> Only **sample 1** starts where every replayed lap starts, so only sample 1
> is the controlled comparison: same starting state, one traversal without a
> reset against many with one. Samples 2-5 begin from states the loop never
> visits.
>
> `_replay_fidelity` scored against their **median**, and on a workload that
> alternates between serving a pipelined request (~3 ms) and waiting out a
> connection boundary (~1050 ms), the median is a cost the armed span never
> takes. Run 88's sample 1 is **2.39 ms** against a 3.297 ms lap -- ratio
> **1.377**, faithful, and 303.3 exec/s is a real rate. Its median is 1051.94,
> which is where "319x diverged" came from.
>
> The corrected reference does not flatter everything, which is the reason to
> trust it: run 91 armed on the expensive mode -- sample 1 is 1052.01 ms
> against a 4.97 ms lap -- and is a genuine 209x divergence by either
> reference. Its 201.1 exec/s stays struck.
>
> Independently corroborated: the **warmup gap** distribution, sampled with no
> arming pause anywhere near it, is itself bimodal on runs 88, 90 and 91
> (p10 ~2.4-3.7 ms against a median ~1050 ms). The cheap mode is the workload
> -- pipelined requests inside one connection -- not an artifact of the vCPU
> stop. Run 99's warmup p10 is 1051 ms: that run had no cheap mode to arm on,
> which is why it reports 0.94 exec/s honestly.
>
> The ordering defect found on the way is real and is fixed regardless. Run
> 88's verdict opens `VALID: 20 verifications, every one byte-identical...` --
> a statement about the RAM oracle alone -- and reached `REPLAY DIVERGES` four
> sentences and ~400 characters later; the `RESULTS` line printed
> `exec_per_s=303.30` with no qualifier at all. `fastloop` now emits
> `exec_per_s_valid`, leads an otherwise-`VALID` verdict with `RATE IS NOT A
> RATE (...)` when it must, and repeats it on the `RESULTS` line;
> `loopcmp.py` prints `fwd1_ms` and `fid1` beside every rate. That the fixed
> instrument's first act was to overturn the conclusion that prompted it is
> the point of fixing it.

**Run 91 is the direct evidence, and run 89 is what it would have been.** Its
first three draws replayed at 1067.68, 1056.73 and 1055.63 ms and were each
correctly called costly. Under the old default of 3, the third of those is
where the counter ran out and the draw is taken regardless -- the exact path
run 89 went down for 0.9 exec/s. With retries available, attempt 4 came back
at 5.11 ms and was accepted on merit. A 207x difference on one run, from a
default.

So `LEAN-LAP.md` was right and this file was wrong to dismiss it: **the arming
point sets the rate.** The reset is a 0.5 ms constant, penguin's syscall hooks
are ~15% of it, and the draw is the rest.

The hook share is now measured rather than extrapolated, and it moved. The
earlier ~35% came from dividing `hook_budget`'s whole-run total by the loop's
iterations, which charges laps for the tens of thousands of hook firings boot
is responsible for. Run 106 carries an `armed` mark, so the split is directly
available: 33,545 firings total, 23,154 already spent by the time the loop
armed, leaving 10,391 across 2,000 laps -- **5.2 firings per lap, 0.498 ms**
at the measured 95.880 us/firing. Against that run's 3.346 ms lap the budget
is:

| term | per lap | share |
|---|---|---|
| reset | 313 us | 9.4% |
| penguin syscall hooks | 498 us | 14.9% |
| the guest actually serving the request | ~2.54 ms | 76% |

Part of the drop is real rather than arithmetic: census off, `one_outstanding`
and the epoll answer cut the hook traffic, and a held-open connection removes
the `accept`/`accept4` pair that fired 3,085 times in run 99. Runs without an
armed mark cannot be compared against this and `loopcmp` now says so instead
of printing them side by side.

What the draw decides is which mode of a bimodal workload the replayed span
sits in. This victim is connection-per-request: inside a connection it serves
pipelined requests in ~3 ms, and at a connection boundary it waits ~1050 ms
for a guest `fork`+`exec` of the driver that `snapfeed` cannot synthesise.
Arm inside a connection and every lap is a 3 ms request/response -- runs 88
and 90, at 303.3 and 225.7 exec/s, both faithful. Arm on a boundary and every
lap replays the wait -- run 99, 0.94 exec/s, also faithful. Run 91 is the
third case: armed on a boundary whose input had already arrived, so the replay
skips the wait the span contained and its rate is not a rate for it.

The mechanism is no longer mysterious either. `fastloop`'s own verdict names
it: the armed span either does or does not contain a ~1.05 s wait for input,
and a replay never pays that wait again because the input is already queued.
That is why the expensive laps are flat to 0.02% -- a timer, not a workload --
and why 194 pages could cost more than 227. The three device- and cache-level
hypotheses this file built and killed were all looking for a cost; there was
no cost, there was a wait.

**What the retry change does not fix.** It buys more draws; it cannot make a
target whose every draw is expensive into a fast one. Runs 89 and 91 both drew
three expensive spans in a row, so the cheap mode here is well under half. A
target where it is rarer still would exhaust 12 the same way -- the honest
report for that case is the low rate, which is what "accepted anyway" already
produces, flagged as an unselected sample.

**And it needed a cap to be safe.** `arm_cost_relax` widens the ceiling per
rejected attempt; at 1.5 each it compounds to 86x by attempt 12. Raising the
retries without capping it turns the axis into a rubber stamp -- caught by the
state-machine suite, where a 455 ms lap passed a 1427 ms ceiling and recorded
"accepted". Capped at 4x. Run 91's ladder ran 14.4 -> 21.5 -> 32.3 -> 48.5 ms,
so the cap does not bind until attempt 5, which is the intended shape: forgive
a draw that is merely close, never forgive one that is 300x.
