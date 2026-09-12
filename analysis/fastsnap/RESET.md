# What a reset actually costs on real firmware

`ALLOWLIST.md` measured a fast reset at 0.07 ms, on a synthetic payload in the
slice0 build (since landed in `qemu_builder` as `src/fastsnap/`). This
measures the reset penguin ships today, on
stridelinx, with the guest doing real work.

**656 ms.** Four orders of magnitude off, and the reason is not what it looks
like.

## The measurement

`notrap.py` drives a loop with no per-iteration guest trap: schedule a
`loadvm`, let the guest resume with its CPU state already at the saved point,
detect that it is running again, repeat. There is no breakpoint, no kernel
uprobe handler and no hypercall in the iteration -- which is the whole point of
a snapshot-based iteration.

The loop is asynchronous because it has to be: `panda.load_snapshot()` is
synchronous but must run on the main loop, and there is no main-loop Python
context -- pyplugin callbacks arrive on vCPU threads via hypercall, which is
why even `Snapshot._do_save_now` uses `schedule_snapshot()`. So completion is
detected with one syscall hook, whose cost (0.133 ms, measured) is subtracted.

The snapshot is taken *mid-request*, triggered from a syscall lighttpd only
makes while actively serving. Taken at idle it would sit in `epoll_wait`, every
restore would resume into a blocking wait, and the loop would measure the idle
timeout instead of the restore.

| guest RAM | restores | median | p10 | p90 | rate |
|---|---|---|---|---|---|
| 2G | 25 | **656.2 ms** | 642.4 | 689.6 | 1.52 /s |
| 256M | 25 | **503.4 ms** | 480.5 | 533.1 | 1.99 /s |

Zero errors in both, and both distributions are tight.

## RAM volume is not the cost

The obvious hypothesis -- a full `loadvm` rewrites all of RAM, and 2 GB at
~3 GB/s is ~0.67 s -- matches 656 ms almost exactly, and is **wrong**. Cutting
RAM 8x cut the restore by 1.30x, not 8x. The coincidence was just that.

A two-point fit:

    restore  ~=  481.6 ms  +  0.0853 ms/MB

    2048 MB -> 656.2 ms      256 MB -> 503.4 ms
     128 MB -> 492.5 ms        0 MB -> 481.6 ms

**73% of the 2G restore is fixed cost that does not depend on guest RAM at
all.** It is the `savevm`/`loadvm` path itself: qcow2 internal-snapshot I/O,
the migration stream, device deserialization, TB invalidation. This measurement
does not say which of those dominates; it says the total is ~482 ms and that
shrinking RAM cannot touch it.

## What that means for dirty-page restore

Restoring only dirty pages attacks the **variable** term -- 180 ms of 656 at
2G, 22 ms of 503 at 256M. Necessary, and not close to sufficient: restoring
*zero* pages still leaves ~482 ms, which is 6,880x the fast-path target.

So the two halves of the fastsnap design are not alternatives and neither works
alone:

| | reset | what it removes |
|---|---|---|
| full `loadvm`, 2G | 656 ms | -- |
| dirty pages only, still via `loadvm` | ~482 ms | the RAM term (1.4x) |
| in-memory device blob + dirty bitmap (`slice0`) | **0.07 ms** | the migration path *and* the RAM term |

The Nyx-style approach -- `device_save_kind()` into a plain memory buffer, and
`memory_global_dirty_log` for RAM -- touches neither qcow2 nor the migration
stream. That is what removes the 482 ms, and the dirty bitmap is what keeps the
remaining RAM half cheap once you are off `loadvm`.

> **The middle row of that table is not a shippable configuration, and neither
> is the device half alone.** Both projections above price the *complete*
> mechanism, device block plus RAM. Measured on real firmware, restoring the
> device block without the RAM half corrupts the guest within a handful of
> restores -- see `REALFW.md`. Nothing here is withdrawn; what is withdrawn is
> the idea that the two halves can be landed, or measured, one at a time.

This is the first measured argument for that design choice in this lane. It was
previously an assumption.

## The corrected picture

"The guest trap is the 2.3x lever" is true only *conditional on a fast reset
existing*. Measured today, a sound reset costs 656 ms, so:

| | exec/s | status |
|---|---|---|
| persist loop, trap-based, **no state reset** | 2,567 | measured -- unsound, state leaks between laps |
| same at a syscall boundary | ~3,700 | estimated from a measured delta |
| **no-trap loop, sound reset, today** | **1.5** | **measured** |
| no-trap loop with the slice0 fast reset | ~5,525 | projected |

The trap was never the bottleneck. Reset is, by three orders of magnitude, and
the gap between the last two rows is the entire project.

## Prerequisite worth recording

Snapshotting is active only when `core.snapshot.save_at` or `boot_from` is set.
Without it, `core.immutable: true` gives the drive `snapshot=on`
(`penguin_run.py:657-660`) -- a throwaway overlay whose internal snapshots are
discarded, so `savevm` has nowhere to persist. `save_at: manual` arms the
Snapshot plugin for on-request saves *and* switches the guest to a persistent
qcow2 overlay. Without that the run fails in a way that looks like a bug in the
restore loop.

## The RAM half: four strategies, not one

The libafl detour made it look as though adopting syx-snapshot was *the* route
to a dirty-page restore. It is not; it is one implementation of one of these.
The device block already landed is orthogonal and pairs with B, C or D.

| | how RAM comes back | QEMU delta |
|---|---|---|
| **A** stream it (`loadvm`) | migration stream + qcow2 | none |
| **B** copy back dirty pages | per-page `memcpy` | tracking-dependent |
| **C** host-side CoW | `mprotect`/`userfaultfd` on the RAMBlock host pointer | none in `accel/tcg` |
| **D** `fork()` per iteration | kernel CoW | none |

A is measured and rejected: ~482 ms fixed, O(total RAM). B is the design this
document already argued for. C and D were never written down and should have
been.

### B splits again, on how pages are tracked

- **B1, syx's way** -- hand-rolled hooks in `accel/tcg/cputlb.c`. See
  `LIBAFL-PORT.md`: the tracking appears to self-disarm after the first write
  to each page, because nothing re-cleans the dirty bitmaps between iterations.
- **B2, QEMU's own dirty log** -- `memory_global_dirty_log_start()`, then per
  iteration `cpu_physical_memory_sync_dirty_bitmap()` to read the set and
  `cpu_physical_memory_clear_dirty_range()` + `tlb_flush()` to re-arm.

`cpu_physical_memory_clear_dirty_range()` already exists and clears all three
clients, which makes `cpu_physical_memory_is_clean()` true again so
`TLB_NOTDIRTY` is reapplied on the next `tlb_set_page_full()`. **That is exactly
the re-arm B1 lacks.** B2 is not a different idea from syx; it is syx using the
supported API that already solves syx's bug.

Note this is the design this document named from the start --
"`device_save_kind()` into a plain memory buffer, and `memory_global_dirty_log`
for RAM". The syx investigation did not turn up a better option; it produced an
independent argument for the one already chosen.

### Why B2 over C

C is genuinely attractive for one reason worth stating plainly: **no patches to
`accel/tcg` at all**, so it survives QEMU rebases. For a curated patch series
over a release tarball -- which is what `qemu_builder` is -- that is a real
value, not a stylistic preference. B2's delta is small and uses supported APIs,
but it is not zero. If B2's per-iteration `tlb_flush` turns out to cost more
than projected, C is the fallback and should be measured rather than assumed
worse.

### D is the oracle, not the product

A fork-per-iteration reset is correct by construction: whole address space,
devices included, no tracking to get wrong. That makes it the reference this
lane has proposed three times and never built. Run one input under fork-reset
and under B2, compare guest state, and the comparison cannot share the fast
path's bugs -- which is the property every instrument this lane built by
instrumenting the fast path itself turned out to lack.

### Costs to measure, not assume

- B2: one helper-path store per page per iteration, plus one `tlb_flush` per
  iteration. `tlb_flush` is **not** the `tb_flush` cliff measured above at
  2.322x -- different mechanism, much cheaper -- but that is an argument for
  measuring it, not for skipping the measurement.
- C: one host page fault per page per iteration, ~1-3 us each.
- D: one page-table copy per iteration, and vCPU threads must be quiesced at
  the fork point.

None of B2, C or D has been measured. The ordering here is from the source and
this lane's existing measurements only.

## Measured: the three strategies, host-side

`scratchpad/resetbench/reset-bench.c`. Sweeps total region size N and dirty
pages per iteration D independently, because the claim under test is that a
dirty-page reset is O(D) and not O(N). Every arm verifies the region against a
reference after reset, so an arm that restored nothing cannot look like the
fastest one. Host: 96 cores, 47 GB, 4 KB pages. p50 microseconds per iteration.

### Scaling in N, with D held at 64 pages

| N | memcpy (B2 floor) | mprotect (C) | fork (D) |
|---|---|---|---|
| 4 MB | 10.5 | 336 | 575 |
| 64 MB | 11.4 | 338 | 2,769 |
| 256 MB | 10.9 | 411 | 8,728 |
| 512 MB | 11.1 | 327 | 18,028 |

**B2 and C are flat in N. fork is linear in N**, ~35 us per MB, and that floor
is paid whether one page is dirty or four thousand.

### At 256 MB, the shape that matters here

| D (dirty) | memcpy (B2 floor) | mprotect (C) | fork (D) |
|---|---|---|---|
| 256 pgs / 1 MB | 79 | 1,411 | 9,125 |
| 1024 pgs / 4 MB | 373 | 5,899 | 10,836 |
| 4096 pgs / 16 MB | 2,136 | 26,600 | 18,831 |

### What that settles

**C is not the cheap rebase-free option it looked like.** A fault plus an
`mprotect` per page costs ~5-6.5 us against memcpy's ~0.17-0.35 us: 15-30x.
At a 4 MB working set that is 5.9 ms versus 0.37 ms. Not having to patch
`accel/tcg` is worth a lot, but it is not worth 15x.

One qualification, because the measured C is the naive implementation: it
issues one `mprotect` syscall per page to re-protect. `userfaultfd` in
write-protect mode can register once and re-protect a batch, which would cut
the syscall count substantially. That variant is **unmeasured**, and C should
not be written off until it is.

**fork is O(total RAM), confirming it cannot be the production path** -- an
8.7 ms floor at 256 MB caps it near 115 exec/s regardless of working set. It
remains the right oracle, where being correct by construction is the point and
10 ms an iteration is affordable.

**B2's floor at our shape is 0.37 ms** for a 4 MB working set. With the device
block already landed at 0.402 ms measured on real firmware, a complete reset
projects to **~0.78 ms, about 1,280 exec/s** -- against `loadvm`'s 482 ms.

### What this does not measure

The memcpy arm models B2's copy term with **tracking assumed free**. Real B2
adds one helper-path store per page on its first write each iteration, plus one
`tlb_flush` per iteration. Neither is in these numbers and both need QEMU. The
expectation is that B2 lands nearer its floor than C, because a helper-path
store is a function call (~100 ns) rather than a trap into the kernel (~5 us) --
but that is reasoning, not measurement, and this lane's record on the
difference is poor.

THP was run as a separate arm and verified to take effect (128 MB of 256 MB
huge-backed). It changes little, except that **fork gets worse** at large N --
CoW granularity becomes 2 MB, so each touched page copies 2 MB.

Baseline (the guest's own write cost, 0.6-54 us) is inside C's and fork's
numbers but not memcpy's. Adding it changes no conclusion.

### Two instrument bugs, both caught by controls

Worth recording because this lane keeps producing checks that cannot fail.

1. `dirty_n` is written by the SIGSEGV handler and read by the mainline, and
   was not `volatile`. At -O2 GCC proved `dirty_pages()` could not touch it,
   cached it across the call, and **compiled the entire reset loop to zero
   iterations**. The arm did no work and reported a time *faster than
   baseline*. The post-reset verification caught it as BAD.
2. The page selector `(i*stride + i*37) % npages` is even when stride is 1, so
   at D == npages it had period D/2 and touched half the intended pages. Caught
   by an added assertion that the fault count equals D. The selector is now
   forced odd and proven injective at every sweep point before running.

The first was caught only because the verification existed; the second only
because a previous failure prompted the assertion. Neither would have announced
itself in the timings, which looked entirely plausible.

## Measured: does it scale across cores?

`scratchpad/resetbench/scale-bench.c`. Every number above was single-threaded
on an idle box. A 4 MB page-copy per iteration is pure memory traffic, so
concurrent instances contend for bandwidth rather than cores. Host is a 96-core
Xeon Gold 6238R, 2 NUMA nodes, 1 MiB L2 per core, ~38 MiB L3.

256 MB region, **4 MB dirty** per iteration:

| workers | p50 us/iter | slowdown | aggregate it/s |
|---|---|---|---|
| 1 | 372 | 1.00 | 2,210 |
| 2 | 389 | 1.05 | 3,801 |
| 4 | 391 | 1.05 | 7,459 |
| 8 | 548 | 1.47 | **8,377** |
| 16 | 1,039 | 2.79 | 7,563 |
| 24 | 1,663 | 4.47 | 6,871 |

**Aggregate peaks at 8 workers and then declines.** 24 workers is worse than 8,
and per-iteration cost is 4.47x. At the peak this is ~67 GB/s of traffic
(read + write), which is the machine's memory bandwidth. Cores past ~8 do not
help and actively hurt.

Same region, **1 MB dirty**, as a control on the explanation:

| workers | p50 us/iter | slowdown | aggregate it/s |
|---|---|---|---|
| 1 | 78 | 1.00 | 10,267 |
| 8 | 82 | 1.04 | 61,477 |
| 24 | 89 | 1.14 | 165,694 |

Flat and near-linear, which confirms bandwidth rather than any lock,
scheduler or syscall effect as the cause.

**But this arm is optimistic and should not be quoted on its own.** The
benchmark rewrites the *same* pages every iteration, so a 1 MB working set
(2 MB footprint with its reference) stays resident in L2/L3 and never reaches
DRAM. A real guest's dirty pages have decent locality but not that. The true
curve sits between these two arms, and moves toward the pessimistic one as the
working set grows.

### Consequence

Fleet throughput is capped by **memory bandwidth, not core count**, and the
dirty set sets both the per-iteration cost and the scaling ceiling. That makes
measuring the real dirty set (step 1 of the plan above) more important than it
already was: it is not a second-order correction, it decides how many instances
the machine can usefully run.

A separate, purely mechanical blocker: Penguin runs its guest in a container
with the fixed name `proj`, so concurrent runs collide today (this lane hit
`docker rm -f proj` conflicts repeatedly). Fixable, but it is a prerequisite for
any parallel campaign and is not currently done.


## MEASURED: the dirty set, and it overturns this document's emphasis

Everything above assumed a 4 MB working set. Measured on the real target
(armel, 256 MB, lighttpd, iteration delimited by a uprobe on the parse entry
point rather than a host clock):

| iteration | n | median pages | KB |
|---|---|---|---|
| whole request | 400 x2 runs | **128 / 130** | 512 / 520 |
| one parse (persistent rewind) | 400 | **23** | 92 |

Union over 11 consecutive iterations: ~350 pages (1.4 MB), so the same pages
are re-dirtied each time rather than the set growing.

**All three columns in the sweep above are wrong on the high side.** 520 KB is
below the *smallest* row. Three consequences, and the first is a reversal of
this lane's priorities:

1. **RAM is not the expensive half.** It is ~54 us. The device block, at
   0.402 ms, is **88% of the reset**. The syx investigation, the B2 design, the
   C-versus-B2 comparison -- all of that argued over 9% of the cost. The
   expensive half is the one already landed and treated as finished.
2. **Memory bandwidth is not the parallelism ceiling.** At 520 KB the scaling
   sweep's near-linear column applies (24+ instances), not the 8-instance
   saturation measured at 4 MB.
3. Re-derived budget: 0.402 (device) + 0.054 (RAM) + 0.111 (guest) = 0.567 ms,
   **~1,760 exec/s**. With the 2.8x device-restore win identified in
   DEVICE-RESTORE-PROFILE.md, ~0.31 ms, **~3,200 exec/s**.

### The re-arm, confirmed from the other direction

LIBAFL-PORT.md argued from source that syx's dirty tracking self-disarms: TCG
traps a store only while the TLB entry carries `TLB_NOTDIRTY`, which it loses on
the first write, and nothing in syx re-cleans the bitmaps.

Building a correct tracker independently produced exactly that requirement. The
clear path must reach `tlb_reset_dirty_range_all()`, which walks every vCPU's
TLB and puts `TLB_NOTDIRTY` back. Without it, **interval 1 is correct and every
interval afterwards under-counts** -- and a poke-N-pages control passes in that
world, which is why the implementation carries a third control that re-pokes in
a second interval.

That is the syx defect reproduced constructively, not just read. It is also a
warning about B2: the same mistake is available to us, and only the second
interval reveals it.
