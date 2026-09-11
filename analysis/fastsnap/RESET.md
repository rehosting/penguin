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
