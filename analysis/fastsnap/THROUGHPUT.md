# What actually caps fuzzing throughput

Measured 2026-09-09, after draft 45 was closed. **These numbers change draft 45's
recommendation** — see the bottom.

Referent: `rehosting/penguin:v3.1.14`
(`sha256:6bf719e2b8ab0894c5082d087f30af5601929ab62c3fc53989ecc24d3a72b2f0`),
armel/4.10, `-smp 1`. Shared host under load — treat these as within ~20%.

## The gap draft 45 left

Draft 45 measured what a restore *costs* and never measured what it *competes
with*. A reset is only worth optimising in proportion to its share of an
iteration, and the other term was never taken.

## Guest work per iteration

`200 x fork+exec` of a static busybox, timed from guest `/proc/uptime`
(`guest_speed.py`):

| plugin profile | 200 spawns | per spawn | ceiling if an iteration spawns |
|---|---|---|---|
| full (37 plugins load by default) | 4.19 s | **21.0 ms** | 47 iter/s |
| lean (14 analysis plugins off) | 2.82 s | **14.1 ms** | 71 iter/s |

Reproduced: the full profile measured 4.23 s and 4.19 s on two runs.

**~33% of guest execution cost is penguin's own instrumentation**, recoverable
by config alone. *Caveat:* the lean set disabled `crashes` (a fuzzer's oracle)
and `pseudofiles` (device-model work needs it), so 14.1 ms is optimistic as a
fuzzing profile — realistically ~15-16 ms, since `crashes` hooks fatal signals
which are rare and cheap while the per-syscall/per-exec hooks are not. The two
use cases want different profiles; the device-model one is slower and does not
care.

## Device half of the hybrid, measured

`device_save_all` / `device_restore_all` in the Slice 0 build, mean of 200,
`-M virt -m 128`:

- **`device_restore_all` = 0.743 ms** (block = 61,987 bytes)
- `device_save_all` = 1.339 ms

Against the faithful path's **~94 ms fixed floor**, that is ~126x on the device
term. The RAM term is still **estimated, not measured** (dirty pages x memcpy);
it is the one number outstanding.

## The levers compose

| | reset | guest | iter/s | vs today |
|---|---|---|---|---|
| today | ~300 ms | 21.0 ms | **3.1** | — |
| + hybrid reset | ~2 ms | 21.0 ms | 37 | 12x |
| + lean profile | ~2 ms | 14.1 ms | **62** | 20x |
| + snapshot inside the request loop | ~2 ms | ~3.5 ms | ~180 | 58x |
| x 32 instances (96 cores here) | | | **~5,800 aggregate** | |

## What this changes

1. **The port is the second-most valuable lever, not the first.** Snapshot
   placement (fuzz at request level, not process level — AFL persistent mode's
   trick) is free and worth more per unit effort. The lean profile is free and
   worth a third of the port.
2. **Per-instance throughput is capped by guest emulation.** Reset optimisation
   closes the gap to that cap; it cannot raise it. Past ~62 iter/s the only
   lever is parallelism.
3. **Which reopens `fork()`** — not for crash isolation, but because aggregate
   throughput is the only way past the per-instance ceiling. Draft 45 declines
   fork on an obstacle (penguin's embedded CPython) that is penguin's
   architectural choice rather than QEMU's constraint: `util/rcu.c:492`
   registers `pthread_atfork` handlers and `tests/qtest/fuzz/fuzz.c:232` calls
   `rcu_enable_atfork()`, so QEMU ships a system-mode fuzzer made fork-safe.
   The `rcu_disable_atfork()` at `system/vl.c:2700` is inside
   `qemu_maybe_daemonize()` — daemonization, not a ban.
4. **Two consumers, and the second is the stronger case.** Device-model
   inference (what should `ioctl_unhandled` return?) has a baseline of a *full
   reboot*, ~20-30 s, so fast reset buys 2-3 orders of magnitude there versus
   12-20x for fuzzing — and its ceiling never binds, because a search over
   candidate device responses is hundreds of trials, not millions.
   `hyperfile.py:470-560` already dispatches every modeled access to a
   host-side Python handler, so the arming point and the variation point both
   exist in-process today.

## Reproducing

```
python3 guest_speed.py --full --label full
python3 guest_speed.py --lean --label lean
```
