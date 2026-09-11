# The device half does not survive real firmware on its own

Everything before this was measured on `-M virt` with a synthetic payload, in
`slice0` and then in the 11.1.0 port. This is the first time the device block
has been taken and restored repeatedly against a booted firmware image with a
full Linux userspace under it.

Two things happened that a synthetic machine could not have shown, and the
second one is the reason this document exists.

## 1. A device block cannot carry virtio

The first restore failed outright:

```
VQ 1 size 0x100 < last_avail_idx 0x9 - used_idx 0x11
error while loading state for instance 0x0 of device
'0000:00:01.0/virtio-net': Failed to load element of type virtio
```

A virtio device's state is split in two. The device model holds
`last_avail_idx`/`used_idx`; the vring itself lives in **guest RAM**. A
device-only restore puts back the first half and leaves the second wherever the
guest has since taken it, and `virtio_load()` is strict enough to reject the
result. The rule generalises: any device whose state is co-located with guest
RAM cannot travel in a block that does not carry that RAM.

`-M virt` has no virtio-net, which is why every prototype measurement missed
it. Denying the three virtio sections took the block from 108,079 bytes to
**16,019** (17 of 20 sections) and the restore then succeeds.

This is the announced trade -- the draft already said the network backend was
sacrificable -- arriving as a bill rather than a willingness.

## 2. Repeated device-only restores destroy the guest

With virtio denied, restores succeed, return rc 0, and take ~400 us. The guest
does not survive them.

Four runs, identical in every respect except whether a restore happens. `noop`
takes the block on the same schedule and then does nothing with it, which is
the only honest control for "the restore is what did this":

| run | mode | detector hits | outcome |
|---|---|---|---|
| 1 | fast | 452 in 79 s | **kernel panic**, `Fatal exception in interrupt` in `rcu_process_callbacks` |
| 2 | noop | 1701 in 300 s | clean |
| 3 | fast | 165 in 300 s | **75x `swap_dup: Bad swap file entry`, 23 OOM kills**, throughput collapsed ~10x |
| 4 | noop | 1701 in 300 s | clean |
| 5 | loadvm | 2002 in 300 s | clean |

**Run 5 is the control that matters most, and it was not planned as one.** The
`loadvm` arm performs the same number of restores on the same cadence, and the
guest is fine -- more detector hits than either `noop` run. So the damage is
not "restoring disturbs a running guest". It is specific to restoring the
device block *without* the RAM that its contents refer to. A full `loadvm`
restores both halves and is sound; this does not.

Both failures are memory corruption. `swap_dup: Bad swap file entry` on a
system with no swap means page-table entries holding values the kernel can only
read as swap entries -- corrupted PTEs. A fatal exception inside
`rcu_process_callbacks` means a corrupted RCU callback list.

### The mechanism -- hypothesised, and under test

Stated as a hypothesis because it has not been tested yet; what follows the
table above is measurement, this is inference from it.

The block includes the `cpu` section, and on ARM that section carries the CP15
registers -- **TTBR0, TTBR1 and CONTEXTIDR** among them. Restoring it rewinds
the MMU's page-table base to the process that was current when the block was
taken. Guest RAM is not restored, so it has moved on: that process may have
exited, its page tables freed and the pages reused for something else. The CPU
then walks page tables that RAM no longer holds, and reads whatever now
occupies those frames as PTEs.

If that is right, it is not a defect in the port. It is what "restore the
devices but not the RAM" means on a machine where the CPU's own state points
into RAM.

**The test.** Deny `cpu,cpu_common` in addition to virtio and run the same fast
arm. That leaves every peripheral section rewound and the MMU alone. If the
guest then survives where it otherwise panics, the CPU section is the cause; if
it dies anyway, the damage is coming from somewhere else and this paragraph is
wrong. Run interleaved with an un-denied fast run so host drift cannot supply
the difference. Result to be recorded here.

### What it costs the measurements

**The `fast` throughput-cliff numbers are void.** They were taken on a guest in
the process of dying:

| run | mode | cliff ratio | window pairs |
|---|---|---|---|
| 1 | fast | 1.055 | 8 |
| 3 | fast | 1.516 | 2, before the collapse |
| 2 | noop | 1.011 | 8 |
| 4 | noop | 1.096 | 8 |
| 5 | **loadvm** | **2.322** | 8 |

The instrument is not blind: the positive control fires hard. A full `loadvm`
goes through `vm_stop(RUN_STATE_RESTORE_VM)`, which `accel/tcg/tcg-all.c` turns
into a `tb_flush`, and the guest runs **2.3x slower** in the window after each
restore than in the window before. That is the re-translation cliff, measured
on real firmware, well outside the 1.011-1.096 floor. So a measurement of 1.055
for the fast arm is a real "no cliff detected", not a failure to look.

**The two noop runs bracket the fast one.** A ratio of 1.055 sits inside a noise
floor that spans 1.011 to 1.096 -- so even setting the corruption aside, the
fast arm shows no cliff distinguishable from doing nothing at all. 1.516 is
two window pairs on a guest that was already dying.

That the floor needed replicating is its own lesson. An earlier pass reported
`fast 1.095` against `noop 0.967` and treated the 13% gap as a possible real
residual. With a second noop run the floor alone covers 1.011-1.096, which
contains both numbers. A single control run is not a noise floor; it is one
sample of one.

The restore-duration numbers (~400 us; n=8 and n=2, measured in C) are not
affected -- they time a single operation, before the damage accumulates.

## What this changes

The draft's plan is: slice 1 the device block, slice 2 the RAM half, "measure
the device half in isolation against the ~94 ms fixed floor". **The device half
is not measurable in isolation on a real target.** It is not a stage that works
less well without RAM; it is a stage that corrupts the guest without RAM.

So the RAM half is not "where the win is" -- it is a *correctness
prerequisite*, and the two slices are one deliverable. The device block's
restore cost (~400 us) and its round-trip correctness (gated in CI) are still
real results; what is not available is an end-to-end throughput figure for the
device half alone.

## What this does to exec/s

Nothing measured today improved the iteration rate. It is worth being explicit
about that, because the restore-cost number (~400 us) looks like progress and
is not, on its own, available.

| configuration | reset cost | exec/s | status |
|---|---|---|---|
| no-trap loop, full `loadvm`, 2G | 656 ms | **1.5** | measured, sound -- what penguin ships |
| no-trap loop, full `loadvm`, 256M | 382-503 ms | **2.0-2.6** | measured, sound |
| trap-based persist loop, no reset | -- | 2,567 | measured, **unsound** (state leaks between laps) |
| device-block reset, real firmware | **0.402 ms** | -- | cost measured, **unsound alone** (corrupts the guest) |
| device block + RAM half | ~0.43 ms | ~1,850 *projected* | not built |

**The projection has to come down.** `RESET.md` carries ~5,525 exec/s for the
fast reset. That rests on `ALLOWLIST.md`'s 0.07 ms reset, which was 0.043 ms of
device restore for a **2-section allowlist** (cpu, timer) plus 0.027 ms of RAM
for 65 dirty pages -- both on `-M virt` with a synthetic payload. On real
firmware the block that actually restores is 17 sections and costs **0.402 ms**,
9.3x the allowlisted figure.

Re-deriving with the same non-reset overhead the original implied
(0.181 - 0.07 = 0.111 ms per iteration):

    0.402 (device, measured on real fw)
  + 0.027 (RAM, still synthetic and still unmeasured here)
  + 0.111 (guest work + loop overhead, as before)
  = 0.540 ms  ->  ~1,850 exec/s

Still 700-1,200x over the 1.5-2.6 exec/s available today, so the case for the
design survives; the headline number does not. Two caveats keep even 1,850
provisional:

- **The allowlist is not obviously available here.** 0.043 ms came from scoping
  the restore to {cpu, timer}. The section implicated in the guest corruption
  above is `cpu`, so the cheap allowlist is the one that keeps the dangerous
  section. Whether a sound allowlist on real firmware is also a cheap one is
  now an open question rather than an assumed yes.
- **The RAM term is still synthetic.** 65 dirty pages was one workload's
  working set on `-M virt`. Nothing has measured a real firmware target's.
