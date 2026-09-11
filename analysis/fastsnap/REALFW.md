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

