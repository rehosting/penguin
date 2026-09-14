# The oracle is 35% of the wall clock, and it can be 18x cheaper

## Where the time is

Run 57, 200,000 laps, 175.1 s:

| | share of wall | laps |
|---|---|---|
| ordinary laps | 62.2% | 199,000 |
| **the fork oracle** | **34.4%** | **1,000 (0.5%)** |
| crash laps | 3.0% | 2,660 |
| unaccounted | 0.00% | -- |

A verified lap is 61.8 ms and **98.7% of it is `fastsnap_fork_ref_diff()`** --
`process_vm_readv()` of 281,346,048 bytes out of the forked child plus a
`memcmp`, at 4.6 GB/s. That is memory-bandwidth bound, so there is no
constant-factor left in it. The only way to make the call cheaper is to read
less, and the only *sound* way to read less is a bound on what can possibly
differ that does not come from the restore's own bookkeeping -- because the
restore's bookkeeping is the thing the oracle exists to not trust.

## There is exactly one such bound, and the kernel provides it

Parent and child share physical frames until copy-on-write breaks. **Two
mappings on the same PFN are byte-identical by kernel guarantee**, so a page
whose PFN still matches needs no comparison at all. A page whose PFN differs
might still be equal, so it gets compared.

The filter therefore fails in the safe direction: it can only ever do extra
work, never miss a difference. `/proc/<pid>/pagemap` is not part of QEMU's
dirty log, TCG's `TLB_NOTDIRTY` path, or fastsnap's bitmap -- it is the
kernel's own account of the mapping, which is what makes it admissible here.

## Measured

`probe/pagemap_oracle_probe.c`, run inside `penguin:fstb` against a 281 MB
private mapping with a forked child, a workload that writes a fixed page set,
and both methods run back to back on the same state:

| divergent pages | full oracle | pagemap read | candidates | filtered total | speedup |
|---|---|---|---|---|---|
| 24 | 94.23 ms | 4.95 ms | 0.26 ms (0.03%) | 5.21 ms | **18.1x** |
| 500 | 83.10 ms | -- | -- | -- | 17.8x |
| 5,000 | 92.40 ms | -- | -- | -- | 6.0x |
| 20,000 | 77.91 ms | -- | -- | -- | 2.0x |

Every row reports the same diff count as the full comparison. Break-even is
around half the pages; this target dirties 24 per lap and `restored_pages` has
a median of 24 and a p90 of 24 across 200,000 laps, so the divergent set is
small and stable.

At 18x the oracle would fall from 34.4% of the wall clock to about 2.7%,
taking throughput from ~1,150 to roughly **1,700 laps/s at the same
verification density** -- no correctness traded, which is what distinguishes
this from turning `verify_every` up.

## The prerequisite, and why this is a note rather than a patch

**PFNs in pagemap are zeroed without `CAP_SYS_ADMIN`.** Measured, in the
shipped image:

```
default:               shared=0      no-pfn=71936   0.8x   (slower)
--cap-add=SYS_ADMIN:   shared=71912  no-pfn=0      18.1x
```

`./penguin` adds only `NET_BIND_SERVICE`. So the fast path is unavailable in
the configuration everyone runs, and a filter that silently degrades to the
slow path is the exact shape this lane keeps writing checks against -- an
instrument that reads as working while doing nothing.

Three things have to be true before this is worth the C:

1. the run opts in to `CAP_SYS_ADMIN` (or runs privileged) **explicitly**;
2. the fallback is loud -- if every PFN reads zero, say so in the verdict, not
   in a debug line, because the cost silently tripling is the tell;
3. the real COW-divergent set is measured *in QEMU*, not in a probe. The probe
   models the guest's stores; QEMU also writes guest RAM from device models and
   DMA, and the fork reference lives for 200,000 laps rather than 200. That
   number decides which row of the table this lands on and it cannot be known
   from outside the process.

(3) needs a build anyway, so the honest first step is a counting-only patch:
read both pagemaps, report the divergent count, compare nothing differently.
That settles the table row at the cost of one rebuild and cannot break the
oracle, because it changes no answer.
