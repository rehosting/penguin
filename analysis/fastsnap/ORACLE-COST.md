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

---

# Built, and measured end to end

Implemented in `qemu_builder` (`fastsnap: prove pages equal by PFN instead of
reading them`), image built with
`PENGUIN_NIX_BUILD_ARGS="--override-input penguin-qemu ../qemu_builder"`.

## The selftest proves the answer does not change

The agreement check runs on a state that HAS differences -- six disturbed pages
-- because agreeing on zero is worth nothing: a filter that skipped every page
would agree on zero. With the capability:

```
fastsnap: prefilter OK - same answer (6 pages) with 65628 pages proven by PFN
          identity and only 256 read back, against 65634 read with it off
fastsnap: fork diff baseline 0 pages differ, 268836864 bytes compared, 1141 us
```

against 52,324 us for the same baseline diff without it: **45.9x**. It also
asserts that `FASTSNAP_FORK_PAGEMAP=0` really proves nothing, so the control is
a control.

## The real target

Four runs on bugbench/mipsel/malta, 200,000 laps each, same image:

| | 58 no cap | 59 cap, non-root | 60 cap + root | 61 cap + root, reporting wired |
|---|---|---|---|---|
| span | 175.3 s | 175.4 s | 120.9 s | **113.6 s** |
| wall laps/s | 1,141 | 1,140 | 1,655 | **1,760** |
| verify lap | 62.38 ms | 61.02 ms | 3.94 ms | **3.96 ms** |
| fork-diff | 61.56 ms | 60.26 ms | 3.32 ms | **3.39 ms** |
| verify % of wall | 35.4% | 34.6% | 3.3% | **3.5%** |
| plain % of wall | 61.8% | 62.4% | 93.3% | **93.1%** |
| diff_pages != 0 | 0/1000 | 0/1000 | 0/1000 | **0/1000** |

**15.7x on the oracle, 1.54x end to end, with the same answer on all 1000
verifications.** The verify share falls from a third of the run to 3.5%, and
ordinary laps go from 62% of the wall clock to 93% -- which is what a loop
should look like.

## Two capabilities, not one

`--cap-add=SYS_ADMIN` alone did nothing (run 59 is indistinguishable from run
58). Reading PFNs needs CAP_SYS_ADMIN **effective**, and a non-root uid has no
effective capabilities however much `--cap-add` grants -- measured directly in
the image: `--cap-add=SYS_ADMIN` as uid 1002 still reports `no-pfn=32768`.

`./penguin` runs the container as the calling user so output files are owned by
the caller. So the invocation is:

```
./penguin --extra_docker_args "--cap-add=SYS_ADMIN -u 0" run <proj>
```

and that needed a wrapper fix of its own: `--extra_docker_args` were appended
*before* the wrapper's own `-u`, and docker takes the last occurrence of a
repeated flag, so they could never override anything the wrapper set
afterwards. Run 59 is what that looks like from the outside -- the flag
accepted, the run correct, the answer identical, and the only symptom the
absence of a speedup.

## What remains on the table

`pages_proved` is 96.40%, not the 99.97% the probe predicted, because the
filter decides per 1 MB chunk: a chunk holding one divergent page is read
whole. Run 61 read 2,560 pages where 24 would do -- 10 chunks of 256. Reading
per-run rather than per-chunk would take the diff from 3.39 ms toward the ~1 ms
the pagemap reads alone cost, which is the floor. That is another ~2.5 ms on
0.5% of laps: worth roughly 2% of the run, against 35% already taken.
