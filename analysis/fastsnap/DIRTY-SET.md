# The dirty set, measured

`RESET.md` prices a dirty-page reset as O(dirty pages) and gives, for a 256 MB
guest:

| dirty set | RAM restore | instances before memory-bandwidth saturation |
|---|---|---|
| 1 MB | 79 us | 24+ |
| 4 MB | 373 us | ~8 |
| 16 MB | 2,136 us | ~2-3 |

Every projection downstream of that table assumed the 4 MB row. Nothing had
asked a guest.

**A real firmware target dirties 130 pages -- 520 KB -- per whole-request
iteration, and 23 pages -- 92 KB -- per parse-only iteration.** Both are below
the *smallest* row in the table. The union over 11 consecutive whole-request
iterations is ~350 pages (1.4 MB), so even a reset that fell 11 iterations
behind would still land in the 1 MB row.

The RAM half is not where this design is expensive.

---

## The control, first

A dirty-page counter is unfalsifiable from its own output. Stuck at zero it
reads as "tiny working set, the design is cheap". Returning every page it reads
as "huge working set, the design is dead". Both are answers to the question
being asked, so neither can be caught by looking at the log. Three controls
separate them, and all three passed before any number below was taken.

**On `-M virt`, in CI** (`qemu_builder/src/fastsnap/selftest.c` phase 5, gated
by `nix build .#checks.x86_64-linux.fastsnap-selftest`):

```
fastsnap: dirty tracking armed, page size 4096, 65634 pages cleared in 1290 us
fastsnap: dirty baseline 0 pages of 65634 scanned, 752 us
fastsnap: control OK - 8 poked pages, counter reports 8 and names all of them
          (mach-virt.ram=8) in [mach-virt.ram+0x200000, +0x210000, +0x220000,
          +0x230000, +0x240000, +0x250000, +0x260000, +0x270000]
fastsnap: dirty count is exact - 8 poked, 8 counted, nothing else was writing
fastsnap: dirty set returns to baseline (0)
fastsnap: control OK - dirty tracking re-arms, second interval counts 8 for
          the same 8 pages
fastsnap: SELFTEST PASSED
```

Eight known pages written, eight counted, **all eight named by address**,
baseline zero on both sides, and the same eight counted again in a *later*
interval.

- **A (poke)** rules out a counter that cannot see writes, and -- because it
  requires the addresses, not just the count -- one that returns a large
  number for unrelated reasons.
- **B (consumed)** rules out a counter that never clears, which would report
  a monotonically growing set and pass A.
- **C (re-arm)** is the one that is easy to omit and the only one that fails in
  the most dangerous world. TCG traps a store to a page only while that page's
  TLB entry carries `TLB_NOTDIRTY`, and the page loses that flag on the first
  write of an interval. If clearing the bitmap did not also walk every vCPU's
  TLB and put the flag back, the **first** interval would be correct and every
  interval after it would silently under-count. A and B both pass in that
  world. This is why the clear is the arm, not bookkeeping after it:
  `physical_memory_test_and_clear_dirty()` ends in
  `physical_memory_dirty_bits_cleared()` -> `tlb_reset_dirty_range_all()`.

**On the real target, at run time**, the same three controls ran on the booted
firmware before each measurement and are recorded in every result file:

```json
"arm_ok": true, "arm_cleared_pages": 98402, "total_pages": 98402,
"poke_pages": 8, "poke_counted": 8, "poke_named_missing": [],
"quiet_after_poke": 0, "repoke_counted": 8, "repoke_named_missing": []
```

`arm_cleared_pages == total_pages` is its own check: RAM blocks are created
with every dirty bit set, so an arm that cleared nothing would mean the bitmap
was never found -- and every count after it would read zero.

## The number

Target: the `stridelinx` project (`rehosting/examples`, public) under
`work/stride/proj`, armel, `-M virt`, **256 MB** main RAM -- the same size
`RESET.md`'s host-side table was taken at, so the page count converts to a
cost with no size correction. Workload: the project's own in-guest driver,
100 x 20 pipelined `GET /` against lighttpd.

The interval is the **iteration itself**, not a stretch of the host clock: a
uprobe on `http_request_parse` is both the boundary and the clock. Two
boundaries are available and they measure different things.

| iteration | n | median pages | median KB | p10 | p90 | max | iteration ms |
|---|---|---|---|---|---|---|---|
| whole request (run 58) | 400 | **128** | 512 | 113 | 186 | 457 | 15.5 |
| whole request (run 60) | 400 | **130** | 520 | 115 | 186 | 444 | 15.6 |
| one parse, rewind (run 59) | 400 | **23** | 92 | 23 | 107 | 506 | 1.61 |

*Whole request* is consecutive natural entries: socket read, parse, response
`writev`, round the event loop. That is the iteration a naive snapshot fuzzer
resets.

*One parse* uses `persist.py`'s rewind -- at entry `LR` still holds the
caller's return address, so overwriting it with the function's own entry makes
the ARM epilogue return into the function. Consecutive entries then bracket one
parse and nothing else. That is the iteration the fast-reset design is shaped
for: DRAFT's "restore to a point inside the parser and re-run only the parse".

Every dirty page in every run was in `mach-virt.ram`. The other six RAMBlocks
(two 64 MB pflash, four ROMs) contributed **zero** across 1,200 samples.

### What that does to the cost model

At `RESET.md`'s 0.42 us/page the RAM term is **0.054 ms** per whole-request
iteration and 0.010 ms per parse. `REALFW.md`'s re-derivation used 0.027 ms
for a synthetic 65 pages; substituting the measured figure:

```
  0.402 (device block, measured on real fw)
+ 0.054 (RAM, measured here -- was 0.027 assumed)
+ 0.111 (guest work + loop overhead, as before)
= 0.567 ms  ->  ~1,760 exec/s     (was ~1,850 with the synthetic RAM term)
```

The headline barely moves, and that is the finding: **the RAM half is not the
expensive half.** At 520 KB a reset is roughly half the 1 MB row's 79 us, so
the memory-bandwidth ceiling is the 24+ column, not ~8 -- parallelism is not
where this design runs out of room. The 0.402 ms device block is 88% of the
reset and is where the remaining cost lives.

## Two implementations, one target

The number above is taken host-side, through `ctypes` on the QEMU library
already mapped into the process, from a uprobe callback holding the BQL. The
same measurement also exists as an op inside QEMU -- `DIRTY_ARM` /
`DIRTY_COUNT` (ops 9/10 in the fastsnap ABI), run from a main-loop bottom half
with the vCPUs stopped, which is how the CI control above runs it.

Run 60 ran both against the same booted guest, in sequence (never concurrently
-- they consume the same bitmap, so a sample taken by one is a sample the other
will never see). The in-QEMU op measured six rounds of 11 whole-request
iterations:

| round | iterations | pages | count cost |
|---|---|---|---|
| 1 | 11 | 330 | 1,179 us |
| 2 | 11 | 409 | 1,187 us |
| 3 | 11 | 497 | 1,191 us |
| 4 | 11 | 369 | 1,197 us |
| 5 | 11 | 150 | 1,169 us |
| 6 | 11 | 322 | 1,177 us |

These are unions, not sums: a page written in five iterations counts once. So
the check is `max(single iteration) <= union(11) <= 11 x median(single)`, i.e.
`444 <= 330..497 <= 1430`, which holds for every round. The two
implementations are consistent, and the gap between 350 and 1,430 says
something the per-iteration number alone does not -- **the same pages are
re-dirtied every iteration.** The steady-state working set is ~350 pages
(1.4 MB) however long you watch; a reset that fell eleven iterations behind
would still be in the 1 MB row.

## What this does NOT establish

- **One target, one workload, one architecture.** armel, `-M virt`, lighttpd
  serving well-formed pipelined `GET /`. A different firmware, a different
  service, or a guest with a busier background (cron, logging to flash, a
  writable overlay) could be anywhere. The claim is "this target lands far
  below the 4 MB assumption", not "all targets do".
- **Well-formed requests, not mutants.** `fuzzdrive.py` was off. Mutants
  usually bail earlier in the parser, so these are the conservative direction
  -- but that is an argument, not a measurement.
- **The numbers are upper bounds on the target's own write set.** The interval
  includes everything the guest did between two boundaries: kernel timers,
  other processes, and the penguin uprobe/portal round trip itself, which
  writes guest memory on every boundary. The parse-only floor (p10 = median =
  23, min 22) is probably mostly that overhead, which would mean the parse
  writes almost nothing. Not separated here; a `laps: 0` probe-overhead arm
  (the shape `parsecost.py` uses) would separate it.
- **0.42 us/page is an input, not a result.** It comes from the Slice 0 build.
  The reset cost in ms above inherits whatever that figure is worth.
- **The reset's own cost is not in the interval.** These runs never restore.
  The measurement answers "how much would a reset have to copy", not "what does
  a reset-per-iteration loop cost end to end". A loop that actually resets may
  dirty a different amount, because each iteration would then start from
  identical state rather than from the previous iteration's leftovers.
- **Rewind mode is unsound as a fuzzer** and known to be -- state leaks between
  laps (AFL persistent mode's own caveat, see `persist.py`). It is used here
  only to get an interval of the right *shape*, not to fuzz.
- **Non-migratable blocks.** `memory_region_get_dirty_log_mask()` gates the
  DMA/`address_space_write` path on `qemu_ram_is_migratable()`, so device
  writes into a non-migratable block would be invisible. On this target all
  seven blocks are migratable, so nothing was lost; the instrument marks such
  blocks with `!` in its block report if one ever appears.

## How to reproduce

The instrument exists twice, deliberately.

**In QEMU** (`qemu_builder`, branch `workspace/fastsnap`, **uncommitted**):
- `src/fastsnap/dirty-track.c`, `src/include/fastsnap/dirty-track.h` -- new.
- `src/include/fastsnap/penguin-fastsnap.h` -- ops 9/10/11 (`DIRTY_ARM`,
  `DIRTY_COUNT`, `DIRTY_STOP`) and five accessors.
- `src/fastsnap/penguin-fastsnap.c` -- dispatch and exported ABI.
- `src/fastsnap/selftest.c` -- phase 5, the three controls.
- `nix/fastsnap-selftest.nix` -- three new grep gates, so a build that loses
  any control fails the check rather than passing quietly.

```sh
cd qemu_builder
nix build -L .#checks.x86_64-linux.fastsnap-selftest    # ~2 min
```

Note it arms with `GLOBAL_DIRTY_DIRTY_RATE`, not `GLOBAL_DIRTY_MIGRATION`.
Both raise the same bitmap, but savevm/loadvm take and *release*
`GLOBAL_DIRTY_MIGRATION` themselves, so sharing it means a snapshot's
`log_stop` silently disarms tracking while every accessor keeps returning
numbers.

**Host-side** (`analysis/fastsnap/dirtyiter.py`): needs no rebuild -- every
symbol it uses is already exported by the shipped QEMU library. It walks
`qemu_ram_foreach_block()` and uses each block's own offset and length.
(`ram_term.py`, the earlier probe, measured one block chosen by name and
passed `start=0` rather than the block's `ram_addr` offset, which is correct
only while the named block happens to be the one at `ram_addr` 0.)

The run recipe, from `penguin/`:

```sh
cp analysis/fastsnap/dirtyiter.py \
   analysis/fastsnap/work/stride/proj/plugins/
# rename patch_zzz_dirtyiter.yaml.off -> .yaml and add it to config.yaml's
# patches list (it must sort LAST: patch_fuzzcal.yaml re-enables notrap)
./penguin --image penguin:fsdirty --name fsdirty-proj --replace \
    run analysis/fastsnap/work/stride/proj
```

`penguin:fsdirty` is the image carrying the in-QEMU ops, built with

```sh
PENGUIN_NIX_BUILD_ARGS="--override-input penguin-qemu path:/abs/qemu_builder" \
  ./penguin --build --image penguin:fsdirty --version
```

`penguin:fastsnap` (the pre-existing image) is enough for the host-side
measurement alone; it lacks ops 9-11, and `dirtyiter.py` logs that and skips
phase 2 rather than failing.

Everything else must be off in the same run, and that is a requirement rather
than tidiness: `vpn` because the dirty log cannot arm while the
vhost-user-vsock backend is attached; `notrap` because savevm/loadvm walk and
clear the same bitmap and a restore rewrites RAM wholesale; `ram_term` because
it arms the identical log and clears the identical bits, so each would see a
fraction of the truth and neither would report an error.

Results: `work/stride/proj/results/58` (whole request), `59` (one parse),
`60` (whole request + in-QEMU cross-check), each with the controls recorded
alongside the number.
