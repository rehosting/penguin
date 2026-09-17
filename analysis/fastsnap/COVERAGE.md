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

## Cost, measured on real firmware (runs 109–112)

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

**This is five times what the selftest guest suggested, and the earlier
estimate of 25–31 µs in this document was wrong to extrapolate.** The scan is
O(map size) with a zero-word skip, and the skip is what collapses: the toy
guest sets 151 bytes so almost every 64-bit word is zero, while real firmware
sets 4,849 per lap spread across the map, leaving about half the words
non-zero. Scan cost is a function of map OCCUPANCY, not of the guest.

### The guest side is below the noise floor

| | control 109 | control 111 | coverage 110 | coverage 112 |
|---|---|---|---|---|
| guest half `bh_to_observed_ms` | 2.9837 | 3.6832 | 2.8411 | 2.8661 |

The two controls differ by **23%** — run 111 drew an expensive span — so
anything under roughly 150 µs is invisible here, and both coverage runs land
*below* both controls, which is the wrong sign for an overhead. The honest
statement is that per-block emission is **not resolved**, not that it is zero.

A first-principles bound from the same runs: a lap executes **13,366 blocks**
(median `hits`, itself a floor because byte counters saturate at 255 per edge),
and eight TCG ops optimise to a handful of host instructions, which puts
emission in the tens of microseconds — consistent with being invisible against
a ±0.5 ms guest half.

**Resolving it needs an in-run A/B**, not more runs: arm coverage, run N laps,
disarm (which flushes the TB cache, so blocks re-translate uninstrumented), run
N laps. Same draw, same snapshot, so draw variance cancels. That instrument
does not exist yet.

### Net effect on the rate

| run | coverage | exec/s median | lap ms |
|---|---|---|---|
| 109 | off | 293.51 | 3.4070 |
| 111 | off | 242.57 | 4.1226 |
| 110 | **on** | 291.05 | 3.4358 |
| 112 | **on** | 287.59 | 3.4772 |

The coverage runs sit inside the controls' range. That is not a claim that
coverage is free — the +164 µs is real and directly measured — it is a
statement that with this workload's draw variance, four runs cannot see a 5%
effect in exec/s. The reset-side number is the one to quote.

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

Two things follow.

**The 64 KiB map is marginal for this target.** At 48.7% occupancy an
AFL-shaped map is well into the range where distinct edges start sharing slots,
which silently costs sensitivity — a new edge that collides with a known one is
simply not new. Either raise `cov_map_size` (the scan cost rises with it,
linearly) or narrow `cov_filter_lo/hi` to the victim's text and stop
instrumenting the kernel, which is where most of those 49,694 blocks are.

**157 new edges in 2,200 laps is the expected reading, not a disappointment.**
These runs had `mutate: 0` — the inputs barely vary, so there is little reason
for coverage to grow. What the number establishes is that the mechanism
responds at all and then settles, which is what a saturated corpus looks like.
The interesting measurement is the same four runs with mutation on, and that
has not been done.

## What this still does not close

- **Per-block cost on real firmware is unmeasured.** Needs an A/B on the same
  target: one run `coverage: 0`, one `coverage: 1`, same driver, same arm axis.
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

So the honest claim after this change is narrower than "we fuzz at 248 exec/s":
it is that an exec/s from this loop can now be quoted with a coverage number
beside it, which is what makes it comparable at all.

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
