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
   plugin dispatch: an indirect call per translated block, against seven inline
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
execution this is a load, an xor, a byte load, an add, a byte store and a
store. No call, no branch, no lookup. The map is 64 KiB by default because that
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

## Cost

Nothing per lap beyond the scan. `clear_on_reset` (default on) folds the
summarise-and-clear into `LOOP_RESET`, in the same bottom half, *after* the
reset's own clock stops so the lap budget stays honest. Measured on the
selftest guest, the scan is **25–31 µs** over 64 KiB with a zero-word skip.

Asking for it as its own op instead would cost a scheduled op per lap, and on
this lane an op is far the more expensive of the two — a hooked syscall is
95.880 µs against 1.161 µs unhooked, and 98.8% of that is portal round trip.

The per-block emission cost is **not yet measured on real firmware.** That is
the honest state of it: seven inline ops is small, and small is not zero, and
the lap it lands in is 3.4 ms of which ~2.06 ms is guest emulation. Arming
coverage before the forward probe (which fastloop does, at the top of warmup)
at least keeps both sides of the fidelity ratio on the same footing, so the
verdict does not move for instrumentation-shaped reasons.

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
