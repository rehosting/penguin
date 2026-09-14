# The device allowlist in a closed loop, and where a crash lap goes

Predictions written BEFORE the run. `ALLOWLIST.md` measured a 17.5x device
restore (0.752 ms for 17 sections, 0.043 ms for `{cpu, timer}`) on an 11.0.50
tree, host-side, over a synthetic payload, and said so honestly: a set derived
by diffing device blocks across a window of guest execution is a **lower bound
on what is required**, not a proof of sufficiency. It has never been re-measured
after the 11.1.0 port and never been run in a loop.

Two things changed since, and both are why this can now be measured rather than
argued:

- the device block can be scoped by allowlist from Python at all
  (`penguin_fastsnap_set_allowlist`), which nothing exported before;
- `LOOP_RESET_VERIFY` now compares device state **per section** against a
  reference covering the FULL set, taken at the arm, whatever the block was
  scoped to. So a scoped reset reports, by name, the sections it failed to put
  back -- which is exactly the sufficiency question `ALLOWLIST.md` could not
  answer.

## Arm 1: discovery -- `allow: "cpu"`

Deliberately too narrow. The point is not the timing; it is to make the device
oracle enumerate what this workload actually needs. bugbench, mipsel/malta,
4,000 laps, verify every 100.

| # | prediction | rationale |
|---|---|---|
| P0 | `"cpu"` is a real section id on this machine, or the run refuses and prints the list | either outcome names the sections; a refusal costs one boot and is the cheaper half of the same measurement |
| P1 | the device oracle reports **> 0** differing sections on essentially every verification lap, and names them | a one-section block cannot be sufficient for a guest doing I/O; if this comes back 0 the oracle is blind and nothing below means anything |
| P2 | `reset_us` median **< 120 us**, from 348 us | the device half is ~95% of the reset and this drops all but one section of it |
| P3 | `exec_per_s` improves by roughly **1.3x**, NOT by anything like 17x | run 14: 1.119 ms lap, 0.348 ms reset. Removing ~0.3 ms leaves ~0.82 ms. **This is the prediction that matters** -- if it holds, the allowlist is not the biggest remaining lever inside a closed loop, and I was wrong to rank it first |
| P4 | RAM diff stays **0** on every lap | device scoping must not touch the RAM half; if it does, the two are coupled in a way nothing in the design says they are |
| P5 | the run's verdict is **FAILED** | by construction. This arm is a probe, not a candidate configuration, and a harness that scored it VALID would be scoring the wrong thing |

## Arm 2: the sufficient set

Take arm 1's named sections, add them, re-run. Predicted: device oracle 0 on
every lap, and a reset between arm 1's and 348 us.

The limit stays the one `ALLOWLIST.md` named. A section can be untouched for
thousands of laps and change on the next input, so "0 over N laps of this
workload" is a measurement of this workload, not a proof. That is why the check
is reported per verification lap rather than settled once.

## The crash lap, split

Run 14: 803 of 60,000 laps ended in a fatal signal, at **43.7 ms** median
against an ordinary lap of 1.119 ms. The reset is not the cause -- `reset_us`
over all 60,000 laps has a median of 348 us and a **maximum of 4,344 us**, so
even the worst reset in the run is a tenth of a median crash lap.

That is as far as the existing instruments go. The remainder is one span from
"reset scheduled" to "the next detector hit noticed it was done", and it
contains two very different things with opposite fixes. `bh_done_us` now splits
it:

- `sched_to_bh_ms` -- main-loop latency plus the operation itself
- `bh_to_observed_ms` -- guest execution plus this plugin's own callback cost

| # | prediction | rationale |
|---|---|---|
| P6 | on ordinary laps the halves sum to ~1.119 ms, with `sched_to_bh` ~0.4-0.5 ms | it should be the 348 us reset plus a short main-loop latency |
| P7 | on crash laps **`bh_to_observed` dominates**, > 60% of 43.7 ms | the crash path runs other subscribers (crash attribution, corpus bookkeeping) on the same thread, and throttling one of them already moved this number from 308.6 ms to 56.9 ms |

P7 is the falsifiable one. If `sched_to_bh` dominates instead, the cost is
getting the bottom half serviced after a fatal signal -- a QEMU-side problem,
not a plugin-side one -- and the fix is somewhere else entirely. My last two
guesses about this path were both wrong, which is why it is written down first.

## Results

`work/bugbench/proj/results/15` (arm 1) and `results/16` (arm 2), mipsel/malta,
4,000 laps each, verify every 25. Baseline for comparison is `results/14`:
full block minus virtio, 348 us reset, 1.119 ms lap, 893.7 exec/s.

First, a fact neither `ALLOWLIST.md` nor anything else in this lane had:
**malta has 37 device sections, not 17.** The 17 was `-M virt`. And the ids
repeat -- `serial` three times, `smbus-eeprom` eight times, `i8259` and `dma`
twice each. Every list-shaped thing built on these ids is coarser than it looks:
naming one matches all of them. The per-section comparison matches by position
for exactly this reason.

### Arm 1 -- `allow: "cpu"`, scored against the predictions

| # | predicted | observed | |
|---|---|---|---|
| P0 | `"cpu"` is real, or the list is printed | real; 37 sections named | ok |
| P1 | oracle reports > 0 and names them | 151/160 non-zero: `mc146818rtc#13` (148), `cpu_common#2` (3) | ok |
| P2 | `reset_us` median < 120 us | **71 us**, from 348 us -- **4.9x** | ok |
| P3 | ~1.3x exec/s, NOT 17x | **893.7 -> 1,278.9 = 1.43x** | ok |
| P4 | RAM diff stays 0 | 160/160 zero | ok |
| P5 | verdict FAILED | FAILED, sections named | ok |
| P6 | `sched_to_bh` ~0.4-0.5 ms | **0.119 ms** | **wrong** |
| P7 | crash lap is `bh_to_observed`-dominated, > 60% | **99.6%** | ok |

**P3 is the one that matters and it means the ranking was wrong.** Cutting the
reset by 4.9x bought 1.43x on the loop, because the reset was never the lap. I
put the allowlist first on the strength of a 17.5x figure measured on the reset
in isolation; in a closed loop it is worth a third of that at best.

P6 was wrong in a way that says where the time actually is. A 0.782 ms lap:

| | | |
|---|---|---|
| reset (its own clock) | 0.071 ms | 9% |
| main-loop latency to the bottom half | ~0.048 ms | 6% |
| **after the bottom half completes** | **0.656 ms** | **84%** |

A `bare` lap -- no arm, no reset -- was measured at 0.111 ms. So about 0.5 ms
of that 0.656 ms exists *only because a reset happened* and is *not* on the
reset's clock. Candidates, in no particular order and none of them measured:
re-translation of the TBs invalidated over the 25 restored pages,
`resume_all_vcpus()`, the detector's portal round trip. Guessing on this path
has been wrong twice, so it is named as open rather than attributed.

### The crash lap

A 22.1 ms crash lap splits as `sched_to_bh` **0.119 ms** and `bh_to_observed`
**22.02 ms** -- **99.6% after the bottom half completed.** Getting the reset
serviced by the main loop after a fatal signal costs the same ~48 us it costs
on any other lap. The crash cost is guest execution plus host-side plugin work
on that path, which is where the earlier 308.6 -> 56.9 ms throttling result
already pointed.

So the crash lap and the "in-QEMU loop" item are the same problem, and it is
not the one either was framed as: neither the reset nor the cost of *scheduling*
one.

### Arm 2 -- and the instrument failure it exposed

Arm 1 named `mc146818rtc#13` on 148 of 160 laps. Read as a scope miss, that
says "add it". Arm 2 did:

| | arm 1 (`cpu`) | arm 2 (`cpu,cpu_common,mc146818rtc`) |
|---|---|---|
| reset_us median | 71 | 95 |
| restored pages | 25 | **59** |
| lap | 0.782 ms | **1.616 ms** |
| exec/s | 1,278.9 | **618.7** |
| oracle names `mc146818rtc` | 148/160 | **153/160** |

**The section was in the block, was restored from it, and the report did not
change.** Throughput halved for nothing.

`hw/rtc/mc146818rtc.c` says why, and it is not a bug: `rtc_pre_save()` calls
`rtc_update_time()`, which reads the live clock and writes the current time
into `cmos_data` -- a saved field -- and `rtc_post_load()` re-derives both
timers from the current clock. **This device cannot serialise to the same bytes
twice, however correct the restore is.** Both arms' reports on it were true
differences and false meanings.

Note what the two fuzzing runs themselves say: 139,413 inputs / 1,881 crashes in
arm 1 against 136,925 / 1,841 in arm 2. The fuzzing was unaffected; only the
lap accounting moved. The cost was real and bought nothing.

### What the instrument does now

The count was one number for two findings:

- **not in the block and differs** -- the scope is too narrow. Widening fixes it.
- **in the block and differs** -- unrestorable. Widening cannot fix it; either
  the save reads state the restore does not own, or the restore is broken for
  that device. A genuine restore bug lands here too, so it is counted and named
  rather than forgiven.

`device_section_in_scope()` supplies the distinction, `*` marks in-block in the
report, and the selftest now requires the full-block control to show that every
section on `-M virt` round-trips -- without which phase 8's positive control is
ambiguous between the two cases.

Read through the corrected instrument, arm 1's actual answer is that **`cpu`
alone was sufficient except for `cpu_common`**, which fired on 3 laps of 160.
That needs re-running against the corrected build, together with a full-block
control at the same 4,000 laps: arm 1 was compared against `results/14`, which
ran 60,000 laps under a different harness version.

### Still not established

- the ~0.5 ms post-reset term, which is now the largest single cost in a lap;
- ~~whether `cpu_common` is a real scope miss or another unrestorable
  section~~ -- **settled: a real miss.** It restores fine; it simply was not in
  the block. Arm 1's 3-laps-of-160 was the low end of a 0.1-4.7% range, which
  is what makes it dangerous rather than negligible: a run can be scoped wrong
  and report VALID. Covering it costs 18% of throughput, 82% of which is the
  guest resuming from the interrupt state the arm captured. `fastloop` now
  completes the `cpu`/`cpu_common` pair itself. See `SCOPE-AB.md`;
- any of this on a second machine. Both arms are malta/mipsel. `ALLOWLIST.md`'s
  `{cpu, timer}` was aarch64-shaped and does not transfer: malta's equivalent
  came out as `cpu` plus possibly `cpu_common`, and `timer` never appeared.
