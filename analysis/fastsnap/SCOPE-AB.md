# The device scope: what is a miss, what is unrestorable, and what it costs

Written before the runs. Every run this lane has done on this target reports
`FAILED`, and the reason has been the same section for thirty-nine runs:
`mc146818rtc#13`. This settles whether that is a scope miss or a fact about the
device, and in doing so it disposes of the other standing open item --
`cpu_common` -- which the archive turns out to have already answered.

## What the archive already says

Replaying every archived `fastloop.json`:

| scope in force | lap (ms) | reset (us) | pages | device diffs |
|---|---|---|---|---|
| full block (deny virtio-blk) | 1.992 | 451 | 59 | `*mc146818rtc#13` |
| `allow: [cpu, cpu_common]` | 2.132 | 93 | 59 | `mc146818rtc#13` |
| `allow: [cpu]` | 0.532 | 60 | 24 | `mc146818rtc#13` (+ `cpu_common#2`) |

Two things fall out of that table that were not previously stated.

**1. The RTC is unrestorable, and the code already knows.** Under the full
block the oracle prefixes it `*` and puts it in the `dev_unrestorable` bucket:
the section WAS carried by the block, WAS restored from it, and still does not
serialise to the same bytes. `penguin-fastsnap.c` names the mechanism --
`rtc_pre_save()` calls `rtc_update_time()`, which reads the live clock, so no
correct restore can make it byte-identical. Under `allow: [cpu]` the same
section is correctly reported as a scope miss, because there it really is one.

The untested case is the one in between: the RTC **inside an allowlist**. Run
16 did that and got a plain diff, no `*` -- but run 16 predates the `*`
classification, which was written afterwards and whose comment describes run 16
as its motivating failure ("a run added it, the report did not change, and
throughput halved"). So nobody has run the fixed code on that case.

**2. `cpu_common` is not a fixed cost. It is a property of the arming draw.**
Counting `cpu_common#2` per verification across all runs at `allow: [cpu]`
gives two clean populations and nothing between them:

| population | runs | cpu_common diff rate |
|---|---|---|
| low | 15, 18, 26, 28, 30, 31, 33, 36, 39, 41, 42, 43, 44, 46, 47, 48, 51, 52 | 0.6% - 4.7% |
| high | 40, 45, 49 | 98.5% - 99.2% |
| none | 38, 53 | 0 of 1000 |

Runs 40, 45 and 49 are interleaved with runs 39, 41, 42, 43 in the same A/B, on
the same host, at the same crash-lap cost (52-62% of wall), with medians inside
1,849-1,894. The only thing that differs is which instant the draw landed on.

That kills the framing this item has carried ("a real scope miss; covering it
costs 4x the lap"). Covering it does cost 4x -- runs 16 and 32 both show pages
going 24 -> 59 and the lap 0.53 -> 2.1 ms -- but the thing being covered is
present on some draws and absent on others. The cheap answer is not to pay 4x
on every draw; it is to **reject a draw that needs it**, which is the third
side of an arm check that already has two.

## The runs

Two, sequential, on an idle host, same image (`penguin:fstb`), same everything
except one line.

* **B (control)** -- run 53's exact configuration, `allow: [cpu]`. Repeats the
  post-`crashes.py` throughput with n=2, and is the first run of the new
  per-lap code (the `on_lap` publish, the rolling health window, bugbench's lap
  stamping) on a real guest.
* **A** -- B plus `mc146818rtc` in the allowlist.

## Predictions

**P0. The RTC will be classified unrestorable, not as a scope miss.** In run A
it appears as `*mc146818rtc#13`, `dev_unrestorable_sections > 0`, and
`dev_diff_sections == 0`.
*Falsifier:* it appears without the `*`, as in run 16. That would mean
`device_section_in_scope()` disagrees with what the block actually carried under
an allowlist, and the bug is in the oracle rather than in the scope.

**P1. Run A's verdict becomes VALID**, naming `['*mc146818rtc#13']` as excluded
by name. This is the point of the exercise: thirty-nine runs have reported
FAILED for a reason that is not a failure.
*Falsifier:* still FAILED.

**P2. The RTC is nearly free.** `reset_us` rises by less than 20 us and the
median lap by less than 5%. Run 16's 1.616 ms came from `cpu_common` pulling
the dirty page count 24 -> 59, not from the RTC, which is a small section.
*Falsifier:* the lap rises materially, which would mean the RTC's restore
does something that touches RAM.

**P3. `restored_pages` stays at ~24 in run A.** A device section is not RAM.
*Falsifier:* pages move, which would falsify the reading of P2's mechanism as
well.

**P4. The new per-lap code is free.** Run B reproduces run 53 within noise:
wall rate 1,100-1,200 laps/s, median 1,850-1,900 exec/s. The added work is one
`plugins.publish` with one subscriber, one modulo-free counter increment, and
one dict store per lap.
*Falsifier:* B lands materially below 53. Anything over ~1% would be worth
chasing, because it is per-lap cost added by an instrument.

**P5. `cpu_common` lands in one of the two populations, not between them.**
A fresh draw is a fresh coin flip: either under ~5% or over ~95%.
*Falsifier:* an intermediate rate (20-80%), which would mean the divergence is
a continuous property of something else and the bimodality is coincidence.

**P6. The new attribution reports what the replay predicted.** `verify` around
35% of the wall clock, `unaccounted` under 0.1%, and the headline note fires at
a median/wall ratio near 1.6.
*Falsifier:* `unaccounted` is material, meaning the live buckets do not
partition the span the way the archive says they do.

---

# Results

Four runs, sequential, idle host, `penguin:fstb`, `--dev`. Each differs from
the one before it in exactly one thing.

| | 53 (archive) | 54 = B | 55 = C | 56 = A | 57 = A2 |
|---|---|---|---|---|---|
| change from previous | -- | new fastloop code | lap binding fixed | + RTC in allowlist | repeat of A |
| iterations | 200,000 | 200,000 | 200,000 | **90,200** | 200,000 |
| wall laps/s | 1,153 | 1,152 | 1,117 | 1,157 | 1,142 |
| `exec_per_s_median` | 1,879 | 1,861 | 1,763 | 1,857 | 1,815 |
| ordinary lap (ms) | 0.5322 | 0.5374 | 0.5672 | 0.5386 | 0.5511 |
| `reset_us` | 60 | 60 | 66 | 61 | 65 |
| `restored_pages` | 24 | 24 | 24 | 23 | 24 |
| crash laps | 1.34% | 1.34% | 1.34% | 1.95% | 1.33% |
| verify % of wall | 35.4% | 35.1% | 34.1% | 34.8% | 34.4% |
| `unaccounted` | 0.00% | 0.00% | 0.00% | 0.00% | 0.00% |
| device diffs | 996/1000 | 996/1000 | 996/1000 | **0**/451 | **0**/1000 |
| verdict | FAILED | FAILED | FAILED | DEGRADED | **VALID** |

**P0 confirmed.** With `allow: cpu,mc146818rtc` the oracle reports
`*mc146818rtc#13`, `dev_unrestorable_sections > 0`, `dev_diff_sections == 0`,
and logs the sentence the code was written to log: *"1 device sections are IN
the block, are restored from it, and still do not serialise identically.
Widening the allowlist cannot fix this."* Run 16's plain diff was the pre-fix
code; the current code gets the classification right.

**P1 confirmed on A2.** `VALID: 1000 verifications, every one byte-identical to
an independently forked reference across 281,346,048 bytes, with 1000 of them
also finding every device section in scope back where the arm left it. 1
sections on this machine never serialise identically and are excluded by name:
['*mc146818rtc#13'].` That is the first VALID verdict this lane has produced on
this target. Thirty-nine runs reported FAILED for a section that cannot round
trip and now says so by name.

**P2 and P3 confirmed. The RTC is free.** `reset_us` 61/65 against controls at
60/66; lap 0.5386/0.5511 against 0.5374/0.5672; pages 23/24 against 24/24. Run
16's 1.616 ms came from `cpu_common` dragging the dirty page count 24 -> 59,
exactly as predicted, and not from the RTC.

**P4 confirmed. The new per-lap code is free.** 54 against 53 is 1,152 against
1,153 laps/s, 0.1%. The lap binding (55) reads 3% lower, but `reset_us` --
measured inside the bottom half, where no Python change can reach -- moved 60
-> 66 on the same run. That is the noise floor, not the subscriber.

**P6 confirmed, live.** `unaccounted` is 0.00% on all four runs, and the
verdict now carries its own indictment without being asked:

> THE HEADLINE RATE IS NOT THE RATE: exec_per_s_median 1861 is 1.6x the
> wall-clock rate 1152. [...] VERIFY LAPS ARE 35% OF THE WALL CLOCK AND 0.5%
> OF THE LAPS.

## P1 was refuted first, by the check added earlier the same day

Run 56 -- the first run with the RTC in the block -- came back `DEGRADED`, not
`VALID`. The rolling health window stopped it at iteration 90,200 with 54.6% of
the last 1,000 laps closing on a fatal signal against a 1.3% baseline.

The crash stream says what happened. At t ~100-124 s the victim produced 538
crashes at **PC 0** in a single decile, and the crash rate stayed at roughly
double its previous level for the rest of the run. PC-0 is a signature this
lane has seen before: the rejected `fast_rng` experiment produced 1,773 of
them.

It did not reproduce. Run 57, the identical configuration, ran 200,000 laps at
a 1.33% crash rate with **zero** PC-0 crashes in any decile, and returned
VALID. Set against runs 54 and 55 -- 400,000 laps at `allow: [cpu]` with no
degradation -- the tally is one anomaly in 690,000 laps, and the RTC is not
implicated by it.

What the run does establish is that the check works. One true positive, no
false positives across three runs of 200,000 clean laps each, and the run
stopped and said where rather than averaging a crashing tail into a rate --
which is what runs 8 and 30 did, twice, unnoticed.

## `cpu_common`: the item is closed, and it was never what it was called

Four consecutive runs report `cpu_common#2` on **0 of 1000** verifications. The
archive's two populations (0.6-4.7% and 98.5-99.2%, nothing between) plus four
draws at zero says this is a property of where the arm lands, not a fixed cost
of the scope. Nothing needs to be added to the allowlist; run 32 measured what
adding it costs (pages 24 -> 59, lap 0.53 -> 2.13 ms) and the answer is that it
should not be paid on every draw for something most draws do not have.

P5 is not falsified -- no run landed between the populations -- but it is not
confirmed either: every recent draw landed at zero, so the high population has
not been re-observed since the attribution was built. What would settle it is
an arm-probe axis that scores the device oracle on the draw, which is the
natural third side of a check that already tests faulting and progress.

## The join, live

The lap boundary ran on a real target for the first time in runs 55 and 57:

| | 55 | 57 |
|---|---|---|
| crashes joined by lap | 3,790 | 3,910 |
| joined by pid (before the loop armed) | 414 | 451 |
| **the two joins disagreeing** | **0** | **0** |
| laps delivering more than one input | 321 | 266 |

So the pid join was not silently wrong on this target -- which is worth knowing
rather than assuming, given it was catastrophically wrong once. And the lap
join is exact by construction on 99.8% of laps.

It also exposed a hole. The guest keeps running after the loop stops -- run 55
delivered 287,000 inputs against 200,000 laps -- and a subscriber holding the
final lap index goes on stamping the tail with it. Fixed: the loop now
announces `on_lap(None, "end")`, and the subscriber falls back to the join it
uses when there is no loop.

---

# `cpu_common`: both halves of the old story were arming artifacts

The claim carried in this lane was "a real scope miss; covering it costs 4x the
lap". Re-measured on the current code with the fast oracle:

| run | scope | lap | reset | pages | exec/s | crash rate | cpu_common diffs | verdict |
|---|---|---|---|---|---|---|---|---|
| 16 | cpu,cpu_common,rtc *(old code)* | 1616 us | 95 | **59** | 248 | **0.00%** | 0/160 | FAILED |
| 32 | cpu,cpu_common *(old code)* | 2132 us | 93 | **59** | 242 | **0.01%** | 0/266 | FAILED |
| 58 | cpu,rtc | 539 us | 61 | 24 | 1141 | 1.33% | 1/1000 | FAILED |
| 61 | cpu,rtc | 528 us | 59 | 23 | **1760** | 1.33% | 0/1000 | VALID |
| 62 | cpu,cpu_common,rtc | 655 us | 75 | 24 | 1441 | 1.33% | **0/1000** | VALID |

**Runs 16 and 32 delivered no inputs.** Crash rates of 0.00% and 0.01% against
1.33% everywhere else: those draws never reached the injector, which is exactly
the idle-arm failure the two-sided probe was later built to reject. Their
1.6-2.1 ms laps and 59-page dirty sets were properties of that draw, not of
`cpu_common`. The "4x" was never measured on a run that was fuzzing anything.

Measured properly, covering `cpu_common` costs **+127 us of lap, 18% of
throughput** -- and it buys a verdict that stops being a coin flip. Without it
the section diverges on 0.1-4.7% of verifications, so a 1000-verification run
returns FAILED or VALID depending on whether a rare event landed (run 58 caught
exactly one and failed; run 61 caught none and passed).

## Where that 127 us goes, which is the interesting part

| | before the guest resumes | after it resumes |
|---|---|---|
| `cpu_common` costs | +22.6 us | **+102.6 us** |

Only 18% of it is the reset doing more work. The other 82% is the guest
**executing differently**, which is the whole purchase: `vmstate_cpu_common`
carries `halted` and `interrupt_request`, so with it in the block the guest
resumes from the interrupt state the arm actually captured instead of carrying
forward whatever the previous lap left behind. It is a fidelity cost, not
overhead.

That also gives the two failures one cause. `mc146818rtc` is unrestorable
because its save reads the live clock -- and it is the periodic timer whose
interrupts set `interrupt_request`. A section that cannot be rewound, driving
the field that occasionally fails to match, is one story rather than two.

**Recommendation: cover it.** 18% is the right price for a scope that is
actually complete, and the alternative is a verdict decided by a coin flip.

# The hook point is worth 4%, not a syscall boundary

The injector hooks `on_sys_read_return` and the detector hooked
`on_sys_read_enter`, so one guest read drove two dispatches. This lane had
measured a syscall boundary at 133-208 us on another target, which predicted a
large win from collapsing them onto one trap. `detector_at` makes that
selectable; one variable, same scope:

| | 62 `enter` | 63 `return` |
|---|---|---|
| lap | 654.9 us | **606.8 us** |
| exec/s | 1,441 | **1,502** |
| crash rate | 1.33% | 1.33% |
| RAM diffs | 0/1000 | 0/1000 |
| verdict | VALID | VALID |

**7.3% on the lap, not 25-40%.** The prediction is falsified and the reason is
worth more than the speedup: penguin's enter and return hooks on the same
syscall are *not* two independent guest traps. Whatever the driver does, the
second hook point is nearly free, so "fewer hook points" is not the lever it
looked like -- and the 490 us still sitting in `bh_to_observed` is not made of
dispatches.

Left as a knob rather than a default, because it moves the arming point: an
iteration is the span from the armed instant to the next detector hit, and
arming at read-return rewinds to an instant where the kernel has already filled
the buffer. Same crash rate, same oracle, but a different instant, and 4% is
not enough to change a measurement's meaning for.
