# Crash finding: what is actually evidenced

Written, then corrected twice, after asserting in-session that crash finding
had "no evidence behind it at all".

That assertion was wrong about the **sensor** and right about **crash finding**,
and the difference is the whole point of this document. 59 `crashes.yaml` files
sit in this lane's results directory; they prove a working signal-delivery
sensor, and they contain not one crash produced by fuzzing. The first revision
of this file read the sensor evidence as crash-finding evidence, which is the
error the next section exists to prevent anyone repeating.

## No crash in this lane was found by fuzzing

Stated first because the rest of this document is easy to misread as evidence
that crash finding works here. It is not.

**Corrected 2026-09-11.** An earlier revision of this file said `fuzzdrive` was
off in every run and no input was ever fed. That is wrong, and the truth is more
useful: `fuzzdrive` was armed in two runs (`run_fuzz.log` -> results/10,
`run_fuzz2.log` -> results/11) and delivered **743 mutated requests**.

The outcome was **zero new crashes**. results/10 and results/11 contain exactly
the same two boot-time records as every other run. And run 11's own controls
passed -- 79 passthrough samples returning `{400:96, 200:59, 401:13, 404:13,
501:3, 411:1, 505:1}`, so the server was not wedged and the parser was being
reached deeply rather than rejecting everything at the door.

So this is a **negative result, not an absence of testing**: 743 mutated
requests through a demonstrably live parser found nothing. The attribution gap
below was never exercised because there was never a crash to attribute.

`patch_fuzzcal.yaml` does carry `# OFF for the G measurement`, which is what
misled the earlier revision -- that comment governs the timing runs, not the two
dedicated fuzzing runs. Reading one config comment and generalising it to 59
runs is the same error as reading a sensor's output as a pipeline's result.

The records below are the firmware's own deterministic boot-time crashes,
recorded passively, and are unchanged by fuzzing:

| run | records |
|---|---|
| 0 | sxnetset@0x00009f3c t=57.2, msdialer@0xb6eec2f0 t=68.7 |
| 12 | sxnetset@0x00009f3c t=57.7, msdialer@0xb6eec2f0 t=69.2 |
| 36 | sxnetset@0x00009f3c t=48.7, msdialer@0xb6eec2f0 t=58.3 |
| 57 | sxnetset@0x00009f3c t=50.2, msdialer@0xb6eec2f0 t=60.1 |

Same two processes, same two program counters, same point in boot, every run.
That is a device bug the firmware reproduces on its own, not a finding. The one
extra record anywhere in the set -- `sleep`@0xb6fe8324 in run 35 -- came from
the deliberately-corrupted-guest experiment, so it is an artifact of a broken
reset rather than a discovered defect.

**Zero crashes were caused by an input** -- now measured over 743 mutated
requests, not merely untested. No crash has ever been attributed to an input on
this target, because none has occurred.

The attribution machinery itself has since been demonstrated end to end against
a planted bug in a purpose-written victim, with replay verification. See
`CRASH-PIPELINE.md`. That proves the pipeline is constructible; it is not
evidence of a finding on the target.

This is the same shape as every other instrument failure in this lane: the
sensor works, and it was observed in a situation where it could not possibly
demonstrate the capability being claimed for it. A directory full of
`crashes.yaml` files reads like evidence of crash finding and is evidence of a
passive sensor logging pre-existing bugs.

## What IS proven: the sensor

`pyplugins/analysis/crashes.py` records userland fatal-signal deliveries via
igloo_driver's signal hooks. From this lane's runs:

```yaml
crashes:
- proc: sxnetset
  pid: 2045
  signal: 11
  signame: SIGSEGV
  pc: '0x00009f3c'
  time: 48.288
  count: 4
- proc: msdialer
  pid: 2349
  signal: 11
  signame: SIGSEGV
  pc: '0xb6eec2f0'
  time: 57.588
  count: 1
```

Process, pid, signal, **faulting instruction address**, time, and a
de-duplicated count. Across ~50 runs the same two boot-time crashes appear at
the *same PCs* with different pids, so detection is stable and reproducible,
not incidental. There are 9 unit tests in `tests/unit/test_crashes_plugin.py`
and an integration fixture.

For synchronous faults the `pc` comes from the task's saved userspace register
frame, so it is the faulting instruction. That is a genuinely useful artifact.

## The claim that an unsound reset manufactures crashes is FALSE

Predicted: a corrupted guest floods `crashes.yaml` with unattributable
findings. Measured, correlating console damage against crash records per run:

| run | console damage lines | crash records | procs |
|---|---|---|---|
| typical healthy | 0 | 2 | msdialer, sxnetset |
| 34, 39, 46, 56 | 1 panic | 2 | msdialer, sxnetset |
| 35 | 1 panic + 32 OOM/swap_dup | **3** | + `sleep` |
| **48** | **98 panic/OOM/swap_dup** | **2** | msdialer, sxnetset |

Run 48 is decisive. The guest was being destroyed -- 98 lines of kernel panic,
`swap_dup: Bad swap file entry`, and OOM kills -- and `crashes.yaml` is
**byte-for-byte the same shape as a healthy run**. Zero extra records.

## The real failure mode is the opposite, and worse

**The crash channel is structurally blind to the damage this reset causes.**

The plugin hooks userspace fatal-signal *delivery* for SIGSEGV, SIGBUS, SIGILL,
SIGABRT, SIGFPE, SIGSYS. A kernel panic is not a signal. An OOM kill is
SIGKILL, which is not in that set and should not be. So kernel-side death --
precisely what a device-without-RAM restore produces -- cannot appear here at
all.

A campaign run on a subtly corrupt guest would show a **clean** `crashes.yaml`
while the guest rots. Absence of crash records is not evidence of guest health,
and nothing in the artifact says so.

And corruption does not produce nothing: run 35 produced exactly one extra
record, `sleep` taking SIGSEGV at `0xb6fe8324`. A random utility segfaulting is
a corruption artifact, but in a fuzzing report it is indistinguishable from a
finding. A trickle of plausible false positives is harder to notice than a
flood.

## What remains genuinely unproven for fuzzing

1. **No input attribution.** A row carries proc/pid/signal/pc/time. Nothing ties
   it to the input that caused it. That is the single largest gap between this
   and a fuzzer.
2. **No snapshot-restore handling.** `crashes.py` has no `on_restore`,
   `save_state` or `load_state`, and none of its 9 tests covers restore. It
   accumulates `self.crashes` with dedup counts that do not rewind when the
   guest does, against this lane's own documented rule that every stateful
   pyplugin needs all three. So today it is a campaign-level artifact, not a
   per-iteration oracle: after a reset the guest rewinds and the report does
   not.
3. **Deliveries, not deaths.** The plugin documents this itself -- a process
   that catches SIGSEGV and survives is still recorded.

## What this means for the design

Crash detection is not the risky half; it exists and works. The risky half is
that **its silence is uninformative**. Any fuzzing campaign here needs a guest
health channel independent of `crashes.yaml` -- console panic/OOM scraping at
minimum, and preferably a state-digest comparison against a known-good reset.

That is an argument for the fork oracle from a second direction: it is not only
how you validate the fast reset, it is how you tell a real finding from a
corrupted guest.
