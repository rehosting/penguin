# Removing what is left, while still doing a restore

The reset is no longer the expensive part of a lap, and this is the experiment
that acts on that.

Measured, run 26 (bugbench, mipsel/malta, 4,000 laps, `allow: cpu`, idle host),
an ordinary lap of **0.7396 ms = 1,352 exec/s**, split:

| term | ms | share |
|---|---|---|
| baseline lap -- guest work, the detector round trip, this harness | 0.5233 | 71% |
| post-resume penalty (`bh_to_observed` minus bare) | 0.1044 | 14% |
| the reset's own clock | 0.0620 | 8% |
| main-loop latency (schedule to bottom half) | 0.0398 | 5% |

The whole reset side is 0.206 ms. Deleting **all** of it -- a perfect,
instantaneous, zero-latency restore -- takes the lap to 0.533 ms and the rate
to 1,876 exec/s: **+39%, and that is the ceiling on every remaining idea about
the reset.** Meanwhile a bare lap with no reset at all costs 0.5233 ms with
this harness loaded and cost **0.1112 ms** without it (run 8). So ~0.41 ms per
lap -- more than half of every iteration -- is host-side Python, and it has
never been attributed to a line.

That is what this experiment removes. The restore stays exactly as it is.

## What is actually on the per-lap path

`bugbench.on_read` fires once per lap and makes **two portal round trips into
the guest**:

- `plugins.osi.get_fd_name(fd)` -- `yield PortalCmd(HYPER_OP_OSI_FDS, ...)`,
  a walk of the guest's fd table serviced by the in-guest driver while the vCPU
  waits.
- `plugins.osi.get_proc()` -- `yield PortalCmd(HYPER_OP_OSI_PROC, ...)`, the
  current task read back the same way.

Neither is cheap and neither is information the loop does not already have.
Plus, per lap: a sha256 of the payload, a `dict` of seven keys, a file created
in the results directory, and `self.sent.pop(0)` -- an O(n) memmove of 5,000
pointers, on the vCPU thread.

### Why the two portal calls are removable *here*

Because of the snapshot, and only because of it. A reset returns the guest to
**one instant**. Every lap therefore sees the same process, at the same point,
with the same descriptor open. The fd number and the pid are constants of the
loop; re-deriving them 1,400 times a second is re-deriving a constant.

"Therefore" is doing too much work unsupported, so the latch is earned and then
audited:

- nothing is cached until `fast_after` (64) consecutive injections agree on the
  same `(fd, pid)`;
- only **positive** fd matches are cached. A negative cache would reproduce the
  exact bug the uncached resolve exists to avoid -- the loader closes its
  library descriptors before the victim opens the request one, so fd numbers
  are reused (observed: `attrib` run 1, `inputs_delivered=0`);
- every `revalidate_every` (1,000) injections **both** answers are derived the
  expensive way and compared. A disagreement drops the latch and is an error in
  the report, not a warning -- a stale latch injects into the wrong descriptor,
  or attributes a crash to an input the crashing process never received, and
  nothing else in the pipeline can notice.

### And the cheap ones

`self.sent` becomes a `deque(maxlen=...)`; the sha256 and the head-hex are
computed lazily, on a crash row or in the final dump, because 99.6% of input
records are discarded having never been read.

## Predictions, written before either run

Committed first so the phase table cannot be read backwards into whatever it
shows.

- **P0** -- `resolve_fd` + `resolve_pid` together are **more than half** of
  `on_read total`. If they are not, the portal calls were never the problem and
  the lean path is not worth its audit.
- **P1** -- `on_read total` means **250-450 us**. It has to be under the 0.41 ms
  cross-run estimate for the whole plugin, because the signal callback and the
  second syscall hook's dispatch sit outside this function.
- **P2** -- `inject (portal)` is the third-largest phase and is **not**
  removable: it is the injection.
- **P3** -- arm B's lap falls by approximately the sum in P0, so if P0 lands at
  ~0.25 ms the lap goes 0.74 -> ~0.49 ms and the rate **1,352 -> ~2,000
  exec/s**. A gain much larger than P0's sum would mean the phase timers are
  not measuring what they name.
- **P4** -- the latch is earned once, `latched/delivered > 0.99`, and
  **zero** latch errors. A single latch error invalidates arm B's inputs.
- **P5** -- the score does not fall. Same victim, same mutator, same seed, more
  budget: **>= 5/7**, zero unattributed crashes, negative control clean.
- **P6** -- the cheap removals (deque, lazy hash) are worth **< 40 us/lap** on
  their own -- they are host-local work with no portal in them. Arm A against
  run 26 prices them, with the caveat that arm A also changes `iters` and
  `verify_every` (verified laps are bucketed apart from ordinary ones, so the
  median should not move for that reason).

## Arms

Identical in every respect but one line:

| arm | `fast` | what it prices |
|---|---|---|
| A | `false` | the phase table, and the cheap removals against run 26 |
| B | `true` | the two portal round trips |

Both keep the full restore, the fork oracle, the device oracle, `allow: cpu`,
and `reset_on_signal`.

`iters: 200000` with `verify_every: 200`: at 4,000 laps the loop was 13 s of a
240 s run and **135,000 of the 139,000 injections happened after it had stopped
resetting**, so the cost table would have described the free-running tail
rather than the loop. Now the loop never ends inside the run and every
injection is a lap.

## Results

All bugbench, mipsel/malta, `allow: cpu`, `reset_on_signal`, 240 s runs whose
loop never stops resetting. Arm A is the control: the same new file with the
lean path off.

| run | arm | `fast` | lap ms | exec/s | `on_read` us | `signal_deliver` us | inputs | crash rate |
|---|---|---|---|---|---|---|---|---|
| 26 | pre-existing | -- | 0.7396 | 1,352 | -- | -- | 139,413 | 1.35% |
| 28 | A | no | 0.7544 | 1,326 | **280.22** | 12,475 | 124,452 | 1.34% |
| 31 | D | yes | 0.5492 | 1,821 | 87.22 | 13,752 | 135,202 | 1.34% |
| 33 | F | yes + journal | **0.5321** | **1,879** | **85.26** | **326.5** | **145,533** | 1.34% |
| 36 | I | yes + journal | 0.5276 | 1,895 | -- | -- | -- | -- |

Run 36 is a repeat of run 33 and agrees with it -- 0.5276 ms over 121,000 laps
-- but it is the first run ever to exhaust `iters: 200000`, after which the
container sat past its own 240 s timeout and had to be stopped by hand, so its
plugin reports are partial. It counts as a third clean draw below and is not
used for anything else. (`core.timeout` not firing on a wedged container is a
known hazard in this lane and is not a result.)

**0.7544 -> 0.5321 ms, 1,326 -> 1,879 exec/s, +42%.** Against run 26 it is
+39%, and run 26 is the weaker comparison in the loop's favour: its loop reset
for 13 s of a 240 s run, run 33's for 220 s, so run 33 delivered *more* inputs
(145,533 vs 139,413) with every one of them under a reset.

Nothing about the restore changed. Reset 64 -> 59 us, restored pages 25 -> 24,
device scope identical, fork oracle clean on every verification in every run.

### Where the 280.22 us went (run 28, 124,452 injections)

| phase | mean us | share | fate |
|---|---|---|---|
| `resolve_fd` (portal) | 128.79 | 46% | **removed** -- learned from open/close |
| `resolve_pid` (portal) | 73.73 | 26% | **removed** -- `syscall_event.pid` |
| `generate` | 28.85 | 10% | kept (see `fast_rng` below) |
| `inject` (portal) | 24.58 | 9% | kept -- it *is* the injection |
| `bookkeeping` | 19.58 | 7% | kept |

The pid was free the whole time. `struct syscall_event` already carries
`current->pid`, and the driver header says why: *"denormalized so the host can
identify the task without a separate OSI_PROC round-trip."* It is trusted only
after agreeing with `get_proc()` on the first 200 injections -- 345/345 and
226/226 across the runs, never once disagreeing -- because a field that is
present and means something slightly else (a tgid where `signal_deliver`
reports a thread id) would break the input-to-crash join silently.

The fd is learned from the guest's own `open`/`openat` returning it and
forgotten on `close`, keyed by `(pid, create_time, fd)`. Run 33: **145,215 of
145,252 reads answered from the map**, 628 opens learned, 314 closes honoured.

### Scoring the predictions

- **P0 CONFIRMED.** 128.79 + 73.73 = 202.52 us of 280.22 = **72%**.
- **P1 CONFIRMED.** 280.22 us, inside the 250-450 us window.
- **P2 WRONG.** `inject` was fourth, not third; `generate` -- 36 `randrange()`
  calls -- beat it at 28.85 us.
- **P3 CONFIRMED, and by the stated mechanism.** The prediction was that the
  lap would fall by the sum in P0 and that a much larger gain would mean the
  timers were not measuring what they named. `bh_to_observed` went
  0.6408 -> 0.4399 ms: **-0.2009 ms against a predicted 0.2025 ms.**
- **P4 FALSIFIED.** See below.
- **P5 CONFIRMED with `fast_rng` off**, falsified with it on. See below.
- **P6 CONFIRMED.** Arm A at 0.7544 ms against run 26's 0.7396: the deque and
  the lazy digests bought nothing measurable. They stay because they are free
  and correct, not because they were worth a run.

### P4, falsified: the first design was wrong and the audit is why we know

The first attempt latched `(fd, pid)` on the reasoning that a snapshot loop
returns the guest to one instant, so both are constants. They are -- **after**
the loop arms. Before it the guest is an ordinary forward-running system whose
victim crashes and restarts, and fd 3 is the dynamic loader's `libgcc_s.so.1`
before it is the victim's request descriptor. The latch was earned in that
window; **2,786 inputs went into the loader's read of its own shared library**,
the exact failure the uncached resolve was written to avoid. The run ended with
3,000 inputs where its control delivered 124,452.

The audit caught it three times and it still ruined the run, which is the
lesson: **a cache whose correctness rests on "the guest is in a state I believe
it is in" is the wrong shape however carefully it is audited.** What replaced
it derives both answers from the guest's own events and assumes nothing.

The audit stayed, and caught its own bug next: in run 33 it reported the map
corrupt twice when `get_fd_name()` had simply come back empty. An instrument
that cannot look has said nothing in either direction -- the same distinction
the fork oracle draws between -1 pages and 0. Blind audits are now counted
apart from disagreements.

### `fast_rng` is measured and NOT recommended

Replacing 36 `randrange()` calls with one `randbytes()` is worth 22.8 us and
changes the byte stream. Run 30 took it and came apart: crash rate 1.34% ->
**3.61%**, 1,773 crashes at PC 0 from t=97 s to the end of the run, B3 lost,
inputs down to 76,198. The single-variable control -- run 31, same lean path,
original stream -- was clean at 1.34% and 135,202 inputs. **22.8 us is not
worth changing what the fuzzer sends.** The flag stays, defaulted off, with
this written next to it.

### The crash lap is not the YAML dump, and that was my expectation

`write_report()` re-dumped the whole growing crash list as YAML every 50
crashes -- O(n^2), which is why the same callback measured 22.5 ms over 54
crashes and 13.75 ms *mean* over 1,802. Replacing it with one appended JSONL
line per crash took `signal_deliver` from **12,475 us to 326.5 us, 38x**, and
delivered 17% more inputs.

It did **not** move the crash lap: `crash_iter_ms` is 66.2 ms before and 69.9 ms
after. So the ~24 s that came off was real throughput and the crash lap's cost
is somewhere else entirely. At 1,632 crash laps of 70 ms that is **114 s of a
220 s loop on 1.4% of the laps** -- now the largest unexplained cost in the
whole measurement, and bigger than everything removed here.

## Two findings this experiment was not looking for

### `cpu_common` is a real scope miss

Every run since the scoped oracle landed has ended `FAILED: ... left device
sections unrestored (['cpu_common#2', 'mc146818rtc#13'])`, and it was not known
whether `cpu_common` was genuinely outside the block or another section that
cannot round-trip. Run 32 settles it: with `allow: cpu,cpu_common` the report
drops to `['mc146818rtc#13']` alone -- the known-unrestorable one. **It was a
real scope miss.**

Widening to fix it is not free and not obviously right: the lap went
0.5492 -> 2.1323 ms, exec/s 1,821 -> 469, restored pages 24 -> 59, and 38,006
of 78,960 reads were the dynamic loader's rather than the victim's -- the
workload got worse, not better. Same shape as run 16, where adding
`mc146818rtc` halved throughput. Open.

### The arming point does not just set the rate -- it can wedge the loop

Runs 34 and 35, identical in effect to run 33 (the diff is the blind-audit
counter, and `audits_blind` was 0 in both, so the new branch never ran),
both came apart the same way: **26,377 and 26,614 inputs against run 33's
145,533**, 9,110 and 9,056 crashes against 1,954, laps of 5.7 and 6.9 ms.
In both, the PC-0 crash class begins in the bucket containing the arm.

The loop armed at an instant where the victim was already broken, and then
rewound to it 8,600 times. Run 30 reached the same state 72 s *after* arming.
**Two wedged of five draws** at this scope and code (31, 33, 36 clean; 34, 35
wedged), plus run 30 drifting in later.

This is the lane's existing headline -- the arming point is a blind draw from
the detector's interval distribution -- in a sharper form than
`LOOP-RESULTS.md` records it. A bad draw does not give a slow lap. It gives a
**permanently crashing** one, at full speed, with a clean fork oracle
throughout, because the guest really is being restored byte-perfectly to a
broken instant. Nothing in the harness currently notices; the rate simply
reads 145 exec/s instead of 1,879.

**The arm needs a health check** -- if the first N laps all close on a fatal
signal, the draw was bad and the loop should re-arm rather than report a rate
for it. That is the next thing to build, and it is worth more than any
remaining microsecond on this page.


---

# The arm, conquered — and the crash lap, finally attributed

Two things were outstanding above: a bad arming draw that silently reports a
13x wrong number, and a 70 ms crash lap that was 114 s of a 220 s loop and that
I could not account for. Both are settled.

## The arm needs TWO health criteria, and finding the second cost a run

**Detection works and is not enough.** The probe went in first: score the first
200 laps, reject a draw where the signal fraction is absurd. It fired on the
first real run and rejected **three draws in a row at 200/200 probe laps**, then
reported `iters=0, exec_per_s=None` rather than 145 exec/s. Correct, and
useless -- rejecting and waiting a fixed interval draws again from the same
distribution.

**So arm on evidence: require the victim to have just survived
`arm_clean_streak` (64) reads.** A victim that crashes on any input cannot
produce a clean streak, which targets the observed failure exactly.

**And that immediately produced the mirror image.** The next run:

```
arm 1 accepted -- 0/200 probe laps closed on a fatal signal (0.0%)
RESULTS iters=200000 iter_median_ms=0.2944 exec_per_s=3396
```

The best numbers this lane has ever produced, and worthless: 27 signal laps in
200,000 where 1.3% was expected, a clean streak of **193,309** reads, and the
crash record showing a 100-second window with **zero crashes** covering the
whole loop. The draw armed on a span that never reaches the injector, so the
loop was faithfully resetting a guest that was not being fuzzed.

I optimised for "the victim did not die" and got an arm that does nothing. A
health check that only looks for death **selects for idleness**.

The probe is now two-sided: the draw must also show PROGRESS, named as
`plugin.attribute` (`bugbench.n_sent`) rather than hardcoded, advancing on at
least half the probe laps. And -- the lane's standing rule -- a configured
counter that cannot be read **refuses the run** instead of warning. That rule
earned itself immediately: on its first run the counter was inert, because the
registry key is the plugin's FILE name and `bug_bench` is the logger's name for
the class. The draw was scored on the signal fraction alone and nobody would
have known.

With both criteria:

```
arm 1 accepted -- 2/200 probe laps closed on a fatal signal (1.0%)
RESULTS iters=113310 iter_median_ms=0.5311 exec_per_s=1883
bugbench: inputs=141104 crashes=1960 attributed=1960   <- 1.39%
```

**1,883 exec/s**, agreeing with runs 33 (1,879) and 36 (1,895). The 3,396 is now
rejected automatically.

## The crash lap is guest-side, and none of it is ours

Split at the fault, over 1,624 crash laps:

| span | median ms |
|---|---|
| reset done -> the guest faults | **71.4406** |
| the fault seen -> the lap closes | **0.0099** |

**99.99% of a crash lap is the guest getting from the restored instant to a
fault.** The harness closes the lap 10 microseconds after seeing the signal.

That retires a guess and redirects the work. Every host-side removal in this
document -- the injector's O(n^2) YAML dump at 12.5 ms a crash included -- was
never the crash lap, which is exactly what the measurement said when removing
it moved throughput and left `crash_iter_ms` at 70 ms. The cost is inside the
guest: resume, read, parse, fault, kernel signal delivery, driver hook.

For scale: the same span on a **non**-crashing lap is 0.43 ms, because
`detector: read` closes an ordinary lap at the next read's ENTRY -- before the
parse. So the fault-and-deliver path costs ~71 ms of guest execution that an
ordinary lap never pays and never measured.

**The next target, and it is bigger than everything above.** 1,624 laps at
71 ms is 115 s of a 220 s loop -- on 1.4% of the laps. Halving it is worth more
than every microsecond removed in this document put together. The first thing
to look at is the one open question this lane already has: the reset invalidates
translated code on every restored page (`tb_invalidate_phys_range`), and the
kernel's fault-and-signal path is precisely code that a crash lap needs and an
ordinary lap does not. `FASTSNAP_TB_SKIP_NOCODE` exists, defaults off, and has
never been A/B'd on an idle host. That is now a much more interesting experiment
than it was when it was filed.
