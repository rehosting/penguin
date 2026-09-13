# Does skipping TB invalidation on code-free pages break the guest?

An open question, once answered wrongly, and the instrument to answer it
properly only started existing today.

## The question

`fastsnap_ram_restore()` calls `tb_invalidate_phys_range()` for every page it
copies back. The obvious optimisation is to skip the call for pages QEMU says
hold no translated blocks:

> `tlb_protect_code()` CLEARS the CODE dirty bit when a block is translated on
> a page, so a SET bit reads as "no code here, nothing to invalidate" -- and
> `cputlb.c`'s notdirty write path makes exactly that test before its own
> `tb_invalidate_phys_range_fast()`.

The polarity is the thing most likely to be got backwards, and it is worth
restating because it reads inverted: **set bit means no code.**

## Why it is open rather than settled

A first A/B appeared to convict the skip outright: with it in place **every one
of 4,000 fuzzing laps ended in a fatal signal**, against 60 without it. That
result did not survive. The identical signature -- nearly every lap closing on
a signal, inputs delivered down several-fold -- was later produced on this same
target by nothing but a loaded host, twice, and the run that convicted the skip
had followed a fifty-minute build. The finding was withdrawn and the code
reverted to the behaviour that cannot be wrong.

## Why this is the right time to re-run it

Not merely "on an idle host". Since that A/B, **two of every five arming draws
on this target produced a wedged loop** -- a victim broken at the armed instant,
rewound to several thousand times, closing essentially every lap on a fatal
signal at 145 exec/s instead of 1,879. That is the same signature again, from a
third cause, and an interleaved A/B would have been poisoned by it with no way
to tell afterwards.

The arm now has to pass a two-sided health check before the loop reports
anything, and a rejected draw is discarded rather than averaged in. A run that
comes back wedged now says so instead of looking like a regression. **That is
what makes this experiment answerable, and it is the reason it is being run
today and not two weeks ago.**

## Design

Four runs, **interleaved** off / on / off / on, same image, same config, one at
a time on an idle host. Interleaving is the control the original A/B lacked:
host conditions drift over an hour, and two adjacent runs cannot tell a code
change from a drift.

The image is a fresh build (`penguin:fstb`) because the shipped one predates
the knob -- verified, not assumed: `strings libqemu-system-mipsel.so | grep -c
FASTSNAP_TB_SKIP_NOCODE` is 0 on `penguin:fsloop`, which is exactly how a
previous pair of runs in this lane was contaminated. `penguin:fsloop` is left
alone so runs 28-40 stay reproducible.

## Predictions, written before the runs

- **P0 -- SAFETY, which is the actual question.** With the arm health check
  active on an idle host, the `on` arms show no elevated signal fraction, no
  fork-oracle failure, and no new device-oracle finding. If the skip is a
  correctness bug this is where it shows, and this time a wedged draw cannot
  masquerade as one.
- **P1 -- the reset's own clock falls but does not vanish.** It is 60 us over
  ~24 restored pages. Predict `reset_us` median drops and stays above 30 us.
- **P2 -- the ordinary lap improves by LESS than 60 us.** The reset is 11% of a
  0.528 ms lap and the skip cannot remove all of it, so predict the lap does
  not go below ~0.47 ms. A larger gain means the skip is removing post-resume
  re-translation as well, which would be a better result than P1 implies.
- **P3 -- the crash lap does NOT materially improve, and this is a prediction
  AGAINST the lever I proposed.** Predict `crash_bh_to_signal_ms` stays within
  15% of 70 ms. The reasoning: the reset restores pages the guest WROTE --
  stack, heap, data -- and kernel text is never written, so the fault-and-signal
  path's translations are never invalidated by the reset in the first place. If
  the crash lap *does* fall sharply, my model of what the reset touches is
  wrong, and that is the more interesting outcome of the two.
- **P4 -- the interleave must agree with itself.** The two `off` arms within 5%
  of each other, and the two `on` arms within 5%. If the two `off` arms
  disagree by more than that, the host was not stable and the run says nothing
  in either direction -- which is precisely the failure that produced the
  withdrawn result.
- **P5 -- the workload is unchanged.** Crash rate 1.3-1.4% and the same planted
  bug set in all four arms. A skip that changed which bugs are found would be a
  correctness finding dressed as a performance one.

## Results

Nine runs on one fresh image (`penguin:fstb`), interleaved, arm mapping taken
from each run's own log rather than from directory order. The `on` arms are
confirmed live: QEMU announces the knob when it reads the env var, the runner
aborts if an `on` arm fails to announce it or an `off` arm does, and all nine
passed that gate.

| run | arm | lap ms | exec/s | reset us | crash->sig ms | crash % | oracle | devices differing |
|---|---|---|---|---|---|---|---|---|
| 41 | off | 0.5247 | 1906 | 60 | 70.12 | 1.34% | clean | cpu_common, rtc |
| 42 | on | 0.5243 | 1907 | 57 | 70.98 | 1.34% | clean | cpu_common, rtc |
| 43 | off | 0.5339 | 1873 | 60 | 71.36 | 1.34% | clean | cpu_common, rtc |
| 44 | on | 0.5287 | 1891 | 56 | 80.79 | 2.03% | clean | + **i8259** |
| 46 | on | 0.5620 | 1779 | 67 | 69.40 | 3.35% | clean | cpu_common, rtc |
| 47 | off | 0.5315 | 1881 | 55 | 76.47 | 1.72% | clean | cpu_common, rtc |
| 48 | on | 0.5219 | 1916 | 54 | 72.01 | 1.52% | clean | cpu_common, rtc |
| 51 | off | 0.5353 | 1868 | 60 | 70.47 | 1.34% | clean | cpu_common, rtc |
| 52 | off | 0.5396 | 1853 | 60 | 70.46 | 1.35% | clean | cpu_common, rtc |

| | off (n=5) | on (n=4) | delta |
|---|---|---|---|
| lap ms | 0.5330 +- 0.0049 | 0.5342 +- 0.0162 | **+0.23%** |
| exec/s | 1876.3 +- 17.3 | 1873.6 +- 55.1 | -0.15% |
| reset us | 59.0 +- 2.0 | 58.5 +- 5.0 | -0.85% |
| crash->sig ms | 71.78 +- 2.38 | 73.29 +- 4.43 | +2.11% |

## The answer: the skip buys nothing, and that closes the question

**Not "it is safe" and not "it is unsafe" -- it is not worth having.** The lap
moves 0.23% in the wrong direction, the reset's own clock moves 0.85%, and both
are inside the run-to-run spread. A change that cannot be measured does not
need its safety established, which is a cheaper and more durable resolution
than the one this experiment set out to get.

**The first two arms said otherwise and were wrong.** Block one alone read
60 -> 57 us on the reset and a consistent small win on the lap. It looked like a
clean 0.6% and it did not survive n=4. Two-point agreement is not a result;
this lane already learned that from a two-point fit that gave 24 us/page when
the within-run slope was 0.81.

## Scoring the predictions

- **P0 (safety) -- NOT ESTABLISHED, and honestly so.** The fork oracle was
  clean on every verification in all nine runs and the planted-bug set was
  identical in all nine, which is real evidence. But the crash RATE is 1.42% in
  the off arms and 2.06% in the on arms, and one on-arm named a device section
  (`i8259#8`) that no other run did. **That comparison is confounded and the
  confound is mine:** a tenth run, an OFF arm, wedged mid-loop and its results
  were destroyed by a watchdog I had just added -- `docker rm -f` is SIGKILL,
  so `uninit()` never wrote `fastloop.json`. The off population is therefore
  missing its worst case while the on population keeps both of its outliers. I
  will not read a safety signal out of a sample I biased by accident.
- **P1 -- FALSIFIED as stated.** Predicted the reset's clock would drop and stay
  above 30 us. It did not drop: 59.0 -> 58.5 us.
- **P2 -- confirmed trivially.** The lap did not go below 0.47 ms because it did
  not move.
- **P3 -- CONFIRMED, and it was a prediction against my own lever.** The crash
  lap was predicted to stay within 15% of 70 ms; it went 71.78 -> 73.29 ms,
  +2.1%. The structural reason given in advance holds: the reset restores pages
  the guest WROTE -- stack, heap, data -- and kernel text is never written, so
  the fault-and-signal path's translations were never invalidated to begin
  with. **Whatever the 70 ms crash lap is, TB invalidation is not it.**
- **P4 -- half failed, informatively.** The five off arms span 0.0149 ms (2.8%
  of the mean), inside the 5% the prediction asked for. The four on arms span
  0.0401 ms (7.5%) and fail it. The on arms are three times noisier, which is
  the only signal in this experiment that favours the skip mattering at all --
  and it is carried entirely by one run.
- **P5 -- confirmed on the bug set** (B2/B3/B4/B5 in all nine, zero unattributed
  crashes), unresolved on the crash rate, as P0 says.

## What this changes

`FASTSNAP_TB_SKIP_NOCODE` stays exactly where it is: default off,
measurement-only, documented as an open safety question. Nothing needs to
change in the shipped path, and no further work on it is justified -- the
upside was measured and it is zero.

**And the crash lap is now the whole prize with no cheap hypothesis left.** It
is 71 ms of guest execution between the reset completing and the fault
arriving, on 1.4% of laps, and 115 s of a 220 s loop. TB invalidation is
eliminated. The next candidates need instrumenting inside the guest rather than
guessing from outside: guest core dumps (`core.core_dumps` is unset and was
never actually tested -- the previous attempt disabled penguin's `core` PLUGIN,
which is a different thing), and the driver's own signal-delivery hook.

## A second finding: the arm check catches wedges AT the arm, not after

The off-arm that was lost wedged *mid-run* -- PC-0 crashes on a single pid,
after a probe it had passed cleanly. Run 30 did the same thing 72 s in. The
health check samples the first 200 laps and then never looks again, so a loop
that degrades later still reports a rate. Worth a continuous check: the same
two-sided test applied on a rolling window, not once.
