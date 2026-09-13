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

_(pending)_
