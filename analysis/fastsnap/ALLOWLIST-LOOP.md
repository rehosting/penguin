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

(pending)
