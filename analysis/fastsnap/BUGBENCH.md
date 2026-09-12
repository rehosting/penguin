# bugbench: a closed, known bug set, and what it measures

Built because "the fuzzer found N crashes" has no denominator. Without a known
bug set you cannot tell a strong fuzzer on a hard target from a weak one on an
easy target, and you cannot tell "did not find B6" from "B6 was never reachable
because the harness stopped delivering bytes that far into the request".

`bugbench_victim.c` has seven planted bugs across four difficulty tiers, plus a
negative control (opcode 0x00, which must never fault) and a canary (B1, which
almost any input reaches). `bugbench_truth.py` is the manifest and the scorer.
Six host-side tests in `test_bugbench_sync.py` keep the guest plugin's inlined
trigger table in step with the manifest.

## Result 1 -- ORACLE mode: the pipeline carries all seven

Sending the seven known triggers deliberately. This measures the PIPELINE, not
the fuzzer.

| id | tier | signal | pc | |
|---|---|---|---|---|
| B1 | trivial | SIGSEGV | 0x41414141 | found |
| B2 | trivial | SIGSEGV | 0x55565a64 | found |
| B3 | trivial | SIGFPE | 0x55565a90 | found |
| B4 | easy | SIGSEGV | 0x55565ac4 | found |
| B5 | easy | SIGSEGV | 0x55565af0 | found |
| B6 | hard | SIGBUS | 0x55565b44 | found |
| B7 | hardest | SIGSEGV | 0x55565b90 | found |

**7/7, seven distinct PCs, three distinct signals, every crash joined to its
input by sha256 with the corpus file retained.** B1's PC is `0x41414141` -- the
filler bytes themselves -- so that attribution is checkable from outside the
harness. Negative control clean.

## Result 2 -- FUZZ mode: blind mutation scores 4/7, as predicted

The expectations below were computed from the guards in the victim and written
down BEFORE the run.

| id | tier | E[hits] | predicted | observed |
|---|---|---|---|---|
| B1 | trivial | 19 | FIND | 19 |
| B2 | trivial | 20.3 | FIND | 18 |
| B3 | trivial | 0.08 | MISS | 0 |
| B4 | easy | 20.3 | FIND | 10 |
| B5 | easy | 15.3 | FIND | 18 |
| B6 | hard | 4.7e-09 | MISS | 0 |
| B7 | hardest | 3.1e-04 | MISS | 0 |

Every prediction matched, observed counts track expected counts, **zero
unclassified crashes**, negative control clean. `VALID: 4/7 (trivial 2/3,
easy 2/2, hard 0/1, hardest 0/1)`.

The benchmark is therefore calibrated: it distinguishes found from missed, and
the miss pattern is exactly what a mutator with no coverage feedback and no
dictionary produces. **The 7/7 - 4/7 gap is the value a better fuzzer has to
add**, and it is concentrated in B6 (a 4-byte magic) and B7 (two conditions at
once) -- the two bugs that reward coverage feedback.

## The budget was 45x smaller in fuzz mode, and that is the fastsnap argument

The prediction was first written against 237,575 inputs, the oracle run's
budget. The fuzz run delivered **5,212**.

The cause is not the mutator. In oracle mode the victim survives after the
seven triggers and loops through thousands of reads per life. Under random
input it crashes almost every restart, so nearly all of its time is process
setup rather than parsing. Crash-dense fuzzing without snapshot reset spends
its budget on restarts.

That is a measured, independent motivation for the reset work: the cost being
paid here is exactly what a fast in-process reset removes. It also cost the run
B3, a *trivial*-tier bug missed only because the budget shrank -- a fuzzer can
be made to look weak purely by making restarts expensive.

**Sharpened afterwards, because "45x" was doing more work than it could bear.**
Both runs ended when the victim's 64 restarts were used up, not when time ran
out: the oracle run's last crash is at t=6.8 s and the fuzz run's at t=11.9 s,
in runs 180 s long. So the 45x is a ratio of inputs PER RESTART BUDGET, which
is the right quantity for "how much of a life a crashing input costs you" and
the wrong one for "how many inputs per second". Read as a rate, the no-reset
run was delivering roughly 1,000 inputs/s while it ran.

The reset-enabled comparison is now measured directly rather than inferred --
see the next section.

## Result 3 -- WITH the fastsnap reset: 5/7, and 24.7x the inputs

The same victim, the same mutator, the same seed, with `fastloop.py` resetting
the guest every iteration and on every fatal signal. Full numbers and controls
in `LOOP-RESULTS.md`; the scoreboard:

| | no reset | snapshot loop |
|---|---|---|
| inputs delivered | 5,212 | **128,742** |
| crashes | 65 | **1,719** |
| unclassified crashes | 0 | **0** |
| negative control | clean | **clean** |
| score | 4/7 | **5/7** |

**B3 flipped from miss to find, and only the budget changed.** It needs opcode
0x03 and `req[1] == 0`: P = 256^-2 = 1.53e-5, so the expected count went from
0.08 to 1.96 and two were found. That is the prediction the manifest made
before either run, holding across a 25x change in budget -- which is a stronger
statement about the benchmark than either score on its own.

B6 and B7 stayed missed, as they should: 25x more random inputs does not reach
a 4-byte magic or two simultaneous conditions. **The reset buys budget, not
search power.** The remaining 2 of 7 are a mutator problem and the benchmark
said so in advance.

Every crash in the reset run was joined to its input and landed on a known PC.
The victim is never restarted by the guest during a lap -- a fatal signal ends
the iteration and the reset rewinds past it to a live victim -- and 30
verifications during the run found the guest byte-identical to an independently
forked reference across all 281,346,048 bytes of its RAM.

## Three manifest errors, all caught by running it

1. **B1 gives SIGABRT, not SIGSEGV** -- the stack protector fires before the
   corrupted return address is used. B1 is the canary, and a missed canary is
   scored as "harness broken", so this would have condemned a *working*
   pipeline on any hardened target.
2. **B6 gives SIGBUS on mipsel, SIGSEGV on x86-64.**
3. The general lesson, having been caught twice: **the signal is not a property
   of the bug.** It is a property of the architecture and the toolchain. The
   durable identity of a planted bug is its faulting function and its distinct
   PC; the signal is corroboration, never the key.

## Not established

The victim is synthetic and its bugs are planted; nothing here says anything
about the target's real defects. Fuzz mode ran once, at one seed, on one arch
(mipsel), with no coverage feedback -- it is a baseline, not a ceiling. The
reset-enabled run is likewise one run at one seed. The two are comparable in
mutator, seed, victim and arch, and NOT in wall clock: the no-reset run stopped
when its 64 restarts ran out, at t~12 s, while the reset run used the full
window. So "24.7x the inputs" is a comparison of what each configuration
delivered in its run, not a like-for-like rate -- the rate comparison is in
`LOOP-RESULTS.md`, where an ordinary lap is 1.119 ms.
