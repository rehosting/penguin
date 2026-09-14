# qemu-user, priced against the loop

Measured 2026-09-14 on an idle 96-core host (load 0.34, no containers).
Artifact: `result_usermode_bench.json`. Reproduce: `python3 usermode_bench.py
--reps 3 --scale`.

`LOOP-RESULTS.md` answers "how fast can a whole emulated system be rewound".
It does not answer the question anyone choosing a fuzzing architecture asks
first: **is that faster than not emulating the system at all?** qemu-user runs
the binary and passes syscalls to the host -- no kernel, no device model, no
system state -- and a fresh process per input is already a reset. If it wins,
the snapshot work is a fidelity tax rather than a speed win, and that should be
said out loud rather than left unmeasured.

## What this can and cannot compare

Taken first, because this lane's recurring failure is a number measured against
the wrong referent.

- **The victim is the best case for qemu-user.** `bugbench_victim` is a static,
  single-threaded parser that reads a buffer and switches on one byte.
  Targets A, B and C are vendor daemons reaching NVRAM, ioctls, device nodes
  and a network stack; **qemu-user cannot run them at all.** So this prices
  full-system fidelity on the one program in the lane that does not need it.
  It is a floor on what fidelity costs, not a verdict on whether to pay it.
- **The competitor is steelmanned.** The forkserver shape omits AFL's pipe
  handshake and input file, so its per-iteration cost here is lower than a real
  AFL++ `qemu_mode` would pay.
- **Two confounds run the other way and are not corrected.** qemu-user here is
  QEMU **6.2.0** (Ubuntu) against penguin's 11.x, and the user-mode side is
  **armel** against the loop's **mipsel**. The loop's reset is a 0.46-0.55 ms
  constant across three architectures, which bounds the confound on that side;
  nothing bounds it on the user-mode side.
- **Rates are measured on non-crashing input** (opcode `0x00`, the victim's
  declared negative control). The mechanisms differ by two orders of magnitude
  in crash handling -- an ordinary lap is 1.119 ms, a crash-closed one 43.70 ms
  -- which would swamp what is being compared.

The victim gained one `#ifdef BUGBENCH_BENCH` mode and nothing else. A second
copy of it would have made this a comparison of two programs.

## The four shapes

Each isolates one mechanism. `floor` runs the one-shot victim on empty input,
so it reads, gets 0, and exits: everything measured is process creation, ELF
load and translation -- the cost a forkserver exists to pay once.

| shape | what resets between inputs | armel (qemu-user) | x86-64 (native) |
|---|---|---|---|
| `floor` | whole process, no work done | 12.81 ms / **78/s** | 0.456 ms / 2,193/s |
| `spawn` | whole process, one parse | 12.83 ms / **78/s** | 0.465 ms / 2,152/s |
| `fork` | process memory, warm parent | 0.854 ms / **1,170/s** | 0.100 ms / 9,958/s |
| `persist` | nothing | 0.0009 ms / **1,163,599/s** | 0.0004 ms / 2,854,342/s |

Spreads 1.01-1.03x across three reps, except `floor`, which moved 11% between
runs and should be read as ~13 ms.

`spawn - floor` is **0.02 ms**: the parse is nothing, and every figure in this
document is a measurement of a reset mechanism, not of emulation speed.

## Against the loop

From `LOOP-RESULTS.md`, bugbench, mipsel, 256 MB guest, 23 pages restored:

| | per iteration | exec/s |
|---|---|---|
| user-mode persistent, no reset (armel) | 0.0009 ms | **1,163,599** |
| full-system `bare`, no reset (mipsel) | 0.1112 ms | 8,996 |
| **full-system snapshot loop** | **0.7243 ms** (404 us reset) | **1,381** |
| qemu-user forkserver, empty address space | 0.891 ms | 1,123 |
| full-system loop + injection + attribution | 1.119 ms | 894 |
| qemu-user forkserver at bugbench's 256 MB | 5.155 ms | 194 |
| qemu-user, no forkserver | 12.81 ms | 78 |

**The in-process full-system snapshot reset is cheaper than fork()ing a
user-mode emulator.** 404 us against 891 us, with the user-mode process holding
nothing at all. That was not the expected result.

## Why: the two mechanisms scale along different axes

`fork()` copies the page tables of everything the parent has mapped, so its
per-iteration cost grows with the **address space**. A dirty-page reset writes
back the pages the iteration **wrote**. Sweeping resident size (`--scale`):

| touched | native fork | qemu-user fork |
|---|---|---|
| 0 MB | **0.099 ms** | 0.891 ms |
| 1 MB | 0.149 ms | 0.924 ms |
| 4 MB | 0.279 ms | 1.025 ms |
| 8 MB | 0.439 ms | 1.176 ms |
| 16 MB | 0.744 ms | 1.471 ms |
| 64 MB | 1.740 ms | 2.459 ms |
| 256 MB | 4.385 ms | 5.155 ms |
| 1024 MB | 17.07 ms | 18.98 ms |

Linear in resident size, both runners. The loop's own reset over the comparable
range is nearly flat: **404 us for 23 pages** on bugbench, **490 us for 227
pages** on target A -- a ~10x change in dirty set for a 21% change in cost.

So there is a crossover, and it is low:

> A **native** forkserver is cheaper than the full-system snapshot reset only
> while the target's resident set stays under about **7 MB**. A **qemu-user**
> forkserver is never cheaper, at any size, because forking the emulator
> already costs 0.891 ms before the guest maps anything.

Any real daemon is past 7 MB. At bugbench's own 256 MB the snapshot loop is
**7.1x** the qemu-user forkserver end to end (1,381 vs 194).

## What it does not say

The counterweight is large and belongs in the same breath: **user-mode
persistent mode is 1,163,599 exec/s**, 843x the full-system loop and 129x the
full-system's own no-reset ceiling of 8,996. Nothing in the reset can touch
that gap, because it is not a reset gap -- it is the cost of running a system.
Part of that 129x is penguin's per-iteration detector, which is a hypercall
into a Python pyplugin, not TCG; how much is unmeasured here.

So the honest reading is two claims, not one:

1. **As a reset mechanism, the snapshot loop beats fork at any realistic
   footprint**, and by a widening margin. The fidelity is not being paid for in
   reset speed.
2. **As an execution mode, full-system costs two orders of magnitude** against
   a user-mode loop that never resets -- and that is the ceiling worth
   attacking, not the 404 us.

Claim 1 retires "why not just use qemu-user" for this project's targets, with
numbers rather than the one-line dismissal in `LIBAFL-PORT.md`. Claim 2 says
the remaining headroom on the full-system path is in the per-iteration harness,
above the reset, and that `BUGBENCH.md`'s finding still governs: a loop that
cannot reset spends its budget on restarts (5,212 inputs against 237,575), so
the persistent-mode ceiling is not reachable on a crash-dense target in any
execution mode.

## Not established

One host, one day, one seed. The user-mode side is armel and the loop side is
mipsel. The 7 MB crossover is interpolated between the 4 MB and 8 MB points,
not measured at the crossing. `floor` is the one config that moved more than 3%
between runs. And the scaling sweep touches one byte per 4096-byte page, which
makes every page present and private -- a real process with shared or
file-backed pages forks more cheaply than this, so the crossover is a lower
bound on where fork stops winning, not an upper one.
