# qemu-user, priced against the loop

Measured 2026-09-14 on an idle 96-core host (load 0.34, no containers).
Artifact: `result_usermode_bench.json`. Reproduce: see "Building the user-mode
QEMU" below, then `python3 usermode_bench.py --reps 3 --scale`.

`LOOP-RESULTS.md` answers "how fast can a whole emulated system be rewound".
It does not answer the question anyone choosing a fuzzing architecture asks
first: **is that faster than not emulating the system at all?** qemu-user runs
the binary and passes syscalls to the host -- no kernel, no device model, no
system state -- and a fresh process per input is already a reset. If it wins,
the snapshot work is a fidelity tax rather than a speed win, and that should be
said out loud rather than left unmeasured.

## The comparison is against penguin's own QEMU, at the loop's own architecture

A first pass used the distro `qemu-arm-static`, and reported the QEMU version
gap (6.2.0 against penguin's 11.1.0) and the architecture gap (armel against
the loop's mipsel) as uncorrected confounds. Both are now closed, and the
distro row is kept so their size is measured rather than asserted.

| confound | measured cost, `fork` shape | direction |
|---|---|---|
| QEMU 6.2.0 -> penguin's 11.1.0, armel | 0.844 -> 1.056 ms, **1.25x** | 6.2 **flattered** the competitor |
| armel -> mipsel, both on 11.1.0 | 1.056 -> 1.164 ms, **1.10x** | armel flattered it further |

Penguin's QEMU is *slower* in user mode than the distro's on every shape --
25% on `fork`, 12% on `persist`, 35% on `floor`. Correcting the confound
therefore strengthens the conclusion below rather than weakening it, which is
the opposite of what a convenient error looks like.

### Penguin's QEMU cannot build a linux-user target

Found while building it, and worth recording on its own. The IGLOO series
routes guest hypercalls into Penguin from the per-target TCG helpers and
**guards none of those call sites with `CONFIG_USER_ONLY`** -- verified zero
guards across all five targets it patches (arm, mips, ppc, riscv, loongarch).
A `--target-list=*-linux-user` build compiles the call and then fails to link:

```
target/arm/tcg/op_helper.c:96: undefined reference to `penguin_handle_guest_hypercall'
```

The implementation lives in `system/penguin.c`, which is system-mode only.
Nothing in penguin needs a user-mode target today, so this is latent rather
than broken -- but it is one stub away from building, and the stub is the
correct semantics: in user mode there is no Penguin, so "not handled, take the
normal path" is what the function means.

## What this can and cannot compare

Taken before the numbers, because this lane's recurring failure is a quantity
measured against the wrong referent.

- **The victim is the best case for qemu-user.** `bugbench_victim` is a static,
  single-threaded parser that reads a buffer and switches on one byte.
  Targets A, B and C are vendor daemons reaching NVRAM, ioctls, device nodes
  and a network stack; **qemu-user cannot run them at all.** So this prices
  full-system fidelity on the one program in the lane that does not need it.
  It is a floor on what fidelity costs, not a verdict on whether to pay it.
- **The competitor is steelmanned.** The forkserver shape omits AFL's pipe
  handshake and input file, so its per-iteration cost here is lower than a real
  AFL++ `qemu_mode` would pay.
- **Optimisation settings match.** `qemu_builder/configs/default.json` passes
  no optimisation-related configure flags and neither does this build, so both
  are QEMU's defaults: `-O2 -g`, `b_ndebug=false`, asserts active. Verified
  from `meson-info/intro-buildoptions.json` rather than assumed.
- **Rates are measured on non-crashing input** (opcode `0x00`, the victim's
  declared negative control). The mechanisms differ by two orders of magnitude
  in crash handling -- an ordinary lap is 1.119 ms, a crash-closed one 43.70 ms
  -- which would swamp what is being compared.

The victim gained one `#ifdef BUGBENCH_BENCH` mode and nothing else. A second
copy of it would have made this a comparison of two programs. After the edit,
7/7 planted bugs still fault at their manifest signals and the negative control
is still clean.

## The four shapes

Each isolates one mechanism. `floor` runs the one-shot victim on empty input,
so it reads, gets 0, and exits: everything measured is process creation, ELF
load and translation -- the cost a forkserver exists to pay once.

| shape | resets between inputs | mipsel/11.1 | armel/11.1 | armel/6.2 | x86-64 native |
|---|---|---|---|---|---|
| `floor` | whole process, no work | 11.56 ms / **87** | 11.98 / 83 | 8.87 / 113 | 0.457 / 2,190 |
| `spawn` | whole process, one parse | 11.59 ms / **86** | 12.07 / 83 | 8.91 / 112 | 0.459 / 2,179 |
| `fork` | process memory, warm parent | 1.164 ms / **859** | 1.056 / 947 | 0.844 / 1,185 | 0.098 / 10,244 |
| `persist` | nothing | 0.0009 ms / **1,169,576** | 0.0010 / 1,027,190 | 0.0009 / 1,172,958 | 0.0003 / 2,862,049 |

Within-run spreads are 1.00-1.03x. **Across** runs, `floor` and `spawn` moved
as much as 45% for an identical configuration (armel/6.2 gave 12.81 ms one run
and 8.87 ms the next); `fork` and `persist` held to 3%. Nothing below rests on
`floor` or `spawn`.

`spawn - floor` is **0.03 ms**: the parse is nothing, and every figure in this
document measures a reset mechanism, not emulation speed.

## Against the loop

Both confounds closed: penguin's QEMU, the loop's architecture. From
`LOOP-RESULTS.md`, bugbench, mipsel, 256 MB guest, 23 pages restored:

| | per iteration | exec/s |
|---|---|---|
| user-mode persistent, no reset | 0.0009 ms | **1,169,576** |
| full-system `bare`, no reset | 0.1112 ms | 8,996 |
| **full-system snapshot loop** | **0.7243 ms** (404 us reset) | **1,381** |
| qemu-user forkserver, empty address space | 1.175 ms | 851 |
| full-system loop + injection + attribution | 1.119 ms | 894 |
| qemu-user forkserver at bugbench's 256 MB | 6.025 ms | 166 |
| qemu-user, no forkserver | 11.56 ms | 87 |

**The in-process full-system snapshot reset is 2.9x cheaper than fork()ing a
user-mode emulator that holds nothing at all** -- 404 us against 1,175 us, same
QEMU, same architecture. End to end the loop is **1.6x** the forkserver (1,381
vs 859), **8.3x** it at bugbench's own 256 MB footprint (vs 166), and **16x**
naive per-process execution (vs 87).

That was not the expected result.

## Why: the two mechanisms scale along different axes

`fork()` copies the page tables of everything the parent has mapped, so its
per-iteration cost grows with the **address space**. A dirty-page reset writes
back the pages the iteration **wrote**. Sweeping resident size, ms per fork:

| touched | x86-64 | armel/6.2 | armel/11.1 | mipsel/11.1 |
|---|---|---|---|---|
| 0 MB | **0.099** | 0.847 | 1.036 | 1.175 |
| 4 MB | 0.276 | 0.973 | 1.233 | 1.320 |
| 8 MB | 0.436 | 1.143 | 1.363 | 1.468 |
| 16 MB | 0.748 | 1.411 | 1.641 | 1.750 |
| 64 MB | 1.838 | 2.251 | 2.568 | 2.773 |
| 256 MB | 4.547 | 5.105 | 5.459 | 6.025 |
| 1024 MB | 17.42 | 17.45 | 18.87 | 18.98 |

Linear in resident size everywhere. The loop's own reset over the comparable
range is nearly flat: **404 us for 23 pages** on bugbench, **490 us for 227
pages** on target A -- a ~10x change in dirty set for a 21% change in cost.

So there is a crossover, and it is low:

> A **native** forkserver is cheaper than the full-system snapshot reset only
> while the target's resident set stays under about **7 MB** (interpolated
> between the 4 MB and 8 MB points). A **qemu-user** forkserver is never
> cheaper, at any size, because forking the emulator already costs 1.175 ms
> before the guest maps anything.

Any real daemon is past 7 MB.

## What it does not say

The counterweight is larger than the win. **User-mode persistent mode is
1,169,576 exec/s**, 847x the full-system loop and 130x the full-system's own
no-reset ceiling of 8,996. Nothing in the reset can touch that gap, because it
is not a reset gap -- it is the cost of running a system. Part of that 130x is
penguin's per-iteration detector, which is a hypercall into a Python pyplugin
rather than TCG; how much is unmeasured here.

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

## Building the user-mode QEMU

Not a packaged target, so the recipe is here:

```sh
tar xf qemu-11.1.0.tar.xz && cd qemu-11.1.0
while read -r p; do patch -p1 -i "$QEMU_BUILDER/patches/$p"; done \
    < "$QEMU_BUILDER/patches/11.1.0/series"
cp -r "$QEMU_BUILDER/src/." .
# The one stub: see "cannot build a linux-user target" above.
cat >> accel/tcg/user-exec-stub.c <<'EOF'
#include "system/penguin.h"
bool penguin_handle_guest_hypercall(CPUState *cs, uint64_t nr,
                                    uint64_t a0, uint64_t a1, uint64_t a2,
                                    uint64_t a3, uint64_t a4, uint64_t a5,
                                    uint64_t *ret) { return false; }
EOF
mkdir build-user && cd build-user
../configure --target-list=arm-linux-user,mipsel-linux-user \
    --disable-system --disable-tools --disable-docs --disable-guest-agent \
    --disable-werror --without-default-features
ninja qemu-arm qemu-mipsel
```

Then point the harness at it:

```sh
export IGLOO_QEMU_BUILD=.../qemu-11.1.0/build-user
export MIPSEL_GCC=$(nix build --no-link --print-out-paths \
    'nixpkgs#pkgsCross.mipsel-linux-gnu.buildPackages.gcc')/bin/mipsel-unknown-linux-gnu-gcc
export MIPSEL_LDFLAGS=-L$(nix build --no-link --print-out-paths \
    'nixpkgs#pkgsCross.mipsel-linux-gnu.glibc.static')/lib
python3 usermode_bench.py --reps 3 --scale --json result_usermode_bench.json
```

Rows whose tools are missing are skipped and named, so a host without the nix
cross toolchain still produces the native and distro rows.

## Not established

One host, one day, one seed. The 7 MB crossover is interpolated between the
4 MB and 8 MB points, not measured at the crossing. `floor` and `spawn` swing
up to 45% between runs and carry none of the argument. The mipsel victim is
built by gcc 15.3.0 against a nixpkgs static glibc, which is not the toolchain
that built the loop's guest -- irrelevant at ~1 us of guest work per record,
but not zero. And the scaling sweep touches one byte per 4096-byte page, making
every page present and private: a real process with shared or file-backed pages
forks more cheaply, so the crossover is a lower bound on where fork stops
winning, not an upper one.
