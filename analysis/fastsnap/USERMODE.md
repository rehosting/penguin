# qemu-user, priced against the loop

Measured 2026-09-14 on an idle 96-core host. Artifact:
`result_usermode_bench.json`. Reproduce: see "Building the user-mode QEMU",
then `python3 usermode_bench.py --reps 3 --scale --syscost`.

## The headline, and the correction it needed

First published as "the snapshot loop beats a qemu-user forkserver". That is
true of the victim it was measured on and **does not generalise**, and the
reason is the thing a reader would ask first: qemu-user does not carry a
kernel, so the host answers the guest's syscalls natively instead of the
guest's own kernel being emulated instruction by instruction.

Quantified, the two mechanisms are a fixed cost plus a per-syscall slope:

    full-system   =   404 us (reset)  +  133.2 us per syscall
    qemu-user     = 1,179 us (fork)   +    0.33 us per syscall

The full-system loop starts **775 us ahead** and spends that lead at
**407x** the rate per syscall. So:

> **The snapshot loop wins only while an iteration makes fewer than about
> 6 syscalls.**

| syscalls/iteration | full-system | qemu-user | winner |
|---|---|---|---|
| 1 | 537 us | 1,179 us | full-system |
| 2 | 670 us | 1,180 us | full-system |
| 4 | 937 us | 1,180 us | full-system |
| 6 | 1,203 us | 1,181 us | qemu-user |
| 8 | 1,470 us | 1,182 us | qemu-user |
| 16 | 2,535 us | 1,184 us | qemu-user |
| 32 | 4,666 us | 1,190 us | qemu-user |

`bugbench_victim` makes **one**. A real HTTP request handler -- accept, read,
stat, open, read, write, close, poll -- makes dozens. So on any realistic
firmware daemon qemu-user would win decisively, and the original headline held
only because the victim sits a factor of six below the crossover.

Two qualifiers, both widening the crossover rather than narrowing it: the
133.2 us is measured **with a penguin hook attached** (`hookcost.py`, cheapest
frequently-firing bracket, `fcntl64`, n=1926), so it is an upper bound on
per-syscall cost; and it was taken on target A (armel lighttpd), not bugbench.

## Where the 133 us actually goes, which is not where I first said

`hookcost.py` splits the bracket:

| | |
|---|---|
| enter->return bracket, `fcntl64` | **133.2 us** |
| host-side Python inside the callback | **0.72 us** |

Python is **0.5%**. The remaining ~132 us is entirely guest-side: the emulated
kernel executing the syscall, plus igloo_driver's hypercall traps on enter and
return, every instruction of it emulated. An earlier version of this document
attributed the gap to "the emulated kernel **plus** penguin's hypercall into
Python"; the second half is noise and the claim was wrong.

That also relocates where optimising pays. Not the 404 us reset, and not the
Python plugin layer -- **the per-syscall emulated-guest round trip**, which at
133 us dominates everything else in this lane by an order of magnitude.

## What this can and cannot compare

- **The victim is the best case for qemu-user**, and now we know by how much:
  one syscall per iteration against a crossover of six. Targets A, B and C are
  vendor daemons reaching NVRAM, ioctls, device nodes and a network stack, and
  **qemu-user cannot run them at all**, so the comparison stays academic for
  them. What it prices is the mechanism, not the choice.
- **The competitor is steelmanned**: the forkserver shape omits AFL's pipe
  handshake and input file.
- **Optimisation settings match.** `qemu_builder/configs/default.json` passes
  no optimisation-related configure flags and neither does this build -- both
  are QEMU defaults, `-O2 -g`, `b_ndebug=false`, asserts active, read back from
  `meson-info/intro-buildoptions.json` rather than assumed.
- **Rates are on non-crashing input** (opcode `0x00`, the declared negative
  control): the mechanisms differ 39x in crash handling (1.119 ms lap vs
  43.70 ms) and that would swamp the comparison.

The victim gained one `#ifdef BUGBENCH_BENCH` mode and nothing else; 7/7
planted bugs still fault at their manifest signals, negative control clean.

## The confounds, closed and measured

A first pass used the distro `qemu-arm-static` -- QEMU 6.2.0 against penguin's
11.1.0, armel against the loop's mipsel -- and named both as uncorrected. Both
are now closed, and every row is kept so their size is measured:

| | stock 11.1 | igloo 11.1 | patch cost |
|---|---|---|---|
| armel `fork` | 1.0931 ms | 1.0919 ms | **-0.1%** |
| armel `persist` | 0.0010 ms | 0.0010 ms | **+0.0%** |
| mipsel `fork` | 1.2122 ms | 1.2121 ms | **-0.0%** |

**The IGLOO series costs nothing measurable in user mode** -- mipsel `fork` is
identical to four significant figures. Predicted before the run, from the
mechanism: the ARM hook sits inside `trans_MCR`, gated on one exact encoding
(`cp==7, opc1==0, rt==0, crn==0, crm==0, opc2==0`), so it runs at TRANSLATE
time and a parser decodes no MCR instructions.

Which means the whole 6.2 -> 11.1 slowdown is **upstream QEMU's**, not
penguin's fork: 1.29x on `fork`, 1.35x on `floor`, 1.11x on `persist`. Worth
someone's attention upstream; it is not something this project introduced.

### Penguin's QEMU cannot build a linux-user target

Found while building it. The series routes guest hypercalls into Penguin from
the per-target TCG helpers and **guards none of those call sites with
`CONFIG_USER_ONLY`** -- zero guards across all five targets it patches. A
`--target-list=*-linux-user` build compiles the call and fails to link:

```
target/arm/tcg/op_helper.c:96: undefined reference to `penguin_handle_guest_hypercall'
```

`system/penguin.c` is system-mode only. Nothing in penguin needs a user-mode
target today, so this is latent rather than broken, and it is one stub away --
returning false means "not handled, take the normal path", which is what user
mode means.

## The four shapes

`floor` runs the one-shot victim on empty input: it reads, gets 0, exits, so
everything measured is process creation, ELF load and translation -- the cost a
forkserver exists to pay once.

| shape | mipsel/stock | mipsel/igloo | armel/stock | armel/6.2 | x86-64 |
|---|---|---|---|---|---|
| `floor` | 11.6765 ms / 86 | 11.6823 ms / 86 | 12.0869 ms / 83 | 8.9287 ms / 112 | 0.4673 ms / 2,140 |
| `spawn` | 11.6500 ms / 86 | 11.7326 ms / 85 | 12.1476 ms / 82 | 8.9658 ms / 112 | 0.4737 ms / 2,111 |
| `fork` | 1.2122 ms / 825 | 1.2121 ms / 825 | 1.0931 ms / 915 | 0.8505 ms / 1,176 | 0.1001 ms / 9,987 |
| `persist` | 0.0008 ms / 1,187,054 | 0.0008 ms / 1,181,324 | 0.0010 ms / 1,020,372 | 0.0009 ms / 1,160,239 | 0.0003 ms / 2,885,657 |

Within-run spreads 1.00-1.03x. **Across** runs `floor` and `spawn` moved up to
45% for an identical configuration (armel/6.2 gave 12.81 ms one run and 8.87 ms
the next); `fork` and `persist` held to 3%. Nothing here rests on `floor` or
`spawn`.

## Per-syscall cost, fitted

`--syscost` adds N `getpid()` calls per record and fits a line, so a per-record
fixed cost cannot be misread as syscall cost. glibc stopped caching `getpid`
in 2.25, so each call is a genuine trap.

| runner | us per syscall | base us per record |
|---|---|---|
| mipsel/stock11.1 | 0.3275 | 1.0923 |
| mipsel/igloo11.1 | 0.3391 | 1.0072 |
| armel/stock11.1 | 0.3799 | 1.0641 |
| armel/igloo11.1 | 0.3790 | 1.1136 |
| armel/qemu6.2 | 0.3165 | 0.9271 |
| x86-64 | 0.1295 | 0.3688 |

Against **133.2 us** for a hooked syscall under full-system emulation.

## Why fork and reset scale differently

`fork()` copies the page tables of everything mapped, so its per-iteration cost
grows with the **address space**. A dirty-page reset writes back the pages the
iteration **wrote**. ms per fork:

| touched | x86-64 | armel/6.2 | armel/stock | mipsel/stock | mipsel/igloo |
|---|---|---|---|---|---|
| 0 MB | 0.099 | 0.847 | 1.065 | 1.179 | 1.179 |
| 4 MB | 0.278 | 1.024 | 1.230 | 1.327 | 1.327 |
| 8 MB | 0.446 | 1.162 | 1.376 | 1.467 | 1.472 |
| 16 MB | 0.748 | 1.448 | 1.658 | 1.739 | 1.756 |
| 64 MB | 1.616 | 2.345 | 2.599 | 2.569 | 2.842 |
| 256 MB | 4.513 | 5.104 | 5.364 | 5.446 | 5.624 |
| 1024 MB | 17.213 | 17.779 | 17.683 | 17.566 | 18.307 |

Linear in resident size everywhere. The loop's reset over the comparable range
is nearly flat: **404 us for 23 pages** on bugbench, **490 us for 227 pages** on
target A -- a ~10x change in dirty set for 21% of cost. So a native forkserver
is cheaper than the snapshot reset only below about **7 MB resident**
(interpolated between the 4 and 8 MB points), and a qemu-user forkserver never
is, at any size.

That axis stands. It is simply not the axis that decides the comparison -- the
syscall count is.

## What it does not say

**User-mode persistent mode is over 1.1 million exec/s**, ~850x the loop and
~130x the loop's own no-reset ceiling of 8,996. That gap is not a reset gap and
nothing in the reset can touch it; it is the cost of running a system, and the
per-syscall term above is most of it.

So the honest reading is three claims:

1. **As a reset mechanism, the snapshot loop beats fork at any realistic
   memory footprint**, by a widening margin. Fidelity is not paid for in reset
   speed.
2. **As an execution mode, full-system costs ~400x per syscall**, and that term
   decides any real comparison. Past ~6 syscalls per iteration a qemu-user
   forkserver is ahead.
3. **For this project's targets the choice does not arise**, because qemu-user
   cannot run them -- which is why the interesting consequence of (2) is where
   to optimise, not which emulator to pick.

`BUGBENCH.md`'s finding still governs the ceiling: a loop that cannot reset
spends its budget on restarts (5,212 inputs against 237,575), so persistent
mode's rate is not reachable on a crash-dense target in any execution mode.

## Building the user-mode QEMU

```sh
tar xf qemu-11.1.0.tar.xz && cd qemu-11.1.0
while read -r p; do patch -p1 -i "$QEMU_BUILDER/patches/$p"; done \
    < "$QEMU_BUILDER/patches/11.1.0/series"
cp -r "$QEMU_BUILDER/src/." .
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

The stock rows use the identical configure line on the pristine tarball, with
no series, no `src/` overlay and no stub. Then:

```sh
export IGLOO_QEMU_BUILD=.../qemu-11.1.0/build-user
export STOCK_QEMU_BUILD=.../qemu111-stock/qemu-11.1.0/build-user
export MIPSEL_GCC=$(nix build --no-link --print-out-paths \
    'nixpkgs#pkgsCross.mipsel-linux-gnu.buildPackages.gcc')/bin/mipsel-unknown-linux-gnu-gcc
export MIPSEL_LDFLAGS=-L$(nix build --no-link --print-out-paths \
    'nixpkgs#pkgsCross.mipsel-linux-gnu.glibc.static')/lib
python3 usermode_bench.py --reps 3 --scale --syscost --json result_usermode_bench.json
```

Rows whose tools are missing are skipped and named.

## Not established

One host, one day, one seed. The 7 MB crossover is interpolated, not measured
at the crossing. The **6-syscall crossover mixes sources**: the reset and fork
terms are from this lane's own runs, the 133.2 us per-syscall term is from
`hookcost.py` on a different target and architecture, with a hook attached. A
same-target measurement of the unhooked per-syscall cost would tighten it and
is not done. `floor` and `spawn` swing up to 45% between runs and carry none of
the argument. The mipsel victim is built by gcc 15.3.0 against a nixpkgs static
glibc, not the toolchain that built the loop's guest. And the scaling sweep
touches one byte per 4096-byte page, making every page present and private, so
the memory crossover is a lower bound on where fork stops winning.
