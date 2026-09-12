# The closed loop, measured

The first exec/s figures in this lane that are wall-clock measurements of a
guest actually being reset, rather than sums of independently measured parts.
Predictions were committed in `LOOP-PREDICTION.md` before the runs; the scoring
against them is at the bottom.

Two targets. `bugbench` is the controlled victim from `BUGBENCH.md` -- a real
rehost (real kernel, real userspace, mipsel) around a program whose seven bugs
are known. `stride` is the firmware image.

**Headline: 1,381 exec/s reset-only, 894 exec/s as a complete fuzzing loop with
input injection and crash attribution, every reset verified byte-identical to
an independently forked reference across 281 MB of guest RAM.**

## 1. What an iteration is, and why it is the whole question

`LOOP_ARM` takes the device block, snapshots RAM, arms dirty tracking and forks
the oracle reference -- in one bottom half, at one instant. Every `LOOP_RESET`
returns the guest to that instant. So the guest re-executes the same span of
work every lap, which is the shape a snapshot fuzzer runs in, and

> **one iteration costs the span from the armed instant to the next detector
> hit.** The reset is a term in that, usually a small one.

Two runs made that concrete before any number below was worth quoting. On
`stride` the loop armed after 40 `writev` calls, which landed 72 s into boot
while the guest was generating SSH host keys: every lap replayed the key
generation and the iteration median was **19.9 seconds**, from a reset costing
1.9 ms. The console shows the same `Creating SSH2 RSA key` line repeating once
per lap -- which is also the clearest evidence in this document that the rewind
works. On `bugbench` the arm never happened at all: the victim finished its
64 restarts inside the warmup window and stopped reading, and the arming
condition is checked on a detector hit.

## 2. bugbench -- the rate, decomposed

20,000 iterations per arm, no input injection, 256 MB guest (281,346,048 bytes
of RAM blocks across 37 sections; only `pci:13.0/virtio-blk` denied).

| arm | what it is | iteration median | exec/s | reset (in QEMU) | pages restored |
|---|---|---|---|---|---|
| `bare` | no arm, no reset | 0.1112 ms | 8,996 | -- | -- |
| `armed` | armed, never reset | 0.1104 ms | 9,055 | -- | -- |
| `loop` | armed, reset every lap | **0.7243 ms** | **1,381** | 404 us | 23 |

**`armed - bare` = -0.0008 ms. Dirty tracking is free.** This was a live
concern: arming turns on QEMU's global dirty log, and every first store to a
clean page then traps through `notdirty_write()`. The prediction allowed for
that costing more than 10%; it costs nothing measurable, and the two arms
differ by less than their own p10-to-p90 spread. A candidate cost is removed
rather than estimated.

**`loop - armed` = 0.614 ms, of which the reset itself is 0.404 ms.** The
remaining **0.210 ms is the schedule-and-observe round trip**: a pyplugin runs
on a vCPU thread, `fastsnap_schedule` posts a bottom half, and the loop cannot
see it finish until the next detector hit. That term is not the reset and it is
not the guest -- it is the loop living outside QEMU.

`restored_pages` was **22-23 on every one of 20,000 iterations** (min 22, max
23). The guest replays the same span and dirties the same pages, which is an
independent check on determinism that costs nothing to read.

### Correctness

    split-order control : 15 pages differ      (must be > 0)
    400 verifications   : 0 pages differ, over 281,346,048 bytes each

The oracle is a child forked at the armed instant, read back with
`process_vm_readv()` and compared page by page; it shares no code with the
restore, which reads an in-process copy. `LOOP_RESET_VERIFY` does both in one
bottom half.

The split-order control is what makes the zeros mean anything, and it is not
decoration: run the same oracle as a SEPARATE bottom half and the guest
executes in the gap, so it reports 15 differing pages for the same correct
reset. A run where both forms report zero has an oracle that cannot see a
running guest, and the plugin scores that INVALID rather than passing it.

## 3. bugbench -- the complete fuzzing loop

Same target with the injector on: a fresh mutated payload written into the
guest every lap, every input hashed and joined to any crash it produces.
60,000 iterations in 113.3 s.

| | value |
|---|---|
| ordinary lap (n=59,167) | **1.119 ms median**, p90 1.388, max 5.105 |
| crash-closed lap (n=803) | 43.70 ms median, p90 60.5 |
| reset (in QEMU) | **348 us** median, p90 415 |
| pages restored | 26 median |
| exec/s, ordinary laps | **894** |
| exec/s, wall clock incl. crashes and oracle | 530 |
| verifications | **30, every one 0 pages over 281,346,048 bytes** |
| inputs delivered | **128,742** |
| crashes | 1,719, all attributed, **zero unclassified** |
| negative control | clean -- opcode 0x00 never faulted |

Input injection costs `1.119 - 0.724 = 0.395 ms` per lap: an `osi.get_fd_name`
resolution, a `mem.write_bytes`, a hash and a corpus record, all through the
portal.

### Score: 5 of 7, up from 4

| id | tier | hits | E[hits] at 128,742 inputs |
|---|---|---|---|
| B1 | trivial (canary) | 359 | -- |
| B2 | trivial | 491 | -- |
| B3 | trivial | **2** | **1.96** |
| B4 | easy | 482 | -- |
| B5 | easy | 385 | -- |
| B6 | hard | 0 | 1e-7 |
| B7 | hardest | 0 | 1.3e-3 |

**B3 flipped from miss to find, and only budget changed.** It needs opcode 0x03
AND `req[1] == 0`: P = 256^-2 = 1.53e-5, so at the 5,212 inputs of the
no-reset run the expectation was 0.08 and at 128,742 it is 1.96. Two were
found. B6 (a 4-byte magic) and B7 (two conditions at once) stay missed at any
budget this side of a coverage-guided fuzzer, exactly as the manifest says they
should.

So the reset bought **24.7x the inputs** in comparable wall clock and one more
bug. It bought budget, not search power -- the remaining 2 of 7 are a mutator
problem, and saying otherwise would be claiming the wrong win.

### The crash lap is the next bottleneck, and 5.4x of it was harness

A crash has to end an iteration. Without that the loop waits for the guest to
restart the victim, which is the per-execution process teardown and setup that
snapshot fuzzing exists to delete -- so `fastloop` resets on fatal signal
delivery as well as on the detector.

Crash laps were still 300x an ordinary lap, and the instrument that found out
why was a bucket rather than a theory: separate the laps a crash closed from
the rest, because a single median hides them.

| | crash lap median | iterations in ~215 s | inputs |
|---|---|---|---|
| report written on every crash | **308.6 ms** | 38,747 | 51,466 |
| report written every 50 | **56.9 ms** | 99,080 | 118,971 |

The injector was re-dumping its whole growing crash list as YAML inside the
signal callback -- on the vCPU thread, which is precisely the thread a bottom
half needs to yield. 1,719 crashes in a run makes that quadratic. Throttling it
gave **2.6x the iterations and 2.3x the inputs**, with the reset unchanged at
~350 us throughout.

The guess before that measurement was "core dumps", and it was wrong twice
over: disabling the `core` plugin is not disabling core dumps -- it is
penguin's core plugin, and without it `plugins.netdevs` is None and the guest
never boots. Guest core dumps are a config key this project never set.

At 43.7 ms a crash lap is still 39x an ordinary one and, at 803 of 60,000 laps,
still a third of the wall clock. What is left is the guest's own signal
delivery plus the host-side plugins on that path.

## 4. stride -- the real firmware image

403,054,592 bytes of RAM across 20 device sections, three virtio sections
denied. Armed 150 s in, once the boot had settled.

    armed in 261 ms
    reset            560 us median   (p10 535, p90 590, max 1307)
    pages restored   210 median      (min 207, max 214)  ~860 KB
    iteration        83.2 ms median  -> 12.0 exec/s
    split-order control              177 pages differ
    8 verifications                  0 pages differ, over 403,054,592 bytes each

**The reset is sound on real firmware.** That is the claim `REALFW.md` could not
make: there, device-only restores killed the guest within a handful of laps --
kernel panic in `rcu_process_callbacks`, `swap_dup: Bad swap file entry`, OOM
kills -- because rewinding the CPU's page-table base into RAM that was never
rewound makes the MMU walk page tables RAM no longer holds. With the RAM half
in place, 200 consecutive resets leave the guest byte-identical to a reference
forked before any of them.

**And the reset is 0.67% of the iteration.** 560 us inside 83.2 ms. Making it
free would take this target from 12.0 to 12.1 exec/s.

### The controls, and the thing they caught

| arm | iteration median | p10 | p90 | min | max | exec/s |
|---|---|---|---|---|---|---|
| `bare` | 8.43 ms | 7.75 | 15.12 | **2.83** | **82.41** | 118.6 |
| `armed` | 10.34 ms | 7.48 | 20.23 | 2.73 | 143.88 | 96.7 |
| `loop` | **83.24 ms** | 82.48 | 84.46 | 82.15 | 87.85 | 12.0 |

The loop is 10x slower than the free-running guest and the reset is 0.56 ms of
it, so the reset is not where the 75 ms went. Read the columns instead of the
medians and it is plain:

**`bare`'s MAX is 82.41 ms. `loop`'s MEDIAN is 83.24 ms.**

The free-running guest's `writev` intervals are spread from 2.8 ms to 82 ms --
mostly requests pipelined inside a live connection, occasionally a connection
boundary with an `nc` teardown, fork, exec and TCP setup in it. The loop armed
on a detector hit, which put the armed instant just before one of those
boundaries, and it then replays **that** span, exactly, forever: p10 82.48,
p90 84.46, a 2% spread against `bare`'s 30x range.

So the loop is not slow. It is pinned to the slowest span in the distribution,
because arming "at the next detector hit" takes whatever span comes next and a
1-in-20 span is what it got. Choosing the fast mode instead would put this
target near 1/2.83 ms = **350 exec/s**, with an unchanged reset.

That tightness is also the cleanest determinism evidence in this document.
A 2% spread over 200 laps, on a target whose own inter-`writev` interval varies
by 30x, is what re-executing one fixed span looks like.

`armed - bare` is +1.9 ms here, against -0.0008 ms on bugbench. **Do not read
that as a cost of dirty tracking.** These are two separate runs on a target
whose run-to-run variance `EXEC-RATE.md` measured at 1.6x, the distributions
overlap almost entirely (p10 7.48 vs 7.75), and n is 200. It is not resolvable
on this target. It IS resolved on bugbench, where 20,000 samples with a 1%
spread put the difference below noise. A real cost is plausible in principle --
stride dirties 210 pages a lap against bugbench's 26, and each first store to a
clean page traps -- so this is left open rather than claimed either way.

That is not a disappointing result, it is the lane's actual finding restated
with the reset finally out of the way: `EXEC-RATE.md` measured an HTTP request
on this target as 0.111 ms of parsing inside ~14.3 ms of TCP loopback, socket
reads, response writes and event loop -- 0.8%. A detector that fires once per
request makes the iteration a request. The 116x between stride's 12 exec/s and
bugbench's 1,381 is not two different resets. It is two different arming
points.

## 5. Scored against the predictions

| prediction | outcome | |
|---|---|---|
| every verification 0 pages, split control > 0 | 438 verifications at 0; controls 15 / 19 / 90 / 177 | **held** |
| reset 400-900 us on stride | 560 us | **held** |
| reset 400-700 us on bugbench | 348-416 us | **low** |
| 20-200 pages restored on stride | 210 | just outside |
| reset under 5% of a stride iteration | 0.67% | **held** |
| stride will NOT be fuzzing-grade, and the reset will not be why | 12 exec/s, reset 0.67% | **held** |
| stride 20-200 exec/s | 12.0 | **wrong, low by 1.7x** |
| stride `loop` within ~1 ms of `bare` | 83.2 ms vs 8.4 ms | **wrong** -- the loop pinned the slow span, not the median one |
| bugbench 0.7-1.5 ms, 700-1,500 exec/s | 0.724 ms, 1,381 | **held** |
| below `persist.py`'s 2,374 exec/s, and the gap is what soundness costs | 1,381 vs 2,374 | **held** |
| the loop may stall (~30% on one arm) | stalled on BOTH first attempts | **held, twice** |
| `armed` may be materially slower than `bare` | -0.7%, inside the noise | **falsified** |

The three that did not hold are worth more than the ones that did. The stride
rate was predicted from a request cost and came in 1.7x slower, because the
arming point landed at a connection boundary rather than mid-pipeline -- which
is the same lesson the 20-second lap taught, at a smaller scale. And the
dirty-log cost, which the prediction treated as a live risk to the design,
is not measurable.

## 6. What this says to do next

1. **Move the loop inside QEMU.** The schedule-and-observe round trip is
   0.210 ms of a 0.724 ms lap -- 29%, and the single largest term after the
   reset. Removing it projects 0.515 ms, ~1,940 exec/s. Projected, not
   measured; this lane's projections have been 3.7x wrong before.
2. **Cut the crash lap.** 803 laps of 60,000 take a third of the wall clock.
   The harness half of it is already 5.4x better; the rest is guest signal
   delivery and host-side plugins on that path.
3. **Choose the arming point deliberately, and say where it is.** It sets the
   rate, and on stride it cost a factor of 29 -- the armed instant landed
   before a connection boundary rather than inside a pipeline, and every lap
   then replayed the boundary. An exec/s figure without a stated arming point
   is not a claim about a reset. Arming "at the next detector hit" is a
   sampling decision from whatever distribution that detector has, and this
   plugin currently makes it blind.
4. **The remaining 2 of 7 bugs are a fuzzer problem, not a throughput
   problem.** B6 and B7 do not fall to 25x more random inputs, and the
   benchmark says so in advance.

## Reproduce

    ./penguin --image penguin:fsloop --name <unique> \
        run analysis/fastsnap/work/bugbench/proj     # tight loop + fuzzing
    ./penguin --image penguin:fsloop --name <unique> \
        run analysis/fastsnap/work/stride/proj       # real firmware

`mode` is `loop` | `armed` | `bare` in `plugins.d/fastloop.yaml` (bugbench) or
`patch_zzz_fastloop.yaml` (stride). The image carries the in-QEMU ops:

    PENGUIN_NIX_BUILD_ARGS="--override-input penguin-qemu path:/abs/qemu_builder" \
      ./penguin --build --image penguin:fsloop --version

Host-side, needing no guest: `python3 analysis/fastsnap/test_fastloop_statemachine.py`
drives the state machine against a fake QEMU with explicit bottom halves, and
its four negative controls are the ones that matter -- a reset that leaves
pages wrong, an oracle that sees nothing, an oracle that cannot read, and an
ABI whose Python bindings are all present and whose C symbols are all absent.

Results: `work/bugbench/proj/results/{6,7,8}` (loop / armed / bare rate arms),
`work/bugbench/proj/results/{11,12}` (the crash-lap instrumentation and the
308 ms measurement it replaced a guess with), `work/bugbench/proj/results/14`
(the complete fuzzing loop, 5/7), `work/stride/proj/results/{62,63,64}` (real
firmware: loop / bare / armed). `work/stride/proj/results/61` is the run whose
every RAM number was fiction -- kept because `CORRECTIONS.md` 7 is about it.
