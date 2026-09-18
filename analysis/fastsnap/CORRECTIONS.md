# Corrections to DESIGN-fastsnap.md, and the RAM term measured on real firmware

A running list of this lane's own claims that turned out to be wrong, and of
the instruments that turned out to be measuring nothing. Every one was found by
checking the design against the code, or against a real target, rather than
against the prototype it was developed on. Recorded here rather than quietly
edited away, because the *kind* of error is the part worth keeping: entries 5,
6 and 7 are all instruments that passed while blind, and 7 did it one layer
below where the check was looking. Entry 9 is the harder relative of those --
an instrument that saw correctly, reported accurately, and had every control
pass, while the number it produced could mean either of two opposite things.
Entry 10 moves the blindness one layer further out again -- an instrument that
was right, said so accurately, and put it fourth in a paragraph headed with the
other half's verdict -- and entry 11 is the reader's version of the same thing:
a conclusion drawn from the two files that were open, which nothing in those
two files contradicted. Entry 12 is the one that keeps the list honest: it
retracts entry 10's conclusion, on evidence entry 10 never looked at. Entry 13
is the furthest out so far -- a model that fitted, held out a sample, passed
that test, and still named the wrong cause, because the thing it got wrong was
invisible to every sample the workload can produce.

## 1. The central integration decision was backwards

`DESIGN-fastsnap.md` says the reset loop belongs in a guest hypercall handler,
which "runs on the vCPU thread with the guest already trapped and quiesced",
and that the API "must **not** go through `aio_bh_schedule_oneshot`".

Wrong on every clause:

- `qemu/target/arm/tcg/translate.c:2365` emits
  `gen_helper_penguin_guest_hypercall(...)` **inline**, then `store_reg(s, 0,
  ret); return true;`. No exception, no `cpu_loop_exit`, no PC update. It is a
  TCG helper, not a trap, so the guest is not "trapped and quiesced".
- `qemu/accel/tcg/cpu-exec.c:543-544` **drops the BQL** while the vCPU
  executes guest code. A helper does not hold it.
- The ported `device-save.c` carries `// iothread must be locked` immediately
  above `device_save_all()`.
- The fork's own comment at `qemu/system/penguin.c:299-303` states the correct
  pattern outright: *"Safe to call from a vCPU thread (e.g. a guest hypercall
  handler): the snapshot itself runs in the main loop context where it can stop
  the vCPUs and pump the loop without deadlocking."* The existing code bounces
  to the main loop **for exactly this reason**, and the design proposed removing
  the bounce.

**The live probe had already said so and it was misread as a probe bug.**
Assuming a pyplugin callback held the BQL produced
`memory_region_transaction_commit: Assertion 'bql_locked()' failed` and killed
the VM. That was the same fact arriving from the other direction.

Consequence: the ~0.04 ms "handshake" is not overhead to design away, it is the
cost of reaching a context where the operation is legal. And the
"vCPU-thread vs main-loop" table never ran on a vCPU thread —
`fastsnap-reset.c` is a `QEMUTimer` callback on the main loop with the VM
already stopped, so it measures a `vm_stop`/`vm_start` pair. **A model was
labelled a measurement.**

## 2. A citation that was invented

The design "corrects" a 117 MIPS figure attributed to `THROUGHPUT.md`.
`grep '117\|MIPS' THROUGHPUT.md` returns **zero hits** — that document measures
fork+exec in milliseconds and derives no instruction rate at all. The
measurement behind 117 was real (a `libinsn` run), but the attribution was
fabricated and then propagated into `ALLOWLIST.md:25` and `STATUS.md`.

## 3. The measurements were taken on a build the design says it avoids

`ALLOWLIST.md` claims the approach "touches neither `cputlb.c` nor
`physmem.c`", and `DESIGN-fastsnap.md` says "Everything below is measured on a
running QEMU". Both are true separately and misleading together: the slice0
binary every number was measured on adds six `fastsnap_note_store()` call sites
to `cputlb.c` (left over from the RAM-tracking probe, compiled
unconditionally). The *shipped* design would have none. The direction is
conservative — real MIPS would be higher — but the absolute instruction-rate
figures and the coverage table were not taken on the configuration they are
offered as evidence for.

## 4. Tier 0 is not the sound oracle it was claimed to be

"every device section is restored, so no allowlist can be wrong" is false.
Sections are dropped in two places, and my first account of this named the
wrong one.

`device_save_kind()` itself skips only two things before any allowlist logic:
`se->is_ram` and `globalstate` (`slice0/vendor/device-save.c:57-62`). It does
**not** filter on `save_setup`. The rest of the loss happens one level down,
inside the `vmstate_save()` it calls: `qemu/migration/savevm.c:1070-1073`
returns 0 — emitting nothing — for any entry that has neither a `vmsd` nor
`ops->save_state`, which is exactly the iterative/`save_setup`-only handlers.
A third path, `vmstate_section_needed()`, can drop a whole section on its
`.needed` predicate.

The conclusion is unchanged and is what matters: a "full" device save is not
the complete capture the phrase implies, so Tier 0 cannot serve as the sound
oracle for triaging Tier 1 crashes — which was the safety argument for
shipping Tier 1 at all.

---

# The RAM term, measured on stridelinx

Target: `stridelinx` from `rehosting/examples` (public). armel, 4.10, 2 GB,
booted to userspace with lighttpd and sshd up. Measured **without rebuilding
QEMU**: every symbol needed is already exported by the shipped image, so a
pyplugin `ctypes.CDLL`s the already-mapped library and calls
`physical_memory_test_and_clear_dirty`, which returns the dirty count and
clears in one call.

| window | median dirty pages | KB | RAM term @0.42 us/page |
|---|---|---|---|
| 1 ms | 51.5 | 206 | **0.022 ms** |
| 5 ms | 80.5 | 322 | 0.034 ms |
| 25 ms | 176 | 704 | 0.074 ms |
| 100 ms | 235.5 | 942 | 0.099 ms |
| 500 ms | 302.5 | 1210 | 0.127 ms |

**Strongly sublinear**: 500x the window buys 6x the pages. The idle working set
saturates near 300 pages (1.2 MB). At fuzz-iteration scale (~1 ms) it is ~51
pages — which means the synthetic payload's 65 pages was, by luck, a good
proxy, and the design's RAM arithmetic survives contact with real firmware.

Scope: this is **idle background churn** from the firmware's own daemons, not
the dirty set of a specific request. A fuzzing iteration adds its own work on
top. What it establishes is the floor a reset pays even when the iteration
itself does nothing.

## 5. The no-`tb_flush` assertion was inert, and only its own negative control found it

The selftest's second phase asserts the thing the whole design turns on: that a
device-only restore never enters `RUN_STATE_RESTORE_VM`, because that state is
the sole `tb_flush` trigger (`accel/tcg/tcg-all.c`, `tcg_vm_change_state`). It
printed "no RUN_STATE_RESTORE_VM transition" and PASSED.

It was checking nothing. Phase 2 ran at machine-init-done, where the VM is not
yet running, and `vm_stop()` on an already-stopped VM returns early **without
notifying change-state handlers**. The assertion's observer was never called,
and "never called" is indistinguishable from "called and saw nothing" if you
only look at the verdict.

Found by injecting the failure it exists to catch: a deliberate
`vm_stop(RUN_STATE_RESTORE_VM)` in the restore path. It still printed PASSED.

Fixed by running phase 2 from a change-state handler once the VM is actually
running, refusing to run at all when stopped, and dropping `-S` from the nix
check so the VM reaches that state. It now fails when the control is injected.

**The generalisation.** A passing assertion is evidence only if you have seen
it fail. This one had a negative control available for the asking and had never
been run against it — and the same shape produced the next entry, and the
reason the real-firmware harness had to grow an A/B/C probe before any of its
timings could be believed.

## 6. Merge order silently put 25 `loadvm` restores inside the measurement windows

The real-firmware harness disables `notrap` so the only restores in a run are
its own. `patch_devblock.yaml` set `plugins.notrap.enabled: false` and the runs
looked clean.

Penguin merges `patch_*.yaml` **in filename order**, and `patch_fuzzcal.yaml`
sorts *after* `patch_devblock.yaml`. It re-enabled `notrap`, whose loop then
ran 25 full `loadvm` restores concurrently with the throughput windows being
measured — each one carrying the ~380 ms cost and the re-translation cliff the
experiment was trying to attribute to something else.

Nothing logged a conflict in the direction that mattered; the config log shows
the last writer winning, which is correct behaviour and reads as unremarkable.
Renamed to `patch_zz_devblock.yaml` so it merges last.

**The generalisation.** A YAML layer that "disables the other thing" is only as
true as its filename sorts. Check the merged config, not the patch you wrote.

## 7. Eleven bindings that were never callable, and every one returned a plausible number

The first real-firmware run of `fastloop.py` produced a complete result set:
a device block of 20 sections, 13 iterations, a reset median of 1,876 us, an
oracle verdict, a JSON report. Three of its numbers were fiction:

    armed in 278712 us, 0 bytes of RAM snapshotted     <- a 256 MB snapshot
    restored_pages median 0                            <- of a guest that ran
    control OK - the oracle sees -1 pages              <- a failed read

Nothing raised. Nothing logged a warning. The run took five minutes and its
output was indistinguishable in shape from a good one.

**The cause.** `penguin-cffi-gen.py` restates the `penguin_fastsnap_*`
prototypes by hand. Six ops and eleven accessors were added to
`include/fastsnap/penguin-fastsnap.h` and not to that script, so `ffi.cdef`
never saw them, `_lib_symbol()` returned `None`, and each binding fell through
to its "symbol absent" default -- `0` for a byte count, `-1` for a page count.
Both are values a working build could legitimately return.

**Why the preflight did not catch it.** `fastloop` has a preflight precisely
for stale images, and it passed. It checks `dir(self.panda)` -- whether the
QemuCompat *methods* exist. They all did. The dependency that was missing was a
*C symbol*, one layer down, and a Python-level question cannot reach it. The
check and the failure were in different layers, so the check was green and
inert at the same time. That is the same shape as corrections 5 and 6: an
instrument that passes while blind.

**The fixes, in the order they matter.**

1. `penguin-cffi-gen.py` now EXTRACTS the prototypes from the header instead of
   restating them, and exits non-zero if the extraction finds none. A
   hand-kept copy of an ABI drifts; this one drifted within a single session.
2. The new bindings raise instead of returning a default. A wrong number that
   reaches a measurement is worse than a traceback.
3. `QemuCompat.fastsnap_missing_symbols()` asks the LIBRARY which symbols are
   callable, and `fastloop` refuses to run if any are absent. The Python-level
   check is kept as well -- they fail in different ways.
4. The split-order oracle control now treats `<= 0` as a failed control, not
   just `== 0`. It had reported `-1` as "control OK - the oracle sees -1 pages
   the guest dirtied", which is a broken oracle passing its own control.
5. `test_fastloop_statemachine.py` reproduces the exact state -- every Python
   binding present, every C symbol absent -- and asserts the run is refused
   before a boot is spent on it.

**What survived from that run.** The device-restore path and `last_us` were
declared, so `reset_us` median 1,876 us is real. And the console is the
strongest evidence in it: the same `Creating SSH2 RSA key` line repeats once
per lap, which is the guest deterministically re-executing the span it was
rewound to. The reset worked. The instrument reading it did not.

## 8. A 20-second iteration from a correct reset

The same run reported a median iteration of **19.9 seconds**. That is not the
reset (1.9 ms of it) and not a defect.

One iteration is the span of guest execution from the armed instant to the next
detector hit, because that is what a reset rewinds. The plugin armed after 40
`writev` calls, which fell 72 s into boot, while the guest was generating SSH
host keys -- so every lap replayed the key generation.

The general statement, which is the one worth keeping: **the arming point sets
the iteration cost, and the reset is a small term in it.** A reset that is free
does not make a 20-second span shorter. `fastloop` gained an `arm_after_s`
floor because a hit count alone does not say where in a boot you are.

## 9. The device oracle was right about the bytes and wrong about the meaning

The per-section device oracle exists to score a device allowlist: it digests
every section at the arm and re-digests them after the reset, and names the
ones that differ. Its first two uses produced a true difference and a false
conclusion, and the conclusion cost a run.

Arm 1 of the allowlist experiment ran `allow: "cpu"` on mipsel/malta. The
oracle named `mc146818rtc#13` on 148 of 160 verification laps. Read the only
way the number could be read -- "this section was not restored" -- that is an
instruction to add it to the allowlist. Arm 2 added it, and:

- the oracle reported it on **153 of 160 laps, while it was in the block**;
- restored pages went 25 -> 59, the lap went 0.782 -> 1.616 ms, and throughput
  went 1,278.9 -> 618.7 exec/s.

`hw/rtc/mc146818rtc.c` explains it and nothing is broken. `rtc_pre_save()`
calls `rtc_update_time()`, which reads the live clock and writes the current
time into `cmos_data` -- a `VMSTATE_BUFFER` field -- and `rtc_post_load()`
re-derives both timers from the current clock. **The device cannot serialise to
the same bytes twice, whatever the restore does.**

What makes this worth an entry is not the device. It is that the oracle was
working perfectly. The bytes really did differ, every report it made was
accurate, and its own controls -- a full-block reset scoring zero on `-M virt`,
and a deliberately dropped section being seen and named -- all passed, because
`-M virt` happens to have no section in this class. The failure was that one
number was answering two questions, and the caller could not tell which.

The kind of error: **an instrument whose referent is ambiguous rather than
wrong.** Entries 5, 6 and 7 are instruments that were blind. This one saw
correctly and reported into a field that could mean either of two opposite
things, so the reader supplied the wrong one. It is the harder version, because
no control on the instrument itself can catch it -- the control has to be on
what the number is allowed to mean.

Fixed by making the two cases different fields rather than different readings
of one: a section the block did not carry is a scope miss and widening fixes
it; a section the block did carry and restored is unrestorable and widening
cannot. A genuine restore bug lands in the second bucket, so it is counted and
named rather than forgiven. The selftest now requires the full-block control to
establish that every section on the test machine round-trips, since without
that the positive control below it is ambiguous between the two.

The measurement it corrupted, re-read: `cpu` alone was sufficient on malta
except for `cpu_common`, which fired on 3 laps of 160 and is still unattributed
between the two buckets.

## 10. A verdict that led with the wrong half, and the day of rates it cost

`fastloop` computes `replay_fidelity`: the armed span's forward traversal
against the same span's replayed lap. Its docstring says what it is for --
"what it can do is refuse to let the rate be quoted as if it were real" -- and
on runs 88 and 91 it worked exactly as designed, classing both `faster` at
ratios of 0.003 and 0.005 and writing out, in full sentences, that the input
arrived during the forward traversal and is still queued at replay so the wait
never happens again.

Both runs were then quoted in `REALFW-LOOP.md` at 303.3 and 201.1 exec/s,
under a heading asserting that the arming draw sets the rate.

Nothing was wrong with the instrument. What was wrong was where it put its
answer. Run 88's `verdict` string is assembled oracle-first:

```
VALID: 20 verifications, every one byte-identical to an independently forked
reference across 403054592 bytes, ... Pass --extra_docker_args
"--cap-add=SYS_ADMIN". REPLAY DIVERGES: the armed span traverses forward in
1051.94 ms and replays in 3.30 ms -- 319x FASTER. ...
```

`VALID` is a claim about the RAM oracle alone. It is also the first word, and
the `RESULTS` log line beside it printed `exec_per_s=303.30` with no qualifier
at all. A reader who takes the headline and the number -- which is what a
headline and a number are for -- gets the opposite of the finding.

This is the same shape as entries 5, 6 and 7 with the blindness moved one
layer out. Those were instruments that reported nothing while appearing to
pass. This one reported correctly, in the wrong order, next to a number that
contradicted it. An instrument is not finished when it is right; it is
finished when the thing it is right about is the first thing read.

Fixed by making the rate carry its own verdict: `exec_per_s_valid` as a field,
`RATE IS NOT A RATE (...)` in front of an otherwise-`VALID` verdict (and only
an otherwise-`VALID` one -- the first attempt displaced a `DEGRADED` headline,
which is the same error inverted), the same marker on the `RESULTS` line, and
`loopcmp.py` printing fidelity beside every rate it shows.

The measurement, re-read -- and then re-read again, see entry 12, which
overturns the paragraph this one originally ended with. The ordering defect
above is real and the fix stands. The conclusion it was used to reach did not.

## 11. The stall blamed on dirty pages, by a reading nothing on screen contradicted

A run with eight concurrent guest connectors produced one lap in twelve
minutes. It had dirtied 949 pages against the usual 380 and its reset cost
1364 us against 787, both genuinely up, and that is what the stall was
attributed to.

The arithmetic refutes it immediately and was never done: 1364 us against a
348 ms lap is 0.4% of one lap. Roughly 570 s of loop time remained after the
arm. A reset three times more expensive cannot turn 1,600 expected laps into
one.

What actually happened is in `snapfeed.json`, a file that was not opened:
`feed_wall_s` 71.9 on a 720 s run. The guest stopped being fed a tenth of the
way in. The cause was in the console log, also not read carefully:
`waited=400s` on all eight connectors. The guest driver's readiness probe
waited for `nc | grep -q HTTP` to see a response, while `swallow_writes: 1`
skips lighttpd's reply at the syscall -- so the probe could not succeed by
construction, and each connector burned its full 400 iterations as a
fork-and-exec storm straight through the arming window. A readiness check that
cannot observe readiness is not a slow check; it is a fixed cost wearing a
check's clothes.

Both the wrong reading and the right one were available in the same results
directory. The difference was which file was open. `loopcmp.py` exists because
of this entry: it puts reset cost as a *fraction of the lap* next to the feed
span, so the number that cannot explain the stall is visibly too small to.

## 12. The correction was wrong: five forward samples are five different spans

Entry 10 used `replay_fidelity` to retract three published rates. Two of those
retractions were wrong, and the reason is a conflation sitting one level below
the instrument -- in what its input means.

`arm_forward_samples` holds five numbers per draw. The `fwd_probe` state
starts a clock at the armed instant and stops it at the next detector hit;
`fwd_probe_more` then clocks that hit to the next, and so on. They are five
**consecutive, different spans**, not five measurements of one. Only sample 1
begins where every replayed lap begins. Samples 2-5 begin from states the loop
never visits.

`_replay_fidelity` scored the lap against their MEDIAN. On this victim --
connection-per-request, so ~3 ms inside a connection and ~1050 ms at a
boundary -- the median is a cost the armed span never takes:

| run | sample 1 | median | lap | vs sample 1 | vs median |
|---|---|---|---|---|---|
| 88 | 2.39 ms | 1051.94 ms | 3.297 ms | **1.377 faithful** | 0.003 "diverged" |
| 90 | 3.67 ms | 4.36 ms | 4.430 ms | 1.207 faithful | 1.016 faithful |
| 91 | 1052.01 ms | 1040.48 ms | 4.973 ms | **0.005 diverged** | 0.005 diverged |
| 99 | 1051.59 ms | 1052.68 ms | 1058.6 ms | 1.007 faithful | 1.006 faithful |

Runs 88 and 90 are real rates -- **303.3 and 225.7 exec/s on real firmware**.
Run 91's 201.1 is not, by either reference, and stays retracted.

Two things make this reading trustworthy rather than convenient. It does not
uniformly flatter: it leaves run 91 exactly where it was. And it is
corroborated by a measurement taken nowhere near the arm -- the **warmup gap**
distribution, which is bimodal on runs 88, 90 and 91 (p10 ~2.4-3.7 ms against
a median ~1050 ms) and unimodal on run 99 (p10 1051 ms). The cheap mode is the
workload. Run 99 simply had no cheap mode to arm on.

The interesting part is the near miss. Before finding the sample-1 semantics I
wrote a different fix: score against whichever of the two forward modes the
lap matches. It produced the same verdicts -- and it was the wrong change,
because I had chosen it after seeing that it reclassified run 88 the way I
half-expected. That version is in the history with its reasoning; what
replaced it is a criterion derived from what the code measures, which happens
to leave one of the three retractions standing. A rule that overturns
everything you doubted is worth more suspicion than one that overturns some of
it.

## 13. A cost model that fit, predicted, and named the wrong cause

The scan's cost model was fitted on two runs and then **tested on a third that
was not used to fit it**, which is the right discipline and is why this one is
worth keeping:

> cost ≈ 0.5 ns × (map/8 words skimmed) + 5.1 ns × (bytes in non-zero words)

The per-byte constant landed in 5.02–5.28 ns across two map sizes and three
runs — 5.1% spread. Run 115 lowered the scan cost by finding fewer edges on
the same map, exactly as predicted. Everything about it was well-behaved.

It was still causally wrong, and no amount of that kind of testing could have
shown it. On this workload a non-zero word holds **about one set byte**, so in
every sample the term "bytes in non-zero words" was numerically identical to
`8 × non-zero words`. The same numbers are equally well described by **41 ns
per non-zero word**. The fit cannot choose between them because nothing in the
data varies the ratio; run 115 varied the *number* of edges, which re-tested
the fit without touching the attribution.

The two readings recommend opposite work, and this lane acted on the wrong
one. "Per byte" says the fix is to stop touching the seven dead bytes of every
non-zero word — which is precisely the `ctz` optimisation the open-questions
list carried, sized at ~134 µs a lap. Implemented and measured against the
shipped scan, it is **slower**, and on a map packed eight set bytes to a word,
where it should win biggest, it loses by more.

**Separating the terms needs an input no real lap produces:** the same number
of set bytes deliberately packed into an eighth as many words. That collapses
the fold cost about fivefold. The corrected model

> cost ≈ 0.56 ns × words + 29 ns × non-zero words + 4.1 ns × set bytes

predicts a 64 KiB map at a different occupancy to 1.9%.

Three things about the shape of this error:

- **The out-of-sample test was real and passed.** Holding back a run is the
  standard defence against overfitting, and it defends against the wrong
  thing here. Collinearity is not overfitting; it is two regressors that no
  sample distinguishes, and a held-out sample drawn from the same process
  inherits the same collinearity. Only a *constructed* input breaks it.
- **The residual is honest about being unexplained.** The 29 ns is not the
  skim, not the seven unset bytes, not branch misprediction on the novelty
  tests (the same code against a saturated cumulative map runs 165.4 vs
  165.7 µs), and not hideable by prefetching. Four implementations were built
  and measured. Naming it "a memory stall" was tempting and is not supported:
  it is the same ~29 ns on a 64 KiB cumulative map that fits in cache.
- **The check that caught the next error was the cheap one.** Timing four
  implementations in a fixed order inside one process, the rig also times the
  shipped scan first *and* last. An attribution probe doing strictly less work
  reported 2.2× the time; without that control it would have been published as
  a finding instead of deleted as an artefact.

## The VPN finding, now with evidence rather than inference

The design said "the fast path requires `vpn.enabled: false`". On the real
target this is not a preference — it is refusal:

```
vhost: Failed to start logging: Protocol error
```

`memory_global_dirty_log_start()` **fails outright** while the
`vhost-user-vsock` backend is attached. With `plugins.vpn.enabled: false` it
arms cleanly. Note the existing snapshot path dodges the same class of blocker
via `migration_snapshot_set_ignore_blockers(true)` (`qemu/system/penguin.c:248`);
fastsnap cannot, because it needs the logging vhost refuses to provide.

Trap worth recording: `static_patches/base.yaml` contains `vpn: {}`, and a
present-but-empty key defaults to **enabled** (`penguin_run.py:511`), so
`plugins.vpn.enabled: false` in `config.yaml` is silently overridden by the
patch chain. Two runs looked like probe bugs and were config precedence.

## Instrument caveats

- The positive control reported 41 pages, not 1. The host write is in there,
  but so is guest churn between arming and sampling, so it proves the
  instrument can *see* dirtying without isolating the injected write. It
  passes the assertion it makes (`>= 1`) and no more.
- `samples` reads 50 per window where the configured count was 10. The window
  boundaries are sound — `elapsed_ms_median` tracks each target closely (1.26,
  5.17, 25.2, 100.4, 500.3) — so the medians are over more samples than
  intended rather than over wrong ones. I have not explained the 5x.
- `physical_memory_test_and_clear_dirty` is O(total RAM) (one atomic per page,
  524,288 for 2 GB). Fine for sampling; it is exactly why the design specifies
  a word-wise sweep for the real thing.

## Reproduce

```
cd analysis/fastsnap/work/stride
penguin --image rehosting/penguin:latest run proj     # patch_fastsnap.yaml
                                                      # disables vpn, adds clock
```
