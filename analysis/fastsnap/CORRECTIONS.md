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
