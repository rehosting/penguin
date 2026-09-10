# Corrections to DESIGN-fastsnap.md, and the RAM term measured on real firmware

Three of this lane's own claims were wrong. All three were found by checking
the design against the code and against a real target rather than against the
prototype it was developed on. Recording them here rather than quietly editing
the design, because two of them are the *kind* of error worth remembering.

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
`device_save_kind()` skips, before any allowlist logic, every handler with
`save_setup` — `slirp`, `globalstate`, and all iterative handlers. That
undermines using Tier 0 to triage Tier 1 crashes, which was the safety
argument for shipping Tier 1 at all.

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
