# fastsnap: the recommendation, after measurement and audit

Supersedes the recommendation section of `DESIGN-fastsnap.md`. The cost model
there survives; the integration decision and the fork decision do not. See
`CORRECTIONS.md` for what was wrong and how it was found.

## Two layers, and neither is `fork()`

**Layer 1 — in-process reset, on the main loop.** Reset the guest thousands of
times per second inside one worker. This is where the speed is.

**Layer 2 — N worker processes.** Aggregate throughput past the per-instance
ceiling, which is guest emulation speed. Penguin already puts its isolation
boundary at a process (`compose.py:659` runs a `ThreadPoolExecutor` whose
threads each `Popen` a `penguin_run` and block on `wait()` — the thread is a
waiter, the process is the isolation).

### `fork()` is blocked, and it was never the lever

The decisive fact is not the embedded CPython. It is that **no point in the
process's life has both guest state and a single thread**: `util/rcu.c:488` is
an `__attribute__((__constructor__))`, so the `call_rcu` thread is created at
`dlopen` (`pyplugins/compat/qemu_compat.py:617`), before `qemu_init` is ever
called. Measured directly: threads go from `['python3.13']` before `dlopen` to
`['call_rcu', 'python3.13']` after. The only fork point is *before* QEMU
exists, which saves ~1 s of CPython import and nothing else — a slow
`posix_spawn`, not a forkserver.

Two corrections to this lane's earlier reasoning:

- I argued `rcu_disable_atfork()` at `system/vl.c:2700` was "inside
  `qemu_maybe_daemonize()` — daemonization, not a ban". It is reached
  **unconditionally** from `vl.c:3778`. The grounds for reopening fork were
  wrong. (It is also the *easiest* obstacle, not a real one:
  `rcu_enable_atfork` is exported from the shipped library, so one CFFI call
  after `qemu_init` restores it, as `tests/qtest/fuzz/fuzz.c:232` does.)
- The harder blocker has no cheap fix: the guest executes on `CPU 0/TCG`
  (`accel/tcg/tcg-accel-ops-rr.c:332`), a thread that does not survive
  `fork()`. The child would have to recreate vCPU threads against a CPU state
  that was serialised rather than inherited, and no upstream API for that
  exists. QEMU's own fork-safe fuzzer sidesteps this by driving the guest from
  the *forking* thread via qtest and hand-controlling the main loop — a
  structure penguin does not have.

**And fork buys the wrong thing.** A worker's startup is ~2.2 s in-container
(~3.2 s with the wrapper), measured: wrapper+container ~1.0 s, config+patch
merge ~1.0 s, plugin load (37 plugins) ~1.0 s, `qemu_init`+machine+`-loadvm`
sub-second. That is 20-60x an in-process `loadvm` — but it is paid **once per
worker**, not per iteration, and amortises after ~150 iterations. Fork
optimises worker spawn; worker spawn is not the cap.

### What Layer 2 actually needs (small, and independently useful)

Measured at N=2: two processes restoring from **separate copies** of the
snapshot overlay both run fine (20.80 s / 20.75 s against a 15 s guest
timeout — contention is small). Two processes on the **same** overlay fail:

```
Failed to get "write" lock
```

because `penguin_run.py:657-658` opens the persistent overlay read-write
*without* `snapshot=on`, unlike the immutable path at `:656`. And the cheap
workaround does not exist: a thin qcow2 overlay **does not inherit the backing
file's internal snapshots** (`qemu-img snapshot -l` lists `boot` on the
snapshot qcow2 and nothing on an overlay of it), so today each worker needs a
full copy.

1. Per-worker overlay, or open a shared one read-only (`penguin_run.py:657`).
2. **Implement `core.snapshot.backend: 'file'`** — already designed, already in
   the schema, currently `NotImplementedError` at `penguin_run.py:585-591`.
   This is the clean answer: vmstate in a separate file N workers each read,
   with per-worker disk overlays, instead of N x 100 MB copies.
3. Generalise compose's index-striped port/CID allocation
   (`compose.py:447-474`) from "N devices" to "N replicas of one device".
4. Run the lean plugin profile in workers (~33% of guest cost, per
   `THROUGHPUT.md`).

## Layer 1: what changes from DESIGN-fastsnap.md

**The loop goes on the main loop via `aio_bh_schedule_oneshot`, not in a
hypercall handler.** The fork's own comment says so
(`qemu/system/penguin.c:299-303`), the hypercall is an inline TCG helper with
the BQL dropped (`target/arm/tcg/translate.c:2365`,
`accel/tcg/cpu-exec.c:543-544`), and the ported `device-save.c` says
`// iothread must be locked`. The ~0.04 ms handshake is not overhead to remove;
it is the cost of reaching a context where the operation is legal. Budget it.

**Tier 0 is not a sound oracle.** `device_save_kind()` skips every `save_setup`
handler — `slirp`, `globalstate`, iterative handlers — so "restore everything,
nothing can be wrong" is false. Either name the exclusion set and accept it, or
triage crashes against a full `loadvm` rather than against Tier 0.

**Cost model (unchanged, and now confirmed on real firmware).** Reset is
0.054 ms with a `{cpu,timer}` allowlist and 0.78 ms with the full device block,
at 16 dirty pages; the RAM half is O(dirty) only if the bitmap is swept
word-wise (the naive per-page walk is O(total RAM) and costs a flat 5.2 ms).
On stridelinx the real idle dirty set is 51 pages/ms rising to ~300 at 500 ms —
0.022 ms of RAM term at iteration scale, close enough to the synthetic's 65
pages that the arithmetic holds.

## The gating problem is host-side state, not speed

`Plugin.reset_state()` exists at `src/penguin/plugin_manager.py:269-277` and its
docstring names this exact use case — *"Reserved for fork/restore-many …
this is the designed seam, not yet driven by any caller."* `grep -rn
reset_state` returns **one hit: the definition.** Zero implementers, zero
callers.

And the existing in-process restore path already has the bug this would
amplify: `pyplugins/core/snapshot.py:148-152` calls `schedule_snapshot(...)`
then only `plugins.publish(...)` — it never calls `_restore_host_state` or
dispatches the `on_restore` *method*, so the three plugins that implement it
(`vpn`, `nvram2`, `netbinds`) are never told; and because `schedule_snapshot`
is fire-and-forget onto a bottom half, the notification precedes the restore.
Latent at 1 Hz, untested, and a fastsnap loop would run it at kHz.

Three failure shapes, all real:

- **Guest-mirrored handles.** `hyper/portal.py:519` holds *suspended Python
  generators* keyed by guest address. A reset mid-transaction strands a
  generator that will be resumed with a response to a command the rolled-back
  guest never issued. Not serialisable at any price — so the reset point must
  be portal-quiescent, which is a hypercall boundary, **not** the syscall
  boundary `snapshot.py`'s existing arming uses.
- **Dedup eats the oracle.** `crashes.py:105` keys on `(comm, sig, pc)` and a
  repeat only does `count += 1`. A thousand distinct inputs hitting one crash
  site collapse to one record carrying the *first* sighting's timestamp. The
  fuzzer's oracle actively suppresses its own results.
- **Merge-not-clear.** `nvram2`'s `save_state`/`load_state` `update()` rather
  than replace, so a restore-many loop accumulates keys from discarded trials.

**Minimum contract:** an epoch counter bumped per `take()`, carried on every
emitted record (this is what makes crash attribution work); `reset_state()`
implemented per stateful plugin and driven through a *registry* rather than the
O(all plugins) `getattr` walk `snapshot.py:183-231` uses; and a declared
three-way split per plugin — **rollback** (trial-scoped), **carry**
(cross-trial: corpus, caches), **forbidden on the fast path** (host wall-clock,
threads, subprocesses, append-only sinks — these get excluded from the fuzzing
config, not "made restore-aware").

## Where it lives

`pyplugins/apis/fastsnap.py`, class `FastSnap(Plugin)` — not beside
`core/snapshot.py`. `apis/` is where a plugin owns a capability others register
against (`syscalls`, `uprobes`, `qmp`); `core/` is config-driven policy.
Fastsnap is a mechanism `hyperfile` handlers and fuzz drivers register against.
`apis/qmp.py` is the precedent to copy: opt-in, lazily binds its C ABI on first
registration. The *policy* half (when to reset, which tier) belongs in the
schema beside `core.snapshot`.

## Slices

0. Done: device half ports and round-trips; RAM half priced; full reset built
   and measured; RAM term confirmed on real firmware.
1. **Prototype the RAM half in Python against today's image.** No rebuild
   needed — every symbol is already exported, and `ram_term.py` demonstrates
   the access pattern. Cheapest possible validation of the whole cost model.
2. Drive `reset_state()`: epoch counter, registry, and the three-way
   classification for the plugins a fuzzing profile actually loads.
3. C ABI in the fork behind a build option, main-loop scheduled; Tier 0 only.
4. Layer 2: `backend: 'file'` + per-worker endpoints.
5. Tier 1 + audit, once Tier 0 has an oracle that is actually sound.

## Still unmeasured

- Throughput at N > 2 workers (contention measured only at N=2: ~0.6 s added).
- Whether guest-side hook/probe/trampoline tables live in guest RAM (restored)
  or in QEMU/host state — decides how bad the guest-mirrored-handle problem is.
  That is an `igloo_driver` question.
- Penguin's pyplugin dispatch cost per reset (the raw CFFI crossing is 0.6 us;
  the plugin-manager layer on top is not measured).
