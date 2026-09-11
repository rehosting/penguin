---
type: issue-draft
title: "A separate fast reset path for fuzzing: syx-snapshot's device block + QEMU's own dirty bitmap"
labels: [enhancement, research, performance]
status: NEW
lane: fastsnap
source-note: "Luke: 'I'm looking for a separate mechanism for fuzzing and or forking' / 'i specifically want people to have the fast path that might make tradeoffs. one might be that the networking backend doesn't work.' / 'i had referenced nyx because it - while mot TCG - cleverly just put device state in a block'"
referents: "penguin @ 16d112ea (== origin/main after fetch, 2026-08-27); qemu @ 56554982 (2026-08-20, VERSION 11.0.50); measured against rehosting/penguin:v3.1.14 (sha256:6bf719e2b8ab0894c5082d087f30af5601929ab62c3fc53989ecc24d3a72b2f0)"
---

# A separate fast reset path for fuzzing

## The recommendation, first

**Build a hybrid: import LibAFL `syx-snapshot`'s device half, and use QEMU's own
dirty bitmap for RAM. Do not build it on `fork()`.** Both halves have been
prototyped and measured (Slice 0 / RAM half below); this is not a paper design.

- **Device state → a flat memory block.** `device_save_kind()`
  (`libafl/syx-snapshot/device-save.c:38`) walks `savevm_state.handlers`, skips
  the iterative ones, and writes the rest through a `QIOChannelBufferWriteback`
  into a plain `uint8_t*`. Restore is a read back from memory. That is Nyx's
  trick, and it keeps QEMU's own vmstate descriptors, so it stays correct for
  devices we did not write. **Measured on our tree: the entire device block for
  `-M virt -m 128` is 62 KB, 17 sections, and it round-trips.**
- **RAM → QEMU's existing `DIRTY_MEMORY_MIGRATION` bitmap**, not syx's hooks.
  Under TCG that bitmap is maintained unconditionally and is load-bearing for
  live migration. `physical_memory_test_and_clear_dirty()` at snapshot, query at
  restore, restore those pages from a root copy.
- **Disk → an in-memory COW cache** (`syx-cow-cache.c`), so the disk rolls back
  without touching the qcow2.
- **Not `fork()`.** Declined on three verified obstacles, one of which (a
  7-thread process with an embedded CPython) is sufficient alone.

### Why the hybrid beats importing syx whole

Not mainly the file count. **The two files the hybrid does not touch —
`accel/tcg/cputlb.c` and `system/physmem.c` — are the two in TCG's hottest
path.** Carrying a fork divergence in the store path means every guest
instruction pays for it and every rebase re-litigates it. The divergence that
remains is in `migration/savevm.c`, which is cold, versioned, and only disturbed
when upstream restructures snapshots.

The measured reason is stronger still: **syx's RAM tracking is unsound for a
snapshot of a warm guest** — see *RAM half*. We would have imported that.

### What it costs — read this before deciding

- **~1 day** of careful work for the device half.
- **5 upstream files**, of which **two (`migration/savevm.c`, `migration/savevm.h`)
  are internals upstream deliberately keeps `static`.** Our fork would diverge
  where upstream has signalled it does not want callers, and every future rebase
  pays for that. Not a reason to decline; a reason to decide deliberately.
- **Three latent bugs in the imported code, all of which must be fixed on the
  way in** — two memory bugs in the device half (a 3-argument declaration
  against a 4-argument `vmstate_save`; a double free in `device_restore_all()`),
  and one soundness gap in the RAM half (the dirty list never re-arms). All
  three were found by building and running it, not by reading it.
- **Provenance:** `rehosting/qemu` is public. Exact upstream commit recorded,
  license headers intact, file-level attribution, GPL-2.0 compatibility stated
  in the PR body. Whether to import third-party code into a public repo at all
  is Luke's call, not this draft's.
- **Posture:** we would be *adopting and repairing*, not tracking upstream.
  Given three bugs and a two-major-version gap, that is the honest framing and
  the cheaper one.

### If you are implementing this, two things will silently sink you

Both were found the expensive way. Neither produces an error.

1. **`SaveStateEntry.is_ram` does not exist in QEMU 11.x, and in 9.x it never
   meant "is RAM".** It was set for any handler with a `save_setup` op — every
   *iterative* handler: `ram`, `dirty-bitmap`, `slirp`, `spapr/htab`, VFIO, s390
   skeys/stattrib, `todclock`. The correct predicate is:

   ```c
   if (se->ops && se->ops->save_setup) { continue; }   /* skip iterative handlers */
   ```

   **Matching on `idstr == "ram"` is the naive version and it is wrong** — it
   silently pulls live handlers into the device block. The obvious reading of
   the field's name is the broken one.

2. **The dirty list is empty on a warm guest unless you re-arm tracking at
   snapshot time.** A slow-path hook fires only when the TLB misses or carries a
   flag; snapshot a guest that has been running and every page's entry is
   already resident, so its stores take the fast path and are never seen.
   Measured: **0 of 64 pages trapped** after a mid-run snapshot point with no
   re-arm; 64/64 with either `tlb_flush(cpu)` per CPU or
   `physical_memory_test_and_clear_dirty()`. Since `syx_snapshot_root_restore()`
   restores *only* the pages in its dirty list, the failure mode is a **silently
   incomplete restore** — the loop runs on partially-reverted state and reports
   findings. No crash, no error, no empty artifact.

Everything below is why, and what it costs. **One finding does not depend on
this recommendation at all** — that half the per-restore cost is invisible to
the benchmark anyone would naturally run — and it has its own section, because
it stays true if the port is rejected entirely.

### A note on method

This lane's recommendation was reversed by its own prototype, and not in the way
anyone predicted. The RAM slice was authorised on the hypothesis that
`cputlb.c` drift between QEMU 9 and 11 would make LibAFL's hooks impractical.
**Drift turned out to be a six-line shift.** The recommendation changed anyway,
because building the thing surfaced a soundness gap that no amount of reasoning
about version gaps would have produced. Had the stated hypothesis been correct,
we would have got a worse answer for a better-sounding reason. *The slice that
changes your mind usually changes it about something else* — which is the
argument for pricing a design by prototyping it rather than by reading it.

## What we are being asked for

A **second** path, for fuzzing throughput, alongside the faithful one — not a
faster `savevm`/`loadvm`. Analysis-state fidelity is explicitly sacrificable;
so is the network backend. That decoupling is most of why "separate mechanism"
is the right framing, and it is what makes the design tractable.

This draft is therefore **not** about PR #898 or draft 41 item [15]. See
*Findings on adjacent work* at the end — both are real and both are about
restore coming back *wrong*, which is a different project.

## What restore costs today

Measured, not estimated. Harness, controls and raw results are in
`penguin/analysis/fastsnap/` (commit `255287c0` on `workspace/fastsnap`);
`README.md` there documents the method.

**Method.** `penguin_save_snapshot` / `penguin_load_snapshot` run in a main-loop
bottom half and stop every vCPU for their duration, so with a syscall-dense
guest the wall-clock gap between consecutive syscall returns brackets the
operation. A pyplugin samples `perf_counter()` on every syscall return.

**Controls.** Three, and the second one earned its place the hard way.

- *Accuracy*: a host-side sleep of known size injected where the snapshot
  request would go. Recovered to within 0.2–0.7% on every run.
- *Density*: the sampler's resolution is the ordinary inter-syscall gap.
  **The first version of this harness reported clean, plausible numbers taken
  entirely from early kernel boot** — the state machine ran to completion on the
  15 syscall returns available before userspace started, and the accuracy
  control passed while it did so. A correct instrument pointed at the wrong
  moment looks exactly like a correct measurement. The density control (refuse
  to measure below a sampling-rate floor, arm only after readiness) is what
  makes the numbers below mean what they say.
- *Self-reference*: two adjacent windows (A then B) inside one restore cycle, so
  a loaded host cannot masquerade as a restore penalty.

**Result 1 — the visible cost.** armel/4.10, `mem=256M`, in-process `loadvm`:
a **~86–160 ms** guest stall per restore (median across runs; run-to-run spread
is wide because this host is shared — treat the order of magnitude as the
finding, not the third digit). Save is comparable, ~100–125 ms.

**Result 2 — it scales with RAM, sub-linearly.** One sweep under matched
conditions:

| `core.mem` | restore stall (median) |
|---|---|
| 128M | 111.0 ms |
| 256M | 146.5 ms |
| 512M | 164.0 ms |
| 1G   | 228.4 ms |

Eight times the RAM buys only twice the time, because the migration path skips
zero pages. A linear fit gives roughly **~94 ms fixed + ~0.13 ms/MB**. The fixed
~94 ms — device traversal, qcow2 I/O, stop/resume — is the larger half at every
realistic size, and it is precisely what "device state in a block" attacks.

The stall is not the whole cost. The other half has its own section below,
because it stands on its own.

## Half the cost is invisible to a restore-latency benchmark

**This finding is independent of the recommendation.** It holds whether or not
we port anything, it is TCG-specific, and it changes how any future work in this
area must be measured — so it should survive a decision to reject everything
else in this draft.

Every `loadvm` goes through `vm_stop(RUN_STATE_RESTORE_VM)`
(`qemu/system/penguin.c:266`), and QEMU registers a vm-change-state handler that
turns that state into a **full `tb_flush`** — throwing away the entire
translation cache:

```c
/* qemu/accel/tcg/tcg-all.c:88 (handler registered at :147) */
static void tcg_vm_change_state(void *opaque, bool running, RunState state)
{
    if (state == RUN_STATE_RESTORE_VM) {
        /*
         * loadvm will update the content of RAM, bypassing the usual
         * mechanisms that ensure we flush TBs for writes to memory
         * we've translated code from, so we must flush all TBs.
         */
        assert(!running);
        tb_flush__exclusive_or_serial();
    }
}
```

So the guest re-translates everything it executes after every restore. That cost
is **not** in the stall; it is paid afterwards as degraded throughput, which is
why a restore-latency benchmark misses it entirely. Measured with adjacent A/B
windows of 2000 syscall returns each, five consecutive restores:

| | window A (0–2000 after restore) | window B (2001–4000) |
|---|---|---|
| rate | 3056, 3067, 3083, 3084, 3093 Hz | 4032, 3989, 3987, 4007, 4024 Hz |

Window A runs at **~76.5% of window B**, identically on all five restores, with
B measured 0.65 s later in the same cycle so host load cannot explain it. That
is **≥ ~152 ms of extra wall-clock per restore** — and it is a lower bound,
because window B (≈4000 Hz) has still not returned to the pre-restore warmup
rate (4338 Hz).

**So the real per-iteration cost is roughly 300 ms, of which about half is
invisible to the obvious benchmark.** At ~3 iterations/second, the faithful path
is not a fuzzing loop.

Three consequences, in decreasing order of how long they outlive this draft:

1. **Any future measurement in this area must measure throughput after the
   restore, not just the restore.** A change that halves the stall and leaves
   the flush in place buys ~25% of the real cost while appearing to buy 50%. The
   obvious benchmark will report a win that the fuzzing loop does not feel.
2. **It is a second, independent argument for bypass over optimise.** A
   mechanism that never enters `RUN_STATE_RESTORE_VM` keeps the translation
   cache warm *for free* — no work, just the absence of a state transition.
   Optimising `load_snapshot()` cannot get this; replacing it does.
3. **It is a reason to prefer many small restores over few large ones**, since
   the flush cost is per-restore and independent of how much state changed.

## Why the faithful path is slow (mechanism, not speculation)

The chain, end to end, all verified in this fork:

`pyplugins/core/snapshot.py` → `self.panda.schedule_snapshot()` →
`pyplugins/compat/qemu_compat.py:1243` → a **CFFI call to an exported C ABI
symbol**, `penguin_schedule_snapshot` (`qemu/system/penguin.c:305`, declared
`qemu/include/system/penguin.h:82`) → `aio_bh_schedule_oneshot` (`:311`) →
`penguin_snapshot_bh` (`:284`) → `penguin_save_snapshot` (`:238`) /
`penguin_load_snapshot` (`:261`) → upstream `save_snapshot()` / `load_snapshot()`
from `migration/snapshot.h`.

Two consequences worth stating plainly:

- **There is no QMP, no monitor and no socket in this path.** A direct
  in-process control surface already exists, so adding a second entry point
  beside `penguin_schedule_snapshot` is cheap. "Separate mechanism" can be
  literal: a second API next to the faithful one, not a flag on it.
- **The cost is the generic migration framework**, which serialises RAM into a
  qcow2 internal snapshot. Confirmed by the artifact: the smoke run's overlay
  reports `VM_SIZE 87.1 MiB` for a guest that had just reached readiness.

## The RAM half is the *easy* half under TCG — verified

Nyx needs hardware assistance (EPT/PML) for dirty-page tracking. **We do not,
and this inverts the usual assumption about TCG being the disadvantaged case.**

QEMU maintains a page-granular software dirty bitmap with three clients
(`qemu/include/system/ram_addr.h:28-31`: `DIRTY_MEMORY_VGA`, `_CODE`,
`_MIGRATION`). Under TCG it is maintained by the softmmu itself: when a TLB
entry is filled for a writable RAM page that is currently clean, QEMU sets
`TLB_NOTDIRTY` on the write flag (`accel/tcg/cputlb.c:1087`), which forces the
*first* store to that page onto the slow path. `notdirty_write()` (`:1336`) then
marks the page dirty and clears the flag, so subsequent stores run at full
speed.

**That is exactly one trapped store per page per epoch, in software, with no
hardware involved** — the property Nyx needs virtualisation extensions for.

LibAFL chose *not* to reuse this bitmap: `syx-snapshot` installs its own hooks
(`accel/tcg/cputlb.c`, `system/physmem.c`) recording dirty pages *with their
previous contents*, which supports nested/incremental snapshots a bare bitmap
cannot. So there were two candidate routes.

**An earlier revision of this draft recommended syx's hooks, on the grounds
that they were the ones demonstrated to work. Measurement reversed that** — see
*RAM half*, where syx's tracking is shown to record nothing at all on a warm
guest. The bitmap is the recommendation. Two further facts settle it: the
bitmap needs no global enable under TCG (verified — the probe read it correctly
having never called `memory_global_dirty_log_start()`), and it is load-bearing
for live migration, so its completeness is upstream's problem rather than
ours.

## Do not build this on `fork()` — closed, on three verified obstacles

Luke's phrasing was "fuzzing and or forking", so forkserver designs were priced
first and are **declined**. All three obstacles were checked in this fork, not
assumed. Obstacles 2 and 3 dissolve if the fast path runs with
`plugins.vpn.enabled: false`, which Luke has sanctioned; **obstacle 1 does not,
and is sufficient on its own.** In-process incremental restore avoids all three,
and syx-snapshot is in-process — so *fast reset* delivers what *forking* was
wanted for.

**1. The process is multithreaded, with an embedded CPython in it — the
sufficient one.** Penguin does not run QEMU as a child process; it loads it as a
library into the Python interpreter via CFFI (`qemu_compat.py` `run()` calls
`lib.qemu_init()` then `lib.qemu_main_loop()`). Observed thread set of a live
run, sampled from `/proc/<pid>/task/*/comm`:

```
python3.13  call_rcu  python3.13  worker  CPU 0/TCG  worker  worker   (7 threads)
```

`fork()` in a multithreaded process keeps only the calling thread. The GIL,
QEMU's BQL, and the RCU thread's state would all survive into the child in
whatever condition they were in at the instant of the fork, with no thread left
alive to release them. Forking safely would mean forking from a controlled
single-threaded point, which in this architecture means before `qemu_init` —
i.e. before there is any guest state worth forking.

**2. Guest RAM is a *shared* mapping whenever VPN is on.** `penguin_run.py:526-533`
builds, under `if vpn_enabled:` (`:515`),
`memory-backend-file,id=mem0,mem-path=...,size=<core.mem>,share=on` plus
`-numa node,memdev=mem0`. `share=on` is `MAP_SHARED`: a forked child would write
the *parent's* guest RAM. Fork-based isolation is not merely awkward there, it
is absent.

**3. The vsock device backend is a separate process.** `penguin_run.py:532`
adds `vhost-user-vsock-pci,chardev=char0`, served by a `vhost-device-vsock`
process spawned by `pyplugins/actuation/vpn.py:321`. `fork()` duplicates QEMU
and not the backend, so every child would share one backend with one device
state.

## What the fast path abandons, and what it keeps

Turning off VPN is a bigger lever than it looks, and in a favourable direction.

**Lost:**
- Host↔guest networking (the vsock VPN bridge, port forwarding, `connect.sh`).
- `penguin guest_cmd` and the guesthopper channel (`src/penguin/utils_cli.py:394`).
- Any analysis whose evidence arrives over the network path.

**Kept — and this is the part that makes the trade acceptable:**
- **Hypercalls and the whole portal.** These do *not* ride vsock. They are a
  direct in-QEMU callback (`penguin_handle_guest_hypercall`,
  `qemu/include/system/penguin.h:37`) registered from Python. So syscalls,
  uprobes, kprobes, kffi, pseudofiles and the modeled-device machinery all
  continue to work with networking gone.

**And the concession removes the obstacle.** `penguin_save_snapshot` has to call
`migration_snapshot_set_ignore_blockers(true)` (`qemu/system/penguin.c:248`)
*because* the vhost-user vsock backend has no `LOG_SHMFD` dirty-page logging.
The device that forces the blocker override is precisely the device now allowed
to be absent. The sanctioned tradeoff and the enabling mechanism are the same
fact from two sides, which is a good sign the cut is in the right place.

**Also deliberately abandoned: host-side analysis state.** The fast path resets
guest state and drops the host plugin overlay. That is the decoupling that lets
this be a separate mechanism at all, and PR #898's whole subject matter is
therefore explicitly *out of scope* for it. Saying so out loud is a design
decision, not an omission.

## Integration shape

1. **New C entry points beside the existing ones**, in `qemu/system/penguin.c`,
   which already has the pattern (hypercall callbacks `:76`/`:89`, snapshot BH
   `:284`, reset-request `:318`): `penguin_fastsnap_take(void)`,
   `penguin_fastsnap_restore(void)`, `penguin_fastsnap_release(void)`. Exported
   with `__attribute__((visibility("default")))` like their neighbours, so the
   existing CFFI `_lib_symbol()` lookup in `qemu_compat.py` picks them up with
   no new plumbing.
2. ~~**Port `syx-snapshot`'s device half** into the fork under its own directory~~
   **DONE — but not into the fork.** It landed in `rehosting/qemu_builder`
   (branch `workspace/fastsnap`) as `src/fastsnap/`, because Penguin's QEMU
   input is moving from the `rehosting/qemu` fork to that curated series over a
   pristine v11.1.0 tarball. Everything below is preserved because it records
   the reasoning, but four of its specifics turned out differently:

   - **Upstream files touched is TWO, not five.** `migration/savevm.{c,h}`.
     `io/channel-buffer.{c,h}` are not touched at all: the borrowed-buffer read
     they were wanted for now lives in our own channel, which also removes an
     upstream double free. The COW cache in `block/block-backend.c` is not part
     of this.
   - **The structs are NOT hoisted and nothing is de-`static`ed.** Two
     accessors inside `savevm.c` instead, so `SaveStateEntry` stays an
     incomplete type outside it. The hoist and the accessor were built and
     probed head to head: on `git am` portability they are indistinguishable,
     so that was not the reason; what separates them is footprint (`+64/-0` vs
     `+46/-35`) and what happens when upstream adds a field to the struct,
     where the accessor applies cleanly and the hoist leaves a `.rej`.
   - **The base is 11.1.0, not 11.0.50.** Two more deltas on top of the ones
     listed below: `hw/boards.h` moved to `hw/core/boards.h`, and QOM's
     `class_init` `class_data` parameter became `const void *`.
   - **Provenance is settled, not open.** Luke approved GPL in `qemu_builder`.
     The declaration is `src/fastsnap/PROVENANCE.md`: whole files with SPDX
     headers and the upstream commit, deliberately never interleaved into patch
     hunks where provenance stops being legible.

   The original text follows.

   Port `syx-snapshot`'s device half into the fork under its own directory
   — `device-save.c` and `channel-buffer-writeback.c` plus headers. Working
   sources and patches from the port gate are in `projects/fastsnap/slice0/`.
   Port delta is QEMU 9.1.1 → 11.0.50: headers moved (`sysemu/` → `system/`,
   `include/exec/ram_addr.h` → `include/system/ram_addr.h`),
   `qemu_load_device_state()` gained an `Error **`, and `SaveStateEntry.is_ram`
   is gone (see the implementer warning at the top — the replacement predicate
   is `se->ops && se->ops->save_setup`, and the obvious `idstr == "ram"` reading
   is wrong).

   Upstream files touched: `migration/savevm.c` and `migration/savevm.h`
   (de-static `savevm_state` and `vmstate_save`; hoist `CompatEntry`,
   `SaveStateEntry`, `SaveState`), `io/channel-buffer.c` and
   `include/io/channel-buffer.h` (`qio_channel_buffer_new_external` is a LibAFL
   addition, not upstream), plus `block/block-backend.c` for the COW cache.
   **Five, and deliberately not `accel/tcg/cputlb.c` or `system/physmem.c`** —
   see *RAM half* for why those two are the ones worth not touching.

   **Provenance is a hard requirement, because `rehosting/qemu` is public.**
   Record the exact upstream commit the port was taken from; keep the original
   license headers intact; add a file-level note saying where each file came
   from. Never strip attribution to make imported code look native, even though
   we intend to maintain it as ours thereafter — *ours to modify, theirs to
   credit.* Both trees are GPL-2.0, so no compatibility problem is expected, but
   the PR body should **state that explicitly** rather than leave a reviewer to
   infer it. Whether to import third-party code into a public repo at all is a
   provenance and licensing decision, not an architectural one; it is Luke's
   call, not this draft's.
3. **Host side**: a `core.fastsnap` config section and a `FastSnap` pyplugin
   exposing `take()` / `restore()`, refusing to load unless `vpn.enabled` is
   false, and hard-failing (not warning) if the symbols are absent.
4. **Do not** route this through `pyplugins/core/snapshot.py`. Different
   contract, different fidelity, different failure modes. A second plugin beside
   it keeps `core.snapshot` honest.

Note `core.snapshot.backend` already declares a `"file"` option that
`penguin_run.py:586-592` raises `NotImplementedError` for. **Do not repurpose
it.** A migration-file backend is a *faithful* backend that happens to write
elsewhere; this is a lossy backend. Conflating them would put a fidelity cliff
behind a word that promises a storage change.

## The fast path must declare its own reduced fidelity

A fuzzing campaign that found nothing because the guest's listener never came up
is indistinguishable, in the artifacts, from one that found nothing because the
target is sound. A mode that silently disables networking manufactures exactly
that ambiguity, and it is the defect class this programme keeps rediscovering:
*artifacts whose normal appearance removes the motive to check them*.

So the fast path must record, in the run's artifacts and not in a log line:

- that the fast path produced this run, and its mechanism version;
- that networking/vsock was absent, as a **positive assertion** rather than the
  absence of network evidence;
- that host-side plugin state was not carried across resets;
- the reset count, so throughput claims are checkable after the fact.

**The requirement is the artifact, not any particular file.** A later reader,
who was not present when the run was launched and does not know which mode was
chosen, must be able to establish from the run's own output that this was a
reduced-fidelity run and what it gave up. Any vehicle that satisfies that is
acceptable; a log line is not one, because scrollback is not an artifact.

The requirement lands **in the same slice as the mode**, never after it. A fast
path that ships one release ahead of its own disclosure is the defect, not a
step towards fixing it.

*Note on a likely home, not a dependency:* `run_manifest.yaml` would be the
natural place once it exists. It is described in `src/penguin/run_summary.py:44`
as the sibling of `summary.json`, but **grep finds no writer for it anywhere at
`16d112ea`** — it is the `scoregate` lane's in-flight work. Coordinate with that
lane rather than inventing a second manifest if it has landed by then; if it has
not, this requirement is still met some other way rather than deferred. Writing
a draft that depends on an artifact a docstring merely promises would itself be
an instance of the class this section is about.

## Slice 0 findings — the port gate, run

Full report and patches: `projects/fastsnap/slice0/` (`FINDINGS.md`,
`port/*.patch`). Built out-of-worktree, so no third-party source sits in
`penguin/` or `qemu/`.

**The device half ports and round-trips.** `qemu-system-arm -M virt -m 128`:
17 device sections, a **62 KB** block with RAM excluded, and a save → perturb →
restore → save cycle that reproduces the original bytes. Controlled three ways:
a positive control (perturb PL011 `UARTIMSC`, assert the block changed — proves
`save()` sees device state at all), a **negative control** (stub
`device_restore_all()` to `return;` and confirm the test reports FAILED — proves
a no-op restore is detected), and an exit-code fix so a PASS does not also dump
core.

Three things the gate changed in this draft:

1. **The port is 7 upstream files, not 3** (importing syx whole; the hybrid
   later brings this down to 5 — see *RAM half*). The earlier figure came from
   grepping for `syx_snapshot` outside the syx directory, which finds only edits
   that mention the string and misses de-static'ing and helper additions. The
   device half alone needs `migration/savevm.c` (de-static `savevm_state` and
   `vmstate_save`, hoist three typedefs), `migration/savevm.h`,
   `io/channel-buffer.c` (`qio_channel_buffer_new_external` is a LibAFL
   addition, not upstream) and `include/io/channel-buffer.h`. Two of those are
   migration internals upstream keeps `static` deliberately.
2. **`SaveStateEntry.is_ram` was removed in 11.x — and it never meant "is
   RAM".** 9.1.1 set it for any handler with a `save_setup` op, i.e. every
   iterative handler (`ram`, `dirty-bitmap`, `slirp`, `spapr/htab`, VFIO, s390).
   The correct port is `se->ops && se->ops->save_setup`. **Matching on
   `idstr == "ram"` would be wrong** and would silently pull live handlers into
   the device block — here the obvious reading of the field name is the broken
   one.
3. **The vendored code carries two real memory bugs**, both of which would have
   been imported silently: a 3-argument `extern` for a 4-argument
   `vmstate_save` (uninitialised `Error **errp` on every call), and a double
   free in `device_restore_all()` — `qio_channel_buffer_new_external()` borrows
   the caller's buffer but upstream's finalizer frees it unconditionally.
   The second was found by running the code, not reading it, and the first
   passing round-trip was obtained while comparing against a buffer restore had
   already freed. It passed by luck. **A passing test that reads freed memory
   looks exactly like a passing test.**

**Cost line for the adopt decision**, since this is what Luke is weighing: the
device half is ~1 day of careful work; the import is 5 upstream files, **two of
which (`migration/savevm.c`, `migration/savevm.h`) are internals upstream keeps
`static` on purpose** — our fork would diverge at a point upstream has signalled
it does not want touched, and every future rebase pays for it. Three latent bugs
in the imported code must be fixed on the way in (two memory bugs in the device
half, one soundness gap in the RAM half). None of that is a reason to decline;
all of it is a reason to decide deliberately, and it is the strongest argument
for the *maintenance* posture this draft recommends: we would not be tracking
upstream, we would be adopting and repairing. It is a real fork commitment — roughly a day of careful
work for the device half, not a weekend — and it is still much cheaper than
originating the mechanism.

**Still unanswered: the RAM half**, where the actual win is. `cputlb.c`'s store
paths changed shape between 9 and 11, and Slice 0 deliberately did not touch
them.

## RAM half — use QEMU's own bitmap, not syx's hooks

Full report: `projects/fastsnap/slice0/FINDINGS-ram.md`.

**Version drift is a non-issue.** All four `cputlb.c` hook sites LibAFL uses
survive into 11.0.50 with the same shapes; the anchor line moved six lines. I
installed all four and built clean. The RAM half is a *cheaper* port than the
device half.

**But syx's RAM tracking is unsound for a mid-run snapshot.**
`syx_snapshot_root_restore()` restores only the pages in its dirty list, so that
list must be complete — and nothing in the entire LibAFL tree flushes TLBs or
touches the dirty bitmap. Measured, with a guest looping stores over 64 pages
and a snapshot point applied mid-run:

| snapshot-point action | slow-path hits after | |
|---|---|---|
| **none** (what syx does) | **0 / 64** | every later write invisible |
| `tlb_flush(cpu)` per CPU | 64 / 64 | re-arms |
| `physical_memory_test_and_clear_dirty()` | 64 / 64 | re-arms |

A slow-path hook only fires when the TLB misses or carries a flag. Snapshot a
*warm* guest — the firmware case — and every page's entry is already resident,
so its stores take the fast path and the dirty list never fills. This is the
third latent bug in the vendored code and the worst, because it yields a
silently incomplete restore rather than a crash. (Consistent with the state of
that code: `syx_snapshot_dirty_list_add_tcg_target()`, documented as being for
generated code, is defined and never called; `cputlb.c:1750` carries LibAFL's
own `// TODO: Does not work?`.)

**QEMU's native bitmap does the job already.** Across every run it reported
64/64 correctly — without the probe ever calling
`memory_global_dirty_log_start()`. Under TCG it is maintained unconditionally
(`cputlb.c:1087` arms `TLB_NOTDIRTY` on clean writable pages; `notdirty_write()`
`:1336` sets VGA+MIGRATION via `DIRTY_CLIENTS_NOCODE` `:1352`). And it is
**load-bearing for live migration, which works under TCG** — so its completeness
is guaranteed by a maintained upstream feature rather than by a parallel
reimplementation we would own.

So for the RAM half: `physical_memory_test_and_clear_dirty()` at snapshot,
query the bitmap at restore, restore those pages from the root copy. **No
`cputlb.c` or `physmem.c` edits at all** — 7 upstream files becomes 5, and the
two dropped are the two in the hottest path in TCG. The cost is nested /
incremental snapshots, which a loop restoring repeatedly to one snapshot does
not need; syx's hooks can be added later if they are ever wanted.

The recommendation to port the **device** half is unchanged and strengthened —
that half has no in-tree equivalent, which is exactly why it is worth importing.

## Findings on adjacent work

- **PR #898 is `CONFLICTING`, not merely stale.** Opened 2026-07-10, last
  touched 2026-07-13, +2184/−86, branch `snapshot-restore-coverage`. It needs a
  rebase before anyone can judge it. On its contents it is a *correctness* PR —
  re-bind host callbacks to surviving guest ids, versioned host sidecar,
  two-phase `load_state`/`on_restore` — and it reads as the answer that draft 41
  item [15] is waiting for. It has been mis-parked as general snapshot work.
  **It is not this lane's deliverable and should not be rebased from here**, but
  it should be re-labelled as the item [15] correctness track and either landed
  or closed rather than left conflicting for two months.
- **Draft 23's grounding is stale.** It states "Snapshot mode does not exist yet
  (greenfield)" and "No savevm / loadvm / migrate ... anywhere". True when
  written; false since `bec1272f` (2026-06-19). Its Slice 3 is substantially
  built. (Being date-stamped by the manager.)
- **`rehosting/penguin:latest` on this machine is not the published image.** It
  is a local build tagged by another lane — identical image id to
  `penguin:entropy918`, no `RepoDigests`, built from `ef37fc91`, which is on
  `workspace/entropy918` and is **not** an ancestor of `origin/main`. Its QEMU
  library happens to be the same nix store path
  (`iwiqnm6v4pgkszncyliv9442wyv9nvaz-penguin-qemu`) as v3.1.14 and
  v3.1.15-portable, so the mechanism under test is the same binary — but anyone
  quoting a number measured against `:latest` on this host is quoting a feature
  branch.

## Slices

**Slice 0, the RAM-half assessment, and the port are DONE.** The first two were
research prototypes, and between them they reversed part of this draft's own
recommendation. Reports in `projects/fastsnap/slice0/`.

The import question is **settled**: Luke approved GPL in `rehosting/qemu_builder`,
and the device half now lives there on branch `workspace/fastsnap` as
`src/fastsnap/`, on QEMU 11.1.0, with a `nix flake check` gate that runs the
round trip and its positive control. `projects/fastsnap/slice0/` is now a
research record, not the live tree.

- ~~**0. Port gate.**~~ **Done, then landed.** Device half builds against
  `56554982` and round-trips; 62 KB block, 17 sections, positive and negative
  controls both pass. Found two memory bugs and corrected the `is_ram`
  predicate. **Re-done on QEMU 11.1.0 in `qemu_builder`** and passing there:
  17 sections, 63029 bytes, control fires, and the gate verified to fail when
  the restore is neutered.
- ~~**RAM-half assessment.**~~ **Done, and it changed the plan.** `cputlb.c`
  drift is a six-line shift, so syx's hooks *would* port — but they record
  nothing on a warm guest, so the recommendation is now QEMU's own bitmap and
  those hooks are not ported at all.
- **1. Device block behind `penguin_fastsnap_*`.** The three entry points beside
  `penguin_schedule_snapshot`; restore devices from the block, RAM still via
  `load_snapshot`. Measures the device half in isolation against the ~94 ms
  fixed floor. Fix the two imported memory bugs here, not later.
- **2. RAM via the native bitmap.** `physical_memory_test_and_clear_dirty()` at
  snapshot, query at restore, restore dirty pages from a root copy. **No
  `cputlb.c` / `physmem.c` edits.** This is where the win is, and where
  `tb_flush` avoidance arrives for free: hand-invalidate TBs for the dirty pages
  only and never enter `RUN_STATE_RESTORE_VM`.
- **3. Block COW cache.** `syx-cow-cache` so disk writes roll back in memory.
- **4. Host surface + fidelity declaration.** `core.fastsnap`, the `FastSnap`
  pyplugin, the vpn-disabled precondition, and the declaration — landing *in the
  same slice as the mode*, never after it.
- **5. A real fuzzing loop on top.** Out of scope here; it is what this
  substrate is for, and it deserves its own draft.

Re-run `penguin/analysis/fastsnap/run_bench.py` against slices 1 and 2 to keep
the comparison honest — it measures both halves of the cost, and the `tb_flush`
half is the one a naive benchmark will claim we already fixed.

## Open questions

- **Is 30–100× actually reachable, or is the portal the next floor?** Once
  restore is a memcpy, the per-iteration cost may be dominated by penguin's own
  hypercall/portal traffic rather than by the snapshot. Worth measuring at
  slice 2 before promising a throughput figure.
- **What is the reset point?** syx snapshots a running VM at an arbitrary
  instant. Penguin's existing safe-spot machinery (`snapshot.py` `_arm`,
  next-syscall / symbol boundaries) is the natural chooser — but a fuzzer wants
  the reset point to be the *input injection* point, which nothing currently
  models.
- ~~**Does anything in the IGLOO device set resist device-block save/restore?**~~
  **Answered, on real firmware, and the answer is yes: virtio.** Not our
  pseudofiles or `igloo` platform devices -- those round-trip. A virtio device
  keeps `last_avail_idx`/`used_idx` in the device model and the vring itself in
  **guest RAM**, so a device-only restore puts back one half and leaves the
  other at whatever the guest has since made of it. `virtio_load()` is strict
  enough to catch it:

      VQ 1 size 0x100 < last_avail_idx 0x9 - used_idx 0x11
      error while loading state for instance 0x0 of device
      '0000:00:01.0/virtio-net': Failed to load element of type virtio

  The rule generalises past virtio: **any device whose state is co-located with
  guest RAM cannot go in a block that does not carry that RAM.** So the fix is
  not to make virtio tolerant, it is to keep those devices out -- the denylist,
  now reachable as `penguin_fastsnap_set_denylist()`. This is the "so is the
  network backend" sacrifice above arriving as a concrete bill rather than a
  stated willingness.

  It could not have been found on `-M virt`, which has no virtio-net, which is
  why every prototype measurement missed it. Once slice 2 carries RAM as well,
  the denial is worth revisiting: the reason for it is precisely the RAM half's
  absence.
- ~~**Upstream tracking.**~~ **Settled: the ported files are ours, from day
  one.** `qemu-libafl-bridge` is at QEMU 9.1.1 and we are now on 11.1.0, so the
  gap is two releases wider than when this question was written. The files live
  in `qemu_builder` under `src/fastsnap/`, **copied, never patched** -- the
  repo's invariant is that no patch modifies a file we created. Provenance and
  licence are declared in `src/fastsnap/PROVENANCE.md` rather than carried as a
  rebase.

  The port is not a transcription. `device-save.c` was rewritten onto two new
  accessors (`qemu_savevm_foreach_handler`, `qemu_savevm_save_one`) instead of
  libafl's hoist of `SaveStateEntry` into a public header, so the struct stays
  an incomplete type outside `savevm.c`; `se->is_ram` no longer exists in 11.x
  and the correct predicate is `se->ops && se->ops->save_setup`; and
  `channel-buffer-writeback.c` grew a reader constructor, which removed both the
  need to patch `io/channel-buffer.c` and libafl's double-free.
