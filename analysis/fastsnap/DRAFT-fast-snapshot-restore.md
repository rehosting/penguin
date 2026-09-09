---
type: issue-draft
title: "A separate fast reset path for fuzzing: port syx-snapshot to the IGLOO QEMU fork"
labels: [enhancement, research, performance]
status: NEW
lane: fastsnap
source-note: "Luke: 'I'm looking for a separate mechanism for fuzzing and or forking' / 'i specifically want people to have the fast path that might make tradeoffs. one might be that the networking backend doesn't work.' / 'i had referenced nyx because it - while mot TCG - cleverly just put device state in a block'"
referents: "penguin @ 16d112ea (== origin/main after fetch, 2026-08-27); qemu @ 56554982 (2026-08-20, VERSION 11.0.50); measured against rehosting/penguin:v3.1.14 (sha256:6bf719e2b8ab0894c5082d087f30af5601929ab62c3fc53989ecc24d3a72b2f0)"
---

# A separate fast reset path for fuzzing

## The recommendation, first

**Port LibAFL's `syx-snapshot` to our QEMU fork rather than designing something
new, and do not build it on `fork()`.**

`syx-snapshot` (in `qemu-libafl-bridge`) is Nyx's device-state-in-a-block idea
already carried across to full-system TCG, by people who had to make it work.
It is 1,743 lines across four C files and four headers, and it touches exactly
three upstream files to install its hooks. It is a port, not a research project.

The three things it does are the three things this problem needs:

1. **Device state into a flat memory block.** `device_save_kind()`
   (`libafl/syx-snapshot/device-save.c:38`) walks `savevm_state.handlers`,
   **skips every `se->is_ram` handler**, and writes the rest through a
   `QIOChannelBufferWriteback` into a plain `uint8_t*`. Restore is a read back
   from memory. That is exactly the Nyx trick, and it keeps QEMU's own vmstate
   descriptors — so it stays correct for devices we did not write and did not
   think about.
2. **RAM by dirty pages, not by volume.** A root snapshot holds a full RAM copy
   in host memory; thereafter only pages written since the snapshot are
   restored.
3. **Block writes into an in-memory COW cache** (`syx-cow-cache.c`), so the disk
   rolls back without touching the qcow2.

Everything below is why, and what it costs.

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

**Result 3 — the invisible cost is about as large as the visible one, and it is
TCG-specific.** Every `loadvm` goes through `vm_stop(RUN_STATE_RESTORE_VM)`
(`qemu/system/penguin.c:266`), and QEMU registers a vm-change-state handler that
turns that state into a **full `tb_flush`**:

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
is not a fuzzing loop. That is the number a fast path has to beat, and the
`tb_flush` half of it is a second, independent reason to bypass
`load_snapshot()` rather than optimise it: a mechanism that never enters
`RUN_STATE_RESTORE_VM` keeps the translation cache warm for free.

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

One honest caveat: LibAFL chose *not* to reuse this bitmap. `syx-snapshot`
installs its own hooks (`accel/tcg/cputlb.c`, `system/physmem.c`) recording
dirty pages *with their previous contents*, which supports nested/incremental
snapshots that a bare bitmap cannot. So there are two viable routes — reuse the
existing `DIRTY_MEMORY_MIGRATION` bitmap (no new hooks, but the bitmap's
lifecycle is owned by the migration subsystem and enabled globally), or take
syx's dedicated hooks. **Recommend syx's**, on the grounds that it is the one
that has actually been made to work.

## Do not build this on `fork()` — three verified obstacles

Luke's phrasing was "fuzzing and or forking", so forkserver designs were priced
first. All three obstacles below were checked in this fork, not assumed.

**1. The process is multithreaded, with an embedded CPython in it.** Penguin
does not run QEMU as a child process; it loads it as a library into the Python
interpreter via CFFI (`qemu_compat.py` `run()` calls `lib.qemu_init()` then
`lib.qemu_main_loop()`). Observed thread set of a live run, sampled from
`/proc/<pid>/task/*/comm`:

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

Obstacles 2 and 3 dissolve if the fast path runs with `plugins.vpn.enabled:
false` — which Luke has sanctioned. **Obstacle 1 does not dissolve**, and it is
by itself sufficient. In-process incremental restore avoids all three, and
syx-snapshot is in-process. This is the main place where the draft declines
part of the brief: *forking* is the wrong mechanism here, *fast reset* is the
right one, and syx gives the second without the first.

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
2. **Port `syx-snapshot`** into the fork under its own directory. Port delta is
   QEMU 9.1.1 → 11.0.50: headers moved (`sysemu/` → `system/`,
   `include/exec/ram_addr.h` → `include/system/ram_addr.h`) and the `cputlb`
   store paths have changed shape. Hook edits land in three upstream files
   (`accel/tcg/cputlb.c`, `system/physmem.c`, `block/block-backend.c`).
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

`run_manifest.yaml` is the natural vehicle. **Referent warning:** it is
described in `src/penguin/run_summary.py:44` as the sibling of `summary.json`,
but grep finds no writer for it anywhere in the tree at `16d112ea` — it is the
`scoregate` lane's in-flight work, not a landed artifact. Coordinate with that
lane rather than inventing a second manifest, and do not assume it exists.

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

0. **Port gate (small, decides everything).** Build `syx-snapshot` against
   `56554982` with the hooks stubbed out, and get `device_save_all()` /
   `device_restore_all()` round-tripping on one arch. If QEMU 9→11 vmstate drift
   makes the device half painful, that is known before any RAM work.
1. **Device block only.** `penguin_fastsnap_*` entry points; restore devices
   from the block, RAM still by `load_snapshot`. Measures the device half in
   isolation against the ~94 ms fixed floor.
2. **RAM by dirty pages.** Port the `cputlb`/`physmem` hooks and the root
   snapshot. This is where the win is, and where the `tb_flush` avoidance
   arrives (hand-invalidate TBs for dirty pages only; never enter
   `RUN_STATE_RESTORE_VM`).
3. **Block COW cache.** `syx-cow-cache` so disk writes roll back in memory.
4. **Host surface + fidelity declaration.** `core.fastsnap`, the `FastSnap`
   pyplugin, the vpn-disabled precondition, and the manifest fields — with the
   declaration landing *in the same slice as the mode*, never after it.
5. **A real fuzzing loop on top.** Out of scope here; it is what this substrate
   is for, and it should be its own draft.

Slices 0–2 are the research content. Re-run
`penguin/analysis/fastsnap/run_bench.py` against each to keep the comparison
honest — the harness measures both halves, and the `tb_flush` half is the one a
naive benchmark will claim we already fixed.

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
- **Does anything in the IGLOO device set resist device-block save/restore?**
  The modeled pseudofiles and `igloo` platform devices have vmstate
  descriptors of our own authorship, and `device_save_kind` supports a denylist.
  Unknown until slice 0.
- **Upstream tracking.** `qemu-libafl-bridge` is at QEMU 9.1.1; we are at
  11.0.50. A port is a fork of a fork. Is it worth carrying the delta, or should
  the ported files be treated as ours from day one? Recommend the latter — the
  file count is small and the alternative is a permanent rebase tax.
