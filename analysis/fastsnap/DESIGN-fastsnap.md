# Recommendation: `fastsnap`, an in-process reset armed on command

Follow-on to `THROUGHPUT.md` and `ALLOWLIST.md`. Draft 45 recommended porting
the device half of LibAFL's `syx-snapshot` and pairing it with QEMU's own dirty
bitmap. That recommendation stands, but it was a shape, not a design. This is
the design, built and measured end to end in the quarantined Slice 0 tree.

**Everything below is measured on a running QEMU, not projected.** The numbers
that came from arithmetic were wrong by 100x — see "What building it changed".

## The mechanism

Two calls. Neither goes through the migration framework; neither touches
`savevm`/`loadvm`; neither adds anything to TCG's execution path.

```
take():                                     restore():
  arm QEMU's dirty log (once)                 word-wise sweep of the dirty bitmap:
  memcpy all guest RAM -> host baseline         for each non-zero word, xchg it to 0
  clear the dirty bitmap                        for each set bit: memcpy 4 KB from
  device_save_kind(<set>) -> block                baseline; tb_invalidate_phys_range()
                                              physical_memory_dirty_bits_cleared()
                                              device_restore_all(block)
```

### Three choices, each of which is the whole design if you get it wrong

**1. A full baseline copy, not copy-on-write.** Knowing *which* pages are dirty
does not give you their *pre-dirty contents*, so a COW cache needs a hook on
first write — which is precisely the `cputlb.c` tax the design exists to avoid.
Buying one guest-RAM-sized host allocation is what keeps TCG's hottest path
untouched and the unarmed cost at zero. `syx-snapshot` pays the hook; we pay
the RAM.

**2. `tb_invalidate_phys_range()` per restored page, never
`vm_stop(RUN_STATE_RESTORE_VM)`.** The latter is what `accel/tcg/tcg-all.c:88`
turns into a full `tb_flush`, measured in this lane at **≥152 ms** — about half
the real cost of today's restore, and invisible to a restore-latency benchmark.
Omitting invalidation entirely is worse than slow: the guest keeps executing
translations of code that has been rolled back. `system/physmem.c:3144` gates
the same call on `DIRTY_MEMORY_CODE`, so only pages actually holding code pay.

**3. A word-wise bitmap sweep, not a per-page walk.** This is the one that
building it caught. See below.

## Cost, measured

512 MB guest, `-M virt`, armel payload. `take()` is **~295 ms** (≈0.58 ms/MB,
dominated by the baseline copy) and is paid **once per snapshot**, not per
iteration. `restore()`:

| dirty pages | Tier 0 (all 17 sections) | Tier 1 (`{cpu,timer}`) |
|---|---|---|
| 16 (64 KB) | 0.777 ms → 1,286/s | **0.054 ms → 18,430/s** |
| 64 (256 KB) | 0.814 ms → 1,229/s | 0.071 ms → 14,088/s |
| 256 (1 MB) | 0.889 ms → 1,125/s | 0.159 ms → 6,288/s |
| 1,024 (4 MB) | 1.207 ms → 828/s | 0.478 ms → 2,094/s |
| 4,096 (16 MB) | 3.172 ms → 315/s | 2.367 ms → 422/s |
| 16,384 (64 MB) | 16.85 ms → 59/s | 17.78 ms → 56/s |

RAM costs **~0.42 µs/page** (memcpy + invalidate). Arming costs 0.20 ms once;
disarming 0.17 ms; the steady-state armed tax is below a ±5% noise floor.

The two halves cross over around 1,000 dirty pages: below it the device block
dominates and the allowlist is the lever; above it, RAM dominates and the
allowlist buys nothing. **Working-set size, not iteration count, decides which
tier is worth using.**

## What building it changed

`ALLOWLIST.md` priced a reset at ~0.07 ms by adding up components. Assembled,
the first working version cost **5.2 ms regardless of dirty-page count** — a
75x error, and it was not in any component. `physical_memory_get_dirty_flag()`
per page and `physical_memory_test_and_clear_dirty()` over a range are both
**O(total RAM)**: one atomic per page, 131,072 of them for 512 MB, whether 16
pages are dirty or 16,000. The whole design collapsed to ~190 resets/s.

`migration/ram.c:940` shows the fix: `xchg` whole words of
`ram_list.dirty_memory[]` and skip the zero ones — 2,048 words for 512 MB —
then call `physical_memory_dirty_bits_cleared()` to re-arm `TLB_NOTDIRTY`. That
call is exported (`include/system/physmem.h:40`), so **the RAM half needs no
new QEMU hook at all.** `FASTSNAP_RESET_SLOWSCAN=1` still reproduces the naive
version, so the cost of getting this wrong stays measurable rather than
asserted.

The re-arm is not optional and its absence is silent. The sweep was exercised
by dirtying pages from the *host*, which reaches the bitmap without going
through `TLB_NOTDIRTY` — so a separate control resumes the guest for 200 ms
after a sweep and checks the next sweep still sees its writes (65 pages: 64
probe + 1 counter). **This is the exact control `syx-snapshot`'s own tracker
fails**, at 0/64 pages, measured earlier in this lane. Without it, every
iteration after the first restores an incomplete set.

## Tiers, mapped to the use cases

**Tier 0 — full device block. The default.** ~0.8–1.2 ms. Safe: every device
section is restored, so no allowlist can be wrong. Serves *device-model
inference* and *snapshot-and-poke* completely, and in-process fuzzing at
~1,000/s.

**Tier 1 — allowlisted device block. Opt-in.** 0.05–0.5 ms. 3–14x on top of
Tier 0 for small working sets. Requires the audit below, because a
diff-derived allowlist is a lower bound, not a proof.

**Tier 2 — parallelism (`fork()`).** The only way past the per-instance
ceiling, which is guest emulation speed (~117 MIPS). **Now much less urgent:**
draft 45 reached for fork because per-instance was 3 iter/s; at thousands/s,
use cases B and C never need it and A only needs it for large campaigns. Still
blocked on penguin's embedded CPython — an architectural choice of penguin's,
not a QEMU constraint (`tests/qtest/fuzz/fuzz.c:232` calls
`rcu_enable_atfork()`).

### Projected exec/s per use case

Reset is measured; guest work is from the measured 117 MIPS; the sum is
arithmetic.

| use case | working set | reset | guest | exec/s |
|---|---|---|---|---|
| A. packet parse, 10k insn | 16–256 pages | 0.056–0.18 (T1, vCPU-thread) | 0.09 | **3,700–6,850** |
| A. same, main-loop driven | 16–256 pages | 0.10–0.22 | 0.09 | 3,200–5,200 |
| A. packet parse, 10k insn | 16–256 pages | 0.78–0.89 (T0) | 0.09 | ~1,100 |
| A. deeper parse, 100k insn | 1,024 pages | 0.48 (T1) | 0.85 | ~750 |
| B. device-model inference | any | 0.8 (T0) | ~0 | ~1,000, vs a 20–30 s reboot |
| C. snapshot-and-poke | 16–256 pages | 0.05–0.9 | — | 0.05–0.9 ms round trip, vs ~250 ms |

Against today's ~3 iter/s for a full-VM-restore loop: **~350–2,000x for
fuzzing, ~4 orders of magnitude for device-model inference, and
snapshot-and-poke becomes interactive.**

## The host loop: put it on the vCPU thread, keep Python

`DESIGN` named host-loop overhead as the thing most likely to spoil Tier 1.
Measured, it does not — but the reason is not the one I expected.

**Crossing into Python is nearly free.** CFFI on this host, both directions:

| crossing | cost |
|---|---|
| Python → C, no-op | 0.00033 ms |
| Python → C, one arg + return | 0.00045 ms |
| C → Python callback, trivial | 0.00039 ms |
| C → Python callback, handler-shaped body | 0.00059 ms |

**~0.6 µs against a 56 µs iteration: about 1%.** Batching iterations into C to
avoid the interpreter would buy nothing. Input generation and triage should
stay in Python, where they belong.

**Crossing threads is what costs.** Penguin runs the vCPU in its own thread, so
a loop driven from the main loop pays a pause/resume handshake per iteration.
Measured as a composite (`[reset + write 1 KB input]`, because the parts
mislead — `address_space_write` reads as 0.26 ms cold and 0.0001 ms warm, and a
reset invalidates the input page between writes):

| dirty pages | vCPU-thread | main-loop | handshake |
|---|---|---|---|
| 16 | **0.0559 ms** | 0.1029 ms | +0.047 ms (84%) |
| 256 | **0.1809 ms** | 0.2190 ms | +0.038 ms (21%) |
| 1,024 | **0.5717 ms** | 0.6096 ms | +0.038 ms (7%) |

The handshake is a flat ~0.04 ms, so it hurts exactly where Tier 1 is supposed
to win. **The loop belongs in a guest hypercall handler**, which runs on the
vCPU thread with the guest already trapped and quiesced — no handoff, and
requirement 1 (quiesce before capture) satisfied for free.

So the C wrapper is worth writing, but for keeping the loop off the main loop,
not for keeping it out of Python:

```c
/* setup, from Python, once per campaign */
bool penguin_fastsnap_arm(const char *const *device_allowlist);
bool penguin_fastsnap_take(void);
void penguin_fastsnap_release(void);

/* registered against a guest hypercall number; runs on the vCPU thread */
bool penguin_fastsnap_on_iteration(penguin_fastsnap_cb_t cb, void *opaque);
```

The guest harness needs one line — a hypercall at end-of-iteration. It needs no
loop of its own, because the restore puts its PC back at the snapshot point.

**Integration hazard.** The handler restores the `cpu` section *while running on
that vCPU*, so the normal hypercall return path — write a result register,
resume after the trap — would clobber the freshly restored PC. The handler must
force re-entry with the restored state (`cpu_loop_exit()`) rather than return
normally, or exclude `cpu` from the block and set registers by hand. This is
the most likely way to get a subtly wrong iteration that still looks like it
works.

**Caveat on the Python numbers.** 0.6 µs is the floor for the crossing itself,
measured against a bare `ffi.callback`. Penguin's actual pyplugin dispatch adds
a plugin-manager hop and argument marshalling on top. Even at 50x it is 0.03 ms
— comparable to reset, not dominant — but it is unmeasured in penguin proper
and worth confirming there.

## What it abandons

R2 permits tradeoffs; these are the ones taken, and they should be declared at
`arm()` time and refused rather than silently degraded:

- **Networking.** The `vhost-user-vsock` backend is a separate process and
  cannot be rolled back. The fast path requires `vpn.enabled: false` — which
  the lane already established also removes the `MAP_SHARED` guest RAM that
  blocked other options.
- **Disk writes.** A guest write to the qcow2 overlay is not rolled back.
  v1 stance: detect and fail loudly, do not port syx's block COW cache yet.
- **Host-visible time.** The `timer` section rolls back guest time; host-side
  chardev and timer state does not. Acceptable for A and B; worth stating.
- **Anything the allowlist omits, in Tier 1.**

## Correctness requirements

1. **Quiesce before capture and before restore.** A running vCPU has not
   written `env` back under TCG; capturing anyway silently yields stale
   registers. This cost two false results in this lane.
2. **Re-arm after every sweep** (`physical_memory_dirty_bits_cleared`).
3. **Invalidate TBs per restored page.**
4. **Audit Tier 1.** Every Nth iteration, restore the full device block instead
   and compare the resulting state to the allowlisted restore. This converts
   the allowlist from an unproven configuration into a sampled, continuously
   checked cache of a derivation. Without it, Tier 1 should not ship.

## Integration in penguin

Export alongside the existing `penguin_save_snapshot` in `qemu/system/penguin.c`
(same visibility-default C ABI, driven over CFFI):

```
bool penguin_fastsnap_arm(const char **device_allowlist);
bool penguin_fastsnap_take(void);
bool penguin_fastsnap_restore(void);
void penguin_fastsnap_release(void);
```

Unlike `penguin_schedule_snapshot`, these must **not** go through
`aio_bh_schedule_oneshot`: the callers that matter (a syscall hook, a
`hyperfile.py` device handler) are already at a point where the guest has
trapped and the vCPU is quiesced, which is exactly where a fuzzing loop wants
to reset. The API should assert that rather than assume it.

Host side: a `fastsnap` pyplugin exposing `arm/take/restore`, following
`pyplugins/core/snapshot.py`'s existing shape. `hyperfile.py:470-560` already
dispatches every modeled device access to a host-side Python handler, so use
case B's arming point and variation point both exist in-process today.

## Slices

0. ✅ *Done.* Device half ports and round-trips; RAM half priced; the full
   reset built and measured; four controls.
1. Export the C ABI in our fork behind a build option; `fastsnap` pyplugin;
   Tier 0 only. Acceptance: an in-process loop resets ≥500/s on a real target
   and a full-restore comparison matches every iteration.
2. Measure the RAM term on a real firmware target (the one number still
   synthetic) and the host-loop overhead (below).
3. Tier 1 plus the audit, with the loop in a hypercall handler. Acceptance: 1,000 iterations with per-N audit, zero
   divergence.
4. Use case B end to end: vary a `hyperfile` handler's return across a
   candidate set, reset between trials.

## Still unmeasured

- **Penguin's own pyplugin dispatch cost.** The raw CFFI crossing is measured
  at 0.6 µs; the plugin-manager layer on top of it is not, and that measurement
  belongs in penguin proper rather than the Slice 0 tree.
- **The RAM term on a real target.** The sweep costs 0.42 µs/page; how many
  pages a real firmware iteration dirties is target-specific and unknown. The
  table is indexed by dirty pages precisely so a real target only needs its own
  number to read its answer off.
- **Allowlist sufficiency** on anything but the synthetic payload (R10).
- **Memory cost**: one guest-RAM-sized host allocation per live snapshot.

## Reproduce

```
cd projects/fastsnap/slice0/qemu-build/build && ninja qemu-system-arm
FASTSNAP_RESET=1 ./qemu-system-arm -M virt -m 512 -display none -serial null \
  -kernel ../../ramprobe/payload5.bin          # add FASTSNAP_RESET_FULLDEV=1
                                               # or FASTSNAP_RESET_SLOWSCAN=1
```
