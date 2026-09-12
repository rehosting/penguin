# Where `device_restore_all()` spends 841 us

Measured 2026-09-11 on `workspace/fastsnap` in `qemu_builder`, `qemu-system-aarch64
-M virt -cpu cortex-a57 -m 128`, 17 device sections / 63,029 bytes.
Host: x86-64, Linux 5.15.

**Headline.** The cost is neither per-section fixed overhead nor "bytes". It is
**per vmstate field element, at ~25-35 ns each**. 95.8% of the block's bytes are
deserialised one byte at a time through three out-of-line calls
(`qemu_get_byte` -> `qemu_peek_byte` + `qemu_file_skip`), and every element pays
an indirect `info->get()` call plus `qemu_file_get_error()`. `post_load` hooks --
the part that is actually device semantics -- are **1% of the restore**.
Two devices are 91% of it, for reasons that are about element *count*, not size.

---

## 1. Method, and the control

Instrumentation lives in `qemu_builder/src/fastsnap/selftest.c`, gated on
`FASTSNAP_PROFILE`, marked TEMPORARY, uncommitted. It runs at machine-init-done
(BQL held, vCPUs never started), and `nix/fastsnap-selftest.nix` was extended to
install the built binary so each measurement runs in a **fresh process**.

Each number is the **median of 31-41 samples, each sample the mean of a 20-op
batch**, after 60 warm-up ops. `clock_gettime(CLOCK_MONOTONIC)`. p10/p90 spread
on `restore_all` is +/-1.5%.

### The control: do the per-section times reconstruct the whole call?

Per-section marginal cost = (restore of an allowlist block containing only that
section) - (restore of an empty block), each measured in its own fresh process
with its own baseline.

```
per-call fixed cost (empty block)      1,180 ns
sum of 17 per-section marginals      848,231 ns
predicted total                      849,411 ns
measured device_restore_all(all)     840,933 ns
                                     ------- 101.0 %
```

**The control passes at 101.0%.** It could have failed, and it did: the first
version of this measurement reported 114%, and a leave-one-out cross-check came
out at **-210%** with wildly negative marginals. That was not noise -- it was
section 2/3 (`pflash_cfi01`) getting 12x slower over the course of the run
(section 5 below). Only the fresh-process-per-measurement design makes the sum
reconstruct the total.

Second, independent corroboration of the file-layer share: a standalone loop of
63,029 `qemu_get_byte()` calls costs 364.6 us (43% of 841 us), and callgrind
independently puts `qemu_peek_byte` + `qemu_get_byte` + `qemu_file_skip` at
**39.9% of the restore's instructions**. Two different instruments, same answer.

---

## 2. Per-section breakdown of `device_restore_all()`

| # | section | bytes | restore (ns) | share | ns/byte | save (ns) |
|---|---|---:|---:|---:|---:|---:|
| 12 | `0000:00:01.0/virtio-net` | 46,185 | **532,674** | 62.7% | 11.5 | 922,965 |
| 6 | `arm_gic` | 9,914 | **241,587** | 28.4% | 24.4 | 493,745 |
| 5 | `cpu` | 5,688 | **50,750** | 6.0% | 8.9 | 74,121 |
| 2 | `pflash_cfi01` | 84 | 5,281* | 0.6% | 62.9* | 1,325 |
| 3 | `pflash_cfi01` | 84 | 5,247* | 0.6% | 62.5* | 1,162 |
| 4 | `cpu_common` | 37 | 2,247 | 0.26% | 60.7 | 878 |
| 7 | `pl011` | 173 | 1,794 | 0.21% | 10.4 | 2,813 |
| 1 | `slirp` | 155 | 1,432 | 0.17% | 9.2 | 1,714 |
| 15 | `fw_cfg` | 99 | 1,308 | 0.15% | 13.2 | 1,392 |
| 13 | `pl061` | 108 | 1,266 | 0.15% | 11.7 | 1,921 |
| 9 | `0000:00:00.0/gpex_root` | 317 | 1,189 | 0.14% | 3.8 | 862 |
| 8 | `pl031` | 75 | 911 | 0.11% | 12.1 | 1,295 |
| 11 | `PCIBUS` | 45 | 617 | 0.07% | 13.7 | 978 |
| 14 | `gpio-key` | 35 | 550 | 0.06% | 15.7 | 705 |
| 0 | `timer` | 48 | 488 | 0.06% | 10.2 | 692 |
| 16 | `virt_acpi_build` | 35 | 466 | 0.05% | 13.3 | 263 |
| 10 | `PCIHost` | 30 | 444 | 0.05% | 14.8 | 653 |
| | *per-call fixed* | - | 1,180 | 0.14% | - | 12,117 |
| | **total** | 63,029 | **840,933** | | 13.3 | **1,538,724** |

\* `pflash_cfi01`'s solo figure is its *first-restore* cost. It grows without
bound -- see section 5.

**Two devices are 91.1% of the restore.** `virtio_load` alone is 64.7% of the
restore's instructions (callgrind, inclusive).

Save control: fixed 12,117 + sum of marginals 1,507,484 = 1,519,601 vs measured
`device_save_all` 1,538,724 -> **98.8%**. Save is ~1.8x restore and has the same
shape (same two devices dominate).

---

## 3. Bytes or fixed overhead? Neither -- it is per *element*

**Per-section fixed cost is ~1% of the call.** Extrapolating the smallest
sections (`PCIHost` 30 B / 444 ns, `virt_acpi_build` 35 B / 466 ns) to zero bytes
gives ~300-400 ns of fixed cost per section; 17 of those is ~6 us, 0.7% of the
total. The per-*call* fixed cost (QEMUFile + channel construction,
`cpu_synchronize_all_post_init`, EOF) is 1.18 us, 0.14%. **Shrinking the number
of sections does nothing. Neither does the per-call setup.**

But it is not "bytes" either. The ns/byte column spans 3.8 (`gpex_root`) to 24.4
(`arm_gic`) -- a 6.4x range -- and the cheap end is exactly the section whose
bytes arrive as one `VMSTATE_BUFFER` (256 bytes of PCI config space) rather than
as individual fields.

The unit of cost is **one vmstate field element**. Per restore (callgrind call
counts, 63,029 bytes):

| | calls per restore |
|---|---:|
| `qemu_peek_byte` | 63,546 (**1.008 per byte of block**) |
| `qemu_get_byte` | 60,410 (**95.8% of bytes read one at a time**) |
| `qemu_file_skip` | 61,527 |
| `qemu_get_be32` | 11,911 |
| `qemu_get_buffer` | 1,085 (covers the other ~2,600 bytes) |
| `vmstate_field_exists` | 15,522 (field visits) |
| `qemu_file_get_error` | 24,876 |
| **instructions per byte** | **92** |

`vmstate_load_vmsd()` runs `for (i = 0; i < n_elems; i++) { vmstate_load_next();
vmstate_load_field(); qemu_file_get_error(); }`, and `vmstate_load_field()` is an
indirect call to `field->info->get()`. So a `VMSTATE_UINT8_ARRAY` of N bytes
costs N trips through ~8 function calls. That is the 24.4 ns/byte on `arm_gic`.

Why the two big sections are big -- both are element *counts*, not data:

- **`arm_gic` (241 us).** `vmstate_gic` has
  `VMSTATE_STRUCT_ARRAY(irq_state, GICState, GIC_MAXIRQ /* 1020 */, 1,
  vmstate_gic_irq_state, ...)`, and `vmstate_gic_irq_state` is 7 one-byte
  fields. 1020 nested `vmstate_load_vmsd()` recursions x 7 element loops = 7,140
  single-byte element visits, before the `VMSTATE_UINT8_ARRAY(irq_target, ...,
  1020)` and the 2D priority arrays.
- **`virtio-net` (533 us).** `vmstate_virtio_virtqueues`,
  `vmstate_virtio_ringsize` and `vmstate_virtio_packed_virtqueues` each carry
  `VMSTATE_STRUCT_VARRAY_POINTER_KNOWN(vq, VirtIODevice, VIRTIO_QUEUE_MAX /*
  1024 */, ...)`. The device has 3 live queues on this board; **1024 are
  serialised every time**, each a nested vmsd of 5 fields. That is ~15k element
  visits and ~24 KB of the 46 KB section.

### Floor measurements (same 63,029-byte block)

| operation | ns | vs restore |
|---|---:|---:|
| `memcpy` of the block | 1,959 | 1x |
| one `qemu_get_buffer` of the block | 4,961 | 2.5x |
| 63,029 x `qemu_get_byte` | 364,583 | 186x |
| `device_restore_all` | 840,933 | **429x** |

`qemu_get_byte` is **73x** more expensive per byte than `qemu_get_buffer`.

### `post_load` is not the cost

Inclusive instruction share, per restore: `cpu_post_load` 0.85%,
`cpu_common_post_load` 0.16%, `pci_device_load` 0.12%; `gic_post_load` and the
virtio post-loads fall below the 0.1% threshold. **All device `post_load`
semantics together are ~1% of the restore.** 99% is the walk.

### Hypothesis tested and killed: memory-region transactions

Plausible story: PCI/pflash `post_load` hooks commit memory-region transactions,
each regenerating flatviews. Test: bracket the whole `device_restore_all()` in
`memory_region_transaction_begin()/commit()`, which collapses every nested
commit into one.

```
bracketed (measured 1st)   852,390 ns      plain (measured 2nd)   850,780 ns
plain     (measured 3rd)   863,843 ns      bracketed (measured 4th) 876,706 ns
ORDER CONTROL: bracketed is 1.00x and 1.01x of the plain run next to it
empty begin/commit pair: 8 ns
```

**No effect.** Flatview regeneration is not in this path. The order control
(measured in both orders) is what makes that a real negative rather than a
drift artifact.

---

## 4. `device_save_all()` (1,539 us) -- same shape, one extra pure-waste term

Callgrind self-instruction share of a save:

| function | share | what it is |
|---|---:|---|
| `add_to_iovec` | 22.7% | per-byte iovec coalescing under `qemu_put_byte` |
| `vmstate_save_vmsd_v'2` | 17.4% | the element walk |
| `qemu_put_byte` | 14.2% | the byte-at-a-time writer |
| `vmstate_save_field_with_vmdesc'2` | 10.2% | |
| `qemu_file_transferred` | 8.8% | **vmdesc bookkeeping, and fastsnap passes vmdesc = NULL** |
| `vmsd_can_compress` (+`'2`) | 10.6% | **ditto** |
| `vmstate_n_elems` | 2.5% | |

`vmstate_save_field_with_vmdesc()` calls `qemu_file_transferred(f)` **twice per
element** to compute a byte count it then hands to `vmsd_desc_field_end()`, which
returns immediately when `vmdesc == NULL`. And `vmsd_can_compress(field)` is
evaluated **inside the element loop** (`migration/vmstate.c:675`), recursing over
all child fields for a `VMS_STRUCT`, purely to size a JSON array that is never
written. `device_save_kind()` always passes `vmdesc = NULL`
(`qemu_savevm_save_one` -> `vmstate_save(f, se, NULL, errp)`).

**~19% of save instructions is JSON-vmdesc bookkeeping fastsnap never consumes.**

Buffer management is *not* a significant term: `save_empty` (which still does
both 32 MB `g_new`/`g_new0` and the QEMUFile) is 12.1 us, and the alloc+
first-touch cost measured on its own is 46.5 us -- together ~3% of 1,539 us.
Worth fixing eventually; not the problem.

---

## 5. Separate bug found: restore cost grows without bound

`device_restore_all()` gets monotonically slower the more times it is called.

```
round  0  after      0 restores   840,933 ns   rss 39,396 kB
round  7  after  6,160 restores   968,725 ns   rss 40,072 kB
round 13  after 11,440 restores 1,053,828 ns   rss 40,812 kB     (+25%)
```

Per-section drift scan (10 rounds x 480 restores, fresh process each) isolates it
to **`pflash_cfi01`, both instances**:

```
section  2 pflash_cfi01   first 6,461 ns  ->  last 77,010 ns   (+1,092%)  rss +260 kB
section  6 arm_gic        first 242,641   ->  last 244,438     (flat)
section 12 virtio-net     first 536,288   ->  last 528,697     (flat)
section  5 cpu            first 52,261    ->  last 53,031      (flat)
```

Cause, `hw/block/pflash_cfi01.c`:

```c
static int pflash_post_load(void *opaque, int version_id)
{
    PFlashCFI01 *pfl = opaque;
    if (!pfl->ro) {
        pfl->vmstate = qemu_add_vm_change_state_handler(postload_update_cb, pfl);
    }
    return 0;
}
```

Every restore appends one entry to the global VM change-state handler list and
never removes it. `qemu_add_vm_change_state_handler()` inserts in priority order
by walking the list, so cost is O(n) per restore and O(n^2) overall -- matching
the exactly-linear growth and the ~60 bytes/restore/instance RSS.

This is a correctness problem, not only a speed one: after N resets, every
`vm_stop`/`vm_start` invokes `postload_update_cb` N times per pflash device.

It is also a **class**, not one bug: any device whose `post_load` registers a
handler, timer, notifier or BH assumes `post_load` runs once per machine
lifetime. fastsnap violates that assumption millions of times. `PCIHost` showed a
smaller drift (1,636 -> 2,280 ns) that was not chased down.

---

## 6. Is a 2-5x available? Yes, and more

Ordered by (win / risk). None of these has been implemented or measured -- the
estimates are from the instruction shares and floor measurements above.

**O1. Inline the QEMUFile scalar getters.** `qemu_peek_byte`, `qemu_get_byte`,
`qemu_file_skip`, `qemu_get_be16/32/64` are out-of-line in
`migration/qemu-file.c`, and `qemu_peek_byte` carries two live `assert()`s
(QEMU does not define `NDEBUG`). Making them `static inline` in `qemu-file.h`
with a single bounds check turns 3 calls + 2 asserts per byte into a few
instructions.
*Evidence:* 39.9% of restore instructions; 364.6 us measured for 63,029
sequential `qemu_get_byte` calls versus 5.0 us for the same bytes via
`qemu_get_buffer` (73x). *Estimate:* restore 841 -> ~520 us (**1.6x**); save
benefits the same way via `qemu_put_byte`/`add_to_iovec` (37% of save
instructions). *Risk:* low, local, format-neutral, helps live migration too.

**O2. Skip vmdesc bookkeeping when `vmdesc == NULL` (save only).** Hoist
`vmsd_can_compress()` out of the element loop and skip the
`qemu_file_transferred()` pair when there is no JSON writer.
*Evidence:* 19.4% of save instructions. *Estimate:* save 1,539 -> ~1,250 us.
*Risk:* very low -- pure dead work when `vmdesc == NULL`; a candidate to send
upstream.

**O3. Bulk-load primitive arrays.** In `vmstate_load_vmsd()`, when a field is a
plain `VMS_ARRAY` of a primitive with no `VMS_POINTER`/`VMS_STRUCT`/`VMS_ALLOC`/
`field_exists`, read all `n_elems` with one `qemu_get_buffer()` and byte-swap in
place instead of N trips through `vmstate_load_next` / `vmstate_load_field` /
`info->get` / `qemu_file_get_error`. Byte-identical stream.
*Evidence:* `arm_gic` is 28.4% of the restore and is almost entirely
`VMSTATE_UINT8_ARRAY` / `_2DARRAY` / `VMSTATE_STRUCT_ARRAY` of one-byte fields at
24.4 ns/byte, against a 0.06 ns/byte `qemu_get_buffer` floor. *Estimate:* most of
`arm_gic`'s 241 us and part of `cpu`'s 51 us. *Risk:* moderate -- needs care for
`VMSTATE_STRUCT_ARRAY` (the gic case needs the struct-of-primitives variant too).

**O1 + O2 + O3 together plausibly land restore near 300 us and save near 900 us
-- 2.8x and 1.7x.** That is the "2-5x" the question asked about, from three
local, format-preserving changes.

**O4 (the real ceiling, bigger design call). Cache a scatter/gather plan.**
`post_load` is 1% of the restore, so 99% of the walk is bookkeeping that produces
the same answer every iteration: the same (host address, length, swap width)
triples, in the same order. Record that plan during the first save; restore
becomes a gather-memcpy over ~15k runs plus the `post_load` hooks. A validity
check is required (varray counts and `needed` subsection predicates are functions
of guest state, so the plan must be invalidated when the section's byte length or
varray counts move) with fallback to the generic walk.
*Evidence for the ceiling:* whole-block `memcpy` is 2.0 us, `post_load` is ~8 us.
*Estimate:* tens of us -- **15-30x** -- not 2-5x. *Risk:* high; this is a design,
not a patch.

**O5. Don't serialise 1,024 virtqueues.** `virtio_load` is 64.7% of the restore
because `VIRTIO_QUEUE_MAX` is baked into three vmsd subsections. Fixing this
changes the migration stream format, so it cannot go upstream as-is -- but
fastsnap's block is never read by another QEMU. Out of scope for a local
optimization; noted because it is where 40%+ of the restore actually is.

**O6. Fix the `pflash_post_load` accumulation (section 5).** Not an optimization
-- a prerequisite. Either make `post_load` idempotent for re-entry, or have
`device_restore_all()` snapshot and restore the VM change-state handler list
around the load. Must be settled before any restore-rate number is meaningful
over a long fuzzing run.

---

## 7. What this does NOT establish

- **Nothing was measured on real firmware.** The 0.402 ms figure in the brief is
  untouched here. The per-element cost model should transfer; the *section mix*
  will not -- a real firmware target has no `-M virt` virtio-net or GICv2 of this
  shape, and those two are 91% of what was measured.
- **No optimization was implemented or measured.** Every win figure in section 6
  is derived from instruction shares and floor micro-benchmarks, not from a
  patched build. O1's estimate in particular assumes the inlined getter
  approaches the `qemu_get_buffer` per-byte rate, which is untested.
- **Measured at machine-init-done, vCPUs never started.** Cross-check: the
  selftest's phase-2 scheduled restore (VM running, via the BH path) reports
  891 us against this harness's 841 us -- 6% apart -- so the context difference
  is small *on this board*. It was not checked on a board where varray counts or
  `needed` subsections differ once the guest has run.
- **One host, one run each.** No cross-machine or cross-build variance; medians
  with p10/p90 only.
- **The `PCIHost` drift (1,636 -> 2,280 ns) was observed but not diagnosed.**
- **Whether `post_load` re-entry is otherwise safe was not audited.** Only
  `pflash_cfi01` was traced; the general hazard class is flagged, not enumerated.

## 8. Reproducing

Instrumentation is uncommitted and env-gated in
`qemu_builder/src/fastsnap/selftest.c` (block marked `TEMPORARY
INSTRUMENTATION`), plus an installPhase addition in
`qemu_builder/nix/fastsnap-selftest.nix` that copies the binary to
`$out/bin`. `FASTSNAP_PROFILE` unset => nothing runs; the selftest passes
unchanged.

```sh
nix build .#checks.x86_64-linux.fastsnap-selftest
Q=./result/bin/qemu-system-aarch64; A="-M virt -cpu cortex-a57 -m 128 -display none"
FASTSNAP_SELFTEST=1 FASTSNAP_PROFILE=list                 $Q $A   # section names
FASTSNAP_SELFTEST=1 FASTSNAP_PROFILE=all                  $Q $A   # totals
FASTSNAP_SELFTEST=1 FASTSNAP_PROFILE=one:12               $Q $A   # one section, fresh
FASTSNAP_SELFTEST=1 FASTSNAP_PROFILE=save:6               $Q $A
FASTSNAP_SELFTEST=1 FASTSNAP_PROFILE=raw                  $Q $A   # memcpy/get_buffer/get_byte floors
FASTSNAP_SELFTEST=1 FASTSNAP_PROFILE=mrt                  $Q $A   # transaction-bracket test
FASTSNAP_SELFTEST=1 FASTSNAP_PROFILE=drift:2 FASTSNAP_PROFILE_ROUNDS=10 $Q $A
```

`FASTSNAP_PROFILE_REPS` / `_BATCH` / `_ROUNDS` tune the sampling. Instruction
counts came from `valgrind --tool=callgrind --collect-atstart=no
--toggle-collect=fs_op_restore` (`perf` is unavailable: `perf_event_paranoid=4`).

---

# Implemented and measured

Three patches written against the recommendations above, exported into the
series as 0016/0017/0018, built, and measured with this document's own harness
on the same host in the same session. Baseline and optimised builds differ only
in those three patches; both carry identical instrumentation.

## Result: restore 1.59x, and the drift is gone

```
                      baseline (14 patches)      optimised (17 patches)
restore_all      842,631 ns (p10 836k p90 868k)  530,081 ns (p10 528k p90 531k)
restore_empty      1,127 ns                        1,187 ns
```

**1.59x.** The distributions do not overlap -- baseline p10 is above optimised
p90 -- so this is not sampling noise. The baseline also reproduces this
document's independently measured 840,933 ns to within 0.2%, which is the
cross-check that the harness itself did not change underneath the comparison.

`pflash_cfi01` restore, median per round, fresh process:

| after N restores | baseline | optimised |
|---|---|---|
| 0 | 8,795 ns | 1,905 ns |
| 1,760 | 35,901 | 1,906 |
| 4,400 | 81,249 | 1,905 |
| 7,920 | **146,903** | **1,905** |
| RSS delta | +788 kB | **0** |

**16.7x drift eliminated, and the allocation leak with it** -- flat to within
0.2% across 7,920 restores. Note the round-0 figure: the baseline was already
4.6x inflated before the drift measurement began, because the selftest's own
earlier restores had accumulated handlers.

## The patches

- **0016 `hw/block/pflash_cfi01`** -- drop an outstanding state handler before
  registering the next. Corrects the drift and the leak above.
- **0017 `migration/vmstate`** -- move the `vmsd_can_compress()` query after the
  `vmdesc == NULL` test, and take the two `qemu_file_transferred()` readings
  only when something will read the result.
- **0018 `migration/qemu-file`** -- inline the in-buffer case of the byte
  reader inside `qemu-file.c`.

## A correction to this document's framing of the pflash bug

The report above reads as though upstream leaks a handler unconditionally. It
does not. `postload_update_cb()` deletes the handler it was registered with --
but only when it *runs*, on the next run-state change. A conventional `loadvm`
resumes the VM, the callback fires, the handler goes.

fastsnap's restore deliberately never makes a run-state transition: it uses
`pause_all_vcpus()` precisely so `accel/tcg` does not flush every translation
block. **So the assumption upstream relies on is one this lane's design breaks
on purpose.** The leak is a consequence of our choice, not an upstream defect,
and 0016 is hardening for a legal-but-unusual caller rather than a bug fix.

The class is five devices wide, found by scanning every `post_load` in `hw/`
for handler, timer and BH registration: `pflash_cfi01`, `vapic` (i386),
`mac_via` (m68k), `spapr_nvram` (ppc64) and `usb/host-libusb` (a BH). Only
pflash is reachable on our ARM targets -- but **a ppc64 target would hit
`spapr_nvram`**, and nothing warns.

## What was NOT achieved

- **Not the projected 2.8x.** O1 as specified meant inlining at external call
  sites, which requires `struct QEMUFile` in a header. That is the same struct
  hoist `src/fastsnap/device-save.c` rejects in its provenance note -- "the
  single most version-fragile thing a curated patch series could carry" -- so it
  was deliberately not done. Only callers inside `qemu-file.c` are inlined;
  `vmstate-types.c` still pays one out-of-line call per byte. The remaining
  gap to 2.8x is mostly that.
- **O3 (bulk primitive-array loading) not attempted.**
- **The save side is unmeasured.** The harness's `all` mode documents
  `save_all`/`save_empty` but emitted neither, so 0017's effect is reasoned
  from instruction counts, not measured. It could be zero.
- **Not measured on real firmware.** All of this is `-M virt`, whose two
  dominant sections are board artifacts. The 1.59x should partly transfer,
  since the qemu-file change helps any scalar-heavy vmstate, but the factor
  will differ and the 0.402 ms figure remains untouched.

## Budget, if 1.59x transfers

0.402 / 1.59 = 0.253 ms device + 0.054 RAM + 0.111 guest = **0.418 ms,
~2,390 exec/s**, from ~1,760. Conditional on a transfer that has not been
measured.
