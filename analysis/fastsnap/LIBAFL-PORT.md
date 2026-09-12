# qemu-libafl-bridge on our QEMU: measured port cost

Asked because the bridge is the closest existing thing to what this lane is
building, and because the draft's statement about it is stale.

## The draft was wrong about the version gap

`DRAFT-fast-snapshot-restore.md` says the bridge is at QEMU **9.1.1**. It is at
**10.2.0** (`VERSION`, `main` @ `fb985a5619`), with a `qemu_update_v10_2_0`
branch showing active tracking. The gap to our 11.1.0 is **one release**, not
two-plus.

## The delta, and what of it is portable

Against pristine upstream `v10.2.0`:

| | |
|---|---|
| total delta | 144 files, +6864 / -219 |
| **modifications to upstream files** | **78** (+1802 / -189) |
| new files (`libafl/`, `include/libafl/`) | the remaining ~5,000 lines |

New files port for free. The 78 modified files are the cost. Replaying the
whole delta onto pristine `v11.1.0` as a single squashed commit, so git's
3-way merge has both bases:

| | |
|---|---|
| **apply cleanly** | **65 / 78** |
| conflict | 13 files, 21 hunks |

### The 13, triaged for what Penguin needs

| file | hunks | relevant? |
|---|---|---|
| `linux-user/syscall.c` | 3 | no -- user-mode; Penguin is full-system |
| `linux-user/elfload.c` | 1 | no |
| `tests/unit/rcutorture.c` | 1 | no |
| `configure`, `meson.build` | 3 | build glue |
| `target/riscv/tcg/translate.c` | 1 | arch we do not build |
| `target/i386/cpu.c` | 1 | probably not |
| `migration/savevm.{c,h}` | 2 | **already solved, see below** |
| `tcg/tcg-op-ldst.c` | 4 | **yes** -- their memory read/write hooks |
| `migration/vmstate-types.c` | 3 | **yes** -- syx-snapshot list reuse |
| `target/arm/machine.c` | 1 | **yes** -- cpreg array guard |
| `gdbstub/system.c` | 1 | maybe |

**~4 files, ~9 hunks of real work.** All three inspected are the same shape --
upstream refactored around their insertion point, so the same insertion needs
re-siting, with no design question:

- `tcg-op-ldst.c`: upstream changed `plugin_gen_mem_callbacks_i32`'s signature;
  their hook wraps that call.
- `vmstate-types.c`: upstream moved to `errp`-style error handling; their
  change (reuse an existing list element instead of allocating) re-applies
  mechanically.
- `target/arm/machine.c`: a `cpreg_array_len > 0` guard, for CPUs like Cortex-M
  with no coprocessors. Context moved; the guard does not.

### savevm.c is already resolved, and for this exact reason

Their conflict there is the **struct hoist**: they move `SaveStateEntry` out of
`savevm.c` into the header, and upstream 11.1.0 still defines it in the `.c`.

This series chose accessors over the hoist, and the argument made at the time
was that a construct whose job is to mirror a struct breaks when the struct
moves. This is upstream moving the struct. Keeping our accessors and adapting
their `device-save.c` to use them is what `src/fastsnap/device-save.c` already
is -- so this conflict is not work, it is work already done.

## Collision with Penguin's own delta

Our series modifies 34 upstream files; theirs modifies 78. The intersection is
**8 files**:

```
accel/kvm/kvm-all.c        meson.build
migration/savevm.c         migration/savevm.h
system/runstate.c          target/arm/tcg/translate-a64.c
target/arm/tcg/translate.c target/i386/kvm/kvm.c
```

Two are KVM (Penguin is TCG), two are the already-solved savevm pair, two are
build/runstate glue, and the two `translate.c` files host our hypercall helper
and their edge hooks at different sites. File-level overlap is not hunk-level
conflict, and this has not been tested -- it is the next thing to measure, not
a claim.

## Integration constraints not visible from the source

Found by building it, not by reading it:

- **`libafl_qemu_sys` pins its own bridge commit** (`d7a6067`) and clones it
  during the build. The Rust crate and the QEMU fork are version-locked, so a
  LibAFL upgrade moves the QEMU under us. Any port has to decide whether we
  track their pin or hold our own.
- **The build wraps the compiler in `linker_interceptor.py`** to harvest link
  lines, so QEMU can be relinked into a Rust binary. Penguin builds
  `libqemu-system-*.so` its own way, through Nix. Reconciling those two is a
  real piece of integration work and is the part least likely to be estimated
  correctly from reading the repo.

## Host toolchain floor

The bridge's own QEMU built fine on this host (957/2063 objects before an
unrelated crate aborted the job). The blockers were all host-environment:

| | needed |
|---|---|
| CMake | >= 3.23 (`libvharness`); host had 3.22.1 |
| LLVM/clang for bindgen | >= rustc's; host clang 14 failed parsing its own `emmintrin.h` |

Both satisfiable. Worth recording because a Nix-provided `libclang` does **not**
work here -- it is built against a newer glibc than the host
(`GLIBC_ABI_GNU2_TLS` missing from libc 2.35), so bindgen cannot `dlopen` it.
The host's own `llvm-18` is the right answer.

## What syx-snapshot actually does, read from its source

The throughput number this lane first took from `qemu_baremetal` (239 exec/s)
does not measure syx-snapshot. That example calls
`.snapshot_manager(QemuSnapshotManager::default())` -- QEMU's own
savevm/loadvm. A profile of it lands ~2/3 of samples in the migration stream
and qcow2 (`qemu_peek_byte` 13.6%, `buffer_zero_avx2` 13.0%, `qemu_get_byte`
10.9%, `ram_load` 5.2%, `qcow2_update_snapshot_refcount` 1.8%), which is the
same path `RESET.md` already measured. `qemu_linux_kernel` and
`qemu_linux_process` both use `FastSnapshotManager`, and
`StdSnapshotManager = FastSnapshotManager` is the default, so the baremetal
Cortex-M3 example is the outlier, not the norm. Switching it to
`FastSnapshotManager` fails immediately (`Lockup: can't escalate 3 to
HardFault`, `R15=00000000` -- PC zero after restore), which is the likely
reason it opts out.

So the 239 exec/s figure is "libafl-qemu on the slow path, 4 MB guest". It
says nothing about syx.

### The restore algorithm

`syx_snapshot_root_restore()` is twenty lines:

```c
device_restore_all(snapshot->root_snapshot->dss);
g_hash_table_foreach(snapshot->rbs_dirty_list, root_restore_rb, snapshot);
syx_cow_cache_flush_highest_layer(snapshot->bdrvs_cow_cache);
syx_snapshot_dirty_list_flush(snapshot);
```

`root_restore_rb_page()` is a single `memcpy` of one page. There is no
migration stream, no serialisation, no zero-scan.

**Cost is O(dirty pages), not O(total RAM).** That settles the open question
that was about to cost a hand-built Linux image: per-iteration cost does not
scale with guest size, so a 256 MB target costs the same as a 4 MB one for the
same working set. The ~270 ms/iteration worst case is off the table.

### Their device half is this lane's device half

`libafl/syx-snapshot/device-save.c` is the file this port adopted. The device
block already landed on v11.1.0 in `qemu_builder` *is* syx's device half --
ported, CI-gated by `fastsnap-selftest`, and improved on: upstream hoists
`SaveStateEntry` and `SaveState` out of `migration/savevm.c` into the header
to walk `savevm_state.handlers` directly, which is a duplicated struct
definition that corrupts memory silently if it drifts. Our version reaches the
list through accessors, so the type stays incomplete outside `savevm.c`.

### And they never restore devices without RAM

`root_restore` does devices *then* dirty pages, always. The reference
implementation agrees with this lane's own finding that a device-only restore
is unsound -- it does not offer the configuration at all.

### The remaining gap

What we do not have is the RAM half: `syx-snapshot.c` (~790 lines),
`syx-cow-cache.c` (~260), and five call sites in `accel/tcg/cputlb.c`.

### One thing to check before trusting it

Dirty tracking is armed nowhere. There is no `tlb_flush`, no
`memory_global_dirty_log_start`, no `TLB_NOTDIRTY` manipulation anywhere in
`libafl/`. Every page enters the dirty list through one of five hooks in
`cputlb.c`, all of which sit on *helper* paths (`probe_access_internal`,
`mmu_lookup`, `atomic_mmu_lookup`). TCG's inline TLB fast path for stores does
not pass through any of them. Whether a store that hits the fast path is
therefore missed -- and the page silently left unrestored -- is a real question
this lane should answer before adopting the RAM half, not after.

Two tells that they were unsure of the same thing: the fast `_tcg_target`
variant is commented out with "TODO: Check if using this method is better for
performances", and at the `mmu_lookup` site the `if (type == MMU_DATA_STORE)`
guard is commented out with "TODO: Does not work?", so pages are marked dirty
on *loads* as well -- a deliberate over-approximation.

### A ready-made oracle

`syx_snapshot_check()` is the differential oracle this lane proposed and never
built. `root_restore_check_memory_rb()` walks `for (i = 0; i < rb->used_length;
i += page_size)` -- the **whole** RAM block, not just the pages it believed
dirty -- and `memcmp`s each page against the reference, reporting per-byte
differences. That is exactly the instrument needed to answer the question
above, and it is already written.

One caveat on it, of the family this lane keeps hitting: the per-block scan is
exhaustive, but the *blocks* it scans come from `g_hash_table_foreach` over
`rbs_dirty_list`. A RAM block that dirty tracking missed entirely is never
checked, and the oracle reports OK. For a guest with one large RAM block that
is a minor concern; it is not zero.

### Following that thread: the tracking appears to self-disarm

Source-level argument, not yet confirmed on a running target. Recorded because
it decides whether the RAM half is adoptable as-is.

QEMU only routes a store through a helper when the TLB entry carries a slow
flag. For a clean RAM page that flag is `TLB_NOTDIRTY`, set in
`tlb_set_page_full()`:

```c
} else if (cpu_physical_memory_is_clean(iotlb)) {
    write_flags |= TLB_NOTDIRTY;
}
```

and `cpu_physical_memory_is_clean()` is `!(vga && code && migration)` -- clean
while *any* of the three clients is still undirtied.

The first store to such a page therefore takes the helper path, syx's
`mmu_lookup` hook fires, and the page is recorded. Then `notdirty_write()`
runs:

```c
cpu_physical_memory_set_dirty_range(ram_addr, size, DIRTY_CLIENTS_NOCODE);
if (!cpu_physical_memory_is_clean(ram_addr)) {
    tlb_set_dirty(cpu, mem_vaddr);          /* clears TLB_NOTDIRTY */
}
```

Once all three clients are dirty the flag is removed from the TLB entry, and
every subsequent store to that page takes TCG's inline fast path -- which
passes through none of syx's five hooks.

`syx_snapshot_root_restore()` ends with `syx_snapshot_dirty_list_flush()`,
emptying syx's list. But nothing re-cleans the VGA/MIGRATION/CODE bitmaps, so
the page stays fast-path. On the *next* iteration the guest can write it
freely and syx never learns. The page is not restored, and state leaks across
iterations.

Restoring the `cpu` section does not rescue this. It flushes the TLB, so the
next access re-runs `tlb_set_page_full` -- but that re-evaluates
`cpu_physical_memory_is_clean()`, which is still false, so `TLB_NOTDIRTY` is
not reapplied.

Re-arming needs `DIRTY_MEMORY_VGA` and `DIRTY_MEMORY_MIGRATION` cleared for the
restored pages each iteration -- the job of the
`memory_global_dirty_log_start` / `sync` machinery. Grepping all of `libafl/`
for `tlb_flush`, `global_dirty_log`, `TLB_NOTDIRTY`,
`cpu_physical_memory_set_dirty` and `memory_region_set_dirty` returns
**nothing**.

If this reading is right, syx tracks only the first write to each page after
the bitmaps last went clean, which is roughly "the first iteration", and the
commented-out `if (type == MMU_DATA_STORE)` guard -- marking pages dirty on
loads as well -- widens the net enough to mask it on short-lived targets.

**What would refute it**, in increasing cost:

1. A `DIRTY_CLIENTS_NOCODE` clear somewhere outside `libafl/` that runs per
   iteration. Not found, but the grep was scoped to `libafl/`.
2. The host TCG backend not emitting an inline store fast path in this build.
   Nothing in `libafl/` or `tcg/` disables it, and `TLB_FORCE_SLOW` is set only
   from `tlb_set_compare()` when slow flags are already present.
3. The direct experiment: run a `FastSnapshotManager` target for more than one
   iteration and call `syx_snapshot_check()`. Their own oracle scans whole RAM
   blocks, so it would show the leaked pages. This needs `qemu_linux_kernel`
   and a hand-built Linux image -- the same blocker as the throughput number.

Note the shape of the argument, because it is this lane's recurring one: the
mechanism is not wrong where it was looked at. It is correct on iteration one,
which is the only iteration a smoke test observes, and `qemu_baremetal` --
the example most likely to be run -- opts out of this path entirely.
