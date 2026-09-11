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
