# Device tiers, measured on a real `virt` machine

Supersedes the two-tier framing in `RECOMMENDATION.md`. Four tiers, not two,
and the cheapest one is complete-by-construction — so most of the win is
probably reachable without the soundness oracle the literature has never built.

## The real section list (19, not the synthetic 17)

Captured from an actual migration stream rather than a synthetic payload:

    qemu-system-arm -M virt,highmem=off -cpu cortex-a15 -m 2G \
        -drive file=d.qcow2,id=hd0,if=none -device virtio-blk-device,drive=hd0 \
        -display none -S -monitor stdio
    (qemu) migrate "exec:cat > stream"
    scripts/analyze-migration.py -f stream -d desc

    timer, <unnamed>, pflash_cfi01 x2, cpu_common, cpu, arm_gic, pl011,
    pl031, gpex_root, PCIHost, PCIBUS, virtio-net, pl061, gpio-key,
    fw_cfg, virtio-blk, virt_acpi_build, globalstate

19 sections against the synthetic's 17 — so the 0.78 ms Tier 0 figure was
measured on a representative machine after all. A penguin run adds netdevs and,
with vpn on, vhost-vsock.

## Which devices reconstruct on load

`post_load` is the thing that decides whether a device can be restored by
copying bytes back. Counted in `qemu/`:

| device        | post_load | pre_save | tier |
|---------------|-----------|----------|------|
| arm_gic       | 1         | 1        | T0   |
| pl011         | 1         | 0        | T0   |
| pl031         | 2         | 1        | T0   |
| virtio-net    | 4         | 4        | T0   |
| fw_cfg        | 1         | 0        | T0   |
| pflash_cfi01  | 1         | 0        | T0   |
| pl061         | 0         | 0        | T1   |
| virtio-blk    | 0         | 0        | T1   |
| gpex_root     | 0         | 0        | T1   |
| cpu_common    | 0         | 0        | T1   |

Six of ~15 real devices need reconstruction. Tree-wide the rate is lower:
687 VMStateDescription definitions in `hw/`, 188 `.post_load` (~27%),
74 `.pre_save`, 61 `VMSTATE_TIMER*`. This machine is above average because it
carries an interrupt controller, a NIC and flash.

Nyx's hand-identified exception set, on this machine, would be about six
entries. That is small enough to enumerate and justify one at a time.

## The tiers

| tier | mechanism | cost | what makes it safe |
|---|---|---|---|
| T0 | full vmstate serialize/deserialize | 0.78 ms | nothing — the default |
| T1 | memcpy the device's heap image (Nyx) | unmeasured | no `post_load`/`pre_save`, no timer in a global list, no host resource |
| T2 | omit + `RESET_TYPE_SNAPSHOT_LOAD` cold reset | ~free | no cross-iteration meaning; known state, not leftover |
| T3 | omit entirely | free | read-set/poisoning argument that nothing reads before writing |

The `{cpu, timer}` allowlist measured at 0.043 ms is a **T3** set. It is the
tier that needs the oracle nobody has built. T1 and T2 are cheaper to justify
and probably capture most of the win.

Rules:

- **Promotion is earned.** A device moves down only after passing the oracle
  for N iterations across M inputs. This is what distinguishes it from Nyx's
  and SAFIREFUZZ's hand-written sets.
- **Assignment is per (machine config, boot state).** Cloud Hypervisor #8693:
  restore panicked on an *inactive* virtio-rng whose ring addresses were all
  zero. Same class as our pl011.
- Per-field vocabulary from QEMU's 2012 QIDL proposal: `q_immutable`,
  `q_derived`, `q_broken`.

## Correction: there is no file-backed RAM on the fast path

`RECOMMENDATION.md` and the ram_term notes say penguin passes
`-machine ...,memory-backend=mem0` so the RAMBlock takes the backend id. That
is wrong twice over:

- `penguin_run.py:515` gates the whole `mem0` object on `vpn_enabled`, and
  `:662` adds `memory-backend=mem0` to the machine only for **mips + vpn**.
  Other arches get `-numa node,memdev=mem0` (`:536`), also vpn-only.
- The artifact agrees: `result_stridelinx_ramterm.json` records
  `"ram_block": "mach-virt.ram"`.

The fast path requires vpn **off**, so guest RAM is anonymous. A host-side
baseline must come from the RAMBlock host pointer, not from mmap'ing a backing
file. `fastsnap-reset.c` already does this correctly; the note was wrong, not
the code.

## Also already there

`penguin_run.py:545` appends `clocksource=jiffies nohz_full nohz=off
no_timer_check` to the kernel command line, commented `# Improve determinism?`.
Penguin is already trying to buy guest-side determinism. The determinism
harness should measure whether it works rather than assume it.
