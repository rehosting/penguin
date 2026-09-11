# The reset floor, measured: 0.043 ms — and it costs nothing when unused

Follow-on to `THROUGHPUT.md`. Two numbers draft 45 does not have.

Measurements ran in the Slice 0 build (`projects/fastsnap/slice0/`), which was
quarantined outside every repo worktree at the time because it carries GPL-2.0
code from `qemu-libafl-bridge`. **That quarantine is over:** Luke approved GPL
in `rehosting/qemu_builder`, and the code now lives there as `src/fastsnap/`
with a declared provenance. `slice0/` is the research record. Full method,
controls and the two instrument failures are in `slice0/FINDINGS-allowlist.md`.

The numbers below were taken on an 11.0.50 tree. The port to 11.1.0 re-runs the
round trip and its controls, but **has not re-measured the timings**.

## 1. The correct device allowlist for an iteration is {cpu, timer}

Restoring only `cpu` costs 0.039 ms against 0.728 ms for all 17 sections, but
that was a floor, not a configuration. Diffing per-section device blocks across
a window of guest execution gives the set an iteration actually dirties:

```
ALL (baseline)   17 sections   61987 bytes   restore 0.752 ms
NATURAL           2 sections    4695 bytes   restore 0.043 ms   (cpu, timer)
cpu only (floor)  1 sections    4647 bytes   restore 0.039 ms
```

Stable at 1 ms, 10 ms and 100 ms windows. **17.5x**, landing on the floor.

Combined with the ~117 MIPS TCG figure from `THROUGHPUT.md`, a
snapshot-and-poke iteration prices out as:

| | cost |
|---|---|
| device restore, correct allowlist | 0.043 ms |
| RAM restore, ~65 dirty pages | 0.027 ms |
| **reset** | **~0.07 ms** |
| guest: 10k-insn parse | 0.09 ms |
| guest: 100k-insn parse | 0.85 ms |

Reset stops being the bottleneck. The iteration rate becomes a property of the
work being done, which is the ceiling in-process fuzzing has under TCG.

**Limit on this number.** `pl011` does not appear in the diff even though the
guest writes its data register every lap — after the first write the saved
state is at a fixed point. It is genuinely unchanged *for this input*. A diff
over one workload is therefore a lower bound on the required set, not a proof
of sufficiency: shipping a diff-derived allowlist needs a conservative union
over many inputs, or a full restore as an oracle.

## 2. On command, and free when not commanded

| | median of 5 |
|---|---|
| arm (`memory_global_dirty_log_start`) | **0.20 ms** |
| disarm (`memory_global_dirty_log_stop`) | **0.17 ms** |
| armed throughput | 96.5% of unarmed |
| recovered throughput | 96.9% of unarmed |

The 3.5% armed tax **is not real**. A control that runs the identical four-phase
schedule and never arms produces the same wobble (100.0 / 100.6 / 96.6% in the
"armed" phase), so ±5% is this measurement's noise floor and the armed tax sits
under it. Not "zero" — "unresolvable above ±5%", for a workload touching 65
pages. A working set of thousands of pages would pay more per clear.

Unarmed cost is zero by construction rather than by measurement, and this is
the reason the hybrid recommendation matters: it touches neither `cputlb.c` nor
`physmem.c`, so TCG's hottest path is unchanged. It arms machinery QEMU already
ships and leaves off. Importing syx whole would have put a permanent hook in
the store path and made the capability a standing tax on every ordinary run.

## What this changes for draft 45

- The port moves back to being the **primary** lever for short in-process
  iterations, not the second. At packet-parse scale, guest work is
  sub-millisecond and reset dominates until the allowlist is scoped.
- The draft has no allowlist section. Scoping the device set is a new
  correctness question — which sections must be restored for a given poke
  point — and the diff method above measures it but does not settle it.
- The RAM term is still target-specific and unmeasured on a real firmware
  target. 65 dirty pages here is the synthetic payload's own working set.
