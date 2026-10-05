# Prediction: the merged QEMU (fa76418) is inert on the armel path

Written 2026-09-24, *before* the run, per the lane rule (HANDOFF §8): write the
prediction first, including what the run cannot decide.

## What is being tested

The merged QEMU `qemu_builder@fa76418` ("merge the AT91SAM9260 board into the
fastsnap series") baked into a fresh `penguin:fastsnap` nix image via
`nix-dev.sh override penguin-qemu ../qemu_builder`, then the resting stridelinx
loop (`work/stride/proj`, config unchanged: `coverage: 1`, `mutate: 1`,
`cov_ab: 0`, `arm_after_s: 150`, `verify_every: 100`).

This is a **regression check of the merge, not a measurement of discovery.**
A single run cannot resolve discovery below a factor (COVERAGE.md: ~69-event
effective sample), so no discovery number will be quoted or compared.

## What the merge actually changed, relative to the last image

`penguin:fastsnap` was built 2026-09-16 20:41 EDT. The tree under test adds, on
top of what that image already had:

- `9ebe228 943c413 75e27fa` — coverage controls wait on a condition; coverage
  arithmetic checks; a missing selftest include.
- `acd59ac b538348` (Sep 18) — measure the coverage scan properly; name the
  clear control's race.
- `fa76418` (Sep 24) — the AT91SAM9260 board. **Board files only**
  (`src/hw/arm/at91sam9260.c`, `base.json`, one patch, the `series` line);
  it touches no fastsnap, reset, coverage or armel-machine code.

So the delta that can affect the **stridelinx armel path** is the coverage
work, not the board. The board is inert here by construction — stridelinx does
not boot `-M at91sam9260`. That is the point of running it: prove the board
merge did not perturb the normal armel path.

## Predictions (falsifiable)

1. **The baked image's `fastsnap-selftest` passes all 7 scan shapes with the
   order control intact.** This is the clean, deterministic signal and is
   independent of the flaky device oracle below. If it fails, the merge or the
   bake is broken. *(Cleanest single check.)*

2. **RAM verification is byte-identical on every verification lap.** Even the
   failing run 99 got "RAM came back clean on all 7 verifications"; the RAM
   oracle is the stable half. `dev_diff_clean` may be *less* than the verify
   count only because of item (5), not because of RAM.

3. **Gross timing stays in the prior armel envelope**: `reset_us` median in the
   hundreds of µs (run 99: 787 µs without the PFN prefilter; with
   `--cap-add=SYS_ADMIN` it should be lower), lap in the few-ms range for a
   non-boundary arm. A regression here (e.g. 2×) would implicate the coverage
   commits. *No precise target*, because run 99 armed at a ~1058 ms connection
   boundary and the arm draw sets the lap (CORRECTIONS §8).

4. **`coverage_on` is true and `tbs_instrumented > 0`** (COVERAGE.md: read this
   first — zero means the address range is wrong in the merged build).

## What this run CANNOT decide

- **It cannot validate the AT91SAM9260 board.** That needs the BYOK at91
  target (uImage.bin + rootfs.stage2.jffs2 + kernel_lift_osi, from kernmod's
  kernel-lift PRs), not stridelinx. A green run here says nothing about the
  board working — only that it did not break armel.
- **The `virtio-net#13` device-scope flag is not a merge signal.** It is
  known-intermittent on the draw (HANDOFF §6: one run lost 47/120, the next 0;
  run 99 lost 5/7). If verifications fail on `virtio-net#13` and RAM is clean,
  that is the pre-existing `deny: auto` scope bug, **not** a regression in
  fa76418. Only a RAM difference, or a device diff on a section other than
  `virtio-net`, would implicate the merge.
- **It cannot separate the board merge from the coverage commits.** The delta
  bundles both. If timing regresses, the suspect is the coverage work
  (acd59ac/b538348), not the board — but this run cannot prove which.
- **A single run cannot resolve discovery**, so `new_edges*` is reported for
  completeness and not interpreted.

## Pass criteria (what makes the merge "usable for a run")

Selftest passes (1) AND RAM byte-identical on all verifications (2) AND timing
in envelope (3) AND coverage armed (4). The `virtio-net#13` device flag is
tolerated and noted, not counted against the merge. Run with
`--extra_docker_args "--cap-add=SYS_ADMIN"` so the PFN prefilter is available
and the oracle is not degraded (run 99's verdict called this out explicitly).
