# fastsnap: measuring what a VM restore costs today

Research lane instrument. Not a product change; nothing here is wired into a
normal `penguin run`.

## What it measures

`penguin_save_snapshot` / `penguin_load_snapshot` (qemu `system/penguin.c:238`
/ `:261`) run in a main-loop bottom half and stop every vCPU for their whole
duration. So with a syscall-dense guest workload, the wall-clock gap between two
consecutive syscall returns brackets the operation. `bench_snapshot.py` samples
`perf_counter()` on every syscall return and attributes the outlier gap that
follows a request it issued.

It also measures the cost that a restore-latency number *misses*: every `loadvm`
goes through `vm_stop(RUN_STATE_RESTORE_VM)`, and `accel/tcg/tcg-all.c:90` turns
that into a full `tb_flush`. The guest then re-translates everything it runs.
That shows up as throughput, not latency, so the plugin measures two adjacent
2000-sample windows after each restore (A then B) and compares them.

## Controls

Three, because an instrument that can report "nothing happened" needs to be
shown reporting something first.

1. **Accuracy** — a host-side sleep of known size (`control_ms`, default 250 ms)
   injected where a snapshot request would go, before any snapshot is taken. The
   run fails if the sampler does not recover it within `control_tol`. Observed
   error across all runs: 0.2%-0.7%.
2. **Density** — the sampler's resolution is the ordinary inter-syscall gap. The
   plugin measures the rate over a warmup window and refuses to measure below
   `min_rate_hz`. This control was added after the first run silently produced
   numbers from *early kernel boot*: the state machine had run to completion on
   the 15 syscall returns available before userspace started. The accuracy
   control passed on that run. It was still meaningless.
3. **Self-reference (A/B)** — window B, taken immediately after window A in the
   same cycle, is the reference for window A. Comparing against a steady-state
   rate measured seconds earlier does not survive a loaded host; comparing two
   adjacent windows does.

## Running it

    python3 run_bench.py -i rehosting/penguin:v3.1.14 --label mylabel \
        --mem 256M --iters 6

Writes `result_<label>.json`. `RESULTS.json` consolidates the runs.

## Referent

Measurements cite `rehosting/penguin:v3.1.14`
(`sha256:6bf719e2b8ab0894c5082d087f30af5601929ab62c3fc53989ecc24d3a72b2f0`).

Note: on this machine the `rehosting/penguin:latest` *tag* is a locally built
image from another lane (identical image id to `penguin:entropy918`, no
RepoDigests, built from `ef37fc91` on `workspace/entropy918`, which is not in
`origin/main`). Its QEMU library is nevertheless the same nix store path
(`iwiqnm6v4pgkszncyliv9442wyv9nvaz-penguin-qemu`) as v3.1.14 and
v3.1.15-portable, so the snapshot mechanism under test is the same binary in all
three. Prefer the digest-pinned tag for anything quotable.
