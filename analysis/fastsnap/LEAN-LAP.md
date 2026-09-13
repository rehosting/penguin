# Removing what is left, while still doing a restore

The reset is no longer the expensive part of a lap, and this is the experiment
that acts on that.

Measured, run 26 (bugbench, mipsel/malta, 4,000 laps, `allow: cpu`, idle host),
an ordinary lap of **0.7396 ms = 1,352 exec/s**, split:

| term | ms | share |
|---|---|---|
| baseline lap -- guest work, the detector round trip, this harness | 0.5233 | 71% |
| post-resume penalty (`bh_to_observed` minus bare) | 0.1044 | 14% |
| the reset's own clock | 0.0620 | 8% |
| main-loop latency (schedule to bottom half) | 0.0398 | 5% |

The whole reset side is 0.206 ms. Deleting **all** of it -- a perfect,
instantaneous, zero-latency restore -- takes the lap to 0.533 ms and the rate
to 1,876 exec/s: **+39%, and that is the ceiling on every remaining idea about
the reset.** Meanwhile a bare lap with no reset at all costs 0.5233 ms with
this harness loaded and cost **0.1112 ms** without it (run 8). So ~0.41 ms per
lap -- more than half of every iteration -- is host-side Python, and it has
never been attributed to a line.

That is what this experiment removes. The restore stays exactly as it is.

## What is actually on the per-lap path

`bugbench.on_read` fires once per lap and makes **two portal round trips into
the guest**:

- `plugins.osi.get_fd_name(fd)` -- `yield PortalCmd(HYPER_OP_OSI_FDS, ...)`,
  a walk of the guest's fd table serviced by the in-guest driver while the vCPU
  waits.
- `plugins.osi.get_proc()` -- `yield PortalCmd(HYPER_OP_OSI_PROC, ...)`, the
  current task read back the same way.

Neither is cheap and neither is information the loop does not already have.
Plus, per lap: a sha256 of the payload, a `dict` of seven keys, a file created
in the results directory, and `self.sent.pop(0)` -- an O(n) memmove of 5,000
pointers, on the vCPU thread.

### Why the two portal calls are removable *here*

Because of the snapshot, and only because of it. A reset returns the guest to
**one instant**. Every lap therefore sees the same process, at the same point,
with the same descriptor open. The fd number and the pid are constants of the
loop; re-deriving them 1,400 times a second is re-deriving a constant.

"Therefore" is doing too much work unsupported, so the latch is earned and then
audited:

- nothing is cached until `fast_after` (64) consecutive injections agree on the
  same `(fd, pid)`;
- only **positive** fd matches are cached. A negative cache would reproduce the
  exact bug the uncached resolve exists to avoid -- the loader closes its
  library descriptors before the victim opens the request one, so fd numbers
  are reused (observed: `attrib` run 1, `inputs_delivered=0`);
- every `revalidate_every` (1,000) injections **both** answers are derived the
  expensive way and compared. A disagreement drops the latch and is an error in
  the report, not a warning -- a stale latch injects into the wrong descriptor,
  or attributes a crash to an input the crashing process never received, and
  nothing else in the pipeline can notice.

### And the cheap ones

`self.sent` becomes a `deque(maxlen=...)`; the sha256 and the head-hex are
computed lazily, on a crash row or in the final dump, because 99.6% of input
records are discarded having never been read.

## Predictions, written before either run

Committed first so the phase table cannot be read backwards into whatever it
shows.

- **P0** -- `resolve_fd` + `resolve_pid` together are **more than half** of
  `on_read total`. If they are not, the portal calls were never the problem and
  the lean path is not worth its audit.
- **P1** -- `on_read total` means **250-450 us**. It has to be under the 0.41 ms
  cross-run estimate for the whole plugin, because the signal callback and the
  second syscall hook's dispatch sit outside this function.
- **P2** -- `inject (portal)` is the third-largest phase and is **not**
  removable: it is the injection.
- **P3** -- arm B's lap falls by approximately the sum in P0, so if P0 lands at
  ~0.25 ms the lap goes 0.74 -> ~0.49 ms and the rate **1,352 -> ~2,000
  exec/s**. A gain much larger than P0's sum would mean the phase timers are
  not measuring what they name.
- **P4** -- the latch is earned once, `latched/delivered > 0.99`, and
  **zero** latch errors. A single latch error invalidates arm B's inputs.
- **P5** -- the score does not fall. Same victim, same mutator, same seed, more
  budget: **>= 5/7**, zero unattributed crashes, negative control clean.
- **P6** -- the cheap removals (deque, lazy hash) are worth **< 40 us/lap** on
  their own -- they are host-local work with no portal in them. Arm A against
  run 26 prices them, with the caveat that arm A also changes `iters` and
  `verify_every` (verified laps are bucketed apart from ordinary ones, so the
  median should not move for that reason).

## Arms

Identical in every respect but one line:

| arm | `fast` | what it prices |
|---|---|---|
| A | `false` | the phase table, and the cheap removals against run 26 |
| B | `true` | the two portal round trips |

Both keep the full restore, the fork oracle, the device oracle, `allow: cpu`,
and `reset_on_signal`.

`iters: 200000` with `verify_every: 200`: at 4,000 laps the loop was 13 s of a
240 s run and **135,000 of the 139,000 injections happened after it had stopped
resetting**, so the cost table would have described the free-running tail
rather than the loop. Now the loop never ends inside the run and every
injection is a lap.

## Results

_(pending)_
