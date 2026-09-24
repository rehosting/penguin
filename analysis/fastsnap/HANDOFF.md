# fastsnap — handoff

Written 2026-09-24. For someone picking this up with no prior context.

Read this, then `CORRECTIONS.md`, then `COVERAGE.md`. In that order, and do
not skip the second one.

---

## 1. What this is

A fast in-process guest reset for fuzzing under penguin/QEMU. Instead of
rebooting or restoring a full VM snapshot between inputs, the guest is rolled
back in place — dirty pages plus device state — so the same code path can be
re-run thousands of times a minute against real firmware.

**The design constraint that shapes everything: no in-guest instrumentation.**
The user's standing steer is *"we have a pipeline that works on any system. I
prefer that. However, I do want it optimized."* Every optimisation must be
host-side and target-agnostic. Do not add guest agents, recompile the target,
or require source.

## 2. Where things live

Workspace `/home/luke/workspace/igloo-dev/projects/fastsnap/`, branch
`workspace/fastsnap` in each worktree.

| | |
|---|---|
| `qemu_builder/src/fastsnap/` | the substance: RAM snapshot, dirty tracking, device save/restore, fork oracle, coverage. Compiled **into** QEMU — it is not a plugin. |
| `qemu_builder/patches/11.1.0/` | 19-patch series over stock QEMU 11.1.0. `0018` emits coverage ops into every translated block; `0019` wires the AT91SAM9260 board. |
| `penguin/analysis/fastsnap/fastloop.py` | the loop: arming, reset scheduling, the verification oracle, all reporting. |
| `penguin/analysis/fastsnap/snapfeed.py` | answers the victim's `read`/`recv` host-side and **skips** the real syscall. |
| `penguin/analysis/fastsnap/loopcmp.py` | compares runs. It now *refuses* comparisons it can prove are confounded. Use it. |
| `penguin/analysis/fastsnap/byok_drive.py` | holds one HTTP connection open from outside the guest, for rootfs with no `/igloo/utils`. |
| `work/stride/proj/` | the run project (**gitignored**). `patch_zzz_fastloop.yaml` is the config and carries long comments explaining every setting. |
| `work/stride/proj/results/<n>/` | per-run JSON. `fastloop.json` and `snapfeed.json` are where all numbers come from. |

Run with `./penguin --pydev run analysis/fastsnap/work/stride/proj` from
`penguin/`. Image tag is `penguin:fastsnap` (`.penguin-image`) — **do not
build over `rehosting/penguin:latest`**.

The project's `plugins/` holds **copies** of the pyplugins. After editing a
plugin, copy it across or the run uses the old one.

## 3. State as of this handoff

**Working and verified.** Lap ~3.4 ms, reset ~320 µs (~9.5% of the lap),
~296 exec/s, and **120/120 verifications byte-identical across 403,054,592
bytes** against an independently forked reference. Coverage costs ~255 µs/lap,
about 7% of the rate.

**Just landed: a merged QEMU** (`fa76418`) carrying both fastsnap and a
faithful AT91SAM9260 board, from a peer session's fork off the same base.
19/19 patches apply with strict context; both halves verified present in one
`libqemu-system-armel.so`; `fastsnap-selftest` passes all 7 scan shapes with
the order control intact. **This has not yet been used for a run.**

**Not working / not built.** Nothing consumes the coverage map — no scheduler
or corpus feedback. Coverage is *measured*, not *guiding*. A coverage-guided
corpus exists (`corpus:` in the config) and showed no replicable effect; it is
off by default and that is the honest state, not a bug to fix.

## 4. The thing that will bite you

**This lane has retracted more numbers than it has published.** Three
instrument faults found in one week, each of which had already produced a
figure someone quoted:

- a stale coverage read on `cov_ab` runs, inflating every discovery total;
- a rate divided by `iterations / median_lap` — a time no run took — which
  flatters exactly the runs with expensive tails, i.e. the ones that discover
  most;
- a cumulative total compared across runs with 3.3× different boundary-lap
  exposure.

`CORRECTIONS.md` entries 14 and 15 have the details. The pattern is the part
to internalise: **all three were caught by checks that had already fired and
been read past.** `exposure`'s "not comparable unless the outlier count
matches", `wall_share`'s impossible −100.5% residual, and a config comment
saying in plain words that `cov_ab` is a cost instrument. Every one correct,
none of them changed a conclusion until a number refused to make sense for an
unrelated reason.

So the guards now live *in the result, next to the number they invalidate*.
`loopcmp.py` refuses a discovery comparison when outlier counts span >2×.
`fastloop.json` carries `new_edges_denominator` and a `cross_run_caveat`.
Keep that pattern; do not add a check that only emits into a log.

**Numbers withdrawn — do not quote, and check anything from before
2026-09-19:**

- *"~103 new edges/s"* → the real figure is **~7.6/s**.
- *the map-size ranking* (55.1 / 103.2 / 100.8) → re-measured at **1.07×
  across a 16× map range**. There is no ranking.

## 5. What is actually known about discovery

Runs 126/127/128 (userspace scope) and 130 (kernel scope), all `cov_ab: 0`:

- **~22–24 new edges per 1,000 typical laps** at every map size from 256 KiB
  to 4 MiB. 1 MiB stays the default on *modelled* collision headroom for
  longer campaigns, not on measured discovery. Say so when you quote it.
- **~69 laps in 12,000 discover anything, and two carry ~43%.** The effective
  sample is sixty-nine events dominated by two. A single run per arm cannot
  resolve less than a factor; the 1.5× threshold used earlier was generous.
- **~48% of discovery comes from the 9–12 laps that replay a process
  fork+exec**, not from request handling.
- **Kernel scope is worse, not better**: 3.12 per 1,000 typical laps against
  userspace's 23.61, with **92%** of it in boundary laps. Kernel coverage
  through an HTTP victim is process creation, not request serving. The
  userspace filter default is right, now for a measured reason.

**Negative results worth not repeating:** four candidate scan implementations
(chunked skim, branchless, two others) were all *slower* than the shipped
reference loop. The bench and its order control are still in
`selftest.c`/`coverage.c`, so a new candidate is one line to measure.

## 6. Open threads

**BYOK / kernel-module fuzzing — the live one.** Module fuzzing is impossible
on the donor-kernel path: target kernel is 3.4.96, donor is 4.10, vendor `.ko`
are ABI-incompatible, `insmod` is shimmed to a no-op, and penguin ships no
loadable modules for any donor kernel. The peer session `kernmod` has built
the alternative — a faithful board booting the real vendor kernel, with a
`sys_call_table` backup providing syscall hooks, verified to support
snapfeed's full contract (enter hook, `skip_syscall`, `write_bytes`, `retval`,
and return-side `accept`). Their Stage 2 booted the real init with lighttpd
live and `writev` flowing through the backup.

**Next concrete step:** run the loop against that composition using the merged
QEMU. Needs (a) the long-lived container and hostfwd port from `kernmod`,
(b) `byok_drive.py` pointed at it, (c) the plugins passed through
`pen_stage2.py`'s plugin dict rather than a project dir. Pass criteria to
check in the JSON: `n_accept > 0`, `fds_learned` non-empty, `n_sent > 0` with
small `n_unmatched`, `iterations > 0`.

**A switch-driver lead, held loosely.** `iface_ioctl.log` shows the firmware's
management stack hitting `lan1`–`lan5` + `cpu` with `SIOCGIFINDEX`,
`SIOCGIFFLAGS` and `SIOCSIFHWADDR`, all `-ENODEV`. Only the last reaches
driver code (`ndo_set_mac_address`). The log is a **lower bound** — the
daemons abort at the first failure — so getting the switch driver to probe
should open much more. Topology from the evidence: **5 user ports + 1 CPU
port**; the `lan1..lan63` sweep is a fixed-range probe, *not* 63 ports. (I
initially misread this log as showing ETHTOOL/MII on the switch ports; it does
not. See `PREDICTION-kernelscope.md`.)

**Unfinished business.** `DEVICE SCOPE TOO NARROW` on `virtio-net` fires on
every run and is **intermittent on the draw** — one run lost 47 of 120
verifications to it, the next lost none. That is worse than a warning that
always fires. `deny: auto` needs revisiting. Also: `tests/unit` has 13
pre-existing collection errors unrelated to this lane.

**People.** `kernmod` is mid-BYOK and expects a ping when the merged QEMU is
used. `taxonomy-47` is building a deck from this lane's output and has the
withdrawal list. `kernpatch-5e` holds the wrong "~103 new edges/s" for a
funder writeup and **is no longer reachable** — that retraction has not
landed and needs a human.

## 7. Standing constraints

- **Never set git author/committer identity.** No `-c user.name=`,
  `--author=`, or `GIT_AUTHOR_*`. `~/.gitconfig` is correct.
- **Never name the device, firmware or vendor** in commits, PRs, issues or
  code.
- Never enable PR automerge unless asked for that PR.
- Never bare `git stash` / `git stash pop` — the stack is shared across
  worktrees and sessions.
- Never `pkill -f <pattern>` where the pattern could match your own command
  line. Use `ps -eo pid,args | awk '/[p]attern/ {print $1}'` then `kill`.
- `docker stop -t 90`, never `rm -f`.
- Portal ops are **appended** to `PORTAL_OP_LIST`, never inserted.
- Don't edit `base/current/projects/*`.
- Write a prediction down *before* a run that is meant to decide something.
  Several in this directory fired against their author; that is the point.

## 8. How to run an experiment here without adding to CORRECTIONS.md

1. Write the prediction first, including **what the design cannot decide**.
2. `cov_ab: 0` unless you are measuring *cost*. It is a cost instrument.
3. Compare on `new_edges_per_1k_typical_laps`, not on totals or per-second
   rates — both are cumulative over exposure.
4. Run `loopcmp.py` over every run in the comparison and **believe its
   refusals**.
5. Check `dev_diff_clean` equals the verify count. If it does not, the reset
   was incomplete and coverage differences may be device drift.
6. If one lap carries most of the result, you have one sample, not one run.
