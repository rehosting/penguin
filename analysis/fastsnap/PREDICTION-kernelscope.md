# Prediction: fuzzing the kernel through the device's own web interface

Written before run 129 so it can fail.

## What is being tested

Every run this lane has recorded filtered coverage to **userspace**
(`[0, 0xC0000000)`), on the argument that kernel blocks execute on every lap
and are novel only once, so they charge emission and scan thousands of times
for a single contribution. That argument is about *cost efficiency for finding
userspace bugs*. It says nothing about whether the kernel is a reachable
fuzzing target, and this run asks that instead.

One config change against the resting configuration:

    cov_filter_lo: 0xC0000000   (3221225472)
    cov_filter_hi: 0xFFFFFFFF   (4294967295)

Everything else identical to runs 126/127/128 — 1 MiB map, `cov_ab: 0`,
mutation on, corpus off, 12,000 laps, seed 1337. So it pairs directly against
run 127, which is the same run with the filter the other way round.

## Why there is reason to think the surface is real

- The kernel is **58.7% of the replayed span's working set** and ~49% of block
  executions (measured, `COVERAGE.md`).
- Runs 126/127/128 filtered out ~30,000 blocks each (`tbs_filtered` 30,332 /
  30,091 / 38,463) against ~20,000 instrumented. The filtered half is the
  kernel and it is the larger one.
- The workload is HTTP into lighttpd, so every lap drives the socket layer,
  the TCP receive path, VFS and the netdev ioctl path. `hook_budget` for run
  127 records `ioctl:return` firing **5,884 times after arming**.

## The predictions

**K1.** `tbs_instrumented` comes back in the 25,000–45,000 range — the same
order as the ~30,000 that runs 126/127 filtered out. If it comes back near
zero the filter is wrong, not the idea; that is the self-check.

**K2.** Per-lap edges are **higher** than the userspace runs' 1,422 median,
because the kernel is the larger half of the working set. Say 1,800–4,000.

**K3.** Discovery per typical lap is **lower** than userspace's ~23 per 1,000.
Kernel paths are hot and repetitive — the same syscall path every lap — so
they saturate early. Say 5–20 per 1,000 typical laps. **This is the
interesting one**: if kernel discovery is comparable to userspace, the kernel
is as good a fuzzing target as the application and the filter default deserves
revisiting. If it is much lower, the current default is right for bug-finding
and this run is a capability demonstration rather than a recommendation.

**K4.** Scan cost rises with edges set per lap, so `cov_scan_us` exceeds run
127's 134 µs. Say 150–300 µs.

**Not predicted, on purpose:** the outlier-lap share. Boundary laps replay a
guest fork+exec, which is mostly *kernel* work, so the kernel scope may make
those laps dominate discovery even harder than userspace's ~48%. No number is
offered because I have no basis for one.

## What this run cannot show

**It is not kernel *module* fuzzing, and cannot be made into it on this
rehost.** The module region `[0xBF000000, 0xC0000000)` holds `igloo.ko` and
nothing else. Four independent reasons, each sufficient:

1. The target kernel is **3.4.96**; the donor is **4.10**. The vendor's own
   modules are ABI-incompatible — the console says so directly:
   `can't load module crc_ccitt (/lib/modules/4.10.0/kernel/lib/crc-ccitt.ko):
   invalid module format`. `/lib/modules/4.10.0` is a symlink to
   `/lib/modules/3.4.96` (`static.kernel_modules.yaml`), so modprobe finds the
   3.4.96 objects under the 4.10 name.
2. `/sbin/insmod` is shimmed to `exit0.sh` (`static.shims.no_modules.yaml`).
3. `kmods` blocks every module but `igloo.ko` by default.
4. **Penguin ships no loadable modules for any donor kernel** — checked inside
   the image: `find /igloo_static/kernels -name '*.ko'` returns only the
   per-arch `igloo.ko`. The donor kernels are monolithic, so there is nothing
   to allowlist even if (2) and (3) were lifted.

Reasons 2 and 3 are configuration and could be changed. Reasons 1 and 4 are
not, and either alone is fatal. Module fuzzing on this target needs the real
3.4.96 kernel, which is the BYOK path.

---

# RESULT — run 129

| | userspace (127) | kernel (129) |
|---|---|---|
| filter | `[0, 0xC0000000)` | `[0xC0000000, 0xFFFFFFFF)` |
| `tbs_instrumented` | 20,311 | **29,968** |
| `tbs_filtered` | 30,091 | 20,243 |
| edges/lap median | 1,422 | **2,927** |
| `cov_scan_us` median | 134 | 181 |
| `exec_per_s_median` | 296.3 | 286.5 |
| `new_edges_per_1k_typical_laps` | 23.61 | *64.6 — see below* |
| novel laps (of 12,000) | 69 | **15** |
| `dev_diff_clean` / verifies | **120 / 120** | **73 / 120** |

## Scored

**K1 — HELD.** 29,968 instrumented against a predicted 25,000–45,000. Better
than that: the two runs **partition the same block set**. Userspace
instrumented 20,311 and filtered 30,091; kernel instrumented 29,968 and
filtered 20,243. Two runs, opposite filters, each one's instrumented count
matching the other's filtered count to within 0.4%. That is the self-check the
prediction asked for, and it passes in a stronger form than was asked.

**K2 — HELD.** 2,927 edges per lap against a predicted 1,800–4,000, and 2.06×
userspace's 1,422. The kernel is the larger half of the working set, as
`COVERAGE.md` said.

**K4 — HELD.** 181 µs scan against a predicted 150–300.

**K3 — NOT SCORED. The run is not clean and the number is not reportable.**

## Why K3 cannot be scored

The nominal figure is 64.6 new edges per 1,000 typical laps, 2.7× userspace,
which would fail the predicted 5–20 in the interesting direction. It does not
survive being looked at.

**One lap contributed 675 of the ~775 typical-lap new edges — 87%.** The
per-lap novelty series for this run is `[675, 58, 23, 6, 3, 3, 2, 2, …]`
against userspace's `[40, 22, 22, 16, 15, 11, 10, 10, …]`. Remove that single
lap and the figure is **~8.2 per 1,000**, below userspace and *inside* the
predicted band. The prediction's fate is decided by one lap in twelve
thousand, which means it is not decided.

**And there is a mechanism for that lap that is not fuzzing.** This run's
device restore failed: `dev_diff_clean` is **73 of 120** — 47 verifications
left `virtio-net` sections unrestored — where runs 126, 127 and 128 were
120/120 clean. A lap whose network-device state drifted takes a different path
through the network stack, and the network stack is most of what this run's
filter selects. A burst of new edges from a drifting NIC is an instrument
failure wearing discovery's clothes, and it would land in exactly this scope.

So the two facts point the same way and neither can be dismissed: the headline
rests on one lap, and the run has a defect that would produce exactly that lap
in exactly that code. Run 130 is an identical replicate, launched to find out
whether the 675 recurs and whether the device failure does.

**Also note only 15 novel laps against userspace's 69.** Even without the
defect, the kernel scope has a *smaller* sample of discovery events, not a
larger one — which is consistent with the K3 reasoning (kernel paths are hot,
repetitive, and saturate early) and makes any kernel discovery figure noisier
than the userspace one it would be compared against.

## What the run does establish

**The capability, unambiguously.** The kernel is reachable, instrumentable and
scannable through the device's own web interface, with no in-guest
instrumentation: ~30,000 blocks instrumented, 2,927 edges per lap, 181 µs per
scan, 286.5 exec/s, over 12,000 laps of mutated HTTP. Everything in that
sentence is measured and none of it depends on the contested number.

What it does not yet establish is whether the kernel is a *better* target than
userspace. That needs a clean run.

## A finding that was not being looked for

`DEVICE SCOPE TOO NARROW` on `virtio-net` fires on every run this lane has
done and has been treated as benign, because it has been: runs 126/127/128 all
emitted it and still verified 120/120 device-clean. Run 129 emitted the same
warning and lost **47 verifications** to it.

So the warning is not benign, it is *intermittent*, and which of those it is
depends on the draw. That is worse than a warning that always fires, because
three clean runs in a row taught me to read past it. Whatever else run 130
decides, `deny: auto` is not sufficient for every arm and the device scope
needs revisiting on its own account.
