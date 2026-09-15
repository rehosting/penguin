#!/usr/bin/env python3
"""Where does penguin's guest time actually go? A measurement scheme.

WHY A SCHEME RATHER THAN A NUMBER
---------------------------------
Three instruments have now failed on this question, each producing a plausible,
linear, reproducible number that was wrong:

  1. `hookcost.py`'s python_in_callback (0.72 us) measures the Python FUNCTION
     BODY, not the portal round trip around it. Read as "Python is 0.5% of a
     hooked syscall" it supported the opposite of the truth.
  2. Guest /proc/uptime brackets reported 4,000,000 emulated getpid calls in
     0.04 s -- which would make an emulated MIPS guest 13x faster than the x86
     host running the identical probe (130-160 ns per call, measured). Guest
     time is not host time: jiffies come from an emulated timer a loaded TCG
     guest cannot keep up with, so they run slow and understate everything in
     proportion.
  3. Host wall-clock differencing across whole runs works, but boot variance is
     seconds and the effects are seconds, so it cannot resolve them.

`guest_speed.py` and therefore `THROUGHPUT.md`'s 21.0 ms/spawn use instrument 2
and inherit its error. That is recorded here rather than quietly worked around.

THE CLOCK THIS USES
-------------------
A host-timestamped stopwatch that the GUEST drives. The probe calls a rare,
side-effect-free marker syscall (`getppid`); a pyplugin hooks only that and
records `time.perf_counter()` on the HOST. Consecutive markers bracket a
segment, so:

  - the clock is the host's, which is not part of what is being measured;
  - brackets live INSIDE one boot, so boot variance is eliminated rather than
    out-run;
  - the marker's own cost (~one hook dispatch) is identical at every marker and
    cancels out of every slope.

The guest's own /proc/uptime is recorded at each marker too -- not to measure
anything, but to quantify how far that clock is wrong, since other tools in
this lane depend on it.

WHAT IT MEASURES
----------------
Segments of known work between markers, several sizes each, fitted:

  compute(n)   pure arithmetic, no syscalls      -> guest instruction rate
  getpid(n)    n syscalls, hook state per config -> per-syscall cost

and three configurations differing in exactly one thing:

  unhooked    no pyplugin hooks getpid          -> emulated kernel + driver
  hooked      a counting pyplugin hooks getpid  -> + portal dispatch
  scope_out   probe outside analysis scope      -> driver's own contribution

CONTROLS, without which none of the above is worth reporting
------------------------------------------------------------
  stopwatch   the host sleeps a KNOWN duration inside one marker hook. The
              bracket containing it must read back that duration. If it does
              not, the stopwatch is not measuring host time and every number
              here is void. This is the control the guest-clock instrument
              did not have, and it is why it went wrong undetected.
  null        two segments of IDENTICAL work at different points in the run.
              Their difference is the noise floor, and nothing smaller than it
              may be reported as an effect.
  zero        a segment with n=0, giving per-segment overhead. The slope must
              not depend on it.
  linearity   >= 4 sizes, with the worst-point residual reported. A bad fit
              means the slope is not a per-unit cost and must not be quoted.

Run: python3 speedscheme.py -i penguin:fastsnap
"""

import json
import re
import shutil
import statistics
import subprocess
import time
from pathlib import Path

import click
import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
PENGUIN = str(REPO / "penguin")

COMM = "speedprobe"
# Also the project name and therefore the container name; see main().
PROJ = "speedscheme"


def reclaim_stale_container():
    """A killed harness leaves its guest running. It holds the container name,
    so every later run dies at startup, and it keeps emulating -- which would
    perturb the timings even if the name were free."""
    out = subprocess.run(
        ["docker", "ps", "-a", "--filter", f"name=^{PROJ}$", "--format",
         "{{.Names}} {{.Image}} {{.Status}}"],
        capture_output=True, text=True).stdout.strip()
    if not out:
        return
    print(f"  preflight: stale container [{out}] -- reclaiming")
    subprocess.run(["docker", "stop", "-t", "90", PROJ],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["docker", "rm", PROJ],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# Segment schedule. (kind, multiplier) -- n = multiplier * base.
# Order matters: the null pair is deliberately far apart so drift within a run
# shows up in it, and the stopwatch check is last so a host sleep cannot
# contaminate a measured segment.
SCHEDULE = [
    ("compute", 0),     # zero point: marker + loop overhead only
    ("getpid", 0),      # zero point for syscall segments
    ("getpid", 1),
    ("getpid", 2),
    ("getpid", 4),
    ("getpid", 8),
    ("getpid", 1),      # NULL PAIR with index 2 -- same work, later
    ("compute", 8),     # guest instruction rate
    ("getpid", 0),      # stopwatch check: host sleeps in the marker before it
]
SYSCALL_SEGS = [2, 3, 4, 5]        # indices whose slope is the syscall cost
NULL_PAIR = (2, 6)
STOPWATCH_SEG = 8
STOPWATCH_MS = 250.0

PROBE_C = r"""/* speedprobe: segments of known work, bracketed by a marker syscall the HOST
 * timestamps. See analysis/fastsnap/speedscheme.py.
 *
 * getppid() is the marker: side-effect free, argument free, and rare enough in
 * a controlled init that a comm-filtered hook on it fires only here. getpid()
 * is the workload for the same reasons minus the rarity -- it is the cheapest
 * real syscall, so what it costs is near the floor for any syscall, which is
 * the conservative direction for a claim that syscalls are expensive.
 */
#include <fcntl.h>
#include <unistd.h>

/* The base is COMPILED IN rather than passed as an argument, because penguin's
 * /igloo/init runs every executable in /igloo/init.d/ itself, sequentially and
 * in the foreground, before igloo_init. An init.sh that also invoked the probe
 * ran it TWICE -- once with no argv and so a different base -- and the two
 * interleaved into one mark list. Nothing failed; there were simply twice as
 * many marks as segments, which is the only reason it was noticed. */
#define BASE %(base)dL

static volatile unsigned int sink;

/* The marker. getppid() is what the host actually times; the uptime line is
 * only so the scheme can report how wrong the guest's own clock is. */
static void mark(void)
{
    char buf[128];
    int fd, n;

    (void)getppid();
    if (write(1, "SPEEDMARK ", 10) < 0) {
        return;
    }
    fd = open("/proc/uptime", O_RDONLY);
    if (fd < 0) {
        return;
    }
    n = (int)read(fd, buf, sizeof buf);
    if (n > 0) {
        if (write(1, buf, (unsigned)n) < 0) {
            close(fd);
            return;
        }
    }
    close(fd);
}

int main(void)
{
    static const int kinds[] = {%(kinds)s};
    static const int mults[] = {%(mults)s};
    int nseg = (int)(sizeof kinds / sizeof kinds[0]);
    long base = BASE;
    int s;
    long i;

    for (s = 0; s < nseg; s++) {
        long n = mults[s] * base;

        mark();
        if (kinds[s] == 0) {
            for (i = 0; i < n; i++) {
                sink += (unsigned int)(i ^ (i >> 3));
            }
        } else {
            for (i = 0; i < n; i++) {
                sink += (unsigned int)getpid();
            }
        }
    }
    mark();
    if (write(1, "SPEEDPROBE-DONE\n", 16) < 0) {
        return 1;
    }
    return 0;
}
"""

MARK_PY = '''"""The stopwatch. Hooks ONLY the marker syscall and timestamps it with the
host's clock, which is the whole point: the guest's clock is demonstrably wrong
under emulation and cannot time its own emulation.

`sleep_at`/`sleep_ms` inject a known host delay into one bracket. That is the
control that proves this is reading host time -- without it, a stopwatch that
silently measured guest time would look exactly the same.
"""
import json
import os
import time

from penguin import Plugin, plugins


class SpeedMark(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.comm = self.get_arg("comm") or "speedprobe"
        self.sleep_at = int(self._arg("sleep_at", -1))
        self.sleep_ms = float(self._arg("sleep_ms", 0))
        self.hook_getpid = bool(int(self._arg("hook_getpid", 0)))
        self.marks = []
        self.n_getpid = 0

        plugins.syscalls.syscall("on_sys_getppid_enter",
                                 comm_filter=self.comm)(self.on_mark)
        if self.hook_getpid:
            # The variable under test. It counts and does nothing else, so the
            # difference against an unhooked run is dispatch cost rather than
            # the cost of whatever a real hook would then do.
            plugins.syscalls.syscall("on_sys_getpid_enter",
                                     comm_filter=self.comm)(self.on_getpid)

    def _arg(self, name, default):
        v = self.get_arg(name)
        return default if v is None or v == "" else v

    def on_mark(self, regs, proto, syscall, *a):
        i = len(self.marks)
        self.marks.append(time.perf_counter())
        if i == self.sleep_at and self.sleep_ms > 0:
            # Blocks the QEMU main loop on purpose: this is host time being
            # injected into the NEXT bracket, and the scheme checks it comes
            # back out.
            time.sleep(self.sleep_ms / 1000.0)
        return
        yield

    def on_getpid(self, regs, proto, syscall, *a):
        self.n_getpid += 1
        return
        yield

    def uninit(self):
        path = os.path.join(self.outdir, "speedmark.json")
        with open(path, "w") as fh:
            json.dump({"marks": self.marks, "n_getpid": self.n_getpid,
                       "comm": self.comm, "hook_getpid": self.hook_getpid}, fh)
        self.logger.info(f"speedmark: {len(self.marks)} marks, "
                         f"getpid seen {self.n_getpid}")
'''

# The probe is NOT invoked here -- /igloo/init already ran it. This exists only
# to keep the guest alive past the probe so the run reaches a clean shutdown.
INIT_SH = """#!/igloo/utils/sh
/busybox echo "[speed] probe already run by /igloo/init.d; idling"
while true; do /busybox sleep 1; done
"""


def penguin(image, *args, cwd, log):
    cmd = " ".join([PENGUIN, "--image", image, *args])
    print(f"$ {cmd}")
    rc = subprocess.run(cmd, cwd=cwd, shell=True, stdout=open(log, "w"),
                        stderr=subprocess.STDOUT).returncode
    if rc != 0:
        subprocess.run(["tail", "-n", "40", str(log)])
    return rc


def fit(xs, ys):
    """Slope, intercept, and the worst residual as a fraction of the fitted
    value. A slope quoted without that residual is a line drawn through
    whatever the points happened to be."""
    n = len(xs)
    mx, my = sum(xs) / n, sum(ys) / n
    denom = sum((x - mx) ** 2 for x in xs)
    slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom
    icept = my - slope * mx
    worst = 0.0
    for x, y in zip(xs, ys):
        pred = slope * x + icept
        if pred > 0:
            worst = max(worst, abs(y - pred) / pred)
    return slope, icept, worst


def run_config(image, work, proj, label, scope, hook_getpid, reps):
    """One configuration, `reps` boots. Returns per-boot segment durations
    measured on the HOST clock, plus the guest's own clock for comparison."""
    (proj / "plugins.d/speedmark.py").write_text(MARK_PY)
    args = {"comm": COMM, "sleep_at": STOPWATCH_SEG, "sleep_ms": STOPWATCH_MS,
            "hook_getpid": 1 if hook_getpid else 0}
    (proj / "plugins.d/speedmark.yaml").write_text(yaml.dump(args, sort_keys=False))

    patch = {
        "core": {"analysis_scope": scope, "timeout": 900, "mem": "256M",
                 "root_shell": False},
        "env": {"igloo_init": "/init.sh"},
        "static_files": {"/init.sh": {"type": "inline_file", "mode": 493,
                                      "contents": INIT_SH}},
        "plugins": {"vpn": {"enabled": False}},
    }
    (proj / "patch_speed.yaml").write_text(yaml.dump(patch, sort_keys=False))
    cfg_p = proj / "config.yaml"
    cfg = yaml.safe_load(cfg_p.read_text())
    if "patch_speed.yaml" not in (cfg.get("patches") or []):
        cfg.setdefault("patches", []).append("patch_speed.yaml")
    cfg_p.write_text(yaml.dump(cfg, sort_keys=False))

    boots = []
    for rep in range(reps):
        log = work / f"run_{label}_{rep}.txt"
        penguin(image, "run", str(cfg_p), cwd=work, log=log)
        res = proj / "results/latest"
        mark_f = res / "speedmark.json"
        if not mark_f.exists():
            why = "see the log"
            txt = log.read_text(errors="replace")
            for needle in ("already in use", "No such image", "Traceback"):
                if needle in txt:
                    why = f"run did not start: {needle!r}"
                    break
            print(f"    rep {rep}: NO speedmark.json -- {why} ({log})")
            continue
        md = json.loads(mark_f.read_text())
        marks = md["marks"]
        if len(marks) != len(SCHEDULE) + 1:
            print(f"    rep {rep}: {len(marks)} marks, expected "
                  f"{len(SCHEDULE) + 1} -- the probe did not complete")
            continue
        host = [marks[i + 1] - marks[i] for i in range(len(SCHEDULE))]
        ups = []
        console = res / "console.log"
        if console.exists():
            ups = [float(m.group(1)) for m in re.finditer(
                r"SPEEDMARK\s+([0-9.]+)", console.read_text(errors="replace"))]
        guest = ([ups[i + 1] - ups[i] for i in range(len(SCHEDULE))]
                 if len(ups) == len(SCHEDULE) + 1 else None)
        boots.append({"host_s": host, "guest_s": guest,
                      "n_getpid": md.get("n_getpid")})
        print(f"    rep {rep}: ok ({len(marks)} marks, "
              f"getpid seen {md.get('n_getpid')})")
    return boots


def analyse(label, boots, base):
    """Controls first. A slope is only reported if the controls that could
    invalidate it have passed."""
    if not boots:
        return {"error": "no usable boots"}

    # Median across boots, per segment.
    per_seg = [statistics.median([b["host_s"][i] for b in boots])
               for i in range(len(SCHEDULE))]

    out = {"label": label, "boots": len(boots), "segment_s": per_seg}

    # CONTROL: the stopwatch. The bracket after the injected sleep must contain
    # it. Without this passing, nothing else here is measuring host time.
    sw = per_seg[STOPWATCH_SEG]
    out["stopwatch"] = {"injected_ms": STOPWATCH_MS, "measured_ms": sw * 1e3,
                        "ratio": (sw * 1e3) / STOPWATCH_MS}
    out["stopwatch_ok"] = 0.8 <= out["stopwatch"]["ratio"] <= 1.5

    # CONTROL: the null pair. Identical work, far apart in the run.
    a, b = NULL_PAIR
    noise = abs(per_seg[a] - per_seg[b])
    denom = max(per_seg[a], per_seg[b], 1e-12)
    out["null_pair"] = {"a_s": per_seg[a], "b_s": per_seg[b],
                        "abs_diff_s": noise, "rel": noise / denom}

    # CONTROL: zero point.
    out["zero_point_s"] = {"compute": per_seg[0], "getpid": per_seg[1]}

    # The slope, net of the zero point.
    xs = [SCHEDULE[i][1] * base for i in SYSCALL_SEGS]
    ys = [per_seg[i] - per_seg[1] for i in SYSCALL_SEGS]
    slope, icept, worst = fit(xs, ys)
    out["us_per_syscall"] = slope * 1e6
    out["fit_intercept_s"] = icept
    out["fit_worst_residual"] = worst
    out["linear_ok"] = worst < 0.10

    # The guest's own clock, for the record rather than for the result.
    if all(b["guest_s"] for b in boots):
        g = [statistics.median([b["guest_s"][i] for b in boots])
             for i in range(len(SCHEDULE))]
        gy = [g[i] - g[1] for i in SYSCALL_SEGS]
        gslope, _, _ = fit(xs, gy)
        out["guest_us_per_syscall"] = gslope * 1e6
        out["guest_clock_understates_by"] = (slope / gslope) if gslope > 0 else None

    # Guest instruction rate, from the pure-compute segment.
    comp = per_seg[7] - per_seg[0]
    out["compute_ns_per_iter"] = comp / (8 * base) * 1e9 if comp > 0 else None
    return out


@click.command()
@click.option("--image", "-i", default="penguin:fastsnap")
@click.option("--arch", "-a", default="mipsel", help="bugbench's architecture")
@click.option("--base", "-n", default=200_000, type=int,
              help="iterations per unit segment")
@click.option("--reps", "-r", default=2, type=int, help="boots per config")
@click.option("--out", default="result_speedscheme.json")
@click.option("--only", default=None,
              help="comma-separated config labels to run; the rest are read "
                   "back from --out if already there")
@click.option("--reuse", is_flag=True,
              help="keep an existing work dir and its built probe rather than "
                   "rebuilding from the image")
def main(image, arch, base, reps, out, only, reuse):
    # A run is six boots and roughly an hour. It used to rebuild the work dir
    # unconditionally and write --out only at the very end, so a kill at boot
    # five threw away every completed config -- which is exactly what happened,
    # and the unhooked number survived only as text in a log. Results are now
    # written after each config, and --only/--reuse let a killed run pick up
    # where it stopped instead of starting over.
    work = HERE / "work_speed_scheme"
    if reuse and work.exists():
        print(f"reusing {work}")
    else:
        if work.exists():
            shutil.rmtree(work)
        work.mkdir(parents=True)

    fs = work / "fs"
    built = (work / "projects" / PROJ / "config.yaml").exists()
    if not (reuse and built):
        fs.mkdir(exist_ok=True)
        cid = subprocess.check_output(f"docker create {image}", shell=True).decode().strip()
        subprocess.run(f"docker cp -L {cid}:/igloo_static/utils.bin/busybox.{arch} {fs}/busybox",
                       shell=True, check=True)
        subprocess.run(f"docker rm -v {cid}", shell=True, check=True,
                       stdout=subprocess.DEVNULL)
    # The tarball name becomes the project name, and the project name becomes
    # the CONTAINER name. Calling it fs.tar.gz -- as every guest_speed-shaped
    # harness in this lane does -- means the container is called `fs`, and a
    # stale `fs` from any of them blocks every run here with "Container name fs
    # is already in use". Six boots were lost to exactly that. A distinctive
    # name also makes the preflight below safe: a container by THIS name can
    # only be ours, so stopping it cannot disturb another worktree's run.
        subprocess.run(f"tar -czf {work}/{PROJ}.tar.gz -C {fs} .", shell=True, check=True)
        reclaim_stale_container()
        penguin(image, "init", f"{work}/{PROJ}.tar.gz", "--force",
                cwd=work, log=work / "init.txt")

    proj = work / "projects" / PROJ
    (proj / "init.d").mkdir(parents=True, exist_ok=True)
    (proj / "plugins.d").mkdir(parents=True, exist_ok=True)
    (proj / "init.d/speedprobe.c").write_text(PROBE_C % {
        "base": base,
        "kinds": ", ".join("0" if k == "compute" else "1" for k, _ in SCHEDULE),
        "mults": ", ".join(str(m) for _, m in SCHEDULE)})

    CONFIGS = (("unhooked", "none", False),
               ("hooked", "none", True),
               ("scope_out", "firmware", False))
    wanted = set(only.split(",")) if only else {c[0] for c in CONFIGS}
    unknown = wanted - {c[0] for c in CONFIGS}
    assert not unknown, f"--only names no such config: {sorted(unknown)}"

    results = {}
    prev = HERE / out
    if prev.exists():
        # Carry forward configs this invocation is not re-running, but only if
        # they actually succeeded -- a stored {"error": ...} is not a result.
        old = json.loads(prev.read_text())
        for label in {c[0] for c in CONFIGS} - wanted:
            if isinstance(old.get(label), dict) and "error" not in old[label]:
                results[label] = old[label]
                print(f"carrying forward {label} from {out}")

    def save():
        (HERE / out).write_text(json.dumps(
            {**results,
             "meta": {"base": base, "reps": reps, "arch": arch,
                      "schedule": SCHEDULE, "stopwatch_ms": STOPWATCH_MS}},
            indent=2))

    for label, scope, hook in CONFIGS:
        if label not in wanted:
            continue
        print(f"\n== {label} (scope={scope}, hook_getpid={hook})")
        boots = run_config(image, work, proj, label, scope, hook, reps)
        results[label] = analyse(label, boots, base)
        save()          # after EVERY config, so a kill costs one config
        r = results[label]
        if "error" in r:
            print(f"  {label}: {r['error']}")
            continue
        print(f"  stopwatch  injected {STOPWATCH_MS:.0f} ms, measured "
              f"{r['stopwatch']['measured_ms']:.1f} ms  "
              f"[{'OK' if r['stopwatch_ok'] else 'FAILED'}]")
        print(f"  null pair  {r['null_pair']['abs_diff_s'] * 1e3:.1f} ms "
              f"({r['null_pair']['rel'] * 100:.1f}%) -- the noise floor")
        print(f"  linearity  worst residual {r['fit_worst_residual'] * 100:.1f}% "
              f"[{'OK' if r['linear_ok'] else 'FAILED'}]")
        if r["stopwatch_ok"] and r["linear_ok"]:
            print(f"  ==> {r['us_per_syscall']:.3f} us per syscall")
        else:
            print("  ==> slope NOT reported: a control failed")
        if r.get("guest_clock_understates_by"):
            print(f"  guest clock understates by "
                  f"{r['guest_clock_understates_by']:.1f}x "
                  f"({r['guest_us_per_syscall']:.3f} us)")

    ok = {k: v for k, v in results.items()
          if "error" not in v and v.get("stopwatch_ok") and v.get("linear_ok")}
    if {"unhooked", "hooked"} <= set(ok):
        results["split"] = {
            "kernel_plus_driver_us": ok["unhooked"]["us_per_syscall"],
            "pyplugin_dispatch_us": (ok["hooked"]["us_per_syscall"]
                                     - ok["unhooked"]["us_per_syscall"]),
            "hooked_total_us": ok["hooked"]["us_per_syscall"]}
        if "scope_out" in ok:
            results["split"]["driver_hypercall_us"] = (
                ok["unhooked"]["us_per_syscall"] - ok["scope_out"]["us_per_syscall"])
            results["split"]["kernel_only_us"] = ok["scope_out"]["us_per_syscall"]
        print("\n== split")
        for k, v in results["split"].items():
            print(f"  {k:<26} {v:9.3f} us")

    save()
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
