#!/usr/bin/env python3
"""What does ONE guest syscall cost under full-system emulation, and why?

SUPERSEDED BY speedscheme.py, AND WRONG IN A WAY WORTH KEEPING. Read this first.

This file has a double-invocation bug, left in place because it is the thing to
recognise rather than the thing to reuse. penguin's /igloo/init auto-runs every
executable in /igloo/init.d/* BEFORE igloo_init -- and the drop-in below ALSO
gets invoked explicitly from the generated /init.sh (see ITERS_CHEAP and the
`/igloo/init.d/syscost %(iters)d` line). So it runs twice: once from the
auto-run with NO argv, taking main()'s 5000 default, and once with the real
500000. The parser below takes the FIRST bracket pair it finds, which is the
auto-run's, while the arithmetic divides by 500000. That is a clean factor of
100.

What it printed as a result: 0.010 us per unhooked syscall -- i.e. that the
emulated guest did syscalls thirteen times faster than the host does natively.
I read that impossible number as evidence that the GUEST CLOCK was broken, and
went on to call guest_speed.py and THROUGHPUT.md's 21.0 ms/spawn suspect on the
strength of it. All of that was wrong, and the instrument was the only thing
broken. speedscheme.py measures 1.165 us on a host clock with three controls
passing, and this file's own FIRST run -- before the bug was introduced --
said ~1.10 us. The guest clock agrees with the host clock to 1%.

The lesson is the one that keeps recurring in this lane: an impossible number
indicts the instrument before it indicts the system. speedscheme.py therefore
compiles its iteration count in rather than passing argv (so the auto-run and
the explicit run cannot differ), does not invoke the drop-in from init.sh at
all, and refuses to report a slope unless an injected-delay control comes back.

Original header follows.


`USERMODE.md` puts the qemu-user comparison on a per-syscall slope: full-system
pays ~133 us where user mode pays 0.33 us, so the snapshot loop wins only while
an iteration makes fewer than about six syscalls. That 133 us came from
`hookcost.py` -- a different target, a different architecture, and WITH a
penguin hook attached, so it is an upper bound on a number the whole comparison
turns on. This measures it directly, on bugbench's own architecture, and splits
it into the three things it is actually made of:

  (a) the emulated kernel doing the syscall              -- unavoidable
  (b) + igloo_driver's hypercall on enter and return     -- penguin, always on
  (c) + portal dispatch into a pyplugin hook             -- penguin, per hook

Three runs of one probe, differing in exactly one thing each:

  scope_out    the probe runs OUTSIDE analysis scope, so the driver gates its
               syscall hypercalls off for it.                        -> (a)
  scope_in     the probe runs inside scope, no plugin hooks getpid.  -> (a)+(b)
  hooked       same, plus a pyplugin that counts getpid.             -> (a)+(b)+(c)

METHOD. A compiled drop-in does ITERS outer iterations, each making K getpid()
calls, for several K, printing /proc/uptime between brackets. The SLOPE of time
against K is the per-syscall cost; the intercept is loop overhead and is
discarded. A slope rather than a single point, because a fixed per-bracket cost
would otherwise be read as syscall cost -- the same mistake the user-mode fit
in `usermode_bench.py --syscost` avoids.

getpid() is the probe because it is the cheapest real syscall: no arguments to
marshal, no file table, no memory. Whatever it costs is close to the floor for
ANY syscall, which is the conservative direction for a claim that says syscalls
are expensive. musl does not cache it, so each call is a genuine trap.

Guest /proc/uptime rather than host wall clock, following `guest_speed.py`:
it excludes host-side scheduling of the QEMU process, and the two brackets are
read by the guest itself.

Run: python3 syscost.py -i penguin:fastsnap
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import click
import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
PENGUIN = str(REPO / "penguin")

# Outer iterations per bracket. Sized so the most expensive configuration
# stays inside the timeout: at ~133 us a syscall the K=8 bracket is ~5 s.
KS = [0, 1, 2, 4, 8]

# Outer iterations per bracket, PER CONFIGURATION. /proc/uptime has 10 ms
# granularity, so an unhooked run at 5,000 iterations produced brackets of
# 0.00-0.04 s -- four resolution units, and a number that could not be
# distinguished from its own quantisation. The unhooked configurations
# therefore run 100x longer. The hooked one cannot: at ~94 us a syscall,
# 500,000 iterations would be over an hour.
ITERS_CHEAP = 500_000
ITERS_HOOKED = 5_000

PROBE_C = r"""/* syscost: the per-syscall cost of full-system emulation, measured from
 * inside the guest. Compiled by penguin's init.d drop-in mechanism for the
 * guest architecture; see analysis/fastsnap/syscost.py for what it is for.
 *
 * getpid() is the cheapest real syscall -- no arguments, no file table, no
 * memory -- so what it costs is near the floor for any syscall. That is the
 * conservative direction: a claim that syscalls are expensive should rest on
 * the cheapest one, not a representative one.
 */
#include <fcntl.h>
#include <unistd.h>

static volatile unsigned int sink;

/* Decimal parse; no stdlib, for the same reason stdio is avoided below. */
static int parse_int(const char *s)
{
    int v = 0;

    while (*s >= '0' && *s <= '9') {
        v = v * 10 + (*s - '0');
        s++;
    }
    return v;
}

/* No stdio: it would buffer the markers past the point they are meant to
 * timestamp, and pull a chunk of libc into a probe that is measuring libc's
 * cheapest path. */
static void emit(const char *tag, int len)
{
    char buf[128];
    int fd, n;

    if (write(1, tag, len) < 0) {
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

int main(int argc, char **argv)
{
    static const int ks[] = {%(ks)s};
    int nk = (int)(sizeof ks / sizeof ks[0]);
    int iters = (argc > 1) ? parse_int(argv[1]) : 5000;
    int k, i, j;

    emit("SYSCOST-BEGIN ", 14);
    for (k = 0; k < nk; k++) {
        for (i = 0; i < iters; i++) {
            for (j = 0; j < ks[k]; j++) {
                sink += (unsigned int)getpid();
            }
        }
        emit("SYSCOST-MARK ", 13);
    }
    emit("SYSCOST-END ", 12);
    return 0;
}
"""

# A pyplugin that only counts. The point is to add the portal round trip and
# nothing else, so the difference against `scope_in` is dispatch cost rather
# than the cost of whatever a real hook would then do.
HOOK_PY = '''"""Count getpid. Registers a hook and does nothing with it, so the
difference against an unhooked run is portal dispatch and not the hook's own
work."""
from penguin import Plugin, plugins


class SysCostHook(Plugin):
    def __init__(self) -> None:
        self.n = 0
        plugins.syscalls.syscall("on_sys_getpid_enter")(self.on_getpid)

    def on_getpid(self, regs, proto, syscall, *a):
        self.n += 1
        return
        yield

    def uninit(self):
        self.logger.info(f"syscost_hook: getpid seen {self.n}")
'''

INIT_SH = """#!/igloo/utils/sh
/busybox echo "[syscost] init up"
/igloo/init.d/syscost %(iters)d
/busybox echo "[syscost] probe done"
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


def parse(log_text):
    """Uptime deltas between markers, in seconds, one per K."""
    ups = [float(m.group(1)) for m in
           re.finditer(r"SYSCOST-(?:BEGIN|MARK|END)\s+([0-9.]+)", log_text)]
    if len(ups) < len(KS) + 1:
        return None
    return [ups[i + 1] - ups[i] for i in range(len(KS))]


def fit(ks, secs, iters):
    """Least squares; the slope is us per syscall, the intercept loop
    overhead per bracket and not interesting."""
    n = len(ks)
    mx = sum(ks) / n
    my = sum(secs) / n
    denom = sum((x - mx) ** 2 for x in ks)
    slope = sum((x - mx) * (y - my) for x, y in zip(ks, secs)) / denom
    return slope / iters * 1e6, (my - slope * mx) / iters * 1e6


def clockcheck(image, work, proj, iters_lo, iters_hi):
    """Is the guest's clock telling the truth?

    THE INSTRUMENT CANNOT ESTABLISH ITS OWN FRAME. /proc/uptime measures GUEST
    time, and under emulation guest time is not host time: timer ticks are
    delivered by an emulated device that a loaded TCG guest can fail to keep up
    with, so jiffies -- and everything derived from them -- run slow. A bracket
    read that way understates every cost in proportion, silently, and the
    result still looks linear and reproducible.

    It caught this experiment: the guest reported 4,000,000 getpid calls in
    0.04 s, which would make an emulated MIPS guest 13x faster than the x86
    host running the identical probe (measured, 130-160 ns per call). That is
    impossible, so the clock is wrong rather than the guest fast.

    So: run the SAME configuration at two iteration counts and difference the
    HOST wall clock. Boot, image load and teardown are common to both and
    cancel. What is left is the real cost of the extra syscalls, in a clock
    that is not part of what is being measured.
    """
    import time as _time

    out = {}
    for tag, iters in (("lo", iters_lo), ("hi", iters_hi)):
        patch = {
            "core": {"analysis_scope": "none", "timeout": 600, "mem": "256M",
                     "root_shell": False},
            "env": {"igloo_init": "/init.sh"},
            "static_files": {"/init.sh": {"type": "inline_file", "mode": 493,
                                          "contents": INIT_SH % {"iters": iters}}},
            "plugins": {"vpn": {"enabled": False}},
        }
        (proj / "patch_syscost.yaml").write_text(yaml.dump(patch, sort_keys=False))
        log = work / f"clockcheck_{tag}.txt"
        t0 = _time.time()
        penguin(image, "run", str(proj / "config.yaml"), cwd=work, log=log)
        wall = _time.time() - t0
        text = log.read_text(errors="replace")
        console = proj / "results/latest/console.log"
        if console.exists():
            text += console.read_text(errors="replace")
        secs = parse(text)
        guest = sum(secs) if secs else None
        out[tag] = {"iters": iters, "host_wall_s": wall, "guest_probe_s": guest}
        print(f"  {tag}: iters={iters:,}  host wall {wall:.1f} s  "
              f"guest probe {guest if guest is None else round(guest, 3)} s")

    d_calls = (iters_hi - iters_lo) * sum(KS)
    d_host = out["hi"]["host_wall_s"] - out["lo"]["host_wall_s"]
    out["extra_syscalls"] = d_calls
    out["host_us_per_syscall"] = d_host / d_calls * 1e6
    if out["hi"]["guest_probe_s"] is not None and out["lo"]["guest_probe_s"] is not None:
        d_guest = out["hi"]["guest_probe_s"] - out["lo"]["guest_probe_s"]
        out["guest_us_per_syscall"] = d_guest / d_calls * 1e6
        out["guest_clock_understates_by"] = (d_host / d_guest) if d_guest else None
    print(f"\n  {d_calls:,} extra syscalls cost {d_host:.1f} s of HOST time "
          f"= {out['host_us_per_syscall']:.3f} us each")
    if "guest_clock_understates_by" in out and out["guest_clock_understates_by"]:
        print(f"  the guest clock understates that by "
              f"{out['guest_clock_understates_by']:.1f}x")
    return out


@click.command()
@click.option("--image", "-i", default="penguin:fastsnap")
@click.option("--clock-check", is_flag=True,
              help="validate the guest clock against host wall time and stop")
@click.option("--arch", "-a", default="mipsel", help="bugbench's architecture")
@click.option("--out", default="result_syscost.json")
def main(image, arch, out, clock_check):
    work = HERE / "work_syscost"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    fs = work / "fs"
    fs.mkdir()
    cid = subprocess.check_output(f"docker create {image}", shell=True).decode().strip()
    subprocess.run(f"docker cp -L {cid}:/igloo_static/utils.bin/busybox.{arch} {fs}/busybox",
                   shell=True, check=True)
    subprocess.run(f"docker rm -v {cid}", shell=True, check=True,
                   stdout=subprocess.DEVNULL)
    subprocess.run(f"tar -czf {work}/fs.tar.gz -C {fs} .", shell=True, check=True)
    penguin(image, "init", f"{work}/fs.tar.gz", "--force",
            cwd=work, log=work / "init.txt")

    proj = work / "projects/fs"
    (proj / "init.d").mkdir(parents=True, exist_ok=True)
    (proj / "init.d/syscost.c").write_text(
        PROBE_C % {"ks": ", ".join(str(k) for k in KS)})
    (proj / "plugins.d").mkdir(parents=True, exist_ok=True)

    results = {}
    # The fourth configuration is the CONTROL, and the split is worthless
    # without it. scope_out and scope_in came back indistinguishable, which has
    # two readings: the driver's hypercall really is free, or `analysis_scope`
    # never gated anything and both runs measured the same thing. A hook under
    # scope=firmware decides it -- if scope gates, the hook sees none of the
    # probe's getpid calls and the slope collapses to the unhooked one.
    for label, scope, hooked, iters in (("scope_out", "firmware", False, ITERS_CHEAP),
                                        ("scope_in", "none", False, ITERS_CHEAP),
                                        ("hooked", "none", True, ITERS_HOOKED),
                                        ("hooked_scope_out", "firmware", True, ITERS_HOOKED)):
        hook = proj / "plugins.d/syscost_hook.py"
        if hooked:
            hook.write_text(HOOK_PY)
        elif hook.exists():
            hook.unlink()

        patch = {
            "core": {"analysis_scope": scope, "timeout": 300, "mem": "256M",
                     "root_shell": False},
            "env": {"igloo_init": "/init.sh"},
            "static_files": {"/init.sh": {"type": "inline_file", "mode": 493,
                                          "contents": INIT_SH % {"iters": iters}}},
            "plugins": {"vpn": {"enabled": False}},
        }
        (proj / "patch_syscost.yaml").write_text(yaml.dump(patch, sort_keys=False))
        cfg_p = proj / "config.yaml"
        cfg = yaml.safe_load(cfg_p.read_text())
        if "patch_syscost.yaml" not in (cfg.get("patches") or []):
            cfg.setdefault("patches", []).append("patch_syscost.yaml")
        cfg_p.write_text(yaml.dump(cfg, sort_keys=False))

        log = work / f"run_{label}.txt"
        penguin(image, "run", str(cfg_p), cwd=work, log=log)
        text = log.read_text(errors="replace")
        console = proj / "results/latest/console.log"
        if console.exists():
            text += console.read_text(errors="replace")
        secs = parse(text)
        if secs is None:
            print(f"  {label}: NO MARKERS -- the probe did not run or did not "
                  f"reach the console; see {log}")
            results[label] = None
            continue
        us, base = fit(KS, secs, iters)
        seen = None
        for line in text.splitlines():
            if "syscost_hook: getpid seen" in line:
                seen = int(line.split()[-1])
        results[label] = {"bracket_s": secs, "us_per_syscall": us,
                          "base_us_per_iter": base, "scope": scope,
                          "hooked": hooked, "iters": iters,
                          "hook_saw_getpid": seen}
        print(f"  {label:<17} {us:8.3f} us/syscall   (loop {base:.4f} us/iter"
              f"{'' if seen is None else f', hook saw {seen:,}'})")

    got = {k: v for k, v in results.items() if v}
    if {"scope_out", "scope_in", "hooked"} <= set(got):
        a = got["scope_out"]["us_per_syscall"]
        ab = got["scope_in"]["us_per_syscall"]
        abc = got["hooked"]["us_per_syscall"]
        results["split"] = {"emulated_kernel_us": a,
                            "driver_hypercall_us": ab - a,
                            "pyplugin_dispatch_us": abc - ab,
                            "total_hooked_us": abc}
        print(f"\n  emulated kernel      {a:8.2f} us")
        print(f"  + driver hypercall   {ab - a:+8.2f} us")
        print(f"  + pyplugin dispatch  {abc - ab:+8.2f} us")
        print(f"  = hooked syscall     {abc:8.2f} us")

    (HERE / out).write_text(json.dumps(results, indent=2))
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
