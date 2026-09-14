#!/usr/bin/env python3
"""Price this lane's victim under qemu-user, against the full-system loop.

The loop's numbers in `LOOP-RESULTS.md` answer "how fast can a whole emulated
system be rewound". They do not answer "is that faster than not emulating the
system at all", which is the question anyone choosing a fuzzing architecture
asks first. qemu-user is the standard alternative: it emulates the binary and
passes syscalls to the host, so there is no kernel, no device model and no
system state -- and a fresh process per input is already a reset.

WHAT THIS CAN AND CANNOT SAY. The victim is a static, single-threaded parser
that reads a buffer and dispatches on one byte. That is the best case for
qemu-user and it is why bugbench is the only target here that can run both
ways: targets A, B and C are vendor daemons that reach NVRAM, ioctls, device
nodes and a network stack, and qemu-user cannot run them at all. So this
measures the price of full-system fidelity on a program that does not need it.
It is a floor on what fidelity costs, not a verdict on whether to pay it.

Four shapes, chosen so each one isolates a mechanism:

  floor    spawn the one-shot victim on EMPTY input. It reads, gets 0, exits.
           Everything measured is process creation, ELF load and translation --
           the cost a forkserver exists to pay once.
  spawn    the same, with one real record. floor plus one parse: naive
           per-input execution, no forkserver.
  fork     one child per record, forked from a warm parent. AFL's forkserver
           shape and the honest competitor to a snapshot reset.
  persist  every record in one process, nothing reset between them. The upper
           bound for user mode, and the counterpart of the loop's `bare` arm.

Run:  python3 usermode_bench.py [--reps 3] [--json out.json]
"""

import argparse
import json
import os
import statistics
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
VICTIM = os.path.join(HERE, "bugbench_victim.c")

# Opcode 0x00 is the victim's declared negative control: it sums the record and
# returns, and must never fault. A rate measured on crashing input would be a
# measurement of each mechanism's crash handling instead -- and those differ by
# two orders of magnitude (an ordinary loop lap is 1.119 ms, a crash-closed one
# 43.70 ms), which would swamp the thing being compared.
RECORD = bytes([0x00] + [0x01] * 15)

# posix_spawn does not search PATH, and a runner resolved per call would put a
# PATH walk inside the timed loop, so every runner is resolved to an absolute
# path once, here.
TARGETS = [
    # label      compiler                    runner prefix
    ("x86-64",   "gcc",                      []),
    ("armel",    "arm-linux-gnueabi-gcc",    ["qemu-arm-static"]),
]
TARGETS = [
    (label, cc, [shutil.which(p) or p for p in prefix])
    for label, cc, prefix in TARGETS
]

SHAPES = ["floor", "spawn", "fork", "persist"]

# Resident sizes for the scaling sweep, in MB. fork() copies the page tables of
# everything mapped, so its per-iteration cost grows with the address space; a
# dirty-page reset pays for what the iteration wrote. 256 MB is bugbench's own
# guest size, which makes the last point directly comparable to the loop.
SCALE_MB = [0, 1, 2, 4, 8, 12, 16, 32, 64, 256, 1024]

# LOOP-RESULTS.md, bugbench `loop` arm: 0.7243 ms per iteration of which 404 us
# is the reset itself, 23 pages restored, 256 MB guest.
FASTSNAP_RESET_MS = 0.404
FASTSNAP_ITER_MS = 0.7243

# Starting record counts. Adaptive from here, so these only need to be within
# an order of magnitude of right.
SEED_N = {"floor": 300, "spawn": 300, "fork": 2000, "persist": 200000}
MIN_WALL = 1.5      # seconds a timed run must cover before it is believed
MAX_N = 20_000_000


def build(outdir):
    """Compile both victim modes for every target. Static, so qemu-user needs
    no sysroot and the dynamic loader is not in the measurement."""
    os.makedirs(outdir, exist_ok=True)
    built = {}
    for label, cc, _ in TARGETS:
        for mode, define in (("bench", "BUGBENCH_BENCH"), ("stdin", "BUGBENCH_STDIN")):
            path = os.path.join(outdir, f"victim_{mode}_{label}")
            cmd = [cc, "-static", "-O2", f"-D{define}", VICTIM, "-o", path]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                raise SystemExit(f"build failed: {' '.join(cmd)}\n{r.stderr}")
            built[(label, mode)] = path
    return built


def records_file(outdir, n):
    """One file of n records, reused across reps so file creation is never in
    a timed window."""
    path = os.path.join(outdir, f"records_{n}.bin")
    if not os.path.exists(path):
        with open(path, "wb") as fh:
            fh.write(RECORD * n)
    return path


def time_spawn(argv, n, record):
    """n process spawns, one input each. posix_spawn rather than subprocess:
    subprocess.Popen costs ~1 ms of Python per call, which would be most of a
    native spawn. What is left is a few tens of microseconds of interpreter per
    iteration -- real, and noted in the writeup, but not dominant."""
    t0 = time.perf_counter()
    for _ in range(n):
        r, w = os.pipe()
        if record:
            os.write(w, record)
        os.close(w)
        pid = os.posix_spawn(
            argv[0], argv, os.environ,
            file_actions=[(os.POSIX_SPAWN_DUP2, r, 0)],
        )
        os.close(r)
        os.waitpid(pid, 0)
    return time.perf_counter() - t0


def time_stream(argv, path, n):
    """One process consuming n records from a file on stdin. The victim prints
    what it consumed; a run that read nothing must not read as an instant one."""
    with open(path, "rb") as fh:
        t0 = time.perf_counter()
        p = subprocess.run(argv, stdin=fh, capture_output=True)
        wall = time.perf_counter() - t0
    if p.returncode != 0:
        raise SystemExit(f"{argv} exited {p.returncode}: {p.stderr[:200]!r}")
    got = int(p.stderr.strip().split()[-1])
    if got != n:
        raise SystemExit(f"{argv} consumed {got} records, expected {n}")
    return wall


def run_shape(label, prefix, built, outdir, shape, reps):
    """Adaptive: grow n until a single rep covers MIN_WALL, then take the
    median of `reps` runs at that size."""
    n = SEED_N[shape]
    while True:
        if shape in ("floor", "spawn"):
            argv = prefix + [built[(label, "stdin")]]
            rec = RECORD if shape == "spawn" else b""
            walls = [time_spawn(argv, n, rec) for _ in range(reps)]
        else:
            argv = prefix + [built[(label, "bench")], shape]
            path = records_file(outdir, n)
            walls = [time_stream(argv, path, n) for _ in range(reps)]
        med = statistics.median(walls)
        if med >= MIN_WALL or n >= MAX_N:
            break
        n = min(MAX_N, max(n * 2, int(n * (MIN_WALL / max(med, 1e-6)) * 1.3)))
    return {
        "n": n,
        "wall_med_s": med,
        "per_exec_ms": med / n * 1e3,
        "exec_s": n / med,
        "spread": max(walls) / min(walls),
    }


def run_scale(built, outdir, reps, n=3000):
    """Fork cost against resident address-space size, which is the axis the
    shape comparison above cannot show: at bugbench's own record size every
    mechanism looks like a constant."""
    path = records_file(outdir, n)
    rows = {}
    for label, _, prefix in TARGETS:
        for mb in SCALE_MB:
            argv = prefix + [built[(label, "bench")], "fork", str(mb)]
            walls = [time_stream(argv, path, n) for _ in range(reps)]
            med = statistics.median(walls)
            rows[f"{label}/{mb}MB"] = {
                "touch_mb": mb,
                "per_fork_ms": med / n * 1e3,
                "exec_s": n / med,
                "spread": max(walls) / min(walls),
            }
            sys.stderr.write(f"  {label:<8} touch={mb:>5} MB  "
                             f"{med / n * 1e3:>8.4f} ms/fork  {n / med:>9,.0f} exec/s\n")
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scale", action="store_true",
                    help="also sweep fork cost against resident address size")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--json", default=None)
    ap.add_argument("--outdir", default="/tmp/usermode_bench")
    args = ap.parse_args()

    built = build(args.outdir)
    results = {}
    for label, _, prefix in TARGETS:
        for shape in SHAPES:
            key = f"{label}/{shape}"
            sys.stderr.write(f"  {key} ... ")
            sys.stderr.flush()
            results[key] = run_shape(label, prefix, built, args.outdir, shape, args.reps)
            sys.stderr.write(f"{results[key]['exec_s']:,.0f} exec/s\n")

    print(f"\n{'config':<18}{'n':>10}{'per exec':>13}{'exec/s':>14}{'spread':>9}")
    for key, r in results.items():
        print(f"{key:<18}{r['n']:>10,}{r['per_exec_ms']:>11.4f} ms"
              f"{r['exec_s']:>14,.0f}{r['spread']:>8.2f}x")

    scale = run_scale(built, args.outdir, args.reps) if args.scale else {}
    if scale:
        print(f"\n{'fork vs resident':<18}{'per fork':>13}{'exec/s':>14}")
        for key, r in scale.items():
            cross = "  < snapshot reset" if r["per_fork_ms"] < FASTSNAP_RESET_MS else ""
            print(f"{key:<18}{r['per_fork_ms']:>11.4f} ms{r['exec_s']:>14,.0f}{cross}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"records": results, "scale": scale, "reps": args.reps,
                       "fastsnap_reset_ms": FASTSNAP_RESET_MS,
                       "fastsnap_iter_ms": FASTSNAP_ITER_MS}, fh, indent=2)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
