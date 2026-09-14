#!/usr/bin/env python3
"""Price this lane's victim under qemu-user, against the full-system loop.

`LOOP-RESULTS.md` answers "how fast can a whole emulated system be rewound".
It does not answer the question anyone choosing a fuzzing architecture asks
first: is that faster than not emulating the system at all? qemu-user runs the
binary and passes syscalls to the host -- no kernel, no device model, no system
state -- and a fresh process per input is already a reset.

FOUR SHAPES, each isolating one mechanism:

  floor    spawn the one-shot victim on EMPTY input. It reads, gets 0, exits.
           Everything measured is process creation, ELF load and translation --
           the cost a forkserver exists to pay once.
  spawn    the same, with one real record. floor plus one parse.
  fork     one child per record, forked from a warm parent. AFL's forkserver
           shape and the honest competitor to a snapshot reset.
  persist  every record in one process, nothing reset between them. The upper
           bound for user mode, and the counterpart of the loop's `bare` arm.

THE RUNNERS MATTER MORE THAN THEY LOOK. A distro qemu-user is a different QEMU
from the one penguin runs -- 6.2.0 against 11.1.0 here -- and TCG codegen moved
a long way between them. The `igloo` rows below are built from penguin's OWN
tree: the v11.1.0 tarball, the 17-patch IGLOO series, and `qemu_builder/src`
overlaid, configured `--target-list=arm-linux-user,mipsel-linux-user`.

That build needs one stub. The series routes guest hypercalls into Penguin from
the per-target TCG helpers and does not guard it with CONFIG_USER_ONLY, so a
linux-user target compiles the call and fails to link against
`penguin_handle_guest_hypercall`, which lives in system-mode-only
`system/penguin.c`. Appending a stub returning false -- "not handled, take the
normal path", which is what user mode means -- links it without touching the
translate path, so codegen still matches penguin's QEMU.

Environment (rows whose tools are absent are skipped and named):

  IGLOO_QEMU_BUILD     dir holding qemu-arm / qemu-mipsel built from penguin's tree
  STOCK_QEMU_BUILD     the same, built from the pristine v11.1.0 tarball
  MIPSEL_GCC           mipsel cross compiler
  MIPSEL_LDFLAGS       e.g. -L<static glibc>/lib

Run:  python3 usermode_bench.py --reps 3 --scale --json result_usermode_bench.json
"""

import argparse
import json
import os
import shutil
import statistics
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

SHAPES = ["floor", "spawn", "fork", "persist"]

# Resident sizes for the scaling sweep, in MB. fork() copies the page tables of
# everything mapped, so its per-iteration cost grows with the address space; a
# dirty-page reset pays for what the iteration wrote. 256 MB is bugbench's own
# guest size, which makes that point directly comparable to the loop.
SCALE_MB = [0, 1, 2, 4, 8, 12, 16, 32, 64, 256, 1024]

# LOOP-RESULTS.md, bugbench `loop` arm, mipsel, 256 MB guest: 0.7243 ms per
# iteration of which 404 us is the reset itself, 23 pages restored.
FASTSNAP_RESET_MS = 0.404
FASTSNAP_ITER_MS = 0.7243

SEED_N = {"floor": 300, "spawn": 300, "fork": 2000, "persist": 200000}
MIN_WALL = 1.5      # seconds a timed run must cover before it is believed
MAX_N = 20_000_000


def discover_targets():
    """Build the row set from what is actually installed, and say what is not.

    Returned in comparison order: the native ceiling, the distro qemu-user that
    a reader would otherwise reach for, then penguin's own QEMU at the loop's
    own architecture."""
    igloo = os.environ.get("IGLOO_QEMU_BUILD", "")
    stock = os.environ.get("STOCK_QEMU_BUILD", "")
    mips_gcc = os.environ.get("MIPSEL_GCC") or shutil.which(
        "mipsel-unknown-linux-gnu-gcc") or shutil.which("mipsel-linux-gnu-gcc")
    mips_ld = os.environ.get("MIPSEL_LDFLAGS", "").split()

    rows, skipped = [], []

    def add(label, cc, ldflags, runner, note):
        if cc and not shutil.which(cc) and not os.path.exists(cc):
            skipped.append(f"{label}: compiler {cc} not found")
            return
        if runner and not os.path.exists(runner[0]):
            skipped.append(f"{label}: runner {runner[0]} not found")
            return
        rows.append({"label": label, "cc": cc, "ldflags": ldflags,
                     "runner": runner, "note": note})

    def qemu(build_dir, binary):
        return [os.path.join(build_dir, binary)] if build_dir else [binary]

    add("x86-64", "gcc", [], [], "native, no emulation")
    add("armel/qemu6.2", "arm-linux-gnueabi-gcc", [],
        [shutil.which("qemu-arm-static") or "qemu-arm-static"],
        "distro qemu-user, a DIFFERENT QEMU from the one penguin runs")
    # stock and igloo are the same tarball and the same configure line; the
    # only delta is the 17-patch series and the vendored src/ overlay. That
    # pair is what separates "the patches cost something" from "the version
    # does", and stock is also the fairest competitor -- a user-mode fuzzer
    # would not be carrying IGLOO patches.
    add("armel/stock11.1", "arm-linux-gnueabi-gcc", [],
        qemu(stock, "qemu-arm"), "upstream 11.1.0, no IGLOO series")
    add("armel/igloo11.1", "arm-linux-gnueabi-gcc", [],
        qemu(igloo, "qemu-arm"), "penguin's QEMU tree, user mode")
    add("mipsel/stock11.1", mips_gcc or "", mips_ld,
        qemu(stock, "qemu-mipsel"),
        "upstream 11.1.0 at the loop's own architecture")
    add("mipsel/igloo11.1", mips_gcc or "", mips_ld,
        qemu(igloo, "qemu-mipsel"),
        "penguin's QEMU tree AND the loop's own architecture")
    return rows, skipped


def runner_version(runner):
    if not runner:
        return "native"
    out = subprocess.run(runner + ["--version"], capture_output=True, text=True)
    return out.stdout.strip().splitlines()[0] if out.stdout else "?"


def build(rows, outdir):
    """Compile both victim modes for every row. Static, so qemu-user needs no
    sysroot and the dynamic loader is not in the measurement."""
    os.makedirs(outdir, exist_ok=True)
    built = {}
    for row in rows:
        for mode, define in (("bench", "BUGBENCH_BENCH"), ("stdin", "BUGBENCH_STDIN")):
            path = os.path.join(outdir, f"victim_{mode}_{row['label'].replace('/', '_')}")
            cmd = [row["cc"], "-static", "-O2", f"-D{define}"] + row["ldflags"] + \
                  [VICTIM, "-o", path]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                raise SystemExit(f"build failed: {' '.join(cmd)}\n{r.stderr}")
            built[(row["label"], mode)] = path
    return built


def records_file(outdir, n):
    """One file of n records, reused across reps so file creation is never in a
    timed window."""
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
        pid = os.posix_spawn(argv[0], argv, os.environ,
                             file_actions=[(os.POSIX_SPAWN_DUP2, r, 0)])
        os.close(r)
        os.waitpid(pid, 0)
    return time.perf_counter() - t0


def time_stream(argv, path, n):
    """One process consuming n records from a file on stdin. The victim reports
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


def run_shape(row, built, outdir, shape, reps):
    """Adaptive: grow n until one rep covers MIN_WALL, then take the median of
    `reps` runs at that size."""
    label, prefix = row["label"], row["runner"]
    n = SEED_N[shape]
    while True:
        if shape in ("floor", "spawn"):
            argv = prefix + [built[(label, "stdin")]]
            walls = [time_spawn(argv, n, RECORD if shape == "spawn" else b"")
                     for _ in range(reps)]
        else:
            argv = prefix + [built[(label, "bench")], shape]
            walls = [time_stream(argv, records_file(outdir, n), n) for _ in range(reps)]
        med = statistics.median(walls)
        if med >= MIN_WALL or n >= MAX_N:
            break
        n = min(MAX_N, max(n * 2, int(n * (MIN_WALL / max(med, 1e-6)) * 1.3)))
    return {"n": n, "wall_med_s": med, "per_exec_ms": med / n * 1e3,
            "exec_s": n / med, "spread": max(walls) / min(walls)}


# Extra syscalls per record for the per-syscall sweep. The comparison against
# the loop turns on cost PER SYSCALL: full-system pays ~133 us for a hooked one
# (hookcost.py, cheapest frequent bracket) against whatever this measures.
SYSCALLS_N = [0, 1, 2, 4, 8, 16, 32]


def run_syscost(rows, built, outdir, reps, n=200000):
    """User-mode cost per guest syscall, from the slope of persist against
    extra getpid() calls per record. An intercept-and-slope fit rather than a
    single point, so a per-record fixed cost cannot be read as syscall cost."""
    path = records_file(outdir, n)
    out = {}
    for row in rows:
        pts = []
        for extra in SYSCALLS_N:
            argv = row["runner"] + [built[(row["label"], "bench")],
                                    "persist", "0", str(extra)]
            walls = [time_stream(argv, path, n) for _ in range(reps)]
            med = statistics.median(walls)
            pts.append((extra, med / n * 1e6))        # us per record
            out[f"{row['label']}/+{extra}"] = {
                "extra_syscalls": extra, "per_record_us": med / n * 1e6,
                "spread": max(walls) / min(walls)}
        # Least squares through the points; the slope is the per-syscall cost.
        xs = [a for a, _ in pts]
        ys = [b for _, b in pts]
        mx = sum(xs) / len(xs)
        my = sum(ys) / len(ys)
        denom = sum((x - mx) ** 2 for x in xs)
        slope = sum((x - mx) * (y - my) for x, y in zip(xs, ys)) / denom
        out[f"{row['label']}/slope_us_per_syscall"] = slope
        out[f"{row['label']}/intercept_us"] = my - slope * mx
        sys.stderr.write(f"  {row['label']:<18} {slope:.4f} us/syscall, "
                         f"base {my - slope * mx:.4f} us/record\n")
    return out


def run_scale(rows, built, outdir, reps, n=3000):
    """Fork cost against resident address-space size -- the axis the shape table
    cannot show, because at one record size every mechanism looks constant."""
    path = records_file(outdir, n)
    out = {}
    for row in rows:
        for mb in SCALE_MB:
            argv = row["runner"] + [built[(row["label"], "bench")], "fork", str(mb)]
            walls = [time_stream(argv, path, n) for _ in range(reps)]
            med = statistics.median(walls)
            out[f"{row['label']}/{mb}MB"] = {
                "touch_mb": mb, "per_fork_ms": med / n * 1e3,
                "exec_s": n / med, "spread": max(walls) / min(walls)}
            sys.stderr.write(f"  {row['label']:<18} touch={mb:>5} MB  "
                             f"{med / n * 1e3:>8.4f} ms/fork  {n / med:>9,.0f} exec/s\n")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--syscost", action="store_true",
                    help="also fit user-mode cost per guest syscall")
    ap.add_argument("--scale", action="store_true",
                    help="also sweep fork cost against resident address size")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--json", default=None)
    ap.add_argument("--outdir", default="/tmp/usermode_bench")
    args = ap.parse_args()

    rows, skipped = discover_targets()
    for s in skipped:
        sys.stderr.write(f"  SKIP {s}\n")
    if not rows:
        raise SystemExit("no runnable configurations")

    versions = {r["label"]: runner_version(r["runner"]) for r in rows}
    for label, v in versions.items():
        sys.stderr.write(f"  {label:<18} {v}\n")

    built = build(rows, args.outdir)
    results = {}
    for row in rows:
        for shape in SHAPES:
            key = f"{row['label']}/{shape}"
            sys.stderr.write(f"  {key} ... ")
            sys.stderr.flush()
            results[key] = run_shape(row, built, args.outdir, shape, args.reps)
            sys.stderr.write(f"{results[key]['exec_s']:,.0f} exec/s\n")

    print(f"\n{'config':<26}{'n':>10}{'per exec':>13}{'exec/s':>14}{'spread':>9}")
    for key, r in results.items():
        print(f"{key:<26}{r['n']:>10,}{r['per_exec_ms']:>11.4f} ms"
              f"{r['exec_s']:>14,.0f}{r['spread']:>8.2f}x")

    syscost = run_syscost(rows, built, args.outdir, args.reps) if args.syscost else {}
    scale = run_scale(rows, built, args.outdir, args.reps) if args.scale else {}
    if scale:
        print(f"\n{'fork vs resident':<26}{'per fork':>13}{'exec/s':>14}")
        for key, r in scale.items():
            cross = "  < snapshot reset" if r["per_fork_ms"] < FASTSNAP_RESET_MS else ""
            print(f"{key:<26}{r['per_fork_ms']:>11.4f} ms{r['exec_s']:>14,.0f}{cross}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"records": results, "scale": scale, "syscost": syscost,
                       "reps": args.reps,
                       "runners": versions,
                       "toolchains": {r["label"]: r["cc"] for r in rows},
                       "skipped": skipped,
                       "fastsnap_reset_ms": FASTSNAP_RESET_MS,
                       "fastsnap_iter_ms": FASTSNAP_ITER_MS}, fh, indent=2)
        print(f"\nwrote {args.json}")


if __name__ == "__main__":
    main()
