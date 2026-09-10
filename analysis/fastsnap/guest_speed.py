#!/usr/bin/env python3
"""How much guest work does a fuzz iteration cost?

The fastsnap draft argues restore is worth optimising. That is only true if
restore is a large fraction of a fuzzing iteration -- and nobody has measured
the other term. This measures guest-side work rate under TCG with penguin's
normal plugin stack: process spawn rate, and shell-loop rate.

A fuzz iteration against a network daemon costs at least one request handled;
these two rates bracket what that costs.
"""
import re, shutil, subprocess, sys, time
from pathlib import Path
import click, yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
PENGUIN = str(REPO / "penguin")
WORK = HERE / "work_speed"

# Two workloads, each printing a marker with the guest's own uptime either side.
INIT_SH = """#!/igloo/utils/sh
/busybox echo "SPEED-BEGIN"
/busybox cat /proc/uptime
i=0
while [ $i -lt 200 ]; do
  /busybox true
  i=$(($i+1))
done
/busybox echo "SPEED-EXEC-DONE"
/busybox cat /proc/uptime
j=0
while [ $j -lt 20000 ]; do
  j=$(($j+1))
done
/busybox echo "SPEED-LOOP-DONE"
/busybox cat /proc/uptime
while true; do /busybox sleep 1; done
"""


def penguin(image, *args, log_name="speed.txt"):
    cmd = " ".join([PENGUIN, "--image", image, *args])
    print(f"$ {cmd}")
    return subprocess.run(cmd, cwd=WORK, shell=True,
                          stdout=open(WORK / log_name, "w"),
                          stderr=subprocess.STDOUT).returncode


@click.command()
@click.option("--image", "-i", default="rehosting/penguin:v3.1.14")
@click.option("--arch", "-a", default="armel")
@click.option("--kernel", "-k", default="4.10")
@click.option("--lean/--full", default=False,
              help="disable analysis plugins a fuzzing profile would not need")
@click.option("--label", default="full")
def main(image, arch, kernel, lean, label):
    global WORK
    WORK = HERE / f"work_speed_{label}"
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    fs = WORK / "fs"; fs.mkdir()
    cid = subprocess.check_output(f"docker create {image}", shell=True).decode().strip()
    subprocess.run(f"docker cp -L {cid}:/igloo_static/utils.bin/busybox.{arch} {fs}/busybox",
                   shell=True, check=True)
    subprocess.run(f"docker rm -v {cid}", shell=True, check=True,
                   stdout=subprocess.DEVNULL)
    subprocess.run(f"tar -czf {WORK}/fs.tar.gz -C {fs} .", shell=True, check=True)
    penguin(image, "init", f"{WORK}/fs.tar.gz", "--force", log_name="init.txt")

    proj = WORK / "projects/fs"
    patch = {
        "env": {"igloo_init": "/speed.sh"},
        "core": {"kernel": str(kernel), "timeout": 120},
        "plugins": {"vpn": {"enabled": False}},
        "static_files": {"/speed.sh": {"type": "inline_file", "mode": 73,
                                       "contents": INIT_SH}},
    }
    if lean:
        # Everything a throughput profile would switch off: per-syscall and
        # per-exec analysis, coverage, health accounting, device discovery.
        for name in ("crashes", "health", "indiv_debug", "interfaces",
                     "lifeguard", "netbinds", "nvram2", "pseudofiles",
                     "shell", "mount", "core_pattern_guard", "scope",
                     "snapshot", "nmap"):
            patch["plugins"][name] = {"enabled": False}
    (proj / "patch_speed.yaml").write_text(yaml.dump(patch, sort_keys=False))
    cfg_p = proj / "config.yaml"
    cfg = yaml.safe_load(cfg_p.read_text())
    cfg.setdefault("patches", []).append("patch_speed.yaml")
    cfg_p.write_text(yaml.dump(cfg, sort_keys=False))

    penguin(image, "run", str(cfg_p), log_name="run.txt")

    console = proj / "results/latest/console.log"
    if not console.exists():
        print("no console.log"); sys.exit(1)
    text = console.read_text(errors="replace")
    # Guest uptime lines follow each marker.
    marks = re.findall(r"SPEED-(BEGIN|EXEC-DONE|LOOP-DONE)\s+([0-9.]+)", text)
    if len(marks) < 3:
        print("markers not found; console tail:")
        print("\n".join(text.splitlines()[-25:])); sys.exit(1)
    t = {m[0]: float(m[1]) for m in marks}
    exec_s = t["EXEC-DONE"] - t["BEGIN"]
    loop_s = t["LOOP-DONE"] - t["EXEC-DONE"]
    print(f"\n  200 x fork+exec  : {exec_s*1000:8.1f} ms  "
          f"-> {200/exec_s:7.1f} spawns/s  ({exec_s*1000/200:.2f} ms each)")
    print(f"  20000 shell iters: {loop_s*1000:8.1f} ms  "
          f"-> {20000/loop_s:7.0f} iters/s")


if __name__ == "__main__":
    main()
