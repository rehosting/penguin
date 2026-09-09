#!/usr/bin/env python3
"""Driver for the fastsnap restore-cost measurement.

Builds a minimal busybox project, drops in the bench_snapshot plugin, and runs
one guest that (1) proves the sampler can see a stall of known size, then
(2) times a savevm and N loadvm cycles.

Usage:
  python3 run_bench.py -i rehosting/penguin:latest [-a armel] [-k 4.10]
                       [--mem 256M] [--iters 5] [--label baseline]
"""
import json
import logging
import shutil
import subprocess
import sys
from pathlib import Path

import click
import yaml

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%H:%M:%S")
log = logging.getLogger("fastsnap.bench")

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent                      # penguin repo root
PENGUIN = str(REPO / "penguin")
WORK = HERE / "work"

# Syscall-dense workload: `yes > /dev/null` is a tight write() loop, which is
# what gives the sampler its sub-millisecond resolution. The sleep loop just
# keeps init alive.
INIT_SH = """#!/igloo/utils/sh
/busybox echo "bench-init up"
/busybox yes > /dev/null &
while true; do /busybox sleep 1; done
"""


def sh(cmd, **kw):
    log.info(f"$ {cmd}")
    return subprocess.run(cmd, shell=True, check=True, **kw)


def penguin(image, *args, log_name="bench.txt"):
    cmd = " ".join([PENGUIN, "--image", image, *args])
    log.info(f"$ {cmd}")
    rc = subprocess.run(cmd, cwd=WORK, shell=True,
                        stdout=open(WORK / log_name, "w"),
                        stderr=subprocess.STDOUT)
    if rc.returncode != 0:
        subprocess.run(["tail", "-n", "60", str(WORK / log_name)])
    return rc.returncode


def build_project(image, arch):
    fs = WORK / "fs"
    (fs / "bin").mkdir(parents=True, exist_ok=True)
    cid = subprocess.check_output(f"docker create {image}",
                                  shell=True).decode().strip()
    sh(f"docker cp -L {cid}:/igloo_static/utils.bin/busybox.{arch} {fs}/busybox")
    sh(f"docker rm -v {cid}")
    sh(f"tar -czf {WORK}/empty_fs.tar.gz -C {fs} .")
    penguin(image, "init", f"{WORK}/empty_fs.tar.gz", "--force",
            log_name="bench_init.txt")
    return WORK / "projects/empty_fs"


def write_patch(project, kernel, mem, iters, control_ms, timeout):
    patch = {
        "env": {"igloo_init": "/bench_init.sh"},
        "core": {
            "kernel": str(kernel),
            "mem": mem,
            "timeout": timeout,
            # A persistent qcow2 overlay (rather than the throwaway immutable
            # one) is required for internal snapshots to survive at all.
            "snapshot": {"save_at": "manual", "tag": "bench"},
        },
        "plugins": {
            "bench_snapshot": {"iters": iters, "control_ms": control_ms},
            # The fast path is allowed to lose networking; more importantly the
            # VPN config swaps guest RAM to memory-backend-file,share=on, which
            # would change what we are measuring.
            "vpn": {"enabled": False},
        },
        "static_files": {
            "/bench_init.sh": {"type": "inline_file", "mode": 73,
                               "contents": INIT_SH},
        },
    }
    p = project / "patch_bench.yaml"
    with open(p, "w") as f:
        yaml.dump(patch, f, sort_keys=False)
    cfg_path = project / "config.yaml"
    cfg = yaml.safe_load(cfg_path.read_text())
    cfg.setdefault("patches", [])
    if "patch_bench.yaml" not in cfg["patches"]:
        cfg["patches"].append("patch_bench.yaml")
    with open(cfg_path, "w") as f:
        yaml.dump(cfg, f, sort_keys=False)
    return str(cfg_path)


@click.command()
@click.option("--image", "-i", default="rehosting/penguin:latest")
@click.option("--arch", "-a", default="armel")
@click.option("--kernel", "-k", default="4.10")
@click.option("--mem", default="256M", help="core.mem; the control knob")
@click.option("--iters", default=5)
@click.option("--control-ms", default=250.0)
@click.option("--timeout", default=180)
@click.option("--label", default="baseline")
def main(image, arch, kernel, mem, iters, control_ms, timeout, label):
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    project = build_project(image, arch)
    # The plugin has to be findable: <proj_dir>/plugins/<name>.py
    (project / "plugins").mkdir(exist_ok=True)
    shutil.copy(HERE / "bench_snapshot.py", project / "plugins" / "bench_snapshot.py")

    cfg = write_patch(project, kernel, mem, iters, control_ms, timeout)
    penguin(image, "run", cfg, log_name="bench_run.txt")

    out = project / "results" / "latest" / "bench_snapshot.json"
    if not out.is_file():
        log.error("no bench_snapshot.json produced; tail of run log:")
        subprocess.run(["tail", "-n", "80", str(WORK / "bench_run.txt")])
        sys.exit(1)
    data = json.loads(out.read_text())
    data["config"] = {"arch": arch, "kernel": kernel, "mem": mem,
                      "image": image, "label": label}
    dest = HERE / f"result_{label}.json"
    dest.write_text(json.dumps(data, indent=2))
    log.info(f"wrote {dest}")

    ctl = data.get("control") or {}
    if not ctl.get("passed"):
        log.error(f"KNOWN-POSITIVE CONTROL FAILED: {ctl}. "
                  f"Numbers below are not trustworthy.")
        sys.exit(2)
    log.info(f"control OK: injected {ctl['expected_s']*1000:.1f} ms, "
             f"observed {ctl['observed_s']*1000:.1f} ms")
    log.info(f"summary: {json.dumps(data['summary'], indent=2)}")
    log.info(f"resolution: {json.dumps(data['resolution'], indent=2)}")


if __name__ == "__main__":
    main()
