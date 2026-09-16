#!/usr/bin/env python3
"""Boot once and ask the driver-side accumulator whether it measures time.

This does not produce a per-syscall cost table. It produces a VERDICT on
whether such a table would mean anything, which has to come first: the
accumulator brackets do_hyp() with guest ktime, and the guest is stopped for
the whole of a hypercall. Whether its clock advances across that gap is a
property of the emulator's timekeeping, not something to assume.

The probe makes marker syscalls; syscost_driver.py enables the accumulator on
the first, burns a known BURN_MS of host time on the next N, and reads back on
the one after. If the driver's total for the marker comes back at or above the
host burn, guest ktime spans the hypercall. If it comes back near zero, it
does not, and no number from the accumulator may be read as round-trip cost.

Run: python3 syscost_driver_run.py -i penguin:fastsnap
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import click
import yaml

HERE = Path(__file__).resolve().parent
PROJ = "syscostdrv"

# Marker calls the probe makes: 1 to enable, BURN to burn on, 1 to read, and a
# few spare so a miscount cannot silently skip the read.
BURN_CALLS = 200

PROBE_C = r"""
/* Marker-only probe. getppid() is the marker: side-effect free, argument
 * free, and rare enough in ordinary userspace that a comm-filtered hook on it
 * catches this and nothing else. The count is COMPILED IN, not passed in
 * argv: penguin's /igloo/init auto-runs every executable in /igloo/init.d/*,
 * so a probe that also gets invoked explicitly runs TWICE with different
 * arguments -- which is exactly how an earlier instrument in this lane came
 * to divide by a count it never used, and reported a syscall cost 100x too
 * low. */
#include <unistd.h>

#define MARKS %(marks)dL

int main(void)
{
    long i;

    for (i = 0; i < MARKS; i++)
        (void)getppid();
    return 0;
}
"""

PLUGIN_PY = "syscost_driver.py"

# The probe is auto-run by /igloo/init from /igloo/init.d/*, BEFORE igloo_init.
# igloo_init still has to exist and has to not exit, or the machine tears down
# before the marker hook has read the accumulator back.
INIT_SH = """#!/igloo/utils/sh
/busybox echo "[syscost] probe already run by /igloo/init.d; idling"
while true; do /busybox sleep 1; done
"""


def sh(cmd, **kw):
    return subprocess.run(cmd, shell=True, check=True, **kw)


def reclaim_stale_container():
    """A container by THIS name can only be ours, so stopping it is safe.

    penguin names the container after the project, which is named after the
    rootfs tarball. A killed run leaves the name held by a container that is
    still emulating, and every subsequent run dies on "Container name is
    already in use" -- six boots went that way once.
    """
    out = subprocess.run(f"docker ps -aq -f name=^{PROJ}$", shell=True,
                         capture_output=True, text=True).stdout.strip()
    if out:
        print(f"reclaiming stale container {PROJ}")
        subprocess.run(f"docker stop -t 90 {PROJ}", shell=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(f"docker rm {PROJ}", shell=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def penguin(image, *args, cwd, log):
    cmd = [str(HERE.parent.parent / "penguin"), "--image", image, *args]
    print("$ " + " ".join(cmd))
    with open(log, "w") as f:
        subprocess.run(cmd, cwd=cwd, stdout=f, stderr=subprocess.STDOUT)


@click.command()
@click.option("--image", "-i", default="penguin:fastsnap")
@click.option("--arch", "-a", default="armel")
@click.option("--burn-ms", default=5.0, type=float)
@click.option("--out", default="result_syscost_driver.json")
def main(image, arch, burn_ms, out):
    work = HERE / "work_syscost_driver"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)

    fs = work / "fs"
    fs.mkdir()
    cid = subprocess.check_output(f"docker create {image}",
                                  shell=True).decode().strip()
    sh(f"docker cp -L {cid}:/igloo_static/utils.bin/busybox.{arch} {fs}/busybox")
    sh(f"docker rm -v {cid}", stdout=subprocess.DEVNULL)
    sh(f"tar -czf {work}/{PROJ}.tar.gz -C {fs} .")

    reclaim_stale_container()
    penguin(image, "init", f"{work}/{PROJ}.tar.gz", "--force",
            cwd=work, log=work / "init.txt")

    proj = work / "projects" / PROJ
    (proj / "init.d").mkdir(parents=True, exist_ok=True)
    (proj / "plugins.d").mkdir(parents=True, exist_ok=True)
    (proj / "init.d/syscostprobe.c").write_text(
        PROBE_C % {"marks": BURN_CALLS + 8})
    shutil.copy(HERE / PLUGIN_PY, proj / "plugins.d" / PLUGIN_PY)

    # A plugins.d drop-in REPLACES the plugin's args from config.yaml and from
    # every patch -- it is an assignment, not a merge -- so arguments put in
    # the patch below would be silently discarded. They go in a sibling .yaml
    # named for the drop-in, which is the only place the drop-in does not
    # overwrite.
    (proj / "plugins.d/syscost_driver.yaml").write_text(yaml.dump(
        # NO outdir here: penguin injects it as the run's own results dir,
        # and setting it is a hard error ("Config for ... overwrites argument
        # outdir"), not an override.
        {"comm": "syscostprobe", "burn_ms": burn_ms,
         "burn_calls": BURN_CALLS}, sort_keys=False))

    patch = {
        "core": {"timeout": 300},
        "env": {"igloo_init": "/init.sh"},
        "static_files": {"/init.sh": {"type": "inline_file", "mode": 493,
                                      "contents": INIT_SH}},
        # analysis_scope none: the probe lives in /igloo/init.d, outside the
        # firmware subtree, and scoping would gate its marker hook off -- the
        # instrument would gate away its own clock, which is exactly how the
        # scoped configuration in speedscheme.py returned zero marks twice.
        "plugins": {
            "vpn": {"enabled": False},
        },
    }
    (proj / "patch_syscostdrv.yaml").write_text(yaml.dump(patch,
                                                          sort_keys=False))
    cfg_p = proj / "config.yaml"
    cfg = yaml.safe_load(cfg_p.read_text())
    cfg.setdefault("patches", []).append("patch_syscostdrv.yaml")
    cfg["core"]["analysis_scope"] = "none"
    cfg_p.write_text(yaml.dump(cfg, sort_keys=False))

    penguin(image, "run", str(cfg_p), cwd=work, log=work / "run.txt")

    res = next(iter(sorted((proj / "results").glob("*/syscost_driver.json"))),
               None)
    if res is None:
        # Surface what the run said rather than a bare "missing file": the
        # usual causes (op absent from an old driver, probe never ran) are all
        # distinguishable in the log.
        log = (work / "run.txt").read_text(errors="replace")
        hits = [ln for ln in log.splitlines()
                if re.search(r"syscost|SYSCALL_COST|verdict", ln, re.I)]
        print("no syscost_driver.json written.")
        print("\n".join(hits[-20:]) or "  (nothing in the log mentions it)")
        raise SystemExit(1)

    data = json.loads(res.read_text())
    (HERE / out).write_text(json.dumps(data, indent=2))
    v = data["verdict"]
    print("\n== verdict")
    print(f"  {v.get('status')}")
    for k in ("host_burn_total_s", "driver_marker_s",
              "ratio_seen_over_burned", "driver_n_calls", "driver_total_ns"):
        if k in v:
            print(f"  {k:24s} {v[k]}")
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()
