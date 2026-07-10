#!/usr/bin/env python3
"""End-to-end snapshot kprobe re-attach test.

A kprobe's guest-side installation lives in the guest kprobe_table and so
survives a QEMU savevm; only the host-side id->callback map is lost across a
cross-process -loadvm. A correct restore therefore re-binds the host callback to
the SAME, surviving probe_id (Kprobes.on_restore) rather than installing a
duplicate or dropping the surviving probe's events.

This drives the regression:
  1. save run  : a probe on do_filp_open registers (id=N), fires, save_at=readiness
  2. restore   : penguin run --from-snapshot; the probe must re-attach to id=N
                 and keep firing.

Asserts the restore run reports the SAME probe_id as the save run and a non-zero
post-restore hit count. Reuses the basic_target busybox machinery + a stay-alive
init (so the guest reaches readiness and keeps opening files after restore).

Usage: python3 snapshot_kprobe_test.py -i <image> [-a armel] [-k 4.10]
"""
import logging
import shutil
import subprocess
from pathlib import Path

import click
import yaml

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt="%H:%M:%S")
logger = logging.getLogger("penguin.kpsnaptest")

TEST_DIR = Path(__file__).resolve().parent
PENGUIN = str(TEST_DIR.parent.parent.parent / "penguin")
PROBE_SRC = TEST_DIR / "snap_kprobe_probe.py"
FS_DIR = TEST_DIR / "fs"
TAG = "boot"

INIT_SH = """#!/igloo/utils/sh
/busybox echo "snap-init up"
while true; do /busybox sleep 1; done
"""


def run_cmd(cmd, **kw):
    logger.info(f"$ {cmd}")
    return subprocess.run(cmd, shell=True, check=True, **kw)


def penguin(image, *args, log="kp_log.txt"):
    cmd = " ".join([PENGUIN, "--image", image, *args])
    logger.info(f"$ {cmd}")
    try:
        subprocess.run(cmd, cwd=TEST_DIR, shell=True, check=True,
                       stdout=open(TEST_DIR / log, "w"), stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        subprocess.run(["tail", "-n", "80", str(TEST_DIR / log)])
        raise


def build_project(image, arch):
    if (TEST_DIR / "projects").exists():
        shutil.rmtree(TEST_DIR / "projects")
    FS_DIR.mkdir(exist_ok=True)
    cid = subprocess.check_output(f"docker create {image}", shell=True).decode().strip()
    run_cmd(f"docker cp -L {cid}:/igloo_static/utils.bin/busybox.{arch} {FS_DIR}/busybox")
    run_cmd(f"docker rm -v {cid}")
    run_cmd(f"tar -czf {TEST_DIR}/empty_fs.tar.gz -C {FS_DIR} .")
    penguin(image, "init", f"{TEST_DIR}/empty_fs.tar.gz", "--force", log="kp_init.txt")
    project = TEST_DIR / "projects/empty_fs"
    # Project-local fixture plugin (auto-discovered from plugins.d/).
    (project / "plugins.d").mkdir(exist_ok=True)
    shutil.copy(PROBE_SRC, project / "plugins.d" / "snap_kprobe_probe.py")
    return project


def write_patch(project, kernel, snapshot):
    patch = {
        "env": {"igloo_init": "/snap_init.sh"},
        "core": {"kernel": str(kernel), "timeout": 45, "snapshot": snapshot},
        "static_files": {"/snap_init.sh": {"type": "inline_file", "mode": 73,
                                           "contents": INIT_SH}},
        "plugins": {"snap_kprobe_probe": {}},
    }
    (project / "patch_snap.yaml").write_text(yaml.dump(patch, sort_keys=False))
    cfg_path = project / "config.yaml"
    cfg = yaml.safe_load(cfg_path.read_text())
    cfg.setdefault("patches", [])
    if "patch_snap.yaml" not in cfg["patches"]:
        cfg["patches"].append("patch_snap.yaml")
    cfg_path.write_text(yaml.dump(cfg, sort_keys=False))
    return str(cfg_path)


def read_probe(project, run_idx):
    ids = project / "results" / str(run_idx) / "kprobe_ids.txt"
    hits = project / "results" / str(run_idx) / "kprobe_hits.txt"
    return (ids.read_text().strip() if ids.exists() else None,
            int(hits.read_text().strip()) if hits.exists() else 0)


@click.command()
@click.option("--image", "-i", required=True)
@click.option("--arch", "-a", default="armel")
@click.option("--kernel", "-k", default="4.10")
def main(image, arch, kernel):
    project = build_project(image, arch)

    logger.info("=== SAVE run (save_at=readiness) ===")
    cfg = write_patch(project, kernel, {"save_at": "readiness", "tag": TAG})
    penguin(image, "run", cfg, log="kp_save.txt")
    save_ids, save_hits = read_probe(project, 0)
    logger.info(f"SAVE: ids={save_ids} hits={save_hits}")
    if not save_ids or save_hits == 0:
        raise AssertionError("probe did not register/fire on the save run")

    logger.info("=== RESTORE run (--from-snapshot) ===")
    cfg = write_patch(project, kernel, {"boot_from": TAG})
    penguin(image, "run", cfg, "--from-snapshot", TAG, log="kp_restore.txt")
    rest_ids, rest_hits = read_probe(project, 1)
    logger.info(f"RESTORE: ids={rest_ids} hits={rest_hits}")

    # The guest probe survived savevm; a correct restore re-attaches to the SAME
    # id and events keep flowing. A regression re-installs (new id) or drops the
    # surviving probe's events (no ids file / zero hits).
    if rest_ids != save_ids:
        raise AssertionError(
            f"kprobe was not re-attached across restore: save {save_ids} "
            f"!= restore {rest_ids} (re-installed a duplicate, or lost the host map)")
    if rest_hits == 0:
        raise AssertionError(
            "re-attached kprobe received no events after restore")
    logger.info(f"OK: kprobe re-attached to {rest_ids} and fired {rest_hits}x "
                "after restore")


if __name__ == "__main__":
    main()
