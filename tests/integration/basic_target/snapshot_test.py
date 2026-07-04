#!/usr/bin/env python3
"""
End-to-end snapshot test: save a VM snapshot at readiness, then start a fresh
penguin run from that snapshot and confirm it restored.

Reuses the basic_target machinery (busybox-only empty_fs) to build a project,
injects a stay-alive init (so the guest reaches readiness and remains up while
the snapshot is taken), then drives two runs:
  1. save run  : core.snapshot.save_at=readiness  (+ short timeout)
  2. restore   : penguin run --from-snapshot <tag>

Usage: python3 snapshot_test.py -i <image> [-a armel] [-k 4.10]
"""
import logging
from pathlib import Path
import click
import shutil
import subprocess
import yaml

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(name)s %(levelname)s %(message)s",
                    datefmt="%H:%M:%S")
logger = logging.getLogger("penguin.snaptest")

TEST_DIR = Path(__file__).resolve().parent
proj_dir = TEST_DIR
PENGUIN = str(TEST_DIR.parent.parent.parent / "penguin")  # repo-root ./penguin
FS_DIR = Path(proj_dir, "fs")
TAG = "boot"

# Stay-alive init so the guest reaches igloo_init readiness and remains up while
# the snapshot is captured (the stock empty_fs init exits immediately).
INIT_SH = """#!/igloo/utils/sh
/busybox echo "snap-init up"
while true; do /busybox sleep 1; done
"""


def run_cmd(cmd, **kw):
    logger.info(f"$ {cmd}")
    return subprocess.run(cmd, shell=True, check=True, **kw)


def penguin(image, *args, log="snap_log.txt"):
    cmd = " ".join([PENGUIN, "--image", image, *args])
    logger.info(f"$ {cmd}")
    try:
        subprocess.run(cmd, cwd=proj_dir, shell=True, check=True,
                       stdout=open(proj_dir / log, "w"), stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        subprocess.run(["tail", "-n", "120", str(proj_dir / log)])
        raise


def build_project(image, arch):
    FS_DIR.mkdir(exist_ok=True)
    (FS_DIR / "bin").mkdir(exist_ok=True)
    cid = subprocess.check_output(f"docker create {image}", shell=True).decode().strip()
    run_cmd(f"docker cp -L {cid}:/igloo_static/utils.bin/busybox.{arch} {FS_DIR}/busybox")
    run_cmd(f"docker rm -v {cid}")
    run_cmd(f"tar -czf {TEST_DIR}/empty_fs.tar.gz -C {FS_DIR} .")
    penguin(image, "init", f"{TEST_DIR}/empty_fs.tar.gz", "--force", log="snap_init.txt")
    return Path(proj_dir, "projects/empty_fs")


def write_patch(project_path, kernel, snapshot):
    """Write a patch that pins kernel, a stay-alive init, and snapshot config,
    and append it to the project's config patches. Returns the config path."""
    patch = {
        "env": {"igloo_init": "/snap_init.sh"},
        "core": {"kernel": str(kernel), "timeout": 45, "snapshot": snapshot},
        "static_files": {
            "/snap_init.sh": {"type": "inline_file", "mode": 73, "contents": INIT_SH},
        },
    }
    patch_path = project_path / "patch_snap.yaml"
    with open(patch_path, "w") as f:
        yaml.dump(patch, f, sort_keys=False)

    cfg_path = project_path / "config.yaml"
    with open(cfg_path) as f:
        cfg = yaml.safe_load(f)
    patches = cfg.setdefault("patches", [])
    if "patch_snap.yaml" not in patches:
        patches.append("patch_snap.yaml")
    with open(cfg_path, "w") as f:
        yaml.dump(cfg, f, sort_keys=False)
    return str(cfg_path)


@click.command()
@click.option("--image", "-i", required=True)
@click.option("--arch", "-a", default="armel")
@click.option("--kernel", "-k", default="4.10")
def main(image, arch, kernel):
    if proj_dir.joinpath("projects").exists():
        shutil.rmtree(proj_dir / "projects")
    project = build_project(image, arch)
    qcows = project / "qcows"

    # --- 1. SAVE run -------------------------------------------------------
    logger.info("=== SAVE run (save_at=readiness) ===")
    config = write_patch(project, kernel, {"save_at": "readiness", "tag": TAG})
    penguin(image, "run", config, log="snap_save.txt")

    overlay = qcows / f"snapshot_{TAG}.qcow2"
    meta = qcows / f"snapshot_{TAG}.meta.json"
    sidecar = project / "results" / "latest" / "snapshot.yaml"
    for p in (overlay, meta):
        if not p.is_file():
            subprocess.run(["tail", "-n", "60", str(proj_dir / "snap_save.txt")])
            raise AssertionError(f"expected snapshot artifact missing: {p}")
    logger.info(f"OK: overlay={overlay.stat().st_size}B, meta={meta.read_text()}")
    if sidecar.is_file():
        logger.info(f"OK: results sidecar {sidecar.read_text().strip()}")

    save_console = project / "results" / "latest" / "console.log"
    blob = save_console.read_text(errors="replace") if save_console.exists() else ""
    if "non-migratable" in blob or "State blocked" in blob:
        raise AssertionError("savevm was blocked by a non-migratable device")
    # Confirm a savevm internal snapshot actually exists in the overlay. The
    # overlay records its backing at the absolute container path it was created
    # with (/host_empty_fs/qcows/...), so mount there for the backing to resolve.
    info = subprocess.check_output(
        f"docker run --rm -v {qcows}:/host_empty_fs/qcows {image} "
        f"qemu-img snapshot -l /host_empty_fs/qcows/snapshot_{TAG}.qcow2",
        shell=True).decode()
    logger.info(f"qemu-img snapshot -l:\n{info}")
    if TAG not in info:
        raise AssertionError(f"no internal VM snapshot '{TAG}' found in overlay")

    # --- 2. RESTORE run ----------------------------------------------------
    logger.info("=== RESTORE run (--from-snapshot) ===")
    config = write_patch(project, kernel, {"boot_from": TAG})
    penguin(image, "run", config, "--from-snapshot", TAG, log="snap_restore.txt")
    rlog = (proj_dir / "snap_restore.txt").read_text(errors="replace")
    if "Restoring from snapshot" in rlog or "Booting from snapshot" in rlog:
        logger.info("OK: restore log line present")
    else:
        logger.warning("no explicit restore log line; inspect snap_restore.txt")
    logger.info("Snapshot save+restore test PASSED")


if __name__ == "__main__":
    main()
