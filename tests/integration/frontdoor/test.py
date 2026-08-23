#!/usr/bin/env python3
"""End-to-end integration test for the telnet + SSH front doors.

Drives the vsock root-shell console's front doors through a real ``penguin run``
(init -> run), the same way qmp_hook does for the QMP hook. A project-local
``frontdoor_probe`` plugin connects to both doors from a host thread and, if an
interactive command round-trips over each, writes a marker the ``verifier``
plugin checks; the test asserts the marker.

Because the doors are host-side (arch-independent) it runs once on x86_64 like
the compose / qmp_hook tests rather than across the arch matrix. A green run
also exercises the (new) Rust guest agent's open-pty path over real vsock -- the
exec-only test_target runs never reach it -- and confirms the gateways bind
their privileged standard ports (23/22) as the non-root container user and that
the SSH gateway's asyncssh import path works on the image.
"""
import logging
from pathlib import Path
import shutil
import subprocess

import click
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("penguin.tests.frontdoor")

TEST_DIR = Path(__file__).resolve().parent
PENGUIN = str(TEST_DIR.parent.parent.parent / "penguin")
FS_DIR = TEST_DIR / "fs"
MARKER_NAME = "frontdoor_result"


def run_cmd(cmd, **kwargs):
    logger.info(f"Running command: {cmd}")
    return subprocess.check_output(cmd, **kwargs)


def _penguin(image, *args):
    log = TEST_DIR / "test_log.txt"
    try:
        subprocess.run(
            " ".join([PENGUIN, "--image", image, *args]),
            cwd=TEST_DIR,
            shell=True,
            check=True,
            stdout=open(log, "w"),
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError:
        logger.error("penguin %s failed; tail of %s:", args[0], log)
        subprocess.run(["tail", "-n", "200", str(log)])
        raise


def run_test(arch, image):
    FS_DIR.mkdir(exist_ok=True)
    # Minimal rootfs: just busybox from the image (mirrors qmp_hook/basic_target).
    cid = run_cmd(f"docker create {image}", shell=True).decode().strip()
    run_cmd(
        f"docker cp -L {cid}:/igloo_static/utils.bin/busybox.{arch} {FS_DIR}/busybox",
        shell=True,
    )
    run_cmd(f"docker rm -v {cid}", shell=True)
    (FS_DIR / "bin").mkdir(exist_ok=True)
    run_cmd(f"tar -czf {TEST_DIR}/frontdoor_fs.tar.gz -C {FS_DIR} .", shell=True)

    _penguin(image, "init", f"{TEST_DIR}/frontdoor_fs.tar.gz", "--force")

    project_path = TEST_DIR / "projects" / "frontdoor_fs"

    # Ship the project-local frontdoor_probe plugin.
    (project_path / "plugins").mkdir(parents=True, exist_ok=True)
    shutil.copy(TEST_DIR / "frontdoor_probe.py", project_path / "plugins" / "frontdoor_probe.py")

    # Layer our knobs via a patch (patches win over the generated base configs).
    shutil.copy(TEST_DIR / "patch.yaml", project_path / "patch.yaml")
    config = str(project_path / "config.yaml")
    with open(config) as f:
        conf = yaml.safe_load(f)
    conf.setdefault("patches", []).append("patch.yaml")
    conf["core"]["kernel"] = "6.13"
    with open(config, "w") as f:
        yaml.dump(conf, f, sort_keys=False)

    _penguin(image, "run", config)

    marker = project_path / "results" / "latest" / MARKER_NAME
    if not marker.exists():
        latest = project_path / "results" / "latest"
        console = latest / "console.log"
        if console.exists():
            logger.error("--- console.log tail ---")
            for line in console.read_text(errors="replace").splitlines()[-60:]:
                logger.error(line)
        raise AssertionError(f"front door marker not written: {marker}")
    contents = marker.read_text()
    if "frontdoor-ok" not in contents:
        raise AssertionError(f"front door marker unexpected contents: {contents!r}")

    logger.info("front door integration test PASSED")


@click.command()
@click.option("--arch", "-a", default="x86_64")
@click.option("--image", "-i", default="rehosting/penguin:latest")
def test(arch, image):
    try:
        run_test(arch, image)
    finally:
        run_cmd(
            f"rm -rf {TEST_DIR}/projects {FS_DIR} {TEST_DIR}/frontdoor_fs.tar.gz "
            f"{TEST_DIR}/test_log.txt",
            shell=True,
        )


if __name__ == "__main__":
    test()
