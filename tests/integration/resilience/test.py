#!/usr/bin/env python3
"""End-to-end resilience test for the guesthopper vsock command channel.

Drives fault injection against the live guest agent through a real ``penguin
run`` (init -> run), the same shape as the frontdoor / qmp_hook integration
tests. A project-local ``resilience_probe`` plugin, from a host thread, talks the
raw frame protocol straight to the vhost-device-vsock socket and:

  * starts a silent long-running command then abruptly disconnects, and confirms
    it is reaped (not orphaned);
  * churns more connect/abort cycles than the session cap and confirms a normal
    command still runs (no permit leak / no wedge);
  * floods the agent with oversize/garbage/silent connections and confirms it
    keeps serving.

On success the probe writes a marker the ``verifier`` plugin checks; the test
asserts the marker. Host-side and arch-neutral, so it runs once on x86_64 like
the compose / frontdoor tests rather than across the arch matrix.
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
logger = logging.getLogger("penguin.tests.resilience")

TEST_DIR = Path(__file__).resolve().parent
PENGUIN = str(TEST_DIR.parent.parent.parent / "penguin")
FS_DIR = TEST_DIR / "fs"
MARKER_NAME = "resilience_result"


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
    # Minimal rootfs: just busybox from the image (mirrors frontdoor/basic_target).
    cid = run_cmd(f"docker create {image}", shell=True).decode().strip()
    run_cmd(
        f"docker cp -L {cid}:/igloo_static/utils.bin/busybox.{arch} {FS_DIR}/busybox",
        shell=True,
    )
    run_cmd(f"docker rm -v {cid}", shell=True)
    (FS_DIR / "bin").mkdir(exist_ok=True)
    run_cmd(f"tar -czf {TEST_DIR}/resilience_fs.tar.gz -C {FS_DIR} .", shell=True)

    _penguin(image, "init", f"{TEST_DIR}/resilience_fs.tar.gz", "--force")

    project_path = TEST_DIR / "projects" / "resilience_fs"

    # Ship the project-local resilience_probe plugin.
    (project_path / "plugins").mkdir(parents=True, exist_ok=True)
    shutil.copy(
        TEST_DIR / "resilience_probe.py", project_path / "plugins" / "resilience_probe.py"
    )

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
        raise AssertionError(f"resilience marker not written: {marker}")
    contents = marker.read_text()
    if "resilience-ok" not in contents:
        raise AssertionError(f"resilience marker unexpected contents: {contents!r}")

    logger.info("resilience integration test PASSED")


@click.command()
@click.option("--arch", "-a", default="x86_64")
@click.option("--image", "-i", default="rehosting/penguin:latest")
def test(arch, image):
    try:
        run_test(arch, image)
    finally:
        run_cmd(
            f"rm -rf {TEST_DIR}/projects {FS_DIR} {TEST_DIR}/resilience_fs.tar.gz "
            f"{TEST_DIR}/test_log.txt",
            shell=True,
        )


if __name__ == "__main__":
    test()
