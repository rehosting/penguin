#!/usr/bin/env python3
"""End-to-end integration test for the Penguin QMP command hook.

This drives the feature through a real ``penguin run`` (init -> run), the same
way the other integration tests do, rather than hand-building a KVMQemu. That
is the point: if the feature can't be reached from ``penguin`` with a config
knob and a plugin, then something user-facing is missing.

The project loads the ``qmp`` plugin (which opens a QMP socket at
``<results>/qmp.sock`` by appending to the QEMU argv, and installs the command
trampoline) plus a project-local ``qmp_probe`` plugin. ``qmp_probe`` registers a
custom QMP command via
``plugins.qmp.command`` and, from a host thread, connects to that socket and
sends the command -- exercising the full path:

    client -> qemu qmp_dispatch -> weak penguin_handle_qmp -> CFFI trampoline
      -> Qmp plugin -> handler -> strdup'd JSON -> qemu decode/g_free -> client

On success it writes a marker file that the ``verifier`` plugin checks; the run
ends when the condition passes (``continuous_eval``). The test then asserts the
marker is present.

Arch-independent (QMP dispatch is host-side, not guest/arch specific), so it
runs once on x86_64 like the compose test rather than across the arch matrix.
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
logger = logging.getLogger("penguin.tests.qmp")

TEST_DIR = Path(__file__).resolve().parent
PENGUIN = str(TEST_DIR.parent.parent.parent / "penguin")
FS_DIR = TEST_DIR / "fs"
MARKER_NAME = "qmp_probe_result"


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
    # Minimal rootfs: just busybox from the image (mirrors basic_target).
    cid = run_cmd(f"docker create {image}", shell=True).decode().strip()
    run_cmd(
        f"docker cp -L {cid}:/igloo_static/utils.bin/busybox.{arch} {FS_DIR}/busybox",
        shell=True,
    )
    run_cmd(f"docker rm -v {cid}", shell=True)
    (FS_DIR / "bin").mkdir(exist_ok=True)
    run_cmd(f"tar -czf {TEST_DIR}/qmp_fs.tar.gz -C {FS_DIR} .", shell=True)

    _penguin(image, "init", f"{TEST_DIR}/qmp_fs.tar.gz", "--force")

    project_path = TEST_DIR / "projects" / "qmp_fs"

    # Ship the project-local qmp_probe plugin.
    (project_path / "plugins").mkdir(parents=True, exist_ok=True)
    shutil.copy(TEST_DIR / "qmp_probe.py", project_path / "plugins" / "qmp_probe.py")

    # Layer our knobs via a patch (patches win over the generated base configs;
    # editing config.yaml directly gets clobbered by base.yaml). patch.yaml sets
    # an idle init and loads qmp + qmp_probe + verifier.
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
        raise AssertionError(f"QMP probe marker not written: {marker}")
    contents = marker.read_text()
    if "qmp-probe-ok" not in contents:
        raise AssertionError(f"QMP probe marker unexpected contents: {contents!r}")

    logger.info("QMP hook integration test PASSED")


@click.command()
@click.option("--arch", "-a", default="x86_64")
@click.option("--image", "-i", default="rehosting/penguin:latest")
def test(arch, image):
    try:
        run_test(arch, image)
    finally:
        run_cmd(
            f"rm -rf {TEST_DIR}/projects {FS_DIR} {TEST_DIR}/qmp_fs.tar.gz "
            f"{TEST_DIR}/test_log.txt",
            shell=True,
        )


if __name__ == "__main__":
    test()
