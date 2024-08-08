#!/usr/bin/env python3
import logging
import os
import shutil
import sys
from pathlib import Path
import click
import subprocess

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("penguin.tests")

SCRIPT_PATH = Path(__file__).resolve().parent.parent  # Script's directory
TEST_DIR = Path(__file__).resolve().parent

proj_dir = Path(__file__).resolve().parent


def penguin_patch(base, patch, image):
    try:
        subprocess.run(
            [
                os.path.dirname(os.path.dirname(SCRIPT_PATH)) + "/penguin",
                "--image",
                image,
                "patch",
                base,
                patch,
            ],
            check=True,
            stdout=open(proj_dir / Path("test_log.txt"), "w"),
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError:
        logger.error("Penguin patch failed, showing last 50 lines from log:")
        subprocess.run(["tail", "-n", "50", proj_dir / Path("test_log.txt")])
        sys.exit(1)


def penguin_run(config, image):
    try:
        subprocess.run(
            [
                os.path.dirname(os.path.dirname(SCRIPT_PATH)) + "/penguin",
                "--image",
                image,
                "run",
                config,
            ],
            check=True,
            stdout=open(proj_dir / Path("test_log.txt"), "w"),
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError:
        logger.error("Penguin run failed, showing last 50 lines from log:")
        subprocess.run(["tail", "-n", "50", proj_dir / Path("test_log.txt")])
        sys.exit(1)


def run_test(kernel, arch, image):
    subprocess.check_output(f"tar -czvf {TEST_DIR}/empty_fs.tar.gz -T /dev/null", shell=True)
    base_config = str(Path(TEST_DIR, "base_config.yaml"))
    new_config = str(Path(TEST_DIR, "config.yaml"))
    shutil.copyfile(base_config, new_config)
    os.makedirs(str(Path(TEST_DIR, "base")), exist_ok=True)
    arch_patch = str(Path(TEST_DIR, f"patches/arches/{arch}-{kernel}.yaml"))
    penguin_patch(new_config, arch_patch, image)
    penguin_run(new_config, image)
    logger.info("Test completed")


DEFAULT_KERNELS = ['4.10']
DEFAULT_ARCHES = ['armel', 'aarch64', 'mipsel', 'mipseb', 'mips64eb']


@click.command()
@click.option("--kernel", "-k", multiple=True, default=DEFAULT_KERNELS)
@click.option("--arch", "-a", multiple=True, default=DEFAULT_ARCHES)
@click.option("--image", "-i", default="rehosting/penguin:latest")
def test(kernel, arch, image):
    logger.info(f"Running tests for {kernel} on {arch}")

    if any(a not in DEFAULT_ARCHES for a in arch):
        logger.error(f"We only support {DEFAULT_ARCHES} at the moment")
        return

    # Run tests for each kernel and architecture
    for k in kernel:
        for a in arch:
            logger.info(f"Running tests for kernel {k} on arch {a}")
            run_test(k, a, image)


if __name__ == "__main__":
    test()
