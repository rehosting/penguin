#!/usr/bin/env python3
import logging
import os
import sys
from pathlib import Path
import click
import subprocess
import yaml

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("penguin.tests")

SCRIPT_PATH = Path(__file__).resolve().parent.parent  # Script's directory
TEST_DIR = Path(__file__).resolve().parent

proj_dir = Path(__file__).resolve().parent


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
            # stdout=open(proj_dir / Path("test_log.txt"), "w"),
            # stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError:
        logger.error("Penguin run failed, showing last 50 lines from log:")
        subprocess.run(["tail", "-n", "50", proj_dir / Path("test_log.txt")])
        sys.exit(1)


def create_tar_gz_with_binaries(dest_tar_gz, files_dict):
    """
    Create a tar.gz archive at dest_tar_gz containing binary files at the root.
    files_dict: dict of {filename: bytes_content}
    """
    import tarfile
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        for fname, content in files_dict.items():
            fpath = tmpdir_path / fname
            with open(fpath, "wb") as f:
                f.write(content)
        with tarfile.open(dest_tar_gz, "w:gz") as tar:
            for fname in files_dict:
                tar.add(tmpdir_path / fname, arcname=fname)


def run_test(kernel, arch, image):
    # Create tar.gz with several binary files at the root
    files_dict = {
        "helloworld": b"helloworld\0",
        "testfile1.bin": b"\x01\x02\x03\x04",
        "testfile2.bin": b"\x10\x20\x30\x40",
    }
    create_tar_gz_with_binaries(f"{TEST_DIR}/empty_fs.tar.gz", files_dict)
    base_config = str(Path(TEST_DIR, "base_config.yaml"))
    new_config = str(Path(TEST_DIR, "config.yaml"))
    os.makedirs(str(Path(TEST_DIR, "base")), exist_ok=True)

    with open(base_config, "r") as file:
        base_config = yaml.safe_load(file)

    base_config["patches"].append(f"patches/arches/{arch}.yaml")

    with open(new_config, "w") as file:
        yaml.dump(base_config, file, sort_keys=False)

    logger.info("Created new config file at " + new_config)
    penguin_run(new_config, image)
    logger.info("Test completed")


DEFAULT_KERNELS = ['6.13']
DEFAULT_ARCHES = ['armel', 'aarch64',
                  'mipsel', 'mipseb', 'mips64el', 'mips64eb',
                  'powerpc64', 'riscv64', 'loongarch64',
                  'x86_64']


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
