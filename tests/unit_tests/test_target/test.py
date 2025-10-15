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


def run_test(kernel, arch, image, test_file=None, docs_only=False):
    # Create tar.gz with several binary files at the root
    files_dict = {
        "helloworld": b"helloworld\0",
        "testfile1.bin": b"\x01\x02\x03\x04",
        "testfile2.bin": b"\x10\x20\x30\x40",
        "shim.txt": b"original data\0",
        "shimtarget.txt": b"target data\0",
    }
    create_tar_gz_with_binaries(f"{TEST_DIR}/empty_fs.tar.gz", files_dict)
    base_config = str(Path(TEST_DIR, "base_config.yaml"))
    new_config = str(Path(TEST_DIR, "config.yaml"))
    os.makedirs(str(Path(TEST_DIR, "base")), exist_ok=True)

    with open(base_config, "r") as file:
        base_config = yaml.safe_load(file)

    base_config["patches"].append(f"patches/arches/{arch}.yaml")
    base_config["core"]["kernel"] = str(kernel)

    if docs_only:
        base_config["plugins"]["pdoc_generator"] = {}

    if test_file:
        logger.info(f"Running specific test: {test_file}")
        # Ensure only our specific test is included
        base_config["patches"] = [p for p in base_config["patches"] if "patches/tests" not in p]
        base_config["patches"].append(f"patches/tests/{test_file}")
        base_config["core"]["auto_patching"] = False

    with open(new_config, "w") as file:
        yaml.dump(base_config, file, sort_keys=False)

    logger.info("Created new config file at " + new_config)
    penguin_run(new_config, image)
    logger.info("Test completed")


DEFAULT_KERNELS = ['4.10', '6.13']
DEFAULT_ARCHES = ['armel', 'aarch64',
                  'mipsel', 'mipseb', 'mips64el', 'mips64eb',
                  'x86_64']

# these are the architectures that only work with certain kernels
NONDEFAULT_KERNEL_ARCHES = {
    '6.13': ['powerpc64', 'loongarch64', 'riscv64'],
}


@click.command()
@click.option("--kernel", "-k", multiple=True, default=DEFAULT_KERNELS)
@click.option("--arch", "-a", multiple=True, default=DEFAULT_ARCHES)
@click.option("--image", "-i", default="rehosting/penguin:latest")
@click.option("--test-file", "-t", default=None, help="Run specific test file from patches/tests/ - no prefix needed (e.g., bash.yaml)")
@click.option("--docs-only", is_flag=True, help="Only build the docs and leave. Useful for CI.")
def test(kernel, arch, image, test_file, docs_only):
    if docs_only:
        logger.info("Docs only mode enabled, will only build docs and exit")
        kernel = ['4.10',]
        arch = ['armel',]
    if test_file:
        logger.info(f"Running specific test: {test_file} for {kernel} on {arch}")
    else:
        logger.info(f"Running all tests for {kernel} on {arch}")


    # Allow DEFAULT_ARCHES plus any arches referenced in NONDEFAULT_KERNEL_ARCHES
    allowed_arches = set(DEFAULT_ARCHES)
    for arches in NONDEFAULT_KERNEL_ARCHES.values():
        allowed_arches.update(arches)

    if any(a not in allowed_arches for a in arch):
        logger.error(
            f"Unsupported architectures specified. Allowed: {sorted(allowed_arches)}")
        return

    # Run tests for each kernel and architecture
    for k in kernel:
        for a in arch:
            # If this architecture is restricted to specific kernels, enforce it
            restricted_kernels = {
                kern for kern, arches in NONDEFAULT_KERNEL_ARCHES.items() if a in arches}
            if restricted_kernels and k not in restricted_kernels:
                logger.info(
                    f"Skipping kernel {k} for arch {a} (requires kernels: {sorted(restricted_kernels)})")
                continue

            logger.info(f"Running tests for kernel {k} on arch {a}")
            run_test(k, a, image, test_file, docs_only)


if __name__ == "__main__":
    test()
