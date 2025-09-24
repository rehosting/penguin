#!/usr/bin/env python3
import logging
import os
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

FS_DIR = Path(proj_dir, "fs")
FS_DIR.mkdir(exist_ok=True)


def run_cmd(cmd, **kwargs):
    logger.info(f"Running command: {cmd}")
    output = subprocess.check_output(cmd, **kwargs)
    logger.info(f"Command result: {output}")
    return output


def penguin_init(fs, image):
    logger.info("penguin init")
    try:
        subprocess.run(
            " ".join([
                os.path.dirname(os.path.dirname(SCRIPT_PATH)) + "/penguin",
                "--image",
                image,
                "init",
                fs,
            ]),
            cwd=proj_dir,
            shell=True,
            check=True,
            stdout=open(proj_dir / Path("test_log.txt"), "w"),
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as e:
        logger.error("Failed in penguin init")
        subprocess.run(["tail", "-n", "50", proj_dir / Path("test_log.txt")])
        raise e


def penguin_run(config, image):
    logger.info("penguin run")
    try:
        subprocess.run(
            " ".join([
                os.path.dirname(os.path.dirname(SCRIPT_PATH)) + "/penguin",
                "--image",
                image,
                "run",
                config,
            ]),
            cwd=proj_dir,
            shell=True,
            check=True,
            stdout=open(proj_dir / Path("test_log.txt"), "w"),
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as e:
        logger.error("Failed in penguin run")
        subprocess.run(["tail", "-n", "1000", proj_dir / Path("test_log.txt")])
        raise e


def run_test(kernel, arch, image):
    id = subprocess.check_output(
        f"docker create {image}", shell=True).decode().strip()
    run_cmd(
        f"docker cp -L {id}:/igloo_static/utils.bin/busybox.{arch} {FS_DIR}/busybox", shell=True)
    run_cmd(f"docker rm -v {id}", shell=True)
    run_cmd(f"tar -czvf {TEST_DIR}/empty_fs.tar.gz -C {FS_DIR} .", shell=True)

    # init
    penguin_init(f"{TEST_DIR}/empty_fs.tar.gz", image)

    base_config = str(Path(proj_dir, "projects/empty_fs/config.yaml"))
    config = str(Path(proj_dir, "projects/empty_fs/config.yaml"))
    run_cmd(
        f"cp {proj_dir}/patch.yaml {proj_dir}/projects/empty_fs/patch.yaml", shell=True)

    with open(base_config, "r") as file:
        bconfig = yaml.safe_load(file)

    bconfig["patches"].append("patch.yaml")
    bconfig["core"]["kernel"] = str(kernel)

    with open(base_config, "w") as file:
        yaml.dump(bconfig, file, sort_keys=False)

    penguin_run(config, image)

    logger.info("Test completed")


DEFAULT_KERNELS = ['4.10', '6.13']
DEFAULT_ARCHES = ['armel', 'aarch64',
                  'mipsel', 'mipseb', 'mips64el', 'mips64eb',
                  'powerpc64', 'riscv64', 'loongarch64',
                  'x86_64']

# architectures that only work with specific kernels
NONDEFAULT_KERNEL_ARCHES = {
    '6.13': ['loongarch64', 'riscv64'],
}


@click.command()
@click.option("--kernel", "-k", multiple=True, default=DEFAULT_KERNELS)
@click.option("--arch", "-a", multiple=True, default=DEFAULT_ARCHES)
@click.option("--image", "-i", default="rehosting/penguin:latest")
def test(kernel, arch, image):
    logger.info(f"Running tests for {kernel} on {arch}")

    # Allow DEFAULT_ARCHES plus any arches referenced in NONDEFAULT_KERNEL_ARCHES
    allowed_arches = set(DEFAULT_ARCHES)
    for arches in NONDEFAULT_KERNEL_ARCHES.values():
        allowed_arches.update(arches)

    if any(a not in allowed_arches for a in arch):
        logger.error(f"Unsupported architectures specified. Allowed: {sorted(allowed_arches)}")
        return

    # Run tests for each kernel and architecture
    for k in kernel:
        for a in arch:
            # If this architecture is restricted to specific kernels, enforce it
            restricted_kernels = {kern for kern, arches in NONDEFAULT_KERNEL_ARCHES.items() if a in arches}
            if restricted_kernels and k not in restricted_kernels:
                logger.info(f"Skipping kernel {k} for arch {a} (requires kernels: {sorted(restricted_kernels)})")
                continue

            logger.info(f"Running tests for kernel {k} on arch {a}")
            run_test(k, a, image)
            run_cmd(f"rm -rf {proj_dir}/projects", shell=True)


if __name__ == "__main__":
    test()
