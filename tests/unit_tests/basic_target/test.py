#!/usr/bin/env python3
import logging
import os
from pathlib import Path
import click
import shutil
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

DROPIN_C_TEST_ARCHES = {
    'armel', 'aarch64',
    'mipsel', 'mipseb', 'mips64el', 'mips64eb',
    'riscv64',
    'x86_64',
    'powerpc', 'powerpc64',
}


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


def assert_lib_inject_dropin_result(project_dir, arch):
    cache_dir = project_dir / "qcows" / "cache"
    matches = sorted(cache_dir.glob("lib_inject_*.so"))
    if not matches:
        raise AssertionError(
            f"no cached lib_inject build found under {cache_dir}"
        )
    marker_bytes = b"libinject-dropin-marker-from-header"
    if not any(marker_bytes in path.read_bytes() for path in matches):
        raise AssertionError(
            f"lib_inject.d marker {marker_bytes!r} missing from cached lib_inject .so files: "
            f"{[p.name for p in matches]}"
        )

    runtime_marker = project_dir / "results" / "latest" / "shared" / "lib_inject_dropin_ran"
    if not runtime_marker.exists():
        raise AssertionError(
            f"lib_inject.d constructor marker not written in guest: {runtime_marker}"
        )
    contents = runtime_marker.read_text()
    if "libinject-dropin-marker-from-header" not in contents:
        raise AssertionError(
            f"lib_inject.d constructor marker had unexpected contents: {contents!r}"
        )


def assert_dropin_c_result(project_dir):
    marker = project_dir / "results" / "latest" / "shared" / "dropin_c_ran"
    if not marker.exists():
        raise AssertionError(f"C drop-in marker file not found: {marker}")
    contents = marker.read_text()
    expected = "dropin-c-ran-from-header"
    if expected not in contents:
        raise AssertionError(
            f"C drop-in marker had unexpected contents: {contents!r}"
        )

    core_config_path = project_dir / "results" / "latest" / "core_config.yaml"
    with open(core_config_path, "r") as file:
        core_config = yaml.safe_load(file)

    static_files = core_config["static_files"]
    if "/igloo/init.d/dropin_c" not in static_files:
        raise AssertionError("compiled C drop-in missing from core_config.yaml")
    if "/igloo/init.d/dropin_c.c" in static_files:
        raise AssertionError("C source should not be installed as an init.d file")
    if "/igloo/init.d/dropin_c_util.h" in static_files:
        raise AssertionError("C header should not be installed as an init.d file")

    host_path = static_files["/igloo/init.d/dropin_c"]["host_path"]
    if ".dropin_build" not in host_path or not host_path.endswith("/dropin_c"):
        raise AssertionError(f"C drop-in did not point at compiled cache: {host_path}")


def run_test(kernel, arch, image):
    id = subprocess.check_output(
        f"docker create {image}", shell=True).decode().strip()
    run_cmd(
        f"docker cp -L {id}:/igloo_static/utils.bin/busybox.{arch} {FS_DIR}/busybox", shell=True)
    run_cmd(f"docker rm -v {id}", shell=True)
    (FS_DIR / "bin").mkdir(exist_ok=True)
    run_cmd(f"tar -czvf {TEST_DIR}/empty_fs.tar.gz -C {FS_DIR} .", shell=True)

    # init
    penguin_init(f"{TEST_DIR}/empty_fs.tar.gz", image)

    project_path = Path(proj_dir, "projects/empty_fs")
    if arch in DROPIN_C_TEST_ARCHES:
        shutil.copytree(TEST_DIR / "init.d", project_path / "init.d", dirs_exist_ok=True)
    else:
        logger.info(f"Skipping C drop-in test fixture for unsupported arch {arch}")
    shutil.copytree(TEST_DIR / "lib_inject.d", project_path / "lib_inject.d", dirs_exist_ok=True)

    base_config = str(project_path / "config.yaml")
    config = str(project_path / "config.yaml")
    run_cmd(
        f"cp {proj_dir}/patch.yaml {proj_dir}/projects/empty_fs/patch.yaml", shell=True)

    with open(base_config, "r") as file:
        bconfig = yaml.safe_load(file)

    bconfig["patches"].append("patch.yaml")
    bconfig["core"]["kernel"] = str(kernel)

    with open(base_config, "w") as file:
        yaml.dump(bconfig, file, sort_keys=False)

    penguin_run(config, image)

    if arch in DROPIN_C_TEST_ARCHES:
        assert_dropin_c_result(project_path)

    assert_lib_inject_dropin_result(project_path, arch)

    logger.info("Test completed")


DEFAULT_KERNELS = ['4.10', '6.13']
DEFAULT_ARCHES = ['armel', 'aarch64',
                  'mipsel', 'mipseb', 'mips64el', 'mips64eb',
                  'riscv64', 'loongarch64',
                  'x86_64']

# architectures that only work with specific kernels
NONDEFAULT_KERNEL_ARCHES = {
    '6.13': ['powerpc64', 'loongarch64', 'riscv64'],
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
