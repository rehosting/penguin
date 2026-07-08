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
                "--force",
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


def penguin_refresh(project_dir, image):
    logger.info("penguin refresh")
    try:
        subprocess.run(
            " ".join([
                os.path.dirname(os.path.dirname(SCRIPT_PATH)) + "/penguin",
                "--image",
                image,
                "refresh",
                str(project_dir),
            ]),
            cwd=proj_dir,
            shell=True,
            check=True,
            stdout=open(proj_dir / Path("test_log.txt"), "w"),
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as e:
        logger.error("Failed in penguin refresh")
        subprocess.run(["tail", "-n", "50", proj_dir / Path("test_log.txt")])
        raise e


def penguin_run(config, image, execution_mode="qemu"):
    logger.info(f"penguin run (mode={execution_mode})")
    try:
        env = os.environ.copy()
        if execution_mode == "kvm":
            if "PENGUIN_KVM_LIB" not in env:
                workspace = Path(__file__).resolve().parents[4]
                env["PENGUIN_KVM_LIB"] = str(
                    workspace / "emulator/kvm-qemu/build-kvm/libqemu-kvm-x86_64.so"
                )
                env["PENGUIN_KVM_CFFI_HEADER"] = str(
                    workspace / "emulator/kvm-qemu/build-kvm/qemu_cffi_kvm_x86_64.h"
                )

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
            env=env,
            stdout=open(proj_dir / Path("test_log.txt"), "w"),
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as e:
        logger.error("Failed in penguin run")
        subprocess.run(["tail", "-n", "1000", proj_dir / Path("test_log.txt")])
        raise e


def assert_lib_inject_dropin_result(project_dir):
    cache_dir = project_dir / "qcows" / "cache"
    matches = sorted(cache_dir.glob("lib_inject_*.so"))
    if not matches:
        raise AssertionError(f"no cached lib_inject build found under {cache_dir}")
    marker_bytes = b"libinject-dropin-marker-from-header"
    if not any(marker_bytes in path.read_bytes() for path in matches):
        raise AssertionError(
            f"lib_inject.d marker {marker_bytes!r} missing from cached lib_inject .so files: "
            f"{[p.name for p in matches]}"
        )

    runtime_marker = project_dir / "results" / "latest" / "shared" / "lib_inject_dropin_ran"
    if not runtime_marker.exists():
        latest = project_dir / "results" / "latest"
        shared = latest / "shared"
        console = latest / "console.log"
        logger.error(f"--- shared/ listing ({shared}) ---")
        if shared.is_dir():
            for entry in sorted(shared.iterdir()):
                logger.error(f"  {entry.name}")
        else:
            logger.error("  (missing)")
        logger.error("--- console.log tail ---")
        if console.exists():
            for line in console.read_text(errors="replace").splitlines()[-80:]:
                logger.error(line)
        else:
            logger.error("(no console.log)")
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


# Kernel-fault signatures that must never appear in a healthy boot. These are
# a regression tripwire for the igloo driver's init/portal paths: e.g. driver
# 0.0.75 shipped a shared-major devfs change that triggered a recursive mipsel
# do_ade (unaligned-access) oops storm at driver init, which was reverted
# without a test to catch it. A minimal boot must produce none of these.
KERNEL_OOPS_SIGNATURES = (
    "Unhandled kernel unaligned access",
    "Unable to handle kernel",
    "do_ade+",
    "Oops[",
    "Oops:",
    "BUG: ",
)


def assert_no_kernel_oops(project_dir):
    console = project_dir / "results" / "latest" / "console.log"
    if not console.exists():
        raise AssertionError(f"no console.log to check for kernel oops: {console}")
    text = console.read_text(errors="replace")
    hits = {sig for sig in KERNEL_OOPS_SIGNATURES if sig in text}
    # basic_target's init.sh intentionally exits, so the guest ends with an
    # expected "Kernel panic ... Attempted to kill init" and reboots. Flag any
    # OTHER kernel panic (a genuine early fault), but not that one.
    for line in text.splitlines():
        if "Kernel panic" in line and "Attempted to kill init" not in line:
            hits.add(line.strip())
    if hits:
        logger.error("--- console.log tail (kernel oops detected) ---")
        for line in text.splitlines()[-60:]:
            logger.error(line)
        raise AssertionError(
            f"kernel oops signature(s) {sorted(hits)} found in guest console: {console}"
        )


def run_test(kernel, arch, image, execution_mode="qemu"):
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

    # refresh: re-run init analyses in place; must succeed and keep the
    # project loadable (idempotent right after init)
    penguin_refresh(project_path, image)
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
    # If kernel is just a version, we need to find it in the host if we are running locally
    # But the CI/CD script expects it to be resolved inside the container.
    # We'll just pass it through and hope the container has it.
    bconfig["core"]["kernel"] = str(kernel)
    bconfig["core"]["execution_mode"] = execution_mode

    with open(base_config, "w") as file:
        yaml.dump(bconfig, file, sort_keys=False)

    penguin_run(config, image, execution_mode=execution_mode)

    # Guard against kernel faults during boot / driver init (e.g. the mipsel
    # do_ade regression that got a shared-major devfs change reverted).
    assert_no_kernel_oops(project_path)

    if arch in DROPIN_C_TEST_ARCHES:
        assert_dropin_c_result(project_path)

    assert_lib_inject_dropin_result(project_path)

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
@click.option("--mode", "-m", default="qemu", type=click.Choice(["qemu", "kvm"]))
def test(kernel, arch, image, mode):
    logger.info(f"Running tests for {kernel} on {arch} (mode={mode})")

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

            logger.info(f"Running tests for kernel {k} on arch {a} (mode={mode})")
            run_test(k, a, image, execution_mode=mode)
            run_cmd(f"rm -rf {proj_dir}/projects", shell=True)


if __name__ == "__main__":
    test()
