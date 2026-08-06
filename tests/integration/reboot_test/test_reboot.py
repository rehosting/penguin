#!/usr/bin/env python3
"""Integration test for guest reboot handling.

Tests that Penguin can handle guest-initiated reboots when allow_reboot: true,
using process-per-boot: a guest reboot exits the process and the
manager respawns the next boot, preserving out_dir across the reboot.
"""
import logging
import os
import sys
from pathlib import Path
import click
import subprocess
import yaml
import tarfile
import tempfile

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("penguin.tests.reboot")

SCRIPT_PATH = Path(__file__).resolve().parent.parent
TEST_DIR = Path(__file__).resolve().parent
proj_dir = TEST_DIR


def create_tar_gz_with_files(dest_tar_gz, files_dict):
    """Create a tar.gz archive at dest_tar_gz containing files.

    Args:
        dest_tar_gz: Path to create the tar.gz file
        files_dict: dict of {filename: bytes_content}
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)

        # Collect all directories needed
        dirs_needed = set()
        for fname in files_dict.keys():
            parts = Path(fname).parts
            for i in range(1, len(parts)):
                dirs_needed.add("/".join(parts[:i]))

        # Create all directories first
        for dirname in sorted(dirs_needed):
            (tmpdir_path / dirname).mkdir(parents=True, exist_ok=True)

        # Create files
        for fname, content in files_dict.items():
            fpath = tmpdir_path / fname
            with open(fpath, "wb") as f:
                f.write(content)
            # Make scripts and binaries executable
            if fname.endswith('.sh') or fname == 'init' or 'bin/' in fname or 'sbin/' in fname:
                fpath.chmod(0o755)

        # Add to tarball - add directories first, then files
        with tarfile.open(dest_tar_gz, "w:gz") as tar:
            # Add directories
            for dirname in sorted(dirs_needed):
                tar.add(tmpdir_path / dirname, arcname=dirname, recursive=False)
            # Add files
            for fname in files_dict:
                tar.add(tmpdir_path / fname, arcname=fname)


def penguin_init(fs_tarball, image):
    """Initialize a Penguin project from a filesystem tarball.

    Args:
        fs_tarball: Path to filesystem tarball
        image: Docker image to use
    """
    wrapper_dir = os.path.dirname(os.path.dirname(SCRIPT_PATH))
    cmd = [
        wrapper_dir + "/penguin",
        "--image",
        image,
        "init",
        str(fs_tarball),
        "--force",
    ]
    logger.info(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            check=True,
            cwd=TEST_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        logger.info("Penguin init completed successfully")
        return result
    except subprocess.CalledProcessError as e:
        logger.error(f"Penguin init failed with exit code {e.returncode}")
        logger.error(f"Output:\n{e.stdout.decode() if e.stdout else '(no output)'}")
        raise


def penguin_run(config, image, timeout=600):
    """Run Penguin with the given config.

    Args:
        config: Path to config file
        image: Docker image to use
        timeout: Timeout in seconds (default 120s for reboot test)
    """
    wrapper_dir = os.path.dirname(os.path.dirname(SCRIPT_PATH))
    cmd = [
        wrapper_dir + "/penguin",
        "--image",
        image,
        "run",
        config,
    ]
    logger.info(f"Running: {' '.join(cmd)}")

    try:
        result = subprocess.run(
            cmd,
            check=True,
            timeout=timeout,
            cwd=TEST_DIR,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        logger.info("Penguin run completed successfully")
        return result
    except subprocess.TimeoutExpired:
        logger.error(f"Penguin run timed out after {timeout}s")
        raise
    except subprocess.CalledProcessError as e:
        logger.error(f"Penguin run failed with exit code {e.returncode}")
        logger.error(f"Output:\n{e.stdout.decode() if e.stdout else '(no output)'}")
        raise


def assert_reboot_test_passed(test_dir):
    """Verify that the reboot test passed by checking output files.

    Expected behavior:
    - Guest boots, writes "BOOT_1" marker (shared) + an on-disk marker
    - Guest reboots (-> process exits, manager respawns the next boot)
    - Guest boots again, writes "BOOT_2" marker (shared)
    - Both boot markers exist, and the on-disk marker survived the reboot
      (core.immutable=False), reported via shared/disk_persist.txt
    """
    latest = test_dir / "results" / "latest"
    shared = latest / "shared"

    # Check for .ran file (indicates Penguin completed)
    ran_file = latest / ".ran"
    if not ran_file.exists():
        raise AssertionError(
            f"Penguin run did not complete successfully; missing {ran_file}"
        )

    # Check for boot markers
    boot1_marker = shared / "boot_1.txt"
    boot2_marker = shared / "boot_2.txt"

    if not boot1_marker.exists():
        raise AssertionError(
            f"First boot marker not found; guest may not have booted initially: {boot1_marker}"
        )

    if not boot2_marker.exists():
        # Log console output for debugging
        console = latest / "console.log"
        if console.exists():
            logger.error("Console log (last 100 lines):")
            for line in console.read_text(errors="replace").splitlines()[-100:]:
                logger.error(line)
        raise AssertionError(
            f"Second boot marker not found; guest did not successfully reboot: {boot2_marker}"
        )

    # Verify markers have expected content
    boot1_content = boot1_marker.read_text().strip()
    boot2_content = boot2_marker.read_text().strip()

    if "BOOT_1" not in boot1_content:
        raise AssertionError(f"Boot 1 marker has unexpected content: {boot1_content!r}")

    if "BOOT_2" not in boot2_content:
        raise AssertionError(f"Boot 2 marker has unexpected content: {boot2_content!r}")

    # Guest disk writes must survive the reboot (core.immutable=False). Boot 2
    # reports whether the on-disk marker written by boot 1 was still present.
    disk_persist = shared / "disk_persist.txt"
    if not disk_persist.exists():
        raise AssertionError(
            f"Disk-persistence result not reported by boot 2: {disk_persist}")
    disk_status = disk_persist.read_text().strip()
    if disk_status != "DISK_PERSISTED":
        raise AssertionError(
            "Guest on-disk write did not survive the reboot "
            f"(core.immutable=False expected persistence): got {disk_status!r}")

    logger.info("✓ Reboot test passed: Guest successfully rebooted, completed "
                "second boot, and on-disk writes persisted across the reboot")


def run_test(kernel, arch, image):
    """Run the reboot integration test.

    Args:
        kernel: Kernel version to use
        arch: Architecture to test
        image: Docker image to use
    """
    logger.info(f"Running reboot test for kernel={kernel} arch={arch}")

    # Create init script that:
    # 1. Checks if this is first or second boot
    # 2. Writes appropriate marker file
    # 3. Reboots on first boot, exits on second boot
    init_script = b"""#!/bin/busybox sh
# Reboot test init script (process-per-boot model).
#
# The boot counter lives on the host-shared 9p mount (/igloo/shared), which
# penguin preserves across the reboot-series respawns, so each boot sees the
# previous count. reboot -f issues a real reboot(2); the manager respawns
# the next boot reusing the persistent disk overlay.

SHARED=/igloo/shared
BOOT_COUNT_FILE=$SHARED/boot_count.txt
BOOT_NUM=1

/bin/busybox mkdir -p $SHARED

# Determine boot number (busybox expr; $(( )) can't call a command)
if [ -f "$BOOT_COUNT_FILE" ]; then
    PREV=$(/bin/busybox cat $BOOT_COUNT_FILE)
    BOOT_NUM=$(/bin/busybox expr $PREV + 1)
fi

/bin/busybox echo $BOOT_NUM > $BOOT_COUNT_FILE
/bin/busybox echo "Boot number: $BOOT_NUM"

# On-disk marker (NOT on the shared mount): written to the guest rootfs on
# boot 1 and checked on boot 2. It only survives the reboot if guest disk
# writes persist across the respawn, i.e. core.immutable=False -- this is what
# the old per-boot overlay used to provide and now falls out of the config's
# immutable flag.
DISK_MARKER=/reboot_disk_marker.txt

# Write boot marker
if [ $BOOT_NUM -eq 1 ]; then
    /bin/busybox echo "BOOT_1" > $SHARED/boot_1.txt
    /bin/busybox echo "DISK_OK" > $DISK_MARKER
    /bin/busybox echo "First boot completed, triggering reboot..."
    /bin/busybox sync
    /bin/busybox sleep 2
    /sbin/reboot -f
elif [ $BOOT_NUM -eq 2 ]; then
    /bin/busybox echo "BOOT_2" > $SHARED/boot_2.txt
    # Report whether the on-disk marker from boot 1 survived the reboot.
    if [ -f "$DISK_MARKER" ]; then
        /bin/busybox echo "DISK_PERSISTED" > $SHARED/disk_persist.txt
    else
        /bin/busybox echo "DISK_LOST" > $SHARED/disk_persist.txt
    fi
    /bin/busybox echo "Second boot completed; idling until penguin timeout ends the run"
    /bin/busybox sync
else
    /bin/busybox echo "ERROR: Unexpected boot number $BOOT_NUM"
    /sbin/poweroff
fi

# Should not reach here
/bin/busybox sleep 999999
"""

    # Get busybox binary from docker image
    logger.info("Extracting busybox from docker image...")
    result = subprocess.run(
        ["docker", "run", "--rm", image, "cat", f"/igloo_static/utils.bin/busybox.{arch}"],
        stdout=subprocess.PIPE,
        check=True
    )
    busybox_binary = result.stdout

    # Create filesystem tar.gz with proper directory structure
    files_dict = {
        "init": init_script,
        "bin/busybox": busybox_binary,
        "sbin/reboot": busybox_binary,  # Copy busybox to sbin too
        "sbin/poweroff": busybox_binary,
    }

    # Clean up stale files
    fs_tarball = TEST_DIR / "reboot_test_fs.tar.gz"
    index_file = Path(str(fs_tarball) + ".index.sqlite")
    if index_file.exists():
        index_file.unlink()

    create_tar_gz_with_files(fs_tarball, files_dict)
    logger.info(f"Created filesystem tarball: {fs_tarball}")

    # Initialize project
    logger.info("Initializing Penguin project...")
    penguin_init(fs_tarball, image)

    # Find the generated project directory (Penguin removes .tar.gz extension)
    project_name = fs_tarball.name.replace(".tar.gz", "")
    project_dir = TEST_DIR / "projects" / project_name
    logger.info(f"Project directory: {project_dir}")

    # Update the project's config.yaml with reboot settings
    config_path = project_dir / "config.yaml"
    with open(config_path, "r") as f:
        config_dict = yaml.safe_load(f)

    # Add reboot-specific configuration
    config_dict["core"]["allow_reboot"] = True  # CRITICAL: Enable reboot support
    config_dict["core"]["kernel"] = str(kernel)
    config_dict["core"]["mem"] = "256M"
    # Persist guest disk writes across the reboot. There is no special reboot
    # overlay: cross-reboot disk persistence is simply core.immutable=False
    # (writes go through to the base image, so the next boot of the series sees
    # them). With the default immutable=True each boot would be throwaway.
    config_dict["core"]["immutable"] = False

    # The default init shims replace /sbin/reboot (and /sbin/halt) with
    # exit0.sh, a no-op that just exits -- so the guest could never issue the
    # reset that reboot handling depends on. Penguin does NOT drop these
    # automatically under allow_reboot: a rehosting that wants real reboots
    # opts in by editing its own config. We do exactly that here: drop the
    # ShimStopBins init plugin (which generates the shim) and the materialised
    # static.shims.stop_bins.yaml patch, so /sbin/reboot reaches the kernel.
    config_dict.get("init_plugins", {}).pop("ShimStopBins", None)
    config_dict["patches"] = [
        pth for pth in config_dict.get("patches", [])
        if "static.shims.stop_bins" not in pth
    ]
    # Host<->guest 9p share mounted at /igloo/shared. Penguin preserves it
    # across the reboot-series respawns, so the boot counter and BOOT_* markers
    # written by init persist between boots and are visible on the host under
    # results/<n>/shared for the assertions below.
    config_dict["core"]["shared_dir"] = True
    # Per-boot wall-clock timeout. Boot 1 reboots long before this fires; boot 2
    # idles until it does, giving a deterministic, ACPI-independent end to the
    # run (penguin's timeout uses the host shutdown path that reliably exits the
    # embedded QEMU).
    config_dict["core"]["timeout"] = 45

    with open(config_path, "w") as f:
        yaml.dump(config_dict, f, sort_keys=False)
    logger.info(f"Updated config file: {config_path}")

    # Run Penguin (will timeout after 120s if reboot hangs)
    logger.info("Starting Penguin run...")
    try:
        penguin_run(str(config_path), image, timeout=600)
    except subprocess.TimeoutExpired:
        logger.error("Test timed out - guest may have hung during reboot")
        raise

    # Verify test results (check project_dir, not TEST_DIR)
    assert_reboot_test_passed(project_dir)

    logger.info("✓ Reboot integration test completed successfully")


@click.command()
@click.option("--kernel", "-k", default="6.13", help="Kernel version to test")
@click.option("--arch", "-a", default="x86_64", help="Architecture to test")
@click.option("--image", "-i", default="rehosting/penguin:latest", help="Docker image")
def main(kernel, arch, image):
    """Run the reboot integration test."""
    try:
        run_test(kernel, arch, image)
    except AssertionError as e:
        logger.error(f"Test failed: {e}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Test error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
