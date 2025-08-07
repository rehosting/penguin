import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from subprocess import check_output
from random import randint
from penguin.defaults import default_preinit_script, static_dir as STATIC_DIR
import tarfile
import time
import io

import click

from penguin import getColoredLogger

"""
gen_image can be run as a separate script if this is loaded at the module
level. This makes it easier to profile.
"""
from penguin.penguin_config import load_config

"""
This class wrapped what used to be a libguestfs interface

At this point it allows us to pretend that the temporary directory we have
is another file system
"""
logger = getColoredLogger("penguin.gen_image")


def get_mount_type(path):
    try:
        stat_output = subprocess.check_output(["stat", "-f", "-c", "%T", path])
        return stat_output.decode("utf-8").strip().lower()
    except subprocess.CalledProcessError:
        return None


def tar_add_min_files(tf_path, config):
    arch = config["core"]["arch"]
    if arch == "intel64":
        arch_dir = "x86_64"
    elif arch == "powerpc64el":
        arch_dir = "powerpc64"
    else:
        arch_dir = arch
    with tarfile.open(tf_path, "a") as tf:
        # Add igloo/ directory
        igloo_dir = tarfile.TarInfo(name="igloo/")
        igloo_dir.type = tarfile.DIRTYPE
        igloo_dir.mode = 0o755
        igloo_dir.mtime = int(time.time())
        igloo_dir.uname = "root"
        igloo_dir.gname = "root"
        tf.addfile(igloo_dir)
        # Add igloo/utils/ directory
        igloo_utils_dir = tarfile.TarInfo(name="igloo/utils/")
        igloo_utils_dir.type = tarfile.DIRTYPE
        igloo_utils_dir.mode = 0o755
        igloo_utils_dir.mtime = int(time.time())
        igloo_utils_dir.uname = "root"
        igloo_utils_dir.gname = "root"
        tf.addfile(igloo_utils_dir)
        # /igloo/preinit
        init_bytes = default_preinit_script.encode()
        ti = tarfile.TarInfo(name="igloo/preinit")
        ti.size = len(init_bytes)
        ti.mode = 0o111
        ti.mtime = int(time.time())
        ti.uname = "root"
        ti.gname = "root"
        tf.addfile(ti, fileobj=io.BytesIO(init_bytes))
        # /igloo/utils/busybox
        busybox_path = f"{STATIC_DIR}/{arch_dir}/busybox"
        tf.add(busybox_path, arcname="igloo/utils/busybox", filter=lambda ti: (setattr(ti, 'mode', 0o755) or ti))
        # /igloo/utils/sh (symlink)
        symlink_info = tarfile.TarInfo(name="igloo/utils/sh")
        symlink_info.type = tarfile.SYMTYPE
        symlink_info.linkname = "/igloo/utils/busybox"
        symlink_info.mode = 0o777
        symlink_info.mtime = int(time.time())
        symlink_info.uname = "root"
        symlink_info.gname = "root"
        tf.addfile(symlink_info)


def make_image(fs, out, artifacts, proj_dir, config_path):
    logger.debug("Generating new image from config...")
    IN_TARBALL = Path(fs)
    ARTIFACTS = Path(artifacts or "/tmp")
    QCOW = Path(out)
    ARTIFACTS.mkdir(exist_ok=True)

    # Unique suffix to avoid conflicts
    suffix = randint(0, 1000000)
    delete_tar = True
    MODIFIED_TARBALL = Path(ARTIFACTS, f"fs_out_{suffix}.tar")
    config = load_config(proj_dir, config_path)
    with tempfile.TemporaryDirectory() as TMP_DIR:
        uncompressed_tar = Path(TMP_DIR, f"uncompressed_{suffix}.tar")
        check_output(f"pigz -dc '{str(IN_TARBALL)}' > '{uncompressed_tar}'", shell=True)
        # Add files directly to the tar
        tar_add_min_files(uncompressed_tar, config)
        check_output(f"pigz -c '{uncompressed_tar}' > '{MODIFIED_TARBALL}'", shell=True)
        TARBALL = MODIFIED_TARBALL
        # 1GB of padding. XXX is this a good amount - does it slow things down if it's too much?
        # Our disk images are sparse, so this doesn't actually take up any space?
        PADDING_MB = 1024
        BLOCK_SIZE = 4096

        # Calculate image and filesystem size
        UNPACKED_SIZE = int(check_output(f'zcat "{TARBALL}" | wc -c', shell=True))
        UNPACKED_SIZE = UNPACKED_SIZE + 1024 * 1024 * PADDING_MB
        REQUIRED_BLOCKS = int((UNPACKED_SIZE + BLOCK_SIZE - 1) / BLOCK_SIZE + 1024)
        FILESYSTEM_SIZE = int(REQUIRED_BLOCKS * BLOCK_SIZE)

        # Calculate the number of inodes - err on the side of too big since we'll add more to the FS later
        INODE_SIZE = 8192  # For every 8KB of disk space, we'll allocate an inode
        NUMBER_OF_INODES = int(FILESYSTEM_SIZE / INODE_SIZE)
        NUMBER_OF_INODES = (
            NUMBER_OF_INODES + 1000
        )  # Padding for more files getting added later

        def _make_img(work_dir, qcow, delete_tar):
            IMAGE = Path(work_dir, "image.raw")
            check_output(["truncate", "-s", str(FILESYSTEM_SIZE), IMAGE])
            subprocess.run([
                "genext2fs",
                "--faketime",
                "-N",
                str(NUMBER_OF_INODES),
                "-b",
                str(REQUIRED_BLOCKS),
                "-B",
                str(BLOCK_SIZE),
                "-a",
                str(TARBALL),
                str(IMAGE),
            ],
                stderr=subprocess.DEVNULL,
                check=True
            )
            check_output(["qemu-img", "convert", "-f", "raw", "-O", "qcow2", str(IMAGE), str(qcow)])
            if delete_tar:
                check_output(["rm", TARBALL])

        # if our QCOW path is a lustrefs we need to operate within the workdir and copy the qcow out
        if get_mount_type(QCOW.parent) == "lustre":
            # Need to convert to qcow within the workdir
            _make_img(TMP_DIR, Path(TMP_DIR, "image.qcow"), delete_tar)
            check_output(["mv", Path(TMP_DIR, "image.qcow"), str(QCOW)])
        else:
            _make_img(TMP_DIR, QCOW, delete_tar)


def fakeroot_gen_image(fs, out, artifacts, proj_dir, config):
    o = Path(out)
    cmd = [
        "fakeroot",
        "gen_image",
        "--fs",
        str(fs),
        "--out",
        str(o),
        "--artifacts",
        str(artifacts),
        "--proj",
        str(proj_dir),
        "--config",
        str(config),
    ]
    if logger.level == logging.DEBUG:
        cmd.extend(["--verbose"])
    p = subprocess.Popen(cmd, stdout=sys.stdout, stderr=sys.stderr)
    p.wait()

    if p.returncode != 0:
        raise Exception(f"Image generation failed with code {p.returncode}")
    if o.exists():
        return str(o)
    raise Exception("No image generated")


@click.command()
@click.option("--fs", required=True, help="Path to a filesystem as a tar gz")
@click.option("--out", required=True, help="Path to a qcow to be created")
@click.option("--artifacts", default=None, help="Path to a directory for artifacts")
@click.option("--proj", required=True, help="Path to a project directory")
@click.option("--config", default=None, help="Path to config file")
@click.option("-v", "--verbose", count=True)
def makeImage(fs, out, artifacts, proj, config, verbose):
    if verbose:
        logger.setLevel(logging.DEBUG)

    if not os.path.isfile(config):
        logger.error(f"Config file {config} not found")
        sys.exit(1)

    try:
        make_image(fs, out, artifacts, proj, config)
    except Exception as e:
        logger.error("Failed to generate image")
        # Show exception
        logger.error(e, exc_info=True, stack_info=True)
        sys.exit(1)


if __name__ == "__main__":
    makeImage()