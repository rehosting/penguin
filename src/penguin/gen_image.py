import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from subprocess import check_output
from random import randint
from penguin.defaults import default_init_script, static_dir as STATIC_DIR

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


class LocalGuestFS:
    def __init__(self, base):
        self.base = base

    def adjust_path(self, fname):
        fn = Path(fname)
        return Path(self.base, "./" + str(fn), follow_symlinks=False)

    # given a path, ensure that all containing folders exist
    def ensure_containing_folders_exists(self, path):
        p = self.adjust_path(path)

        for i in p.parents:
            if not i.exists():
                # Can't be a symlink, because we already resolved (recursively)
                i.mkdir(exist_ok=True, parents=True)
            else:
                # stop once we hit a directory that exists
                break

    def write(self, path, content):
        self.ensure_containing_folders_exists(path)
        p = self.adjust_path(path)
        with open(p, "w" if type(content) is str else "wb") as f:
            f.write(content)

    def exists(self, fname):
        # https://stackoverflow.com/questions/75444181/pathlib-path-exists-returns-false-for-broken-symlink
        q = self.adjust_path(fname)
        return q.is_symlink() or q.exists()

    def is_file(self, d):
        p = self.adjust_path(d)
        return p.is_file()

    def is_dir(self, d):
        p = self.adjust_path(d)
        return p.is_dir()

    def is_symlink(self, d):
        # https://stackoverflow.com/questions/75444181/pathlib-path-exists-returns-false-for-broken-symlink
        p = self.adjust_path(d)
        return p.is_symlink()

    def resolve_symlink(self, d):
        base = ""
        for part in d.split("/"):
            if self.is_symlink(base):
                target = self.readlink(base)
                logger.debug(f"Found (and resolved) symlink {base}->{target}")
                new_d = d.replace(base, target + "/")
                return self.resolve_symlink(new_d)
            base += part + "/"

        return base[:-1] if len(base) else base

    def mkdir_p(self, d):
        # Create all parent directories (and resolve symlinks) as necessary
        # Then make the child directory requested
        self.ensure_containing_folders_exists(d)
        p = self.adjust_path(d)
        p.mkdir(exist_ok=True)

    def readlink(self, path):
        p = self.adjust_path(path)
        return str(p.readlink())

    def ln_s(self, target, path):
        self.ensure_containing_folders_exists(Path(target))
        self.ensure_containing_folders_exists(Path(path))
        p = self.adjust_path(path)
        p.symlink_to(target)

    def chmod(self, mode, fpath):
        fp = self.adjust_path(fpath)
        if self.is_symlink(fpath):
            # theoretically this could stack overflow
            self.chmod(mode, self.readlink(fpath))
        else:
            # better to do this with pathlib, but it follows symlinks until v3.10
            os.chmod(fp, mode)

    def _mknod(self, t, mode, major, minor, file_path):
        self.ensure_containing_folders_exists(file_path)
        f = self.adjust_path(file_path)
        check_output(f"mknod -m {oct(mode)[2:]} {f} {t} {major} {minor}", shell=True)

    def mknod_b(self, mode, major, minor, file_path):
        self._mknod("b", mode, major, minor, file_path)

    def mknod_c(self, mode, major, minor, file_path):
        self._mknod("c", mode, major, minor, file_path)

    def mv(self, fr, to):
        self.ensure_containing_folders_exists(to)
        self.ensure_containing_folders_exists(fr)
        from_ = self.adjust_path(fr)
        to_ = self.adjust_path(to)
        check_output(f"mv {from_} {to_}", shell=True)

    def rm(self, path):
        self.rm_rf(path)

    def rm_rf(self, path):
        p = self.adjust_path(path)
        # gross, but the most accurate
        check_output(f"rm -rf {p}", shell=True)

def _symlink_modify_guestfs(g, file_path, file):
    # file['target'] is what we point to
    linkpath = file_path  # This is what we create
    # Delete linkpath AND CONTENTS if it already exists
    if g.exists(linkpath):
        try:
            g.rm_rf(linkpath)
        except RuntimeError as e:
            # If directory is like /asdf/. guestfs gets mad. Just warn.
            logger.warning(f"could not delete exixsting {linkpath} to recreate it: {e}")
            return

    # If target doesn't exist, we can't symlink
    if not g.exists(file["target"]):
        raise ValueError(
            f"Can't add symlink to {file['target']} as it doesn't exist in requested symlink from {linkpath}"
        )

    g.ln_s(file["target"], linkpath)
    # Chmod the symlink to be 777 always
    g.chmod(0o777, linkpath)


def _modify_guestfs(g, file_path, file, project_dir, config):
    """
    Given a guestfs handle, a file path, and a file dict, perform the specified action on the guestfs filesystem.
    If the action is unsupported or fails, we'll print details and raise an exception.
    """

    if "../" in file_path:
        logger.warning(f"Skipping file {file_path} as it contains '/..'")
        return

    # Check if file_path involves a broken symlink, if so bail
    try:
        g.is_dir(file_path)
    except RuntimeError:
        logger.warning(
            f"Skipping file {file_path} as it's a broken symlink (detected on exn)"
        )
        return

    try:
        action = file["type"]
        if action in ("inline_file", "host_file"):
            if "contents" in file:
                contents = file["contents"]
            elif "host_path" in file:
                # absolute paths are used as-is, relative paths are relative to the project directory
                if os.path.isabs(file["host_path"]):
                    hp = file["host_path"]
                else:
                    hp = os.path.join(project_dir, file["host_path"])

                if "*" in hp:
                    from glob import glob

                    matches = glob(hp)
                    if len(matches) > 1:
                        # only handling * case for now
                        folder = Path(file_path).parent
                        for m in matches:
                            new_file = file
                            new_file["host_path"] = m
                            new_file_path = str(Path(folder, Path(m).name))
                            _modify_guestfs(g, new_file_path, new_file, project_dir, config)
                        return

                try:
                    contents = open(hp, "rb").read()
                except FileNotFoundError:
                    raise FileNotFoundError(
                        f"Could not find host file at {hp} to add to image as {file_path}"
                    )
            mode = file["mode"]
            # Delete target if it already exists
            if g.is_file(file_path):
                logger.warning(f"Deleting existing file {file_path} to replace it")
                g.rm(file_path)

            if g.is_symlink(file_path):
                # We could alternatively follow the symlink and delete the target
                logger.warning(
                    f"Deleting existing symlink {file_path}->{g.readlink(file_path)} to replace it"
                )
                g.rm_rf(file_path)

            # Check if this directory exists, if not we'll need to create it
            # XXX: Might ignore permissions set elsewhere in config - how
            # does order of operations work with these config fiiles?
            file_path = g.resolve_symlink(file_path)

            if not g.is_dir(os.path.dirname(file_path)):
                g.mkdir_p(os.path.dirname(file_path))
            g.write(file_path, contents)
            g.chmod(mode, file_path)

        elif action == "symlink":
            _symlink_modify_guestfs(g, file_path, file)
        else:
            raise RuntimeError(f"Unknown file system action {action}")

    except Exception as e:
        logger.error(
            f"Exception modifying guest filesystem for {file_path}: {file}: {e}"
        )
        raise e

def fs_make_min_config(fs_base, config, project_dir):
    g = LocalGuestFS(fs_base)
    arch = config["core"]["arch"]
    if arch == "intel64":
        arch_dir = "x86_64"
    elif arch == "powerpc64el":
        arch_dir = "powerpc64"
    else:
        arch_dir = arch

    min_static_files = {
        "/igloo/init": {
            "type": "inline_file",
            "contents": default_init_script,
            "mode": 0o111,
        },
        "/igloo/utils/busybox": {
            "type": "host_file",
            "host_path": f"{STATIC_DIR}/{arch_dir}/busybox",
            "mode": 0o755,
        },
        "/igloo/utils/sh": {
            "type": "symlink",
            "target": "/igloo/utils/busybox",
        },
    }
    for file_path, file in min_static_files.items():
        _modify_guestfs(g, file_path, file, project_dir, config)


def make_image(fs, out, artifacts, proj_dir, config_path):
    logger.debug("Generating new image from config...")
    IN_TARBALL = Path(fs)
    ARTIFACTS = Path(artifacts or "/tmp")
    QCOW = Path(out)
    ARTIFACTS.mkdir(exist_ok=True)

    # Unique suffix to avoid conflicts
    suffix = randint(0, 1000000)
    project_dir = os.path.dirname(os.path.realpath(config_path))

    delete_tar = True
    MODIFIED_TARBALL = Path(ARTIFACTS, f"fs_out_{suffix}.tar")
    config = load_config(proj_dir, config_path)
    with tempfile.TemporaryDirectory() as TMP_DIR:
        fs_make_min_config(TMP_DIR, config, project_dir)
        check_output(["tar", "-cf", "/tmp/min_tar.tar", "-C", TMP_DIR, "."])
        uncompressed_tar = Path(TMP_DIR, f"uncompressed_{suffix}.tar")
        check_output(f"pigz -dc '{str(IN_TARBALL)}' > '{uncompressed_tar}'", shell=True)
        check_output(["tar", "-Af", str(uncompressed_tar), "/tmp/min_tar.tar"])
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
                TARBALL,
                IMAGE,
            ],
                stderr=subprocess.DEVNULL,
                check=True
            )
            check_output(["qemu-img", "convert", "-f", "raw", "-O", "qcow2", IMAGE, qcow])
            if delete_tar:
                check_output(["rm", TARBALL])

        # if our QCOW path is a lustrefs we need to operate within the workdir and copy the qcow out
        if get_mount_type(QCOW.parent) == "lustre":
            # Need to convert to qcow within the workdir
            _make_img(TMP_DIR, Path(TMP_DIR, "image.qcow"), delete_tar)
            check_output(["mv", Path(TMP_DIR, "image.qcow"), QCOW])
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
