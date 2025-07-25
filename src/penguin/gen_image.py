import logging
import os
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from subprocess import check_output
from random import randint
import keystone

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


def do_copy_tar(g, tar_host_path, guest_target_path, merge=False):
    """
    Copy a host tar file to a guestfs filesystem. Merge or replace as necessary.
    """

    # Ensure the guest path exists and is a directory
    if not g.is_dir(guest_target_path):
        g.mkdir_p(guest_target_path)
    try:
        with tarfile.open(tar_host_path, "r:*") as tar:
            for member in tar.getmembers():
                member_path = os.path.join(guest_target_path, member.name)
                if member.isdir():
                    if not g.is_dir(member_path) or not merge:
                        g.mkdir_p(member_path)
                elif member.isfile():
                    # Extract file contents
                    f = tar.extractfile(member)
                    contents = f.read()
                    f.close()

                    # Check if file exists and should be replaced
                    if g.exists(member_path) and not g.is_dir(member_path):
                        if merge:
                            # Replace file
                            g.rm(member_path)
                        else:
                            # Skip existing files when merging
                            continue

                    g.write(member_path, contents)
                elif member.issym():
                    # Handle symbolic links (if necessary)
                    pass
                # Additional handling for other types (symlinks, devices, etc.) as necessary
    except Exception as e:
        raise RuntimeError(
            f"Failed to extract tar archive {tar_host_path} to {guest_target_path}: {e}"
        )


def _move_modify_guestfs(g, file_path, file):
    # Move a file (or directory and children) TO
    # the key in yaml (so we can avoid duplicate keys)
    if g.is_symlink(file["from"]):

        symlink_target = g.readlink(file["from"])
        g.rm(file["from"])

        if not os.path.isabs(symlink_target):
            symlink_target = os.path.normpath(
                os.path.join(os.path.dirname(file["from"]), symlink_target)
            )

        try:
            g.ln_s(symlink_target, file_path)
        except Exception as e:
            print(f"WARNING: could not recreate symlink {file_path} to {symlink_target}: {e}")

    elif not g.exists(file["from"]):
        raise ValueError(f"Can't move {file['from']} as it doesn't exist")
    else:
        g.mv(file["from"], file_path)
        if "mode" in file:
            g.chmod(file["mode"], file_path)


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

    if file_path.startswith("/dev/") or file_path == "/dev":
        logger.warning(
            f"/dev/ must be populated dynamically in config.pseudofiles - ignoring request to modify {file_path}"
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

        elif action == "dir":
            if g.is_dir(file_path):
                try:
                    logger.warning(f"Deleting existing dir {file_path} to replace it")
                    g.rm_rf(file_path)  # Delete the directory AND CONTENTS
                except RuntimeError as e:
                    # If directory is like /asdf/. guestfs gets mad. Just warn.
                    logger.warning(
                        f"could not delete directory {file_path} to recreate it: {e}"
                    )
                    return

            # Note we ignore mode here?
            dirname = g.resolve_symlink(file_path)
            g.mkdir_p(dirname)

        elif action == "symlink":
            _symlink_modify_guestfs(g, file_path, file)

        elif action == "dev":
            major = file["major"]
            minor = file["minor"]
            mode = file["mode"]
            if file["devtype"] == "char":
                g.mknod_c(mode, major, minor, file_path)  # Chardev
            elif file["devtype"] == "block":
                g.mknod_b(mode, major, minor, file_path)  # Blockdev
            else:
                raise RuntimeError(
                    f"Unknown devtype {file['devtype']} - only block and char are supported"
                )

            # chmod device to be 777 always
            g.chmod(0o777, file_path)

        elif action == "delete":
            # Delete the file (or directory and children)
            if not g.exists(file_path) and not g.is_symlink(file_path):
                raise ValueError(f"Can't delete {file_path} as it doesn't exist")
            g.rm_rf(file_path)  # We make this one fatal if there's an error.

        elif action == "move":
            # Move a file (or directory and children) TO
            # the key in yaml (so we can avoid duplicate keys)
            _move_modify_guestfs(g, file_path, file)

        elif action == "chmod":
            # Change the mode of a file or directory
            if not g.exists(file_path):
                raise ValueError(f"Can't chmod {file_path} as it doesn't exist")
            g.chmod(file["mode"], file_path)

        elif action == "copytar":
            tar_host_path = file["host_path"]
            # absolute paths are used as-is, relative paths are relative to the project directory
            if os.path.isabs(tar_host_path):
                hp = tar_host_path
            else:
                hp = os.path.join(project_dir, tar_host_path)
            guest_target_path = file_path
            merge = file["merge"] if "merge" in file else False
            do_copy_tar(g, hp, guest_target_path, merge)

        elif action == "shim":
            # Store original file
            move_file_path = "/igloo/utils/" + file_path.split("/")[-1] + ".orig"
            move_file = {"type": "move", "from": file_path}
            _move_modify_guestfs(g, move_file_path, move_file)

            # Create a symlink to desired target
            symlink_file = {"type": "symlink", "target": file["target"]}
            _symlink_modify_guestfs(g, file_path, symlink_file)
        elif action == "binary_patch":
            file_offset = file.get("file_offset")
            bytes_hex = file.get("hex_bytes")
            asm = file.get("asm")

            if bool(bytes_hex) == bool(asm):
                raise ValueError("Exactly one of 'hex_bytes' or 'asm' must be specified for binary_patch")

            if asm:
                arch_map = {
                    "armel": getattr(keystone, "KS_ARCH_ARM"),
                    "aarch64": getattr(keystone, "KS_ARCH_ARM64"),
                    "mipsel": getattr(keystone, "KS_ARCH_MIPS"),
                    "mipseb": getattr(keystone, "KS_ARCH_MIPS"),
                    "mips64el": getattr(keystone, "KS_ARCH_MIPS"),
                    "mips64eb": getattr(keystone, "KS_ARCH_MIPS"),
                    "intel64": getattr(keystone, "KS_ARCH_X86"),
                }
                mode_map = {
                    "aarch64": getattr(keystone, "KS_MODE_LITTLE_ENDIAN") | getattr(keystone, "KS_MODE_64"),
                    "mipsel": getattr(keystone, "KS_MODE_MIPS32") | getattr(keystone, "KS_MODE_LITTLE_ENDIAN"),
                    "mipseb": getattr(keystone, "KS_MODE_MIPS32") | getattr(keystone, "KS_MODE_BIG_ENDIAN"),
                    "mips64el": getattr(keystone, "KS_MODE_MIPS64") | getattr(keystone, "KS_MODE_LITTLE_ENDIAN"),
                    "mips64eb": getattr(keystone, "KS_MODE_MIPS64") | getattr(keystone, "KS_MODE_BIG_ENDIAN"),
                    "intel64": getattr(keystone, "KS_MODE_64"),
                }
                arch = config["core"]["arch"]
                ks_arch = arch_map.get(arch)
                if ks_arch is None:
                    raise ValueError(f"Unsupported arch: {arch}")

                # Handle ARM mode selection
                if arch == "armel":
                    user_mode = file.get("mode", "arm")
                    if user_mode == "thumb":
                        ks_mode = getattr(keystone, "KS_MODE_THUMB") | getattr(keystone, "KS_MODE_LITTLE_ENDIAN")
                    else:
                        ks_mode = getattr(keystone, "KS_MODE_ARM") | getattr(keystone, "KS_MODE_LITTLE_ENDIAN")
                else:
                    ks_mode = mode_map.get(arch)
                    if ks_mode is None:
                        raise ValueError(f"Unsupported mode for arch: {arch}")

                ks = keystone.Ks(ks_arch, ks_mode)
                encoding, _ = ks.asm(asm)
                patch_bytes = bytes(encoding)
            else:
                patch_bytes = bytes.fromhex(bytes_hex.replace(" ", ""))

            if file_offset is None:
                raise ValueError("binary_patch requires file_offset")

            target_path = file_path
            p = g.adjust_path(target_path)
            if not os.path.isfile(p):
                raise FileNotFoundError(f"Target file for binary_patch not found: {target_path}")

            with open(p, "r+b") as f:
                f.seek(file_offset)
                f.write(patch_bytes)

        else:
            raise RuntimeError(f"Unknown file system action {action}")

    except Exception as e:
        logger.error(
            f"Exception modifying guest filesystem for {file_path}: {file}: {e}"
        )
        raise e


def fs_make_config_changes(fs_base, config, project_dir):
    g = LocalGuestFS(fs_base)

    bin_sh_exists_before_mods = g.exists("/bin/sh")

    # Iterate over files from the YAML file and add them to the guest file system
    # XXX: file['type'] are a bit of a misnomer, it's more of a filesystem action type
    # so we can add/delete files, create directories, etc.

    def resolve_symlink_path(g, path):
        parts = path.strip("/").split("/")
        resolved_path = "/"
        for i, part in enumerate(parts[:-1]):
            # Build the current path incrementally
            current_path = (
                os.path.join(resolved_path, part)
                if resolved_path != "/"
                else "/" + part
            )
            if not current_path.startswith("/"):
                current_path = "/" + current_path

            # Check if the current path is a symlink and resolve it
            try:
                symlink = g.is_symlink(current_path)
            except RuntimeError:
                # Bail - infinite loop?
                logger.error(f"Unable to resolve symlink {current_path} - bailing out")
                return None

            if symlink:
                link_target = g.readlink(current_path)
                # If the link is absolute or the current part is not the last part (indicating a directory symlink), resolve fully
                if os.path.isabs(link_target) or i < len(parts) - 1:
                    current_path = os.path.normpath(link_target)
                else:
                    # If the link target is relative and we're at the last part, adjust the path without changing the base
                    current_path = os.path.normpath(
                        os.path.join(os.path.dirname(resolved_path), link_target)
                    )
                    # Prevent changing the base directory if the symlink is for a file
                    if not g.is_symlink(current_path):
                        current_path = os.path.join(
                            os.path.dirname(resolved_path), parts[-1]
                        )

            # Update the resolved path only if not dealing with the last component or if it's not a symlink
            if i < len(parts) - 1 or not g.is_symlink(current_path):
                resolved_path = current_path

        return resolved_path + "/" + parts[-1]

    # Sort files by the length of their path to ensure directories are created first
    # But we'll handle 'move_from' types first - we need to move these out *before* we
    # replace them (i.e., /bin/sh goes into /igloo/utils/sh.orig and then we replace /bin/sh)
    files = config["static_files"] if "static_files" in config else {}

    # First we'll make any requested directories (which rm -rf anything that exists)
    mkdirs = {k: v for k, v in files.items() if v["type"] == "dir"}
    sorted_mkdirs = sorted(mkdirs.items(), key=lambda x: len(x[0]))
    for file_path, file in sorted_mkdirs:
        # resolved_file_path = resolve_symlink_path(g, file_path)
        # resolved_file_path = os.path.dirname(resolved_file_path) + '/' + os.path.basename(file_path)
        if resolved_file_path := file_path:
            _modify_guestfs(g, resolved_file_path, file, project_dir, config)

    # Next, we'll do any move_from operations
    move_from_files = {k: v for k, v in files.items() if v["type"] == "move_from"}
    sorted_move_from_files = sorted(
        move_from_files.items(), key=lambda x: len(files[x[0]])
    )
    for file_path, file in sorted_move_from_files:
        _modify_guestfs(g, file_path, file, project_dir, config)

    # Now we'll do everything, except symlinks
    sorted_files = {
        k: v
        for k, v in files.items()
        if v["type"] not in ["move_from", "dir", "symlink", "shim"]
    }
    sorted_files = sorted(sorted_files.items(), key=lambda x: len(x[0]))
    for file_path, file in sorted_files:
        if resolved_file_path := resolve_symlink_path(g, file_path):
            resolved_file_path = (
                os.path.dirname(resolved_file_path) + "/" + os.path.basename(file_path)
            )
            # resolved_file_path = file_path
            # if resolved_file_path != file_path:
            #    print(f"WARNING: Resolved file path {file_path} to {resolved_file_path}")
            _modify_guestfs(g, resolved_file_path, file, project_dir, config)

    # Create symlinks after everything else because guestfs requires destination to exist
    # move_from_files = {k: v for k, v in files.items() if v["type"] == "symlink"}
    move_from_files = {
        k: v for k, v in files.items() if v["type"] in ["symlink", "shim"]
    }
    sorted_move_from_files = sorted(
        move_from_files.items(), key=lambda x: len(files[x[0]]["target"])
    )
    for file_path, file in sorted_move_from_files:
        _modify_guestfs(g, file_path, file, project_dir, config)

    # Sanity checks. Does guest still have a /bin/sh? Is there a /igloo directory?
    if (
        bin_sh_exists_before_mods
        and not g.is_file("/bin/sh")
        and not g.is_symlink("/bin/sh")
    ):
        raise RuntimeError(
            "Guest filesystem does not contain /bin/sh after modifications"
        )

    if not g.is_dir("/igloo"):
        raise RuntimeError(
            "Guest filesystem does not contain /igloo after modifications"
        )


def make_image(fs, out, artifacts, proj_dir, config_path):
    logger.debug("Generating new image from config...")
    IN_TARBALL = Path(fs)
    ARTIFACTS = Path(artifacts or "/tmp")
    QCOW = Path(out)
    ARTIFACTS.mkdir(exist_ok=True)

    # Unique suffix to avoid conflicts
    suffix = randint(0, 1000000)

    # Decompress the archive and store in artifacts/fs_orig.tar
    # XXX: Why do we do this?
    # ORIGINAL_DECOMP_FS = Path(ARTIFACTS, f"fs_orig.tar")
    # check_output(f'gunzip -c "{IN_TARBALL}" > "{ORIGINAL_DECOMP_FS}"', shell=True)

    project_dir = os.path.dirname(os.path.realpath(config_path))

    if config_path:
        delete_tar = True
        MODIFIED_TARBALL = Path(ARTIFACTS, f"fs_out_{suffix}.tar")
        config = load_config(proj_dir, config_path)
        with tempfile.TemporaryDirectory() as TMP_DIR:
            contents = check_output(["tar", "-x", "--use-compress-program=pigz", "-vpf", IN_TARBALL, "-C", TMP_DIR]).splitlines()
            # Gracefully handle emptyfs
            if contents and contents[0] != b"./":
                logger.warning("Filesystem tar does not have a leading ./")
                logger.warning("You may encounter strange errors due to unexpected rootfs format!")
                logger.warning("You can resolve this by running fw2tar on your filesystem.")
            from .penguin_prep import prep_config

            prep_config(config)
            fs_make_config_changes(TMP_DIR, config, project_dir)
            check_output(["tar", "-c", "--use-compress-program=pigz", "-pf", MODIFIED_TARBALL, "-C", TMP_DIR, "."])
        TARBALL = MODIFIED_TARBALL
    else:
        delete_tar = False
        TARBALL = IN_TARBALL

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

    with tempfile.TemporaryDirectory() as WORK_DIR:
        # if our QCOW path is a lustrefs we need to operate within the workdir and copy the qcow out
        if get_mount_type(QCOW.parent) == "lustre":
            # Need to convert to qcow within the workdir
            _make_img(WORK_DIR, Path(WORK_DIR, "image.qcow"), delete_tar)
            check_output(["mv", Path(WORK_DIR, "image.qcow"), QCOW])
        else:
            _make_img(WORK_DIR, QCOW, delete_tar)


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
