import click
import logging
import os
import subprocess
import sys
import tarfile
import tempfile

from pathlib import Path
from subprocess import check_output
from typing import Union

from penguin import getColoredLogger
from .penguin_prep import prep_config
from unifyroot import build_filesystem_from_map


'''
gen_image can be run as a separate script if this is loaded at the module
level. This makes it easier to profile.
'''
from penguin.penguin_config import load_config

'''
This class wrapped what used to be a libguestfs interface

At this point it allows us to pretend that the temporary directory we have
is another file system
'''
logger = getColoredLogger("penguin.gen_image")

def get_mount_type(path):
    try:
        stat_output = subprocess.check_output(['stat', '-f', '-c', '%T', path])
        return stat_output.decode('utf-8').strip().lower()
    except subprocess.CalledProcessError:
        return None

class LocalGuestFS:
    def __init__(self, base):
        self.base = base

    def adjust_path(self, fname):
        fn = Path(fname)
        return Path(self.base, "./"+str(fn), follow_symlinks=False)

    def write(self, path, content):
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

    def mkdir_p(self, d):
        p = self.adjust_path(d)
        p.mkdir(exist_ok=True)

    def readlink(self, path):
        p = self.adjust_path(path)
        return str(p.readlink())

    def ln_s(self, target, path):
        path = self.adjust_path(path)
        path.symlink_to(target)

    def chmod(self, mode, fpath):
        fp = self.adjust_path(fpath)
        if self.is_symlink(fpath):
            # theoretically this could stack overflow
            l = self.readlink(fpath)
            self.chmod(mode, l)
        else:
            # better to do this with pathlib, but it follows symlinks until v3.10
            os.chmod(fp, mode)

    def _mknod(self, t, mode, major, minor, file_path):
        f = self.adjust_path(file_path)
        check_output(f"mknod -m {oct(mode)[2:]} {f} {t} {major} {minor}",shell=True)

    def mknod_c(self, mode, major, minor, file_path):
        self._mknod("b", mode, major, minor, file_path)

    def mknod_c(self, mode, major, minor, file_path):
        self._mknod("c", mode, major, minor, file_path)

    def mv(self, fr, to):
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
    '''
    Copy a host tar file to a guestfs filesystem. Merge or replace as necessary.
    '''

    # Ensure the guest path exists and is a directory
    if not g.is_dir(guest_target_path):
        g.mkdir_p(guest_target_path)
    try:
        with tarfile.open(tar_host_path, 'r:*') as tar:
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
        raise RuntimeError(f"Failed to extract tar archive {tar_host_path} to {guest_target_path}: {e}")

def _modify_guestfs(g, file_path, file, project_dir):
    '''
    Given a guestfs handle, a file path, and a file dict, perform the specified action on the guestfs filesystem.
    If the action is unsupported or fails, we'll print details and raise an exception.
    '''

    if '../' in file_path:
        logger.warning(f"Skipping file {file_path} as it contains '/..'")
        return

    # Check if file_path involves a broken symlink, if so bail
    try:
        g.is_dir(file_path)
    except RuntimeError as e:
        logger.warning(f"Skipping file {file_path} as it's a broken symlink (detected on exn)")
        return

    if file_path.startswith("/dev/") or file_path == "/dev":
        logger.warning(f"/dev/ must be populated dynamically in config.pseudofiles - ignoring request to modify {file_path}")
        return

    try:
        action = file['type']
        if action in ('inline_file', 'host_file'):
            if "contents" in file:
                contents = file['contents']
            elif "host_path" in file:
                # absolute paths are used as-is, relative paths are relative to the project directory
                if os.path.isabs(file['host_path']):
                    hp = file['host_path']
                else:
                    hp = os.path.join(project_dir, file['host_path'])
                try:
                    contents = open(hp, 'rb').read()
                except FileNotFoundError:
                    raise FileNotFoundError(
                        f"Could not find host file at {hp} to add to image as {file_path}")
            mode = file['mode']
            # Delete target if it already exists
            if g.is_file(file_path):
                logger.warning(f"Deleting existing file {file_path} to replace it")
                g.rm(file_path)

            if g.is_symlink(file_path):
                # We could alternatively follow the symlink and delete the target
                logger.warning(f"Deleting existing symlink {file_path}->{g.readlink(file_path)} to replace it")
                g.rm_rf(file_path)

            # Check if this directory exists, if not we'll need to create it
            # XXX: Might ignore permissions set elsewhere in config - how
            # does order of operations work with these config fiiles?
            if not g.is_dir(os.path.dirname(file_path)):
                g.mkdir_p(os.path.dirname(file_path))
            g.write(file_path, contents)
            g.chmod(mode, file_path)

        elif action == 'dir':
            if g.is_dir(file_path):
                try:
                    logger.warning(f"Deleting existing dir {file_path} to replace it")
                    g.rm_rf(file_path) # Delete the directory AND CONTENTS
                except RuntimeError as e:
                    # If directory is like /asdf/. guestfs gets mad. Just warn.
                    logger.warning(f"could not delete directory {file_path} to recreate it: {e}")
                    return

            # Note we ignore mode here?
            dirname = file_path
            g.mkdir_p(dirname)

        elif action == 'symlink':
            # file['target'] is what we point to
            linkpath = file_path # This is what we create
            # Delete linkpath AND CONTENTS if it already exists
            if g.exists(linkpath):
                logger.warning(f"{linkpath} already exists - deleting it to add a link to {file['target']}")
                try:
                    g.rm_rf(linkpath)
                except RuntimeError as e:
                    # If directory is like /asdf/. guestfs gets mad. Just warn.
                    logger.warning(f"could not delete exixsting {linkpath} to recreate it: {e}")
                    return

            # If target doesn't exist, we can't symlink
            if not g.exists(file['target']):
                raise ValueError(f"Can't add symlink to {file['target']} as it doesn't exist in requested symlink from {linkpath}")

            # If the linkpath directory doesn't exist, we can't create the symlink.
            # XXX what if the linkpath dir is a symlink to a dir?
            if not g.is_dir(os.path.dirname(linkpath)):
                # Should we raise an error or a warning? With libinject symlinks potentially getting affected by
                # changing partitions, I'm going to vote for a warning for now. We lack the ability to do a static
                # analysis after we change partition maps and that causes some issues with libinject symlinks that
                # lead to this warning.
                #raise ValueError(f"Cannot create symlink at {linkpath} as parent directory does not exist")
                logger.warning(f"Cannot create symlink at {linkpath} as parent directory does not exist")
                return

            g.ln_s(file['target'], linkpath)
            # Chmod the symlink to be 777 always
            g.chmod(0o777, linkpath)

        elif action == 'dev':
            major = file['major']
            minor = file['minor']
            mode = file['mode']
            if file['devtype'] == 'char':
                g.mknod_c(mode, major, minor, file_path) # Chardev
            elif file['devtype'] == 'block':
                g.mknod_b(mode, major, minor, file_path) # Blockdev
            else:
                raise RuntimeError(f"Unknown devtype {file['devtype']} - only block and char are supported")

            # chmod device to be 777 always
            g.chmod(0o777, file_path)

        elif action == 'delete':
            # Delete the file (or directory and children)
            if not g.exists(file_path) and not g.is_symlink(file_path):
                raise ValueError(f"Can't delete {file_path} as it doesn't exist")
            g.rm_rf(file_path) # We make this one fatal if there's an error.

        elif action == 'move':
            # Move a file (or directory and children) TO
            # the key in yaml (so we can avoid duplicate keys)
            if g.is_symlink(file['from']):
                #print(f"Warning: skipping move_from for symlink {file['from']}")
                #return
                # Let's delete it and make a new symlink (might break?) - xxx does break
                dest = g.readlink(file['from'])
                g.rm(file['from'])
                # Resolve the symlink and make a new one
                # XXX: This is a bit of a hack, but we'll resolve the symlink and make a new one
                new_dest = dest
                if dest[0] != '/':
                    new_dest = os.path.normpath(os.path.join(os.path.dirname(file['from']), dest))
                    logger.debug(f"Moving symlink {file['from']}->{dest} to {file_path}->{new_dest}")

                try:
                    g.ln_s(dest, file_path)
                except Exception as e:
                    print(f"WARNING: could not recreate symlink {file_path} to {dest}: {e}")

            elif not g.exists(file['from']):
                raise ValueError(f"Can't move {file['from']} as it doesn't exist")
            else:
                g.mv(file['from'], file_path)

        elif action == 'chmod':
            # Change the mode of a file or directory
            if not g.exists(file_path):
                raise ValueError(f"Can't chmod {file_path} as it doesn't exist")
            g.chmod(file['mode'], file_path)

        elif action == 'copytar':
            tar_host_path = file['host_path']
            # absolute paths are used as-is, relative paths are relative to the project directory
            if os.path.isabs(tar_host_path):
                hp = tar_host_path
            else:
                hp = os.path.join(project_dir, tar_host_path)
            guest_target_path = file_path
            merge = file['merge'] if 'merge' in file else False
            do_copy_tar(g, hp, guest_target_path, merge)

        else:
            raise RuntimeError(f"Unknown file system action {action}")

    except Exception as e:
        logger.error(f"Exception modifying guest filesystem for {file_path}: {file}: {e}")
        raise e


def add_static_files(fs_base, files, project_dir):
    g = LocalGuestFS(fs_base)

    bin_sh_exists_before_mods = g.exists("/bin/sh")

    # Iterate over files from the YAML file and add them to the guest file system
    # XXX: file['type'] are a bit of a misnomer, it's more of a filesystem action type
    # so we can add/delete files, create directories, etc.

    def resolve_symlink_path(g, path):
        parts = path.strip('/').split('/')
        resolved_path = '/'
        for i, part in enumerate(parts[:-1]):
            # Build the current path incrementally
            current_path = os.path.join(resolved_path, part) if resolved_path != '/' else '/' + part
            if not current_path.startswith('/'):
                current_path = '/' + current_path

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
                    current_path = os.path.normpath(os.path.join(os.path.dirname(resolved_path), link_target))
                    # Prevent changing the base directory if the symlink is for a file
                    if not g.is_symlink(current_path):
                        current_path = os.path.join(os.path.dirname(resolved_path), parts[-1])

            # Update the resolved path only if not dealing with the last component or if it's not a symlink
            if i < len(parts) - 1 or not g.is_symlink(current_path):
                resolved_path = current_path

        return resolved_path + '/' + parts[-1]

    # Sort files by the length of their path to ensure directories are created first
    # But we'll handle 'move_from' types first - we need to move these out *before* we
    # replace them (i.e., /bin/sh goes into /igloo/utils/sh.orig and then we replace /bin/sh)

    # First we'll make any requested directories (which rm -rf anything that exists)
    mkdirs = {k: v for k, v in files.items() if v['type'] == 'dir'}
    sorted_mkdirs = sorted(mkdirs.items(), key=lambda x: len(x[0]))
    for file_path, file in sorted_mkdirs:
        #resolved_file_path = resolve_symlink_path(g, file_path)
        #resolved_file_path = os.path.dirname(resolved_file_path) + '/' + os.path.basename(file_path)
        if resolved_file_path := file_path:
            _modify_guestfs(g, resolved_file_path, file, project_dir)


    # Next, we'll do any move_from operations
    move_from_files = {k: v for k, v in files.items() if v['type'] == 'move_from'}
    sorted_move_from_files = sorted(move_from_files.items(), key=lambda x: len(files[x[0]]))
    for file_path, file in sorted_move_from_files:
        _modify_guestfs(g, file_path, file, project_dir)

    # Now we'll do everything, except symlinks
    sorted_files = {k: v for k, v in files.items() if v['type'] not in ['move_from', 'dir', 'symlink']}
    sorted_files = sorted(sorted_files.items(), key=lambda x: len(x[0]))
    for file_path, file in sorted_files:
        if resolved_file_path := resolve_symlink_path(g, file_path):
            resolved_file_path = os.path.dirname(resolved_file_path) + '/' + os.path.basename(file_path)
            #resolved_file_path = file_path
            #if resolved_file_path != file_path:
            #    print(f"WARNING: Resolved file path {file_path} to {resolved_file_path}")
            _modify_guestfs(g, resolved_file_path, file, project_dir)

    # Create symlinks after everything else because guestfs requires destination to exist
    move_from_files = {k: v for k, v in files.items() if v['type'] == 'symlink'}
    sorted_move_from_files = sorted(move_from_files.items(), key=lambda x: len(files[x[0]]['target']))
    for file_path, file in sorted_move_from_files:
        _modify_guestfs(g, file_path, file, project_dir)

    # Sanity checks. Does guest still have a /bin/sh? Is there a /igloo directory?
    if bin_sh_exists_before_mods and not g.is_file("/bin/sh") and not g.is_symlink("/bin/sh"):
        raise RuntimeError("Guest filesystem does not contain /bin/sh after modifications")

    if not g.is_dir("/igloo"):
        raise RuntimeError("Guest filesystem does not contain /igloo after modifications")

def apply_static_fs_changes(initial_tarball: Path, config: dict, proj_dir: Path, tmp_path: Path) -> Path:
    '''
    Extract tarball to a scratch directory, apply any static filesystem changes, and repackage.
    '''
    tmp_extract = tmp_path / "scratch"
    tmp_extract.mkdir()

    check_output(["tar", "xpsvf", str(initial_tarball), "-C", str(tmp_extract)])

    add_static_files(tmp_extract, config.get("static_files", {}), proj_dir)

    updated_tarball = tmp_path / "updated.tar"
    check_output(["tar", "czpvf", updated_tarball, "-C", tmp_extract, "."])
    return updated_tarball

def create_qcow_image(tarball: Path, qcow_path: Path):
    '''
    Convert a tarball to a qcow2 image.
    '''
    PADDING_MB = 1024
    BLOCK_SIZE = 4096
    INODE_SIZE = 8192

    unpacked_size = int(check_output(f'zcat "{tarball}" | wc -c', shell=True))
    unpacked_size += 1024 * 1024 * PADDING_MB
    required_blocks = int((unpacked_size + BLOCK_SIZE - 1) / BLOCK_SIZE + 1024)
    filesystem_size = required_blocks * BLOCK_SIZE
    number_of_inodes = int(filesystem_size / INODE_SIZE) + 1000

    def _make_img(work_dir: Path, qcow: Path):
        '''
        Helper to convert a raw image to a qcow2 image within work_dir
        '''
        image = work_dir / "image.raw"
        check_output(["truncate", "-s", str(filesystem_size), image])
        check_output([
            "genext2fs", "--faketime", "-N", str(number_of_inodes),
            "-b", str(required_blocks), "-B", str(BLOCK_SIZE),
            "-a", tarball, image
        ])
        check_output(["qemu-img", "convert", "-f", "raw", "-O", "qcow2", image, qcow])

    with tempfile.TemporaryDirectory() as work_dir:
        work_dir_path = Path(work_dir)
        if get_mount_type(qcow_path.parent) == "lustre":
            temp_qcow = work_dir_path / "image.qcow"
            _make_img(work_dir_path, temp_qcow)
            check_output(["mv", temp_qcow, qcow_path])
        else:
            _make_img(work_dir_path, qcow_path)

def create_initial_tarball(proj_dir: Path, config: dict, tmp_path: Path) -> Path:
    '''
    Get or create an initial tarball either by selecting core.fs from the config
    or by combining partitions as specified in core.mounts.
    '''
    if config['core'].get('mounts'):
        logger.info("Building filesystem from mount points: %s", config['core']['mounts'])
        initial_tarball = tmp_path / "fs.tar"
        full_mounts = {"." + k: v + ".tar.gz" for k, v in config['core']['mounts'].items()}
        build_filesystem_from_map(
            str(proj_dir / "base/partitions"),
            str(initial_tarball),
            full_mounts
        )
    else:
        logger.info("Building filesystem from initial tarball %s", config['core']['fs'])
        initial_tarball = proj_dir / config['core']['fs']
    return initial_tarball

def make_image(proj_dir: Union[str, Path], config_path: str, out: str):
    """
    Given a project directory, a configuration, and a path for an output qcow,
    build the output according to the config.

    If the config specifies <core.mounts> we'll combine partitions within
    proj_dir/base/partitions/<partition_name>.tar.gz as specified. Otherwise we'll
    begin with the single tarball specified in <core.fs> (which is also relative to
    proj_dir). After we have our initial filesystem, we'll apply any static filesystem
    changes specified in the config. Finally, we'll convert it into a qcow image at
    the output path.
    """

    logger.info("Generating new image from config...")
    proj_dir = Path(proj_dir)
    config = load_config(config_path)
    prep_config(config) # Add libinject into config.static_files

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        initial_tarball = create_initial_tarball(proj_dir, config, tmp_path)
        updated_tarball = apply_static_fs_changes(initial_tarball, config, proj_dir, tmp_path)

        # Copy updated tarball to /tmp/debug.tar.gz
        #debug_tarball = Path("/tmp/debug.tar.gz")
        #check_output(["cp", updated_tarball, debug_tarball])

        create_qcow_image(updated_tarball, Path(out))

def fakeroot_gen_image(proj, config, out):
    o = Path(out)
    cmd = ["fakeroot", "gen_image",
           "--proj", str(proj),
           "--config", str(config),
           "--out", str(o)]
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
@click.option('--proj', default=None, help="Path to project directory")
@click.option('--config', default=None, help="Path to config file")
@click.option('--out', required=True, help="Path to a qcow to be created")
@click.option('-v', '--verbose', count=True)
def makeImage(proj, config, out, verbose):
    if verbose:
        logger.setLevel(logging.DEBUG)

    if not os.path.isfile(config):
        logger.error(f"Config file {config} not found")
        sys.exit(1)

    if not os.path.isdir(proj):
        logger.error(f"Project directory {proj} not found")
        sys.exit(1)

    try:
        make_image(proj, config, out)
    except Exception as e:
        logger.error(f"Failed to generate image")
        # Show exception
        logger.error(e, exc_info=True, stack_info=True)
        sys.exit(1)

if __name__ == "__main__":
    makeImage()
