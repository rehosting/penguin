#!/usr/bin/env python3
import guestfs
import os
import subprocess
import tarfile
import sys
from tempfile import TemporaryDirectory
import shutil
from .common import yaml, hash_yaml
from .utils import get_mount_type

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

def _modify_guestfs(g, file_path, file):
    '''
    Given a guestfs handle, a file path, and a file dict, perform the specified action on the guestfs filesystem.
    If the action is unsupported or fails, we'll print details and raise an exception.
    '''

    if '../' in file_path:
        print(f"WARNING: Skipping file {file_path} as it contains '/..'")
        return

    # Check if file_path involves a broken symlink, if so bail
    try:
        g.is_dir(file_path)
    except RuntimeError as e:
        print(f"WARNING: Skipping file {file_path} as it's a broken symlink (detected on exn)")
        return

    try:
        action = file['type']
        if action == 'file':
            if "contents" in file:
                contents = file['contents']
            elif "hostpath" in file:
                try:
                    contents = open(file['hostpath'], 'rb').read()
                except FileNotFoundError:
                    raise FileNotFoundError(
                        f"Could not find host file at {file['hostpath']} to add to image as {file_path}")
            mode = file['mode']
            # Delete target if it already exists
            if g.is_file(file_path):
                print(f"WARNING: Deleting existing file {file_path} to replace it")
                g.rm(file_path)

            if g.is_symlink(file_path):
                # We could alternatively follow the symlink and delete the target
                print(f"WARNING: Deleting existing symlink {file_path}->{g.readlink(file_path)} to replace it")
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
                    print(f"WARNING: Deleting existing dir {file_path} to replace it")
                    g.rm_rf(file_path) # Delete the directory AND CONTENTS
                except RuntimeError as e:
                    # If directory is like /asdf/. guestfs gets mad. Just warn.
                    print(f"WARNING: could not delete directory {file_path} to recreate it: {e}")
                    return

                # Note we ignore mode here?
                dirname = file_path
                g.mkdir(dirname)

        elif action == 'symlink':
            # file['target'] is what we point to
            linkpath = file_path # This is what we create
            # Delete linkpath AND CONTENTS if it already exists
            if g.exists(linkpath):
                try:
                    g.rm_rf(linkpath)
                except RuntimeError as e:
                    # If directory is like /asdf/. guestfs gets mad. Just warn.
                    print(f"WARNING: could not delete exixsting {linkpath} to recreate it: {e}")
                    return

            # If target doesn't exist, we can't symlink
            if not g.exists(file['target']):
                raise ValueError(f"Can't add symlink to {file['target']} as it doesn't exist in requested symlink from {linkpath}")

            g.ln_s(file['target'], linkpath)
            # Chmod the symlink to be 777 always
            g.chmod(0o777, linkpath)

        elif action == 'dev':
            if file_path.startswith("/dev/"):
                print("WARNING: devices in /dev/ should be populated dynamically")
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
            if not g.exists(file_path):
                raise ValueError(f"Can't delete {file_path} as it doesn't exist")
            g.rm_rf(file_path) # We make this one fatal if there's an error.

        elif action == 'move_from':
            # Move a file (or directory and children) TO
            # the key in yaml (so we can avoid duplicate keys)
            if g.is_symlink(file['from']):
                #print(f"Warning: skipping move_from for symlink {file['from']}")
                #return
                # Let's delete it and make a new symlink
                dest = g.readlink(file['from'])
                g.rm(file['from'])
                g.ln_s(dest, file_path)

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
            tar_host_path = file['hostpath']
            guest_target_path = file_path
            merge = file['merge'] if 'merge' in file else False
            do_copy_tar(g, tar_host_path, guest_target_path, merge)

        else:
            raise RuntimeError(f"Unknown file system action {action}")

    except Exception as e:
        print(f"Exception modifying guest filesystem for {file_path}: {file}: {e}")
        print("Guest filesystem details:")
        print(g.df())
        print(g.statvfs("/"))
        print(g.mountpoints())
        raise


def _rebase_and_add_files(qcow_file, new_qcow_file, files):
    assert(os.path.isfile(qcow_file)), f"Could not find base qcow file {qcow_file}"
    cmd = ['qemu-img', 'create', '-f', 'qcow2', '-b', qcow_file, '-F', 'qcow2', new_qcow_file]

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate() # Wait for termination
    except subprocess.CalledProcessError as e:
        print(f"An exception occurred launching {cmd}: {str(e)}")
        print(e.output)
        raise

    if process.returncode:
        print(f"Error running {cmd}: Got return code {process.returncode}")
        print("STDOUT:", stdout)
        print("STDERR:", stderr)

    g = guestfs.GuestFS(python_return_dict=True)

    # Attach the new QCOW2 file
    g.add_drive_opts(new_qcow_file, format="qcow2", readonly=0)
    g.launch()

    # Mount the file system
    devices = g.list_devices()
    g.mount(devices[0], "/")

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
                print(f"Unable to resolve symlink {current_path} - bailing out")
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
    sorted_mkdirs = sorted(mkdirs.items(), key=lambda x: len(files[x[0]]))
    for file_path, file in sorted_mkdirs:
        #resolved_file_path = resolve_symlink_path(g, file_path)
        #resolved_file_path = os.path.dirname(resolved_file_path) + '/' + os.path.basename(file_path)
        if resolved_file_path := file_path:
            _modify_guestfs(g, resolved_file_path, file)


    # Next, we'll do any move_from operations
    move_from_files = {k: v for k, v in files.items() if v['type'] == 'move_from'}
    sorted_move_from_files = sorted(move_from_files.items(), key=lambda x: len(files[x[0]]['from']))
    for file_path, file in sorted_move_from_files:
        _modify_guestfs(g, file_path, file)

    # Now we'll do everything else
    sorted_files = {k: v for k, v in files.items() if v['type'] not in ['move_from', 'dir']}
    sorted_files = sorted(sorted_files.items(), key=lambda x: len(x[0]))
    for file_path, file in sorted_files:
        if resolved_file_path := resolve_symlink_path(g, file_path):
            resolved_file_path = os.path.dirname(resolved_file_path) + '/' + os.path.basename(file_path)
            #resolved_file_path = file_path
            #if resolved_file_path != file_path:
            #    print(f"WARNING: Resolved file path {file_path} to {resolved_file_path}")

            _modify_guestfs(g, resolved_file_path, file)

    # Sanity checks. Does guest still have a /bin/sh? Is there a /igloo directory?
    if bin_sh_exists_before_mods and not g.is_file("/bin/sh") and not g.is_symlink("/bin/sh"):
        print("LS /bin:", g.ls("/bin"))
        raise RuntimeError("Guest filesystem does not contain /bin/sh after modifications")

    if not g.is_dir("/igloo"):
        raise RuntimeError("Guest filesystem does not contain /igloo after modifications")

    # Shutdown and close guestfs handle
    g.shutdown()
    g.close()

    # Now, after we've made our changes, we can rebase the QCOW2 file back to the original to shrink it
    # We want to run this command, but if it fails dump the output to the user
    try:
        subprocess.run(['qemu-img', 'rebase', '-b', qcow_file, '-F', 'qcow2', new_qcow_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f"WARNING: Failed to rebase qcow file {new_qcow_file} to {qcow_file}. Output was:")
        print(e.output)
        raise


def derive_qcow_from(qcow_file, out_dir, files, out_filename=None):
    '''
    Make a new qcow in outdir, backed by qcow_file, with the specified files added.
    '''

    new_qcow_file = os.path.join(out_dir, (out_filename if out_filename else "image.qcow2"))

    if get_mount_type(os.path.dirname(new_qcow_file)) == "lustre":
        # This FS doesn't support the operations we need to do in converting raw->qcow. Instead try using /tmp
        if "ext3" not in get_mount_type("/tmp"):
            raise RuntimeError("Incompatible filesystem. Neither output_dir ({new_qcow_file}) nor /tmp are ext3")

        with TemporaryDirectory() as temp_dir:
            tmp_in_qcow = temp_dir + "/tmp_in.qcow"
            tmp_out_qcow = temp_dir + "/tmp.qcow"
            shutil.copy(qcow_file, tmp_in_qcow)

            # Both input and output are in our temp dir
            _rebase_and_add_files(tmp_in_qcow, tmp_out_qcow, files)

            # Now update the generated image so that it's rebased on the original qcow
            subprocess.run(['qemu-img', 'rebase', '-u', '-b', qcow_file, '-F', 'qcow2', tmp_out_qcow], check=True)

            # Now move the generated qcow to the right output path
            shutil.move(tmp_out_qcow, new_qcow_file)

    else:
        # We can use the output dir directly
        _rebase_and_add_files(qcow_file, new_qcow_file, files)

    # Sanity check: make sure the new qcow isn't empty
    assert(os.path.getsize(new_qcow_file) > 0), f"New qcow file {new_qcow_file} is empty. Something went very wrong."

    return new_qcow_file

def prepare_run(conf, out_dir, out_filename="image.qcow2"):
    base_qcow = conf['core']['qcow']
    config_files = conf['static_files'] if 'static_files' in conf else {}
    config_nvram = conf['nvram'] if 'nvram' in conf else {}

    config_files[f"/igloo/libnvram/"] = {
        'type': "dir",
        'mode': 0o755,
    }

    # For each key in config_nvram, we'll just add it to the FS
    for k, val in config_nvram.items():
        if isinstance(val, str):
            encoded = val.encode()
        elif isinstance(val, int):
            encoded = str(val).encode() #???
        else:
            raise ValueError(f"Unknown type for nvram value {k}: {type(val)}")

        config_files[f"/igloo/libnvram/{k}"] = {
            'type': "file",
            'contents': encoded,
            'mode': 0o644,
        }

    # Given this yaml config, we need to make the specified changes both statically and dynamically

    # We make the static changes to guest disk in this function
    new_image = derive_qcow_from(base_qcow, out_dir, config_files, out_filename)

    # This config's static_files section is all we cared about when making the qcow. So we can write that down.
    h = hash_yaml(config_files)
    new_conf = f"{out_dir}/files_config_{h}.yaml"
    with open(new_conf, "w") as f:
        yaml.dump(conf['static_files'], f)
    return new_conf

if __name__ == "__main__":
    if len(sys.argv) < 3:
        raise RuntimeError(f"USAGE {sys.argv[0]} [config.yaml] [qcow_dir]")
    prepare_run(sys.argv[1], sys.argv[2])