#!/usr/bin/env python3
import guestfs
import os
import subprocess
import sys
from tempfile import TemporaryDirectory
import shutil
from .common import yaml, hash_yaml
from .utils import get_mount_type

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

        # Iterate over files from the YAML file and add them to the guest file system
        # XXX: file['type'] are a bit of a misnomer, it's more of a filesystem action type
        # so we can add/delete files, create directories, etc.
    for file_path, file in files.items():
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
                    g.rm(file_path)
                g.write(file_path, contents)
                g.chmod(mode, file_path)

            elif action == 'dir':
                if g.is_dir(file_path):
                    g.rm_rf(file_path) # Delete the directory AND CONTENTS
                # Note we ignore mode here?
                dirname = file_path
                g.mkdir(dirname)

            elif action == 'symlink':
                # file['target'] is what we point to
                linkpath = file_path # This is what we create
                # Delete linkpath AND CONTENTS if it already exists
                if g.exists(linkpath):
                    g.rm_rf(linkpath)

                # If target doesn't exist, we can't symlink
                if not g.exists(file['target']) and not g.is_dir(file['target']):
                    raise ValueError(f"Can't add symlink to {file['target']} as it doesn't exist in requested symlink from {linkpath}")

                g.ln_s(file['target'], linkpath)
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
            elif action == 'delete':
                # Delete the file (or directory and children)
                if not g.exists(file_path) and not g.is_dir(file_path):
                    raise ValueError(f"Can't delete {file_path} as it doesn't exist")
                g.rm_rf(file_path)

            elif action == 'move_from':
                # Move a file (or directory and children) TO
                # the key in yaml (so we can avoid duplicate keys)
                if not g.exists(file['from']) and not g.is_dir(file['from']):
                    raise ValueError(f"Can't move {file['from']} as it doesn't exist")
                g.mv(file['from'], file_path)

            elif action == 'chmod':
                # Change the mode of a file or directory
                if not g.exists(file_path) and not g.is_dir(file_path):
                    raise ValueError(f"Can't chmod {file_path} as it doesn't exist")
                g.chmod(file['mode'], file_path)

            else:
                raise RuntimeError(f"Unknown file system action {action}")

        except Exception as e:
            print(f"Exception modifying guest filesystem for {file_path}: {file}: {e}")
            print("Guest filesystem details:")
            print(g.df())
            print(g.statvfs("/"))
            print(g.mountpoints())
            raise

    # Shutdown and close guestfs handle
    g.shutdown()
    g.close()

    # Now, after we've made our changes, we can rebase the QCOW2 file back to the original to shrink it
    #subprocess.run(['qemu-img', 'rebase', '-b', qcow_file, '-F', 'qcow2', new_qcow_file], check=True)
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

    # For each key in config_nvram, we'll just add it to the FS
    for k, val in config_nvram.items():
        if isinstance(val, str):
            encoded = val.encode()
        elif isinstance(val, int):
            encoded = str(val).encode() #???
        else:
            raise ValueError(f"Unknown type for nvram value {k}: {type(val)}")

        config_files[f"/firmadyne/libnvram.override/{k}"] = {
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