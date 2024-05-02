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

def add_lib_inject(config):
    arch = config['core']['arch']

    target_triple = {
        "armel": "armv5-linux-musleabi",
        "mipsel": "mipsel-linux-musl",
        "mipseb": "mips-linux-musl",
        "mips64eb": "mips64-linux-musl",
    }[arch]

    lib_inject = config.get('lib_inject', dict())

    p = subprocess.run(
        [
            "clang",
            "-fuse-ld=lld", "-Oz", "-shared", "-nostdlib",
            "-target", target_triple,
            f"/igloo_static/libnvram/nvram.o.{arch}",
            "--language", "c", "-",
            "-o", "-",
            "-Wl," + ",".join([
                f"--defsym={sym}={repl}"
                for sym, repl in lib_inject.get('aliases', dict()).items()
            ])
        ],
        input=lib_inject.get('extra', '').encode(),
        stdout=subprocess.PIPE,
    )
    assert p.returncode == 0

    config['static_files']['/igloo/lib_inject.so'] = {
        'type': 'inline_file',
        'contents': p.stdout,
        'mode': 0o444,
    }

def prepare_run(proj_dir, conf, out_dir, out_filename="image.qcow2"):
    base_qcow = os.path.join(proj_dir, conf['core']['qcow'])
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
            'type': "inline_file",
            'contents': encoded,
            'mode': 0o644,
        }

    add_lib_inject(conf)

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
    prepare_run(os.path.dirname(sys.argv[1]), sys.argv[1], sys.argv[2])
