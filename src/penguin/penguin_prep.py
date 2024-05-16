#!/usr/bin/env python3
import subprocess

def add_lib_inject_with_bits(config, bits):
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
            "clang-11",
            "-fuse-ld=lld", "-Oz", "-shared", "-nostdlib",
            "-target", target_triple, f"-m{bits}",
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

    lib_prefix = "lib64" if bits == 64 else "lib"
    config['static_files'][f'/igloo/{lib_prefix}_inject.so'] = {
        'type': 'inline_file',
        'contents': p.stdout,
        'mode': 0o444,
    }

def add_lib_inject(config):
    add_lib_inject_with_bits(config, 32)
    if "64" in config['core']['arch']:
        add_lib_inject_with_bits(config, 64)

def prep_config(conf):
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
