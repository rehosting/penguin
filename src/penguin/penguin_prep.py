#!/usr/bin/env python3
import subprocess
target_triples = {
        "armel": "armv5-linux-musleabi",
        "aarch64": "aarch64-linux-musl",
        "mipsel": "mipsel-linux-musl",
        "mipseb": "mips-linux-musl",
        "mips64eb": "mips64-linux-musl",
}

def add_lib_inject(config):
    arch = config['core']['arch']

    target_triple = target_triples[arch]
    lib_inject = config.get('lib_inject', dict())

    p = subprocess.run(
        [
            "clang-11",
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

    config['static_files']['/igloo/lib64/lib_inject.so'] = {
        'type': 'inline_file',
        'contents': p.stdout,
        'mode': 0o444,
    }
    if arch == "aarch64":
        arch = "armel"
        target_triple = target_triples[arch]
        p = subprocess.run(
            [
                "clang-11",
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

        config['static_files']['/igloo/lib32/lib_inject.so'] = {
            'type': 'inline_file',
            'contents': p.stdout,
            'mode': 0o444,
        }

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
