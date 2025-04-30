#!/usr/bin/env python3

import subprocess

# Information about each ABI
#   - `target_triple`: The target triple for the architecture
#   - `libnvram_arch_name`: The architecture name used in libnvram
#   - `default_abi`: The ABI used for the binaries in /igloo/utils
#   - `musl_arch_name`: The architecture name used in musl
#   - `m_flags`: The `-m` flags passed to the compiler to compile for this ABI.
#                (e.g. -mfloat-abi=hard)
ARCH_ABI_INFO = dict(
    armel=dict(
        target_triple="armv5-linux-musleabi",
        libnvram_arch_name="arm",
        default_abi="soft_float",
        abis=dict(
            soft_float=dict(
                musl_arch_name="arm",
                m_flags=dict(),
            ),
            hard_float=dict(
                target_triple="armv7-linux-musleabi",
                musl_arch_name="arm",
                m_flags=dict(float_abi="hard")
            ),
        ),
    ),
    aarch64=dict(
        target_triple="aarch64-linux-musl",
        libnvram_arch_name="aarch64",
        default_abi="default",
        abis=dict(
            default=dict(
                musl_arch_name="aarch64",
                m_flags=dict(),
            ),
            soft_float=dict(
                libnvram_arch_name="arm",
                target_triple="armv5-linux-musleabi",
                musl_arch_name="arm",
                m_flags=dict(),
            ),
            hard_float=dict(
                libnvram_arch_name="arm",
                target_triple="armv7-linux-musleabi",
                musl_arch_name="arm",
                m_flags=dict(float_abi="hard")
            ),
        ),
    ),
    powerpc=dict(
        target_triple="powerpc-linux-musl",
        libnvram_arch_name="ppc",
        default_abi="default",
        abis=dict(
            default=dict(
                musl_arch_name="powerpc",
                m_flags=dict(),
            ),
        ),
    ),
    powerpc64=dict(
        target_triple="powerpc64-linux-musl",
        libnvram_arch_name="ppc64",
        default_abi="default",
        abis=dict(
            default=dict(
                target_triple="powerpc-linux-musl",
                libnvram_arch_name="ppc",
                musl_arch_name="powerpc",
                m_flags=dict(),
            ),
            ppc64=dict(
                musl_arch_name="powerpc64",
                m_flags=dict(),
            ),
        ),
    ),
    powerpc64le=dict(
        target_triple="powerpc64le-linux-musl",
        libnvram_arch_name="ppc64le",
        default_abi="default",
        abis=dict(
            default=dict(
                target_triple="powerpcle-linux-musl",
                musl_arch_name="powerpc",
                m_flags=dict(),
            ),
            ppc64=dict(
                musl_arch_name="powerpc64le",
                m_flags=dict(),
            ),
        ),
    ),
    riscv64=dict(
        target_triple="riscv64-linux-musl",
        libnvram_arch_name="riscv64",
        default_abi="default",
        abis=dict(
            default=dict(
                musl_arch_name="riscv64",
                m_flags=dict(),
            ),
        ),
    ),
    mipsel=dict(
        target_triple="mipsel-linux-musl",
        libnvram_arch_name="mips",
        default_abi="o32",
        abis=dict(
            o32=dict(
                musl_arch_name="mips",
                m_flags=dict(abi="32"),
            )
        ),
    ),
    mipseb=dict(
        target_triple="mips-linux-musl",
        libnvram_arch_name="mips",
        default_abi="o32",
        abis=dict(
            o32=dict(
                musl_arch_name="mips",
                m_flags=dict(abi="32"),
            )
        ),
    ),
    mips64el=dict(
        target_triple="mips64el-linux-musl",
        libnvram_arch_name="mips",
        default_abi="n64",
        abis=dict(
            o32=dict(
                musl_arch_name="mips",
                m_flags=dict(abi="32"),
            ),
            n32=dict(
                musl_arch_name="mipsn32",
                m_flags=dict(abi="n32"),
            ),
            n64=dict(
                musl_arch_name="mips64",
                m_flags=dict(abi="64"),
            ),
        ),
    ),
    mips64eb=dict(
        target_triple="mips64-linux-musl",
        libnvram_arch_name="mips",
        default_abi="n64",
        abis=dict(
            o32=dict(
                musl_arch_name="mips",
                m_flags=dict(abi="32"),
            ),
            n32=dict(
                musl_arch_name="mipsn32",
                m_flags=dict(abi="n32"),
            ),
            n64=dict(
                musl_arch_name="mips64",
                m_flags=dict(abi="64"),
            ),
        ),
    ),
    intel64=dict(
        target_triple="x86_64-unknown-linux-musl",
        libnvram_arch_name="x86_64",
        default_abi="default",
        abis=dict(
            default=dict(
                musl_arch_name="x86_64",
                m_flags=dict()
            ),
            i386=dict(
                target_triple="i386-unknown-linux-musl",
                libnvram_arch_name="i386",
                musl_arch_name="i386",
                m_flags=dict(),
                extra_flags=["-fPIC"]
            )
        )
    ),
    loongarch64=dict(
        target_triple="loongarch64-unknown-linux-musl",
        libnvram_arch_name="loongarch64",
        default_abi="default",
        abis=dict(
            default=dict(
                musl_arch_name="loongarch64",
                m_flags=dict(),
            ),
        ),
    )
)


def add_lib_inject_for_abi(config, abi):
    """Compile lib_inject for the ABI and put it in /igloo"""

    arch = config["core"]["arch"]

    lib_inject = config.get("lib_inject", dict())
    arch_info = ARCH_ABI_INFO[arch]
    abi_info = arch_info["abis"][abi]
    headers_dir = f"/igloo_static/musl-headers/{abi_info['musl_arch_name']}/include"
    libnvram_arch_name = abi_info.get(
        'libnvram_arch_name', None) or arch_info['libnvram_arch_name']
    aliases = lib_inject.get("aliases", dict())

    hash_options = "-Wl,--hash-style=both" if "mips" not in arch else ""

    args = (
        ["clang-20", "-fuse-ld=lld", "-Oz", "-shared", "-nostdlib", "-nostdinc",
         hash_options
         ]
        + [
            f"-m{key.replace('_', '-')}={value}"
            for key, value in abi_info["m_flags"].items()
        ]
        + [
            "-target",
            abi_info.get("target_triple", None) or arch_info["target_triple"],
            "-isystem",
            headers_dir,
            f"-DCONFIG_{libnvram_arch_name.upper()}=1",
            "/igloo_static/libnvram/nvram.c",
            "/igloo_static/guest-utils/ltrace/inject_ltrace.c",
            "--language",
            "c",
            "-",
            "-o",
            "-",
        ]
        +
        ([] if len(aliases) == 0 else ["-Wl," +
         ",".join(
             [
                 f"--defsym={sym}={repl}"
                 for sym, repl in aliases.items()
             ]
         )])
        + abi_info.get("extra_flags", [])
    )
    p = subprocess.run(
        args,
        input=lib_inject.get("extra", "").encode(),
        stdout=subprocess.PIPE,
    )
    if p.returncode != 0:
        print("FATAL: Failed to build lib_inject. Did your config specify an invalid alias target in libinject.aliases? Did you create a new function in libinject.extra with a syntax error?")
        raise Exception("Failed to build lib_inject")

    config["static_files"][f"/igloo/lib_inject_{abi}.so"] = dict(
        type="inline_file",
        contents=p.stdout,
        mode=0o444,
    )


def add_lib_inject_all_abis(conf):
    """Add lib_inject for all supported ABIs to /igloo"""

    arch = conf["core"]["arch"]
    arch_info = ARCH_ABI_INFO[arch]
    for abi in arch_info["abis"].keys():
        add_lib_inject_for_abi(conf, abi)

    # This isn't covered by the automatic symlink-adding code,
    # so do it manually here.
    # Having access to lib_inject from the binaries in /igloo/utils is useful
    # for unit tests.
    conf["static_files"]["/igloo/dylibs/lib_inject.so"] = dict(
        type="symlink",
        target=f"/igloo/lib_inject_{arch_info['default_abi']}.so",
    )


def prep_config(conf):
    config_files = conf["static_files"] if "static_files" in conf else {}
    config_nvram = conf["nvram"] if "nvram" in conf else {}

    config_files["/igloo/libnvram/"] = {
        "type": "dir",
        "mode": 0o755,
    }

    # For each key in config_nvram, we'll just add it to the FS
    for k, val in config_nvram.items():
        if isinstance(val, str):
            encoded = val.encode()
        elif isinstance(val, int):
            encoded = str(val).encode()  # ???
        else:
            raise ValueError(f"Unknown type for nvram value {k}: {type(val)}")

        config_files[f"/igloo/libnvram/{k}"] = {
            "type": "inline_file",
            "contents": encoded,
            "mode": 0o644,
        }

    add_lib_inject_all_abis(conf)
