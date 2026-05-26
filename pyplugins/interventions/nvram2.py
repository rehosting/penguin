"""
NVRAM Tracker Plugin
====================

This module provides a plugin for tracking NVRAM (non-volatile RAM) operations in the guest environment.
It is intended for use with the Penguin analysis framework and is implemented as a plugin.

Purpose
-------

- Tracks NVRAM get (hit/miss), set, and clear operations.
- Logs all operations to a CSV file for later analysis.
- Optionally enables debug logging for set operations.

Usage
-----

The plugin can be configured with the following arguments:
- `outdir`: Output directory for logs.
- `verbose`: Enables debug logging for set operations.
- `logging`: Enables or disables logging of NVRAM operations (default: True).

Example
-------

.. code-block:: python

    from penguin import plugins
    plugins.load("interventions.nvram2", outdir="/tmp", verbose=True)

If logging is enabled, NVRAM operations are logged to `nvram.csv` in the specified output directory.

"""

from penguin import Plugin, plugins
from penguin.abi_info import ARCH_ABI_INFO
import subprocess
import os
import hashlib
import glob
import re
from pathlib import Path

log = "nvram.csv"

# access: 0 = miss get, 1 = hit get, 2 = set, 3 = clear


def _lib_inject_dropin_files(proj_dir):
    """Return (sorted .c paths, sorted .h paths) under proj_dir/lib_inject.d/."""
    if not proj_dir:
        return [], []
    d = Path(proj_dir) / "lib_inject.d"
    if not d.is_dir():
        return [], []
    visible = [p for p in d.iterdir() if p.is_file() and not p.name.startswith(".")]
    c_files = sorted(p for p in visible if p.suffix == ".c")
    h_files = sorted(p for p in visible if p.suffix == ".h")
    return c_files, h_files


def _append_build_log(build_log_path, message):
    if not build_log_path:
        return
    with open(build_log_path, "a") as f:
        f.write(message.rstrip() + "\n")


def _summarize_compiler_stderr(stderr):
    text = stderr.decode(errors="replace") if isinstance(stderr, bytes) else str(stderr)
    patterns = re.compile(r"(error:|fatal error:|undefined reference|ld\.lld: error|clang-\d+: error)", re.IGNORECASE)
    matches = [line for line in text.splitlines() if patterns.search(line)]
    return "\n".join(matches[:20]) if matches else "\n".join(text.splitlines()[-20:])


def add_lib_inject_for_abi(config, abi, cache_dir, proj_dir=None, build_log_path=None):
    """Compile lib_inject for the ABI and put it in /igloo, using cache_dir for caching"""

    arch = config["core"]["arch"]
    lib_inject = config.get("lib_inject", dict())
    arch_info = ARCH_ABI_INFO[arch]
    abi_info = arch_info["abis"][abi]
    headers_dir = f"/igloo_static/musl-headers/{abi_info['musl_arch_name']}/include"
    libnvram_arch_name = abi_info.get(
        'libnvram_arch_name', None) or arch_info['libnvram_arch_name']
    aliases = lib_inject.get("aliases", dict())

    cache_dir = Path(cache_dir)
    os.makedirs(cache_dir, exist_ok=True)

    dropin_c, dropin_h = _lib_inject_dropin_files(proj_dir)
    dropin_include = []
    if dropin_c or dropin_h:
        dropin_include = ["-I", str(Path(proj_dir) / "lib_inject.d")]

    hash_options = "-Wl,--hash-style=both" if "mips" not in arch else ""

    args = (
        ["clang-20", "-fuse-ld=lld", "-Oz", "-shared", "-nostdlib", "-nostdinc", "-fPIC",
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
        ]
        + dropin_include
        + [
            "/igloo_static/libnvram/nvram.c",
            "/igloo_static/guest-utils/ltrace/inject_ltrace.c",
        ]
        + [str(p) for p in dropin_c]
        + [
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
    # Create a hash of all relevant inputs for caching
    source_files_content = []
    source_patterns = [
        "/igloo_static/libnvram/*.c",
        "/igloo_static/libnvram/*.h",
        "/igloo_static/guest-utils/ltrace/inject_ltrace.c",
    ]
    source_file_names = []
    for pattern in source_patterns:
        for file_path in glob.glob(pattern):
            try:
                with open(file_path, 'rb') as f:
                    source_files_content.append(f.read())
                source_file_names.append(file_path)
            except Exception:
                pass  # Ignore files that can't be read
    dropin_signature = []
    for p in dropin_c + dropin_h:
        try:
            dropin_signature.append((p.name, p.read_bytes()))
        except Exception:
            pass

    hash_input = str((arch, abi, aliases, lib_inject.get("extra", ""), args, [n for n, _ in dropin_signature])).encode()
    for content in source_files_content:
        hash_input += content
    for _, content in dropin_signature:
        hash_input += content
    cache_key = hashlib.sha256(hash_input).hexdigest()
    cache_path = cache_dir / f"lib_inject_{arch}_{abi}_{cache_key}.so"
    _append_build_log(
        build_log_path,
        f"[{arch}/{abi}] cache_key={cache_key} cache_path={cache_path}",
    )
    _append_build_log(
        build_log_path,
        f"[{arch}/{abi}] hashed_sources={','.join(sorted(source_file_names))}",
    )

    if cache_path.exists():
        so_data = cache_path.read_bytes()
        _append_build_log(build_log_path, f"[{arch}/{abi}] cache hit size={len(so_data)}")
    else:
        _append_build_log(build_log_path, f"[{arch}/{abi}] compiling: {' '.join(args)}")
        p = subprocess.run(
            args,
            input=lib_inject.get("extra", "").encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        _append_build_log(
            build_log_path,
            f"[{arch}/{abi}] returncode={p.returncode} stdout_bytes={len(p.stdout)} stderr_bytes={len(p.stderr)}",
        )
        if p.stderr:
            _append_build_log(build_log_path, f"[{arch}/{abi}] stderr:\n{p.stderr.decode(errors='replace')}")
        if p.returncode != 0:
            print("FATAL: Failed to build lib_inject. Did your config specify an invalid alias target in libinject.aliases? Did you create a new function in libinject.extra with a syntax error?")
            print("Compiler stderr summary:")
            print(_summarize_compiler_stderr(p.stderr))
            raise Exception("Failed to build lib_inject")
        so_data = p.stdout
        cache_path.write_bytes(so_data)
        _append_build_log(build_log_path, f"[{arch}/{abi}] wrote cache")

    config["static_files"][f"/igloo/lib_inject_{abi}.so"] = dict(
        type="inline_file",
        contents=so_data,
        mode=0o444,
    )


def add_lib_inject_all_abis(conf, cache_dir, proj_dir=None, build_log_path=None):
    """Add lib_inject for all supported ABIs to /igloo"""

    arch = conf["core"]["arch"]
    arch_info = ARCH_ABI_INFO[arch]
    for abi in arch_info["abis"].keys():
        add_lib_inject_for_abi(conf, abi, cache_dir, proj_dir=proj_dir, build_log_path=build_log_path)

    # This isn't covered by the automatic symlink-adding code,
    # so do it manually here.
    # Having access to lib_inject from the binaries in /igloo/utils is useful
    # for unit tests.
    conf["static_files"]["/igloo/dylibs/lib_inject.so"] = dict(
        type="symlink",
        target=f"/igloo/lib_inject_{arch_info['default_abi']}.so",
    )
    conf["static_files"]["/etc/ld.so.preload"] = dict(
        type="inline_file",
        contents="/igloo/dylibs/lib_inject.so\n",
        mode=0o644,
    )

    # Binaries in /igloo/utils (e.g. test_nvram) are compiled with the dynamic
    # linker path /igloo/dylibs/ld-musl-<penguin-arch>.so.1.  The actual loader
    # file mounted under /igloo/dylibs/ uses the musl loader name, which differs
    # for several arches (armel→arm, mipseb→mips, mips64eb→mips64).  Add a
    # symlink so LD_PRELOAD works with these binaries in minimal rootfs envs.
    #
    # We detect the actual loader name by globbing the dylibs directory rather
    # than deriving it from musl_arch_name, because musl_arch_name reflects the
    # headers directory (shared between endianness variants) not the loader
    # filename (which encodes endianness: ld-musl-mipsel.so.1 ≠ ld-musl-mips.so.1).
    _dylib_dir_overrides = {
        "aarch64": "arm64",
        "intel64": "x86_64",
        "loongarch64": "loongarch",
        "powerpc": "ppc",
        "powerpc64": "ppc64",
        "powerpc64le": "ppc64el",
    }
    dylib_dir = _dylib_dir_overrides.get(arch, arch)
    canonical_loader = f"ld-musl-{arch}.so.1"
    actual_loaders = glob.glob(f"/igloo_static/dylibs/{dylib_dir}/ld-musl-*.so.1")
    if actual_loaders:
        actual_loader = os.path.basename(sorted(actual_loaders)[0])
        if canonical_loader != actual_loader:
            conf["static_files"][f"/igloo/dylibs/{canonical_loader}"] = dict(
                type="symlink",
                target=actual_loader,
            )


def prep_config(conf, cache_dir, proj_dir=None, build_log_path=None):
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

    _append_build_log(build_log_path, "lib_inject build log start")
    add_lib_inject_all_abis(conf, cache_dir, proj_dir=proj_dir, build_log_path=build_log_path)


class Nvram2(Plugin):
    """
    Nvram2 Plugin
    =============

    Tracks and logs NVRAM operations in the guest.

    Attributes
    ----------
    outdir : str
        Output directory for logs.

    Behavior
    --------
    - Subscribes to NVRAM get (hit/miss), set, and clear events.
    - Logs each operation to a CSV file.
    """

    def __init__(self):
        """
        Initialize the Nvram2 plugin.

        Reads configuration arguments, subscribes to NVRAM events, sets up logging and internal state.

        Returns
        -------
        None
        """
        self.outdir = self.get_arg("outdir")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        config = self.get_arg("conf")
        proj_dir = self.get_arg("proj_dir")
        self.logging_enabled = self.get_arg_bool("logging", default=True)
        self.logger.info(f"logging nvram accesses: {self.logging_enabled}")
        cache_dir = Path(proj_dir).resolve() / "qcows" / "cache" if proj_dir else Path(os.path.dirname(os.path.abspath(__file__))).resolve() / "qcows" / "cache"
        os.makedirs(cache_dir, exist_ok=True)
        build_log_path = os.path.join(self.outdir, "lib_inject_build.log")
        prep_config(config, cache_dir, proj_dir=proj_dir, build_log_path=build_log_path)
        # Even at debug level, logging every nvram get/clear can be very verbose.
        # As such, we only debug log nvram sets

        self.log_write("key,operation,value\n")

    def log_write(self, entry: str) -> None:
        """
        Write a log entry to the CSV file.

        Parameters
        ----------
        entry : str
            Log entry to write

        Returns
        -------
        None
        """
        if self.logging_enabled:
            with open(f"{self.outdir}/{log}", "a") as f:
                f.write(entry)

    @plugins.subscribe(plugins.Events, "igloo_nvram_get_hit")
    def on_nvram_get_hit(self, regs, key: str) -> None:
        """
        Handles an NVRAM get hit event.

        Parameters
        ----------
        regs : object
            CPU register/context (opaque, framework-specific)
        key : str
            NVRAM key accessed

        Returns
        -------
        None
        """
        return self.on_nvram_get(regs, key, True)

    @plugins.subscribe(plugins.Events, "igloo_nvram_get_miss")
    def on_nvram_get_miss(self, regs, key: str) -> None:
        """
        Handles an NVRAM get miss event.

        Parameters
        ----------
        regs : object
            CPU register/context (opaque, framework-specific)
        key : str
            NVRAM key accessed

        Returns
        -------
        None
        """
        return self.on_nvram_get(regs, key, False)

    def on_nvram_get(self, regs, key: str, hit: bool) -> None:
        """
        Logs an NVRAM get operation (hit or miss).

        Parameters
        ----------
        regs : object
            CPU register/context (opaque, framework-specific)
        key : str
            NVRAM key accessed
        hit : bool
            True if get was a hit, False if miss

        Returns
        -------
        None
        """
        if "/" not in key:
            return 0
        key = key.split("/")[-1]  # It's the full /igloo/libnvram_tmpfs/keyname path

        status = "hit" if hit else "miss"
        self.log_write(f"{key},{status},\n")
        if regs is not None:
            self.panda.arch.set_arg(regs, 1, 0)
        return 0
        # self.logger.debug(f"nvram get {key} {status}")

    @plugins.subscribe(plugins.Events, "igloo_nvram_set")
    def on_nvram_set(self, regs, key: str, newval: str) -> None:
        """
        Handles and logs an NVRAM set operation.

        Parameters
        ----------
        regs : object
            CPU register/context (opaque, framework-specific)
        key : str
            NVRAM key being set
        newval : str
            New value being set

        Returns
        -------
        None
        """
        if "/" not in key:
            return 0
        key = key.split("/")[-1]  # It's the full /igloo/libnvram_tmpfs/keyname path
        self.log_write(f"{key},set,{newval}\n")
        if regs is not None:
            self.panda.arch.set_arg(regs, 1, 0)
        self.logger.debug(f"nvram set {key} {newval}")
        return 0

    @plugins.subscribe(plugins.Events, "igloo_nvram_clear")
    def on_nvram_clear(self, regs, key: str) -> None:
        """
        Handles and logs an NVRAM clear operation.

        Parameters
        ----------
        regs : object
            CPU register/context (opaque, framework-specific)
        key : str
            NVRAM key being cleared

        Returns
        -------
        None
        """
        if "/" not in key:
            return 0
        key = key.split("/")[-1]  # It's the full /igloo/libnvram_tmpfs/keyname path
        self.log_write(f"{key},clear,\n")
        if regs is not None:
            self.panda.arch.set_arg(regs, 1, 0)
        return 0
        # self.logger.debug(f"nvram clear {key}")
        # self.logger.debug(f"nvram clear {key}")

    @plugins.subscribe(plugins.Events, "igloo_nvram_logging_enabled")
    def on_nvram_logging_enabled(self, regs,) -> None:
        """
        Handles and logs an NVRAM clear operation. Sets return value register to 1 if logging is enabled, 0 otherwise.

        Parameters
        ----------
        regs : object
            CPU register/context (opaque, framework-specific)

        Returns
        -------
        None
        """
        rval = (1 if self.logging_enabled else 0)
        self.logger.debug(f"nvram logging enabled query, returning {rval}")
        if regs is not None:
            self.panda.arch.set_retval(regs, rval)
        return rval
