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
from pathlib import Path

log = "nvram.csv"

# access: 0 = miss get, 1 = hit get, 2 = set, 3 = clear


def add_lib_inject_for_abi(config, abi, cache_dir):
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
    # Create a hash of all relevant inputs for caching
    source_files_content = []
    for pattern in ["/igloo_static/libnvram/*.c", "/igloo_static/libnvram/*.h"]:
        for file_path in glob.glob(pattern):
            try:
                with open(file_path, 'rb') as f:
                    source_files_content.append(f.read())
            except Exception:
                pass  # Ignore files that can't be read

    hash_input = str((arch, abi, aliases, lib_inject.get("extra", ""), args)).encode()
    for content in source_files_content:
        hash_input += content
    cache_key = hashlib.sha256(hash_input).hexdigest()
    cache_path = cache_dir / f"lib_inject_{arch}_{abi}_{cache_key}.so"

    if cache_path.exists():
        so_data = cache_path.read_bytes()
    else:
        p = subprocess.run(
            args,
            input=lib_inject.get("extra", "").encode(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if p.returncode != 0:
            print("FATAL: Failed to build lib_inject. Did your config specify an invalid alias target in libinject.aliases? Did you create a new function in libinject.extra with a syntax error?")
            print("Compiler stderr output:")
            print(p.stderr.decode(errors="replace"))
            raise Exception("Failed to build lib_inject")
        so_data = p.stdout
        cache_path.write_bytes(so_data)

    config["static_files"][f"/igloo/lib_inject_{abi}.so"] = dict(
        type="inline_file",
        contents=so_data,
        mode=0o444,
    )


def add_lib_inject_all_abis(conf, cache_dir):
    """Add lib_inject for all supported ABIs to /igloo"""

    arch = conf["core"]["arch"]
    arch_info = ARCH_ABI_INFO[arch]
    for abi in arch_info["abis"].keys():
        add_lib_inject_for_abi(conf, abi, cache_dir)

    # This isn't covered by the automatic symlink-adding code,
    # so do it manually here.
    # Having access to lib_inject from the binaries in /igloo/utils is useful
    # for unit tests.
    conf["static_files"]["/igloo/dylibs/lib_inject.so"] = dict(
        type="symlink",
        target=f"/igloo/lib_inject_{arch_info['default_abi']}.so",
    )


def prep_config(conf, cache_dir):
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

    add_lib_inject_all_abis(conf, cache_dir)


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
        prep_config(config, cache_dir)
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
        self.on_nvram_get(regs, key, True)

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
        self.on_nvram_get(regs, key, False)

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
            return
        key = key.split("/")[-1]  # It's the full /igloo/libnvram_tmpfs/keyname path

        status = "hit" if hit else "miss"
        self.log_write(f"{key},{status},\n")
        plugins.cas.set_arg(regs, 1, 0)
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
            return
        key = key.split("/")[-1]  # It's the full /igloo/libnvram_tmpfs/keyname path
        self.log_write(f"{key},set,{newval}\n")
        plugins.cas.set_arg(regs, 1, 0)
        self.logger.debug(f"nvram set {key} {newval}")

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
            return
        key = key.split("/")[-1]  # It's the full /igloo/libnvram_tmpfs/keyname path
        self.log_write(f"{key},clear,\n")
        plugins.cas.set_arg(regs, 1, 0)
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
        plugins.cas.set_retval(regs, rval)
