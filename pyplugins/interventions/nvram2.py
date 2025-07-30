"""
# NVRAM Tracker Plugin

This module provides a plugin for tracking NVRAM (non-volatile RAM) operations in the guest environment.
It is intended for use with the Penguin analysis framework and is implemented as a plugin.

## Purpose

- Tracks NVRAM get (hit/miss), set, and clear operations.
- Logs all operations to a CSV file for later analysis.
- Optionally enables debug logging for set operations.

## Usage

The plugin can be configured with the following arguments:
- `outdir`: Output directory for logs.
- `verbose`: Enables debug logging for set operations.

## Example

```python
from penguin import plugins
plugins.load("interventions.nvram2", outdir="/tmp", verbose=True)
```

All NVRAM operations are logged to `nvram.csv` in the specified output directory.

"""

from penguin import Plugin, plugins
from penguin.abi_info import ARCH_ABI_INFO
import subprocess

log = "nvram.csv"

# access: 0 = miss get, 1 = hit get, 2 = set, 3 = clear


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


class Nvram2(Plugin):
    """
    Nvram2 is a Penguin plugin that tracks and logs NVRAM operations in the guest.

    ## Attributes
    - outdir (`str`): Output directory for logs.

    ## Behavior
    - Subscribes to NVRAM get (hit/miss), set, and clear events.
    - Logs each operation to a CSV file.
    """

    def __init__(self):
        """
        Initialize the Nvram2 plugin.

        - Reads configuration arguments.
        - Subscribes to NVRAM events.
        - Sets up logging and internal state.

        **Arguments**:
        - None (uses plugin argument interface)

        **Returns**:
        - None
        """
        self.outdir = self.get_arg("outdir")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        config = self.get_arg("conf")
        prep_config(config)
        # Even at debug level, logging every nvram get/clear can be very verbose.
        # As such, we only debug log nvram sets

        with open(f"{self.outdir}/{log}", "w") as f:
            f.write("key,access,value\n")

    @plugins.subscribe(plugins.Events, "igloo_nvram_get_hit")
    def on_nvram_get_hit(self, regs, key: str) -> None:
        """
        Handles an NVRAM get hit event.

        **Arguments**:
        - regs: CPU register/context (opaque, framework-specific)
        - key (`str`): NVRAM key accessed

        **Returns**:
        - None
        """
        self.on_nvram_get(regs, key, True)

    @plugins.subscribe(plugins.Events, "igloo_nvram_get_miss")
    def on_nvram_get_miss(self, regs, key: str) -> None:
        """
        Handles an NVRAM get miss event.

        **Arguments**:
        - regs: CPU register/context (opaque, framework-specific)
        - key (`str`): NVRAM key accessed

        **Returns**:
        - None
        """
        self.on_nvram_get(regs, key, False)

    def on_nvram_get(self, regs, key: str, hit: bool) -> None:
        """
        Logs an NVRAM get operation (hit or miss).

        **Arguments**:
        - regs: CPU register/context (opaque, framework-specific)
        - key (`str`): NVRAM key accessed
        - hit (`bool`): True if get was a hit, False if miss

        **Returns**:
        - None
        """
        if "/" not in key:
            return
        key = key.split("/")[-1]  # It's the full /igloo/libnvram_tmpfs/keyname path

        status = "hit" if hit else "miss"
        with open(f"{self.outdir}/{log}", "a") as f:
            f.write(f"{key},{status},\n")
        self.panda.arch.set_arg(regs, 1, 0)
        # self.logger.debug(f"nvram get {key} {status}")

    @plugins.subscribe(plugins.Events, "igloo_nvram_set")
    def on_nvram_set(self, regs, key: str, newval: str) -> None:
        """
        Handles and logs an NVRAM set operation.

        **Arguments**:
        - regs: CPU register/context (opaque, framework-specific)
        - key (`str`): NVRAM key being set
        - newval (`str`): New value being set

        **Returns**:
        - None
        """
        if "/" not in key:
            return
        key = key.split("/")[-1]  # It's the full /igloo/libnvram_tmpfs/keyname path
        with open(f"{self.outdir}/{log}", "a") as f:
            f.write(f"{key},set,{newval}\n")
        self.panda.arch.set_arg(regs, 1, 0)
        self.logger.debug(f"nvram set {key} {newval}")

    @plugins.subscribe(plugins.Events, "igloo_nvram_clear")
    def on_nvram_clear(self, regs, key: str) -> None:
        """
        Handles and logs an NVRAM clear operation.

        **Arguments**:
        - regs: CPU register/context (opaque, framework-specific)
        - key (`str`): NVRAM key being cleared

        **Returns**:
        - None
        """
        if "/" not in key:
            return
        key = key.split("/")[-1]  # It's the full /igloo/libnvram_tmpfs/keyname path
        with open(f"{self.outdir}/{log}", "a") as f:
            f.write(f"{key},clear,\n")
        self.panda.arch.set_arg(regs, 1, 0)
        # self.logger.debug(f"nvram clear {key}")
        # self.logger.debug(f"nvram clear {key}")
