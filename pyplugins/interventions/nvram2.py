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

log = "nvram.csv"

# access: 0 = miss get, 1 = hit get, 2 = set, 3 = clear


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
        # Even at debug level, logging every nvram get/clear can be very verbose.
        # As such, we only debug log nvram sets

        with open(f"{self.outdir}/{log}", "w") as f:
            f.write("key,access,value\n")

    @plugins.Events.handler('igloo_nvram_get_hit')
    def on_nvram_get_hit(self, cpu, key: str) -> None:
        """
        Handles an NVRAM get hit event.

        **Arguments**:
        - cpu: CPU context (opaque, framework-specific)
        - key (`str`): NVRAM key accessed

        **Returns**:
        - None
        """
        self.on_nvram_get(cpu, key, True)

    @plugins.Events.handler('igloo_nvram_get_miss')
    def on_nvram_get_miss(self, cpu, key: str) -> None:
        """
        Handles an NVRAM get miss event.

        **Arguments**:
        - cpu: CPU context (opaque, framework-specific)
        - key (`str`): NVRAM key accessed

        **Returns**:
        - None
        """
        self.on_nvram_get(cpu, key, False)

    def on_nvram_get(self, cpu, key: str, hit: bool) -> None:
        """
        Logs an NVRAM get operation (hit or miss).

        **Arguments**:
        - cpu: CPU context (opaque, framework-specific)
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
        self.panda.arch.set_arg(cpu, 1, 0)
        # self.logger.debug(f"nvram get {key} {status}")

    @plugins.Events.handler('igloo_nvram_set')
    def on_nvram_set(self, cpu, key: str, newval: str) -> None:
        """
        Handles and logs an NVRAM set operation.

        **Arguments**:
        - cpu: CPU context (opaque, framework-specific)
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
        self.panda.arch.set_arg(cpu, 1, 0)
        self.logger.debug(f"nvram set {key} {newval}")

    @plugins.Events.handler('igloo_nvram_clear')
    def on_nvram_clear(self, cpu, key: str) -> None:
        """
        Handles and logs an NVRAM clear operation.

        **Arguments**:
        - cpu: CPU context (opaque, framework-specific)
        - key (`str`): NVRAM key being cleared

        **Returns**:
        - None
        """
        if "/" not in key:
            return
        key = key.split("/")[-1]  # It's the full /igloo/libnvram_tmpfs/keyname path
        with open(f"{self.outdir}/{log}", "a") as f:
            f.write(f"{key},clear,\n")
        self.panda.arch.set_arg(cpu, 1, 0)
        # self.logger.debug(f"nvram clear {key}")
        # self.logger.debug(f"nvram clear {key}")
