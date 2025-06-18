"""
# Signals Plugin (`signals.py`) for Penguin

This module provides the `Signals` plugin for the Penguin framework, enabling the triggering of core dumps, crash snapshots, and custom signals in the guest OS via the hypervisor portal. It is useful for debugging, analysis, and automation of guest process state.

## Features

- Trigger a full snapshot and core dump in the guest.
- Send SIGABRT or custom signals to the current process in the guest.
- Coroutine-based API for integration with other Penguin plugins.

## Example Usage

```python
from penguin import plugins

# Trigger a full snapshot and core dump
pid = yield from plugins.signals.crash_snapshot()

# Send SIGABRT to the current process
pid = yield from plugins.signals.self_abort()

# Send a custom signal (e.g., SIGTERM)
pid = yield from plugins.signals.self_signal(15)
```
"""

from penguin import Plugin
from hyper.consts import HYPER_OP as hop
from hyper.portal import PortalCmd
from typing import Optional, Generator, Any


class Signals(Plugin):
    """
    ## Signals Plugin

    Provides methods to trigger core dumps, crash snapshots, and send signals to guest processes via the hypervisor portal.
    """

    def dump(self, mode: int = 0,
             signal: int = 0) -> Generator[Any, None, Optional[int]]:
        """
        ### Trigger a core dump or signal in the guest

        **Args:**
        - `mode` (`int`, optional): Dump mode (`0`=full snapshot and coredump, `1`=self abort, `2`=custom signal). Default is `0`.
        - `signal` (`int`, optional): Signal number to send (only used with `mode=2`). Default is `0`.

        **Returns:**
        - `Optional[int]`: PID of the process that received the signal, or error code, or `None` on failure.
        """
        # mode in lowest 8 bits, signal in next 8 bits
        dump_addr = ((signal & 0xFF) << 8) | (mode & 0xFF)
        response = yield PortalCmd(hop.HYPER_OP_DUMP, dump_addr, 0)
        if response is None:
            self.logger.error("Failed to execute dump operation")
            return None
        return response

    def crash_snapshot(self) -> Generator[Any, None, Optional[int]]:
        """
        ### Create a snapshot and core dump in the guest (default dump mode)

        **Returns:**
        - `Optional[int]`: PID of the process that received the signal, or error code, or `None` on failure.
        """
        return (yield from self.dump(mode=0))

    def self_abort(self) -> Generator[Any, None, Optional[int]]:
        """
        ### Send SIGABRT to the current process in the guest

        **Returns:**
        - `Optional[int]`: PID of the process that received SIGABRT, or error code, or `None` on failure.
        """
        return (yield from self.dump(mode=1))

    def self_signal(self, signal: int) -> Generator[Any, None, Optional[int]]:
        """
        ### Send a custom signal to the current process in the guest

        **Args:**
        - `signal` (`int`): Signal number to send (1-31).

        **Returns:**
        - `Optional[int]`: PID of the process that received the signal, or error code, or `None` on failure.

        **Raises:**
        - `ValueError`: If the signal number is not between 1 and 31.
        """
        if not 1 <= signal <= 31:
            raise ValueError(
                f"Invalid signal number: {signal}. Must be between 1 and 31.")
        return (yield from self.dump(mode=2, signal=signal))
