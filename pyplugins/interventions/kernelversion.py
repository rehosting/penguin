"""
# Kernel Version Utilities

This module provides utilities for parsing, comparing, and representing Linux kernel
version strings. It is intended to help plugins and scripts that need to reason about
kernel versions in the Penguin framework or similar environments.

## Features

- Parse kernel version strings into structured objects
- Compare kernel versions for ordering and equality
- Convert kernel version objects back to string representation

```

## Classes

- `KernelVersion`: Represents a parsed kernel version and supports comparison.

"""

from typing import Any, Optional
from penguin import plugins, Plugin

RETRY: int = 0xDEADBEEF
NO_CHANGE: int = 0xABCDABCD


class KernelVersion(Plugin):
    """
    Represents a Linux kernel version and supports comparison operations.

    **Attributes**
    - `outdir` (`Optional[str]`): Output directory.
    - `sysname` (`Optional[str]`): System name.
    - `nodename` (`Optional[str]`): Node name.
    - `release` (`Optional[str]`): Kernel release string.
    - `version` (`Optional[str]`): Kernel version string.
    - `machine` (`Optional[str]`): Machine architecture.
    - `domainname` (`Optional[str]`): Domain name.

    **Example**
    ```python
    v = KernelVersion(5, 10, 0, "-rc1")
    ```
    """

    outdir: Optional[str]
    sysname: Optional[str]
    nodename: Optional[str]
    release: Optional[str]
    version: Optional[str]
    machine: Optional[str]
    domainname: Optional[str]

    def __init__(self) -> None:
        """
        Initialize the KernelVersion plugin and subscribe to the 'igloo_uname' event.
        """
        self.outdir = self.get_arg("outdir")
        self.sysname = self.get_arg("sysname")
        self.nodename = self.get_arg("nodename")
        self.release = self.get_arg("release")
        self.version = self.get_arg("kversion")
        self.machine = self.get_arg("machine")
        self.domainname = self.get_arg("domainname")

        plugins.subscribe(plugins.Events, "igloo_uname", self.change_uname)

    def create_string(self) -> str:
        """
        Construct a comma-separated string of uname fields.

        Returns:
            str: The constructed uname string, with 'none' for missing fields.
        """
        uname_str = ""

        uname_str += self.sysname + "," if self.sysname else "none,"
        uname_str += self.nodename + "," if self.nodename else "none,"
        uname_str += self.release + "," if self.release else "none,"
        uname_str += self.version + "," if self.version else "none,"
        uname_str += self.machine + "," if self.machine else "none,"
        uname_str += self.domainname + "," if self.domainname else "none,"

        return uname_str

    def change_uname(self, cpu: Any, buf_ptr: int, filler: Any) -> None:
        """
        Event handler to change the uname string in the guest.

        Args:
            cpu (Any): The CPU context.
            buf_ptr (int): Pointer to the buffer where uname is written.
            filler (Any): Unused filler argument.

        Returns:
            None
        """
        new_uname = self.create_string()

        if new_uname == "none,none,none,none,none,none,":
            self.panda.arch.set_retval(cpu, NO_CHANGE)
            return

        try:
            self.panda.virtual_memory_write(
                cpu, buf_ptr, (new_uname.encode("utf-8") + b"\0")
            )
            self.panda.arch.set_retval(cpu, 0x1)
        except ValueError:
            self.panda.arch.set_retval(cpu, RETRY)
