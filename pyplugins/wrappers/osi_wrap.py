"""
# osi_wrap.py - Wrappers for process memory mappings (Operating System Introspection)

This module provides Pythonic wrappers for handling process memory mappings, typically as returned by a plugin or API that exposes Linux process memory map information. The wrappers are designed to make it easy to inspect, filter, and display memory mappings, such as those found in /proc/<pid>/maps.

## Overview
This module defines two main classes:
- **MappingWrapper**: Wraps a single memory mapping, providing properties for permissions, addresses, and device info.
- **MappingsWrapper**: Wraps a list of MappingWrapper objects, providing search and display utilities.

These wrappers are useful for analyzing process memory layouts, debugging, or building tools that need to inspect memory regions of Linux processes. They abstract away the raw dictionary or struct data and provide convenient Pythonic accessors and search methods.

## Typical Usage
Suppose you have a plugin or API that returns a list of memory mapping dictionaries for a process (e.g., from `/proc/<pid>/maps` or a similar source):

```python
from wrappers.osi_wrap import MappingWrapper, MappingsWrapper

# Example: plugin.get_mappings() returns a list of dicts, one per mapping
raw_mappings = plugin.get_mappings()  # Each dict should have keys: flags, base, size, dev, pgoff, inode, name
mappings = [MappingWrapper(m) for m in raw_mappings]
all_mappings = MappingsWrapper(mappings)
```

You can then perform various queries and inspections:

```python
# Find a mapping by address:
mapping = all_mappings.get_mapping_by_addr(0x7f1234567000)
if mapping:
    print(f"Permissions: {mapping.perms}, Name: {mapping.name}")

# List all mappings for a library:
libc_maps = all_mappings.get_mappings_by_name('libc')
for m in libc_maps:
    print(m)

# Print all mappings in a format similar to /proc/<pid>/maps:
print(all_mappings)
```

The MappingWrapper exposes properties such as `.perms`, `.start`, `.end`, `.dev_major`, `.dev_minor`, and `.name`, making it easy to work with mapping attributes.

## Classes
- **MappingWrapper**: Wraps a single memory mapping, providing properties for permissions, addresses, and device info.
- **MappingsWrapper**: Wraps a list of MappingWrapper objects, providing search and display utilities.
"""

from typing import List, Optional

from wrappers.generic import Wrapper, ArrayWrapper

VM_READ = 0x00000001
VM_WRITE = 0x00000002
VM_EXEC = 0x00000004
VM_MAYSHARE = 0x00000080


class MappingWrapper(Wrapper):
    """
    Wraps a single process memory mapping, providing convenient properties for permissions, addresses, and device information.

    Attributes:
        flags (int): Bitmask of mapping permissions and flags.
        base (int): Start address of the mapping.
        size (int): Size of the mapping in bytes.
        dev (int): Device number (major:minor) of the mapping.
        pgoff (int): Offset into the mapped file.
        inode (int): Inode number of the mapped file.
        name (str): Name or path of the mapped file.
    """

    @property
    def exec(self) -> bool:
        """Check if the mapping is executable."""
        return self.flags & VM_EXEC != 0

    @property
    def read(self) -> bool:
        """Check if the mapping is readable."""
        return self.flags & VM_READ != 0

    @property
    def write(self) -> bool:
        """Check if the mapping is writable."""
        return self.flags & VM_WRITE != 0

    @property
    def share(self) -> bool:
        """Check if the mapping is shareable."""
        return self.flags & VM_MAYSHARE != 0

    @property
    def perms(self) -> str:
        """Return the permissions of the mapping."""
        r = 'r' if self.read else '-'
        w = 'w' if self.write else '-'
        x = 'x' if self.exec else '-'
        s = 's' if self.share else 'p'
        return f"{r}{w}{x}{s}"

    @property
    def start(self) -> int:
        """Return the start address of the mapping."""
        return self.base

    @property
    def end(self) -> int:
        """Return the end address of the mapping."""
        return self.base + self.size

    @property
    def dev_major(self) -> int:
        """Return the major number of the mapping.
        In Linux, the major number is in the high 12 bits of dev."""
        return (self.dev >> 20) & 0xFFF

    @property
    def dev_minor(self) -> int:
        """Return the minor number of the mapping.
        In Linux, the minor number is in the low 20 bits of dev."""
        return self.dev & 0xFFFFF

    def get_addr_offset(self, addr: int) -> Optional[int]:
        """Return the offset of the address within the mapping."""
        if self.start <= addr < self.end:
            return addr - self.start
        return None

    def __str__(self) -> str:
        """Return a string representation of the wrapped object."""
        a = self
        return f"{a.start:x}-{a.end:x} {a.perms} {a.pgoff:x} {a.dev_major:02x}:{a.dev_minor:02x} {a.inode} {a.name}"


class MappingsWrapper(ArrayWrapper):
    """
    Wraps a list of MappingWrapper objects, providing utilities to search and display memory mappings.

    Methods:
        get_mapping_by_addr(addr): Return the mapping containing the given address.
        get_mappings_by_name(name): Return all mappings whose name contains the given string.
    """

    def get_mapping_by_addr(self, addr: int) -> Optional[MappingWrapper]:
        """Find the mapping for a given address."""
        for mapping in self._data:
            if mapping.start <= addr < mapping.end:
                return mapping
        return None

    def get_mappings_by_name(self, name: str) -> List[MappingWrapper]:
        """Find all mappings whose name contains the given string."""
        mappings = []
        for mapping in self._data:
            if name in mapping.name:
                mappings.append(mapping)
        return mappings

    def __str__(self) -> str:
        """Return a string representation of all mappings."""
        return "\n".join(str(mapping) for mapping in self._data)
