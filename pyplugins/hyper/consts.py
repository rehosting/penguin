"""
# Hypervisor Constants Loader (`consts.py`)

This module provides a convenient interface for accessing hypervisor-related constants and enumerations
used by plugins in the Penguin hypervisor environment. It dynamically loads enums from the kernel FFI
and exposes them as Python objects for easy and type-safe access.

## Overview

- Loads and exposes enums such as `HYPER_OP`, `portal_type`, `igloo_hypercall_constants`, and others.
- Wraps each enum in a `Wrapper` object for attribute-style access.
- Ensures that all required enums are present and raises an assertion error if any are missing.

## Example Usage

```python
from hyper import consts

# Access a constant from HYPER_OP
op_code = consts.HYPER_OP.READ

# Access a constant from igloo_hypercall_constants
hypercall_num = consts.igloo_hypercall_constants.IGLOO_HYPER_REGISTER_MEM_REGION
```

## Exposed Enums

- `HYPER_OP`
- `portal_type`
- `igloo_hypercall_constants`
- `hyperfs_ops`
- `hyperfs_file_ops`
- `value_filter_type`

## Implementation Details

- Uses `plugins.kffi.get_enum_dict` to fetch enum values from the kernel FFI.
- Wraps each enum dictionary in a `Wrapper` for attribute-style access.
- All enums are loaded at module import time.

"""

from penguin import plugins
from wrappers.generic import Wrapper

enum_names: list[str] = [
    "HYPER_OP",
    "portal_type",
    "igloo_hypercall_constants",
    "hyperfs_ops",
    "hyperfs_file_ops",
    "value_filter_type",
]

for name in enum_names:
    hyperconsts: dict[str, int] = plugins.kffi.get_enum_dict(name)
    assert len(hyperconsts.items()) > 0, f"Failed to get enum {name}"
    globals()[name] = Wrapper(hyperconsts)
