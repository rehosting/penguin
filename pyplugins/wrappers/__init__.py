"""
# wrappers - Pythonic wrappers for plugin and emulation data structures

This package provides a set of Python wrapper classes for working with data structures returned by plugins, emulators, or analysis frameworks (such as PANDA). The wrappers offer a uniform, Pythonic interface for accessing fields, iterating over arrays, and performing architecture-agnostic analysis of process state, memory mappings, and more.

## Purpose
- Abstract away raw C structs, ctypes, or dicts returned by plugins.
- Provide convenient attribute access, conversion to dict/list, and pretty-printing.
- Enable architecture-independent analysis of process state (registers, memory maps, etc).
- Facilitate building analysis tools, plugins, and scripts that work across architectures and plugins.

## Example Usage
Importing wrappers for use in your analysis code:

```python
from wrappers.generic import Wrapper, ArrayWrapper
from wrappers.ptregs_wrap import get_pt_regs_wrapper, PtRegsWrapper
from wrappers.osi_wrap import MappingWrapper, MappingsWrapper
```

Wrapping plugin data:

```python
# Wrap a struct or dict
obj = Wrapper(plugin.get_struct())
print(obj.field1)

# Wrap an array of objects
objs = ArrayWrapper([Wrapper(x) for x in plugin.get_array()])
for o in objs:
    print(o)

# Architecture-agnostic register access
regs = plugin.get_pt_regs()
wrapper = get_pt_regs_wrapper(panda, regs, arch_name=panda.arch_name)
print(wrapper.get_pc())

# Memory mapping analysis
raw_maps = plugin.get_mappings()
maps = MappingsWrapper([MappingWrapper(m) for m in raw_maps])
print(maps)
```

See the individual modules for more details and advanced usage.
"""
