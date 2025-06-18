"""
# generic.py - Base wrappers for plugin data structures

This module provides generic Python wrapper classes for plugin data structures, such as those returned by PANDA or other emulation/analysis frameworks. These wrappers provide a uniform interface for accessing fields, converting to dicts, and working with arrays of wrapped objects.

## Overview

The main classes are:
- `Wrapper`: A base class for wrapping a single object, providing attribute access, dict conversion, and pretty-printing.
- `ArrayWrapper`: A base class for wrapping a list/array of objects, providing list-like access and iteration.

These classes are intended to be subclassed for specific data structures, but can also be used directly for simple cases.

## Typical Usage

Suppose you have a plugin that returns a C struct or dict-like object:

```python
from wrappers.generic import Wrapper, ArrayWrapper

# Wrap a single object
data = plugin.get_struct()
obj = Wrapper(data)
print(obj.field1)
print(obj.to_dict())

# Wrap an array of objects
array_data = plugin.get_array()
objs = ArrayWrapper([Wrapper(x) for x in array_data])
for o in objs:
    print(o)
```

## Classes
- `Wrapper`: Base class for single-object wrappers.
- `ArrayWrapper`: Base class for array/list wrappers.
"""

from typing import Any, Dict, Iterator, List, Sequence, TypeVar, Generic

T = TypeVar('T')


class Wrapper:
    """
    Base class for wrapping a single object, providing attribute access, dict conversion, and pretty-printing.
    """

    def __init__(self, obj: Any) -> None:
        """Initialize the wrapper with the given object."""
        super().__setattr__('_obj', obj)  # Set wrapped object safely
        # Store attributes set on the wrapper itself
        super().__setattr__('_extra_attrs', {})

    def __getattr__(self, name: str) -> Any:
        """Delegate attribute access to the wrapped object."""
        if name in self._extra_attrs:  # Check wrapper-specific attributes
            return self._extra_attrs[name]
        if type(self._obj) is dict:
            if name in self._obj:
                return self._obj[name]
        # Otherwise, access wrapped object attributes
        return getattr(self._obj, name)

    def __setattr__(self, name: str, value: Any) -> None:
        """Set an attribute on the wrapper or the wrapped object."""
        if type(self._obj) is dict:
            self._obj[name] = value
        elif hasattr(self._obj, name):
            setattr(self._obj, name, value)  # Modify wrapped object attributes
        else:
            # Store attributes directly on the wrapper
            self._extra_attrs[name] = value

    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-like access to attributes."""
        return self.__getattr__(key)  # Allow dictionary-like access

    def __dir__(self) -> List[str]:
        """Retrieve all attributes of both wrapper and wrapped object."""
        return list(self._extra_attrs.keys()) + \
            dir(self._obj)  # Merge both sets of attributes

    def to_dict(self) -> Dict[str, Any]:
        """Convert the wrapped object to a dictionary (if possible)."""
        if hasattr(self._obj, '__dict__'):
            return dict(self._obj.__dict__)
        elif isinstance(self._obj, dict):
            return dict(self._obj)
        else:
            # Fallback: try to extract fields
            return {k: getattr(self._obj, k)
                    for k in dir(self._obj) if not k.startswith('_')}

    def __repr__(self) -> str:
        """Return a string representation of the wrapper."""
        return f"{self.__class__.__name__}({repr(self._obj)})"

    def __str__(self) -> str:
        """Return a pretty string representation of the wrapped object."""
        return str(self._obj)


class ArrayWrapper(Generic[T]):
    """
    Base class for wrapping a list/array of objects, providing list-like access and iteration.
    """

    def __init__(self, data: Sequence[T]) -> None:
        """Initialize the array wrapper with a sequence of objects."""
        self._data = list(data)

    def __getitem__(self, idx: int) -> T:
        """Get the item at the given index."""
        return self._data[idx]

    def __len__(self) -> int:
        """Return the number of items in the array."""
        return len(self._data)

    def __iter__(self) -> Iterator[T]:
        """Iterate over the wrapped objects."""
        return iter(self._data)

    def to_list(self) -> List[T]:
        """Return the underlying list of wrapped objects."""
        return list(self._data)

    def __repr__(self) -> str:
        """Return a string representation of the array wrapper."""
        return f"{self.__class__.__name__}({repr(self._data)})"

    def __str__(self) -> str:
        """Return a pretty string representation of the array wrapper."""
        return str(self._data)
