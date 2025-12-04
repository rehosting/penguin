"""
generic.py - Base wrappers for plugin data structures
=====================================================

This module provides generic Python wrapper classes for plugin data structures, such as those returned by PANDA or other emulation/analysis frameworks. These wrappers provide a uniform interface for accessing fields, converting to dicts, and working with arrays of wrapped objects.

Overview
--------

The main classes are:
- Wrapper: A base class for wrapping a single object, providing attribute access, dict conversion, and pretty-printing.
- ArrayWrapper: A base class for wrapping a list/array of objects, providing list-like access and iteration.

These classes are intended to be subclassed for specific data structures, but can also be used directly for simple cases.

Typical Usage
-------------

Suppose you have a plugin that returns a C struct or dict-like object:

.. code-block:: python

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

Classes
-------

- Wrapper: Base class for single-object wrappers.
- ArrayWrapper: Base class for array/list wrappers.
"""

from typing import Any, Dict, Iterator, List, Sequence, TypeVar, Generic, Type

T = TypeVar('T')


class Wrapper:
    """
    Optimized base class for wrapping a single object.
    Uses __slots__ and cached type flags to minimize __getattr__ overhead.
    """
    
    __slots__ = ('_obj', '_extra_attrs', '_is_dict')

    def __init__(self, obj: Any) -> None:
        object.__setattr__(self, '_obj', obj)
        object.__setattr__(self, '_extra_attrs', {})
        object.__setattr__(self, '_is_dict', isinstance(obj, dict))

    def __getattr__(self, name: str) -> Any:
        # 1. Check extra_attrs (fastest local check)
        extras = self._extra_attrs
        if name in extras:
            return extras[name]

        # 2. Access the wrapped object based on cached type
        obj = self._obj
        if self._is_dict:
            try:
                return obj[name]
            except KeyError:
                # FIX: If 'name' isn't a data key, check if it's a dict method
                # (e.g., .items(), .values(), .get())
                return getattr(obj, name)
        
        # 3. Standard object access for non-dicts
        return getattr(obj, name)

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ('_obj', '_extra_attrs', '_is_dict'):
            object.__setattr__(self, name, value)
            return
        if self._is_dict:
            self._obj[name] = value
        else:
            # Optimistic approach: try to set it on the object first.
            # This is faster than 'hasattr' which internally does a get/catch.
            try:
                setattr(self._obj, name, value)
            except AttributeError:
                self._extra_attrs[name] = value

    def __getitem__(self, key: str) -> Any:
        return self.__getattr__(key)

    def __dir__(self) -> List[str]:
        base = list(self._extra_attrs.keys())
        # Dicts don't support dir() well for keys, handle separately
        if self._is_dict:
            return base + list(self._obj.keys())
        return base + dir(self._obj)

    def to_dict(self) -> Dict[str, Any]:
        if self._is_dict:
            return dict(self._obj)
        elif hasattr(self._obj, '__dict__'):
            return dict(self._obj.__dict__)
        else:
            return {k: getattr(self._obj, k) 
                    for k in dir(self._obj) if not k.startswith('_')}

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({repr(self._obj)})"

    def __str__(self) -> str:
        return str(self._obj)


class ArrayWrapper(Generic[T]):
    """
    Optimized base class for wrapping a list/array of objects.
    Performs LAZY wrapping: objects are only wrapped when accessed.
    """

    def __init__(self, data: Sequence[Any], wrapper_cls: Type[T] = Wrapper) -> None:
        self._data = data
        self._wrapper_cls = wrapper_cls

    def __getitem__(self, idx: int) -> T:
        # Wrap on demand!
        return self._wrapper_cls(self._data[idx])

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self) -> Iterator[T]:
        # Generator expression for lazy iteration
        return (self._wrapper_cls(x) for x in self._data)

    def to_list(self) -> List[T]:
        return [self._wrapper_cls(x) for x in self._data]

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({repr(self._data)})"
    
    def __str__(self) -> str:
        return str(self._data)


class ConstDictWrapper:
    """
    A read-only wrapper for dictionaries optimized for maximum read speed.
    
    Attributes are injected directly into the instance's __dict__ at 
    initialization time, allowing for native C-speed attribute access 
    (obj.field) without the overhead of __getattr__.
    """
    def __init__(self, data: Dict[str, Any]) -> None:
        """
        Initialize the wrapper.
        
        This performs a shallow copy of the dictionary keys into the 
        object's namespace.
        """
        # DIRECT INJECTION: This is the magic speed trick.
        # By updating __dict__ directly, we bypass __setattr__ logic
        # and populate the attributes immediately.
        self.__dict__.update(data)

    def __setattr__(self, name: str, value: Any) -> None:
        """Block attempts to change values or add new attributes."""
        raise TypeError(f"'{self.__class__.__name__}' object is immutable")

    def __delattr__(self, name: str) -> None:
        """Block attempts to delete attributes."""
        raise TypeError(f"'{self.__class__.__name__}' object is immutable")

    def __getitem__(self, key: str) -> Any:
        """Allow dictionary-like access (wrapper['key'])."""
        return self.__dict__[key]

    def __setitem__(self, key: str, value: Any) -> None:
        """Block dictionary-like assignment."""
        raise TypeError(f"'{self.__class__.__name__}' object is immutable")

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({self.__dict__})"

    def to_dict(self) -> Dict[str, Any]:
        """Return the underlying data as a dict."""
        # Since our __dict__ IS the data, we just return a copy of it.
        return self.__dict__.copy()

    def items(self):
        """Pass-through for dict iteration."""
        return self.__dict__.items()

    def keys(self):
        """Pass-through for keys."""
        return self.__dict__.keys()
    
    def values(self):
        """Pass-through for values."""
        return self.__dict__.values()