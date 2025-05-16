class Wrapper:
    def __init__(self, obj):
        super().__setattr__('_obj', obj)  # Set wrapped object safely
        # Store attributes set on the wrapper itself
        super().__setattr__('_extra_attrs', {})

    def __getattr__(self, name):
        if name in self._extra_attrs:  # Check wrapper-specific attributes
            return self._extra_attrs[name]
        # Otherwise, access wrapped object attributes
        return getattr(self._obj, name)

    def __setattr__(self, name, value):
        if hasattr(self._obj, name):
            setattr(self._obj, name, value)  # Modify wrapped object attributes
        else:
            # Store attributes directly on the wrapper
            self._extra_attrs[name] = value

    def __getitem__(self, key):
        return self.__getattr__(key)  # Allow dictionary-like access

    def __dir__(self):
        """Retrieve all attributes of both wrapper and wrapped object."""
        return list(self._extra_attrs.keys()) + dir(self._obj)  # Merge both sets of attributes


class ArrayWrapper:
    def __init__(self, data=None):
        """Initialize the wrapper with a list or an empty array."""
        self._data = list(data) if data is not None else []

    def append(self, value):
        """Append a value to the wrapped array."""
        self._data.append(value)

    def get(self, index):
        """Retrieve an item by index."""
        return self._data[index]

    def set(self, index, value):
        """Set a value at a specific index."""
        self._data[index] = value

    def __len__(self):
        """Get the length of the array."""
        return len(self._data)

    def __getitem__(self, index):
        """Allow bracket-style access."""
        return self._data[index]

    def __setitem__(self, index, value):
        """Allow bracket-style assignment."""
        self._data[index] = value

    def __repr__(self):
        """Return a string representation."""
        return f"ArrayWrapper({self._data})"
