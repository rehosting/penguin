"""Pluggable registry for pseudofile models.

This is the low-friction "expand models with Python code" path: a local
plugin (e.g. a file in a project's ``plugins.d/``) can register a new model
mixin under a name, after which that name is usable directly in ``config.yaml``
via the ``custom`` model selector::

    # plugins.d/my_models.py
    from hyperfile.models.registry import register_model
    from hyperfile.models.read import ReadBufWrapper

    @register_model("read", "my_sensor")
    class MySensorRead(ReadBufWrapper):
        ...

    # config.yaml
    pseudofiles:
      /dev/sensor:
        read: {model: custom, model_name: my_sensor}

The registry covers the mixin-based domains (read, write, poll, and the extra
VFS ops lseek/mmap/open/release). Built-in models keep their first-class names;
the registry is consulted *in addition* to the built-in tables.
"""

_DOMAINS = ("read", "write", "poll", "lseek", "mmap", "open", "release", "ioctl")

_REGISTRY = {d: {} for d in _DOMAINS}


def register_model(domain, name):
    """Decorator: register ``cls`` as model ``name`` for ``domain``.

    ``domain`` is one of read/write/poll/lseek/mmap/open/release/ioctl.
    """
    if domain not in _REGISTRY:
        raise ValueError(
            f"register_model: unknown domain '{domain}' "
            f"(expected one of {', '.join(_DOMAINS)})")

    def _wrap(cls):
        _REGISTRY[domain][name] = cls
        return cls

    return _wrap


def get_model(domain, name):
    """Return the registered model class for ``(domain, name)`` or None."""
    return _REGISTRY.get(domain, {}).get(name)
