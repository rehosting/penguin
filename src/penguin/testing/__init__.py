"""Host-side test harness for driving pyplugins in place (no PANDA/guest).

See :mod:`penguin.testing.harness` for the design. Public API:

    from penguin.testing import load_pyplugin
"""
from .harness import (
    load_pyplugin,
    LoadedPlugin,
    NullManager,
    NullPanda,
    RecorderStub,
)

__all__ = [
    "load_pyplugin",
    "LoadedPlugin",
    "NullManager",
    "NullPanda",
    "RecorderStub",
]
