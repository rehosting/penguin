"""Host-side test harness for driving pyplugins in place (no PANDA/guest).

See :mod:`penguin.testing.harness` for the design. Public API:

    from penguin.testing import load_pyplugin
"""
from .harness import (
    load_pyplugin,
    load_module,
    LoadedPlugin,
    NullManager,
    NullPanda,
    RecorderStub,
    drive,
    install_real_consts,
    resolve_igloo_ko_isf,
    RealKffi,
)

__all__ = [
    "load_pyplugin",
    "load_module",
    "LoadedPlugin",
    "NullManager",
    "NullPanda",
    "RecorderStub",
    "drive",
    "install_real_consts",
    "resolve_igloo_ko_isf",
    "RealKffi",
]
