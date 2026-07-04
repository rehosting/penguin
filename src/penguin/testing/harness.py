"""
In-place pyplugin test harness (``penguin.testing``)
====================================================

Drive a Penguin pyplugin **where it lives**, with no PANDA, no guest, and no
emulation, so its host-side logic (the files it writes, the events it emits) can
be tested by a fast host-side unit test instead of a per-arch guest boot.

The problem this solves
-----------------------

A pyplugin cannot simply be imported and instantiated standalone: its module and
class body reference the live ``plugins`` manager (``@plugins.portalcall(...)``,
``plugins.subscribe(plugins.Events, ...)``, sibling ``plugins.<name>`` calls),
which are normally late-bound against a running PANDA/portal. Importing without a
manager raises (see the recursion in ``IGLOOPluginManager.__getattr__``); the old
approach was a bespoke ``sys.modules`` stub per test file.

This harness replaces that with **one reusable null backend**:

* ``NullManager`` stands in for the plugin manager. Known siblings resolve to
  test doubles you register; unknown ones resolve to a recording no-op
  (``RecorderStub``) so decorators and sibling calls are harmless and observable.
* ``NullPanda`` stands in for the emulator handle (``self.panda``). It records
  callback registrations and exposes a configurable ``endianness``.
* The plugin is loaded via the *real* loader (``_exec_plugin_module``) and
  constructed via the real ``Plugin`` protocol (``__new__`` → ``__preinit__`` →
  ``__init__``), so behaviour matches production construction.

Scope
-----

Faithful for plugins that **consume events and write host files** (the
``analysis/`` writers, pseudofile models, loggers). A plugin that round-trips
through the guest (hypercall request → guest action → response) is out of scope
and stays a ``tests/integration/`` fixture — register a hand-written double for
the piece that talks to the guest if you must, or don't use the harness.

Example
-------

.. code-block:: python

    from penguin.testing import load_pyplugin

    lp = load_pyplugin(
        "pyplugins/analysis/netbinds.py",
        outdir=tmp_path,
        args={"shutdown_on_www": False},
    )
    lp.dispatch("igloo_ipv4_setup", cpu=None, procname="httpd", sin_addr=0)
    lp.dispatch("igloo_ipv4_bind", cpu=None, port=port_be, is_steam=True)
    lp.finalize()  # runs uninit() -> lifecycle CSV
    assert "httpd" in (tmp_path / "netbinds.csv").read_text()
"""
from __future__ import annotations

import inspect
import os
from typing import Any, Callable, Dict, List, Optional, Tuple

from penguin.plugin_manager import Plugin, _exec_plugin_module


class RecorderStub:
    """Recursive no-op that records attribute access and calls.

    Stands in for any plugin-manager attribute the harness has not been given a
    real double for (sibling plugins, ``plugins.Events``, nested APIs). Behaves as
    a decorator (``@x`` and ``@x(...)``), an empty container, and a callable, so
    class/module-body and ``__init__`` code touching it does not blow up. Every
    call is appended to the shared ``log`` for assertions.
    """

    def __init__(self, path: str = "plugins", log: Optional[List[Tuple]] = None):
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_log", log if log is not None else [])

    def __getattr__(self, name: str) -> "RecorderStub":
        return RecorderStub(f"{self._path}.{name}", self._log)

    def __call__(self, *args: Any, **kwargs: Any):
        self._log.append((self._path, args, kwargs))
        # Behave as a bare decorator: @x on a function returns the function.
        if len(args) == 1 and not kwargs and callable(args[0]):
            return args[0]
        # Behave as a decorator factory: @x(...) returns a decorator.
        return RecorderStub(f"{self._path}()", self._log)

    def __getitem__(self, _):
        return RecorderStub(f"{self._path}[]", self._log)

    def __len__(self):
        return 0

    def __iter__(self):
        return iter(())

    def __bool__(self):
        return False

    def __contains__(self, _):
        return False

    def __repr__(self):
        return f"<RecorderStub {self._path}>"


class NullPanda:
    """Stand-in for ``self.panda``: records callback registrations, exposes a
    configurable ``endianness``. Any other attribute is a :class:`RecorderStub`.
    """

    def __init__(self, endianness: str = "little", log: Optional[List[Tuple]] = None):
        object.__setattr__(self, "endianness", endianness)
        object.__setattr__(self, "_log", log if log is not None else [])

    def __getattr__(self, name: str) -> RecorderStub:
        return RecorderStub(f"panda.{name}", self._log)


class NullManager:
    """Null backend standing in for ``IGLOOPluginManager``.

    Records ``subscribe``/``register``/``publish``/``portal_publish`` calls,
    resolves registered doubles by name, and falls back to a recording stub for
    everything else. It never tries to load a real plugin (no recursion).
    """

    def __init__(self, args: Dict[str, Any], doubles: Dict[str, Any],
                 panda: NullPanda, log: List[Tuple]):
        # Real attributes; __getattr__ only fires for names not set here.
        self.args = args
        self.panda = panda
        self._doubles = doubles
        self._log = log
        self.subscriptions: List[Tuple[Any, str, Callable]] = []
        self.registrations: List[Tuple[Any, str, tuple, dict]] = []
        self.published: List[Tuple[Any, str, tuple, dict]] = []
        self.plugins: Dict[str, Plugin] = {}

    # --- manager surface a plugin's __init__ touches ---------------------- #
    def subscribe(self, publisher: Any, event: str, callback: Callable, *a, **k) -> None:
        self.subscriptions.append((publisher, event, callback))

    def register(self, plugin: Any, event: str, *a, **k) -> None:
        self.registrations.append((plugin, event, a, k))

    def publish(self, plugin: Any, event: str, *args: Any, **kwargs: Any) -> None:
        self.published.append((plugin, event, args, kwargs))

    def portal_publish(self, plugin: Any, event: str, *args: Any, **kwargs: Any):
        self.published.append((plugin, event, args, kwargs))
        return iter(())

    def portalcall(self, *a, **k):
        """Identity decorator factory: ``@plugins.portalcall(magic)``."""
        def decorator(func):
            return func
        return decorator

    def get_plugin_by_name(self, name: str) -> Optional[Any]:
        return self._doubles.get(name) or self._doubles.get(name.lower())

    def __contains__(self, name: str) -> bool:
        return self.get_plugin_by_name(name) is not None

    def __getitem__(self, name: str) -> Any:
        return self.get_plugin_by_name(name) or RecorderStub(f"plugins.{name}", self._log)

    def __getattr__(self, name: str) -> Any:
        # Only reached for names not set in __init__. Return a registered double
        # if we have one, else a recording stub — never recurse into loading.
        doubles = object.__getattribute__(self, "_doubles")
        if name in doubles:
            return doubles[name]
        log = object.__getattribute__(self, "_log")
        return RecorderStub(f"plugins.{name}", log)


class LoadedPlugin:
    """A constructed plugin plus the null backend it was built against.

    Attributes
    ----------
    plugin : the constructed plugin instance (drive its handlers directly, or use
        :meth:`dispatch`).
    manager : the :class:`NullManager` (inspect ``.subscriptions``, ``.published``,
        ``.registrations``).
    panda : the :class:`NullPanda`.
    calls : the shared recorder log of stub calls ``(path, args, kwargs)``.
    """

    def __init__(self, plugin: Plugin, manager: NullManager, panda: NullPanda,
                 log: List[Tuple]):
        self.plugin = plugin
        self.manager = manager
        self.panda = panda
        self.calls = log

    @property
    def subscriptions(self) -> List[Tuple[Any, str, Callable]]:
        return self.manager.subscriptions

    @property
    def published(self) -> List[Tuple[Any, str, tuple, dict]]:
        return self.manager.published

    def dispatch(self, event: str, *args: Any, **kwargs: Any) -> List[Any]:
        """Invoke every handler the plugin subscribed to ``event``.

        Mirrors the manager delivering an event to subscribers. Returns the list
        of handler return values. Raises if no handler is subscribed to ``event``
        (a silent no-op usually means a typo in the event name).
        """
        handlers = [cb for (_pub, ev, cb) in self.manager.subscriptions if ev == event]
        if not handlers:
            known = sorted({ev for (_p, ev, _c) in self.manager.subscriptions})
            raise KeyError(f"no handler subscribed to {event!r}; known events: {known}")
        return [cb(*args, **kwargs) for cb in handlers]

    def finalize(self) -> None:
        """Run the plugin's teardown (``uninit``) if it has one — many plugins
        flush their final output file there (e.g. netbinds' lifecycle CSV)."""
        uninit = getattr(self.plugin, "uninit", None)
        if callable(uninit):
            uninit()


def load_pyplugin(
    path_or_name: str,
    *,
    args: Optional[Dict[str, Any]] = None,
    outdir: Optional[str] = None,
    doubles: Optional[Dict[str, Any]] = None,
    class_name: Optional[str] = None,
    endianness: str = "little",
    pyplugins_dir: Optional[str] = None,
) -> LoadedPlugin:
    """Load and construct a pyplugin against a null backend, ready to drive.

    Parameters
    ----------
    path_or_name : filesystem path to the plugin ``.py`` (recommended), or a bare
        module basename resolved against ``pyplugins_dir``.
    args : the plugin's arguments (the ``conf['plugins'][name]`` block). ``outdir``
        is injected automatically when given.
    outdir : output directory the plugin writes into (a tmp dir in tests). Added to
        ``args`` as ``outdir``.
    doubles : mapping of sibling name -> test double, resolved by
        ``plugins.<name>`` / ``get_plugin_by_name``. Unlisted siblings become a
        recording :class:`RecorderStub`.
    class_name : which ``Plugin`` subclass to construct when the module defines
        more than one. Defaults to the sole subclass.
    endianness : ``self.panda.endianness`` value ("little" or "big").
    pyplugins_dir : directory to resolve a bare ``path_or_name`` against.
    """
    args = dict(args or {})
    if outdir is not None:
        args["outdir"] = str(outdir)
    doubles = dict(doubles or {})

    path = _resolve_path(path_or_name, pyplugins_dir)

    log: List[Tuple] = []
    panda = NullPanda(endianness=endianness, log=log)
    # Manager-level args mirror the run's global args dict (a "plugins" section is
    # expected by some manager paths); per-plugin args are passed at __preinit__.
    manager = NullManager(args={"plugins": {}}, doubles=doubles, panda=panda, log=log)

    # Ride the real loader: bind our null manager as `plugins` during import so
    # class/module-body decorators resolve against it, and return the classes.
    classes = dict(_exec_plugin_module(path, manager, panda))
    cls = _pick_class(classes, class_name, path)

    plugin = _construct(cls, manager, panda, args)
    manager.plugins[cls.__name__] = plugin
    doubles.setdefault(cls.__name__, plugin)
    return LoadedPlugin(plugin, manager, panda, log)


def _resolve_path(path_or_name: str, pyplugins_dir: Optional[str]) -> str:
    if os.path.sep in path_or_name or path_or_name.endswith(".py"):
        if not os.path.isfile(path_or_name):
            raise FileNotFoundError(f"plugin file not found: {path_or_name}")
        return path_or_name
    if pyplugins_dir is None:
        raise ValueError(
            f"{path_or_name!r} is a bare name; pass a filesystem path or set "
            "pyplugins_dir="
        )
    import glob
    matches = glob.glob(os.path.join(pyplugins_dir, "**", f"{path_or_name}.py"),
                        recursive=True)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {path_or_name}.py under "
                         f"{pyplugins_dir}, found {matches}")
    return matches[0]


def _pick_class(classes: Dict[str, type], class_name: Optional[str], path: str) -> type:
    if class_name is not None:
        if class_name not in classes:
            raise KeyError(f"{class_name!r} not in {path}; found {sorted(classes)}")
        return classes[class_name]
    if len(classes) == 1:
        return next(iter(classes.values()))
    raise ValueError(
        f"{path} defines multiple Plugin classes {sorted(classes)}; "
        "pass class_name= to choose one"
    )


def _construct(cls: type, manager: NullManager, panda: NullPanda,
               args: Dict[str, Any]) -> Plugin:
    """Construct a plugin the way IGLOOPluginManager.load does: __new__, then
    __preinit__ (wires manager/panda/args), then __init__ (0- or 1-arg)."""
    obj = cls.__new__(cls)
    obj.__preinit__(manager, args)
    nparams = len(inspect.signature(obj.__init__).parameters)
    if nparams == 1:
        obj.__init__(panda)
    else:
        obj.__init__()
    return obj
