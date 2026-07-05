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

from penguin.plugin_manager import Plugin, _exec_plugin_module, _plugin_root_on_path


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


class _NullFFI:
    """Minimal stand-in for ``panda.ffi`` (a cffi FFI object).

    Syscall/logger handlers routinely call ``self.panda.ffi.cast("target_long",
    fd)`` to reinterpret an unsigned register as signed, then ``int(...)`` it.
    A :class:`RecorderStub` can't be ``int()``-ed, so model the two operations
    plugins actually use — ``cast`` (identity: the value is already a Python int
    host-side) and ``string`` — and record anything else.
    """

    NULL = object()

    def __init__(self, log: List[Tuple]):
        object.__setattr__(self, "_log", log)

    def cast(self, ctype: Any, value: Any) -> Any:
        return value

    def string(self, value: Any) -> bytes:
        return value if isinstance(value, bytes) else str(value).encode()

    def __getattr__(self, name: str) -> RecorderStub:
        return RecorderStub(f"panda.ffi.{name}", self._log)


class NullPanda:
    """Stand-in for ``self.panda``: records callback registrations, exposes a
    configurable ``endianness`` and a minimal ``ffi``. Any other attribute is a
    :class:`RecorderStub`.
    """

    def __init__(self, endianness: str = "little", log: Optional[List[Tuple]] = None):
        object.__setattr__(self, "endianness", endianness)
        object.__setattr__(self, "_log", log if log is not None else [])
        object.__setattr__(self, "ffi", _NullFFI(self._log))

    def __getattr__(self, name: str) -> RecorderStub:
        return RecorderStub(f"panda.{name}", self._log)


def _clean_syscall_name(name: str) -> str:
    """Strip ``compat_`` / ``sys_`` prefixes and leading underscores, mirroring
    ``apis.syscalls.Syscalls._clean_syscall_name`` so hook names match by their
    bare syscall name (``sys_kill`` / ``kill`` / ``__x64_sys_kill`` all → ``kill``)."""
    if name.startswith("compat_"):
        name = name[7:]
    if name.startswith("sys_"):
        name = name[4:]
    return name.lstrip("_")


def _parse_syscall_pattern(name_or_pattern: Optional[str], on_enter, on_return):
    """Resolve a ``@syscalls.syscall(...)`` registration to (cleaned_name,
    on_enter, on_return). Handles the two forms the built-in plugins use:
    the hsyscall pattern ``on_sys_<name>_enter``/``_return`` and a plain
    ``sys_<name>`` / ``<name>`` with explicit ``on_enter``/``on_return`` kwargs.
    """
    name = name_or_pattern or ""
    oe, orr = on_enter, on_return
    if name.startswith("on_"):
        parts = name.split("_")
        if len(parts) >= 4 and parts[1] == "sys":
            phase = parts[-1]
            name = "_".join(parts[2:-1])
            oe = phase == "enter"
            orr = phase == "return"
    return _clean_syscall_name(name), oe, orr


class _SyscallRegistry:
    """Stand-in for ``plugins.syscalls``: records ``@syscall(...)`` registrations
    into a shared hook list so :meth:`LoadedPlugin.dispatch_syscall` can find and
    drive them. Exposes ``_clean_syscall_name`` because some plugins call it."""

    def __init__(self, hooks: List[dict], log: List[Tuple]):
        self._hooks = hooks
        self._log = log

    def syscall(self, name_or_pattern: Optional[str] = None, on_enter=None,
                on_return=None, **kwargs) -> Callable:
        def decorator(func):
            name, oe, orr = _parse_syscall_pattern(name_or_pattern, on_enter, on_return)
            self._hooks.append({"name": name, "on_enter": oe, "on_return": orr,
                                "handler": func, "pattern": name_or_pattern})
            return func
        return decorator

    def unregister(self, target: Callable) -> None:
        self._hooks[:] = [h for h in self._hooks if h["handler"] is not target]

    def _clean_syscall_name(self, name: str) -> str:
        return _clean_syscall_name(name)

    def __getattr__(self, name: str) -> RecorderStub:
        return RecorderStub(f"plugins.syscalls.{name}", self._log)


def drive(gen: Any, responses: Optional[List[Any]] = None) -> Any:
    """Run a portal-style generator handler to completion and return its value.

    Penguin's syscall-return / OSI / mem handlers are generators that ``yield
    from`` sibling API calls (``plugins.mem.read_bytes``, ``plugins.osi.*``); at
    runtime the portal fulfils each yielded request and resumes the generator.
    Host-side, the sibling *doubles* are themselves generators that yield nothing
    and ``return`` a canned value, so ``yield from`` resolves immediately and this
    pump just exhausts the outer generator (running its side effects) and returns
    its final value. ``responses`` (optional) is fed in order to any bare yields a
    handler makes directly (rare); exhausted responses send ``None``.
    """
    if not inspect.isgenerator(gen):
        return gen
    resp_iter = iter(responses or [])
    try:
        gen.send(None)  # prime; StopIteration immediately if it yields nothing
        while True:
            gen.send(next(resp_iter, None))
    except StopIteration as e:
        return e.value


class _AutoIntEnum:
    """Stand-in for one ``hyper.consts`` enum (``HYPER_OP``, ``value_filter_type``,
    …). Returns a stable, auto-assigned int for *any* member name, by attribute or
    item access, so code that reads enum constants at import/class-definition time
    (e.g. ``ValueFilter.__init__``'s ``vft.SYSCALLS_HC_FILTER_EXACT`` default arg)
    or builds ``PortalCmd(hop.SOMETHING, …)`` gets an int and does not crash.

    The values are meaningless (assignment order), so any portal command built
    from them is bogus — fine in the null backend, where nothing is sent to a
    real guest. This trades correctness of the enum *values* for the ability to
    import and exercise the plugin logic that sits behind the FFI-enum boundary.
    """

    def __init__(self, name: str):
        object.__setattr__(self, "_name", name)
        object.__setattr__(self, "_vals", {})

    def _get(self, member: str) -> int:
        vals = object.__getattribute__(self, "_vals")
        if member not in vals:
            vals[member] = len(vals) + 1
        return vals[member]

    def __getattr__(self, member: str) -> int:
        if member.startswith("_"):
            raise AttributeError(member)
        return self._get(member)

    def __getitem__(self, member: str) -> int:
        return self._get(member)

    def items(self):
        return list(object.__getattribute__(self, "_vals").items())

    def to_dict(self):
        return dict(object.__getattribute__(self, "_vals"))


def install_fake_enums():
    """Install an auto-int fake ``hyper.consts`` into ``sys.modules`` (idempotent).

    ``hyper.consts`` builds its enum tables at import from
    ``plugins.kffi.get_enum_dict(...)`` and wraps them in ``ConstDictWrapper``,
    which *eagerly* materializes members — so faking ``get_enum_dict`` alone can't
    work (unknown members raise ``AttributeError``). Instead we replace the module
    with one whose every enum is an :class:`_AutoIntEnum`. The real
    ``hyper.portal`` / ``apis.syscalls`` then import against it, so plugins behind
    the enum boundary (``analysis/interfaces``, syscall-analysis plugins, …) load
    and their host-side logic can be exercised. Enum *values* are bogus; portal
    command numbers built from them are meaningless (never sent host-side).

    Returns the fake module. Safe to call repeatedly.
    """
    import sys
    import types

    existing = sys.modules.get("hyper.consts")
    if existing is not None and getattr(existing, "_penguin_fake_enums", False):
        return existing

    mod = types.ModuleType("hyper.consts")
    mod._penguin_fake_enums = True
    _enums: Dict[str, _AutoIntEnum] = {}

    def _module_getattr(name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        if name not in _enums:
            _enums[name] = _AutoIntEnum(name)
        return _enums[name]

    mod.__getattr__ = _module_getattr  # PEP 562: resolves `from hyper.consts import X`
    mod.enum_names = []
    sys.modules["hyper.consts"] = mod
    return mod


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
        # Syscall-hook registry: @plugins.syscalls.syscall(...) records here so
        # LoadedPlugin.dispatch_syscall can find and drive the generator handler.
        self.syscall_hooks: List[dict] = []
        self.syscalls = _SyscallRegistry(self.syscall_hooks, log)

    # --- manager surface a plugin's __init__ touches ---------------------- #
    def subscribe(self, publisher: Any, event: str, callback: Callable = None, *a, **k):
        """Record a subscription. Mirrors the real manager: with no ``callback``
        it returns a decorator (the class-body ``@plugins.subscribe(pub, event)``
        form), otherwise it records directly."""
        if callback is None:
            def decorator(cb):
                self.subscriptions.append((publisher, event, cb))
                return cb
            return decorator
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
        return [self._bind(cb)(*args, **kwargs) for cb in handlers]

    def dispatch_syscall(self, name: str, *args: Any,
                         on_return: Optional[bool] = None,
                         responses: Optional[List[Any]] = None) -> List[Any]:
        """Invoke every ``@plugins.syscalls.syscall(...)`` hook registered for
        ``name`` and drive each (they are portal generators) to completion.

        ``name`` matches by bare syscall name (``sys_kill``/``kill``/
        ``on_sys_kill_enter`` all select ``kill``). Pass ``on_return=True/False``
        to disambiguate enter vs return hooks. Returns each handler's final value.
        Raises if no hook matches. The handler args are the syscall-callback args
        (``regs, proto, syscall, *syscall_args``); sibling API calls the handler
        makes (``plugins.mem``/``plugins.osi``) must be satisfied by generator
        ``doubles``.
        """
        clean = _clean_syscall_name(name)
        matches = [h for h in self.manager.syscall_hooks
                   if h["name"] == clean
                   and (on_return is None or bool(h["on_return"]) == on_return)]
        if not matches:
            known = sorted({h["name"] for h in self.manager.syscall_hooks})
            raise KeyError(f"no syscall hook for {name!r}; known: {known}")
        return [drive(self._bind(h["handler"])(*args), responses) for h in matches]

    def _bind(self, handler: Callable) -> Callable:
        """Bind a class-body-subscribed handler to the constructed instance.

        ``@plugins.subscribe(...)`` in a class body records the *unbound*
        function (the instance doesn't exist yet). If it belongs to this plugin's
        class, bind it so ``self`` is supplied — mirroring what the real manager's
        publish() does via resolve_bound_method_from_class.
        """
        if inspect.isfunction(handler) and not hasattr(handler, "__self__"):
            owner = getattr(type(self.plugin), handler.__name__, None)
            if owner is handler:
                return handler.__get__(self.plugin, type(self.plugin))
        return handler

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
    call_init: bool = True,
    fake_enums: bool = False,
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
    call_init : run the plugin's ``__init__`` (default). Set False for plugins
        whose ``__init__`` does host-impossible I/O (e.g. nvram2 shells out to
        ``clang-20`` to compile lib_inject) — the class still imports (so
        class-body ``@subscribe``/``@syscall`` decorators register), the instance
        is ``__new__``/``__preinit__``-wired, and the test sets the handful of
        attributes the handlers need before driving them.
    fake_enums : install an auto-int fake ``hyper.consts`` before import (see
        :func:`install_fake_enums`) so plugins behind the FFI-enum boundary — those
        importing ``apis.syscalls``/``hyper`` (e.g. ``analysis/interfaces``) — load
        host-side. Enum values are bogus; only use it for logic that doesn't depend
        on real enum constants.
    """
    if fake_enums:
        install_fake_enums()
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

    # Put the pyplugins root on sys.path so sibling-package imports in the target
    # (`from apis.syscalls import ...`, `import hyper`) resolve the same way they
    # do at runtime, then ride the real loader (binds our null manager as
    # `plugins` during import so class/module-body decorators resolve against it).
    root = pyplugins_dir or _pyplugins_root(path)
    with _plugin_root_on_path(root):
        classes = dict(_exec_plugin_module(path, manager, panda))
        cls = _pick_class(classes, class_name, path)
        plugin = _construct(cls, manager, panda, args, call_init=call_init)
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


def load_module(path_or_name: str, *, doubles: Optional[Dict[str, Any]] = None,
                pyplugins_dir: Optional[str] = None,
                endianness: str = "little",
                fake_enums: bool = False) -> Tuple[Any, "NullManager"]:
    """Import a pyplugin *module* (not necessarily a ``Plugin`` subclass) with a
    null ``plugins`` bound, and return ``(module, manager)``.

    Use this for modules whose testable logic lives in plain classes/functions
    rather than a ``Plugin`` (e.g. the ``hyperfile/models/*`` read/write mixins):
    import once, then instantiate the classes directly and drive their generator
    methods with :func:`drive`, resolving ``plugins.<name>`` against ``doubles``.

    The module is imported under its real dotted name (``hyperfile.models.read``)
    so intra-package ``from .base import …`` resolves; ``penguin.plugins`` is set
    to the null manager for the duration of the import so module-body /
    ``from penguin import plugins`` bindings resolve against it.
    """
    import importlib
    import penguin

    if fake_enums:
        install_fake_enums()
    doubles = dict(doubles or {})
    path = _resolve_path(path_or_name, pyplugins_dir)
    root = pyplugins_dir or _pyplugins_root(path)
    if root is None:
        raise ValueError(f"no pyplugins root above {path}; pass pyplugins_dir=")

    rel = os.path.relpath(os.path.realpath(path), os.path.realpath(root))
    dotted = rel[:-3].replace(os.sep, ".") if rel.endswith(".py") else rel

    log: List[Tuple] = []
    panda = NullPanda(endianness=endianness, log=log)
    manager = NullManager(args={"plugins": {}}, doubles=doubles, panda=panda, log=log)

    saved = getattr(penguin, "plugins", None)
    penguin.plugins = manager
    try:
        with _plugin_root_on_path(root):
            module = importlib.import_module(dotted)
    finally:
        penguin.plugins = saved
    # import_module returns the *cached* module if a prior test already imported
    # it — in which case its module-global `plugins` is bound to whatever was
    # active then (often the real singleton), not our manager. Force it, so the
    # module's functions/methods resolve `plugins.<name>` against our doubles at
    # call time regardless of who imported the module first.
    module.plugins = manager
    return module, manager


def _pyplugins_root(path: str) -> Optional[str]:
    """Find the ``pyplugins`` root above a plugin file so sibling packages
    (``apis``, ``hyper``, …) import. Returns the ancestor dir named ``pyplugins``,
    else None (a bare path with no such ancestor needs pyplugins_dir=)."""
    p = os.path.dirname(os.path.realpath(path))
    while p and os.path.dirname(p) != p:
        if os.path.basename(p) == "pyplugins":
            return p
        p = os.path.dirname(p)
    return None


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
               args: Dict[str, Any], call_init: bool = True) -> Plugin:
    """Construct a plugin the way IGLOOPluginManager.load does: __new__, then
    __preinit__ (wires manager/panda/args), then __init__ (0- or 1-arg).

    ``call_init=False`` stops after ``__preinit__`` (used for plugins whose
    ``__init__`` does host-impossible I/O); the caller sets handler-needed attrs."""
    obj = cls.__new__(cls)
    obj.__preinit__(manager, args)
    if not call_init:
        return obj
    nparams = len(inspect.signature(obj.__init__).parameters)
    if nparams == 1:
        obj.__init__(panda)
    else:
        obj.__init__()
    return obj
