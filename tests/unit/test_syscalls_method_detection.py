"""Regression coverage for hook-callback classification in the three probe APIs
(``pyplugins/apis/{syscalls,uprobes,kprobes}.py``).

Each decorator has to tell three kinds of callable apart:

* a **bound method** (``func.__self__`` set),
* an **unbound plugin method** captured at class-definition time (qualname
  ``Plugin.method``) — re-resolved to the bound method on the live plugin
  instance at event time, and
* a **nested closure** (qualname ``Outer.method.<locals>.handler``) — a plain
  function that must be used *as-is*.

The original heuristic classified anything with a dotted ``__qualname__`` as a
method. A closure's qualname always contains ``<locals>`` and dots, so it was
misclassified, and ``_resolve_callback`` then split the qualname and tried
``getattr(plugins, "Outer")`` / ``hasattr(instance, "handler")``. The
consequences differed by API:

* **syscalls** logged ``"Could not find method handler on instance"`` and
  returned ``None`` — silently dropping the hook (the ``breakpoint syscall`` CLI
  bug, since ``HookLogger.register_syscall`` wraps every action in a nested
  ``handler`` closure);
* **uprobes/kprobes** fell through to ``return f`` (hook still fired) *unless* a
  plugin was registered under the closure's outer name and exposed a matching
  attribute — then they bound to the **wrong** callable.

The fix, in all three, is to also require ``<locals>`` be absent from the
qualname, so a nested closure is never mistaken for a method. These tests drive
the real modules (behind the ``hyper.consts`` FFI-enum boundary, so they need the
real ISF fixture) with a null ``plugins`` bound.
"""
from pathlib import Path

import pytest

from penguin.testing import load_module

REPO_ROOT = Path(__file__).resolve().parents[2]
APIS = REPO_ROOT / "pyplugins" / "apis"


# --- module-level stand-ins ------------------------------------------------- #
# Defined at module scope on purpose: a real Penguin plugin is a module-level
# class, so its methods have qualname "Plugin.method" (no "<locals>"), while a
# handler closure created *inside* one of its methods has "<locals>" in its
# qualname. Defining these inside a test function would inject an extra
# "<locals>" into every qualname and mask the distinction under test.

class _ClosureMaker:
    """Stands in for ``HookLogger``: a method that returns a nested closure,
    just like ``register_syscall``/``register_uprobe`` do with their ``handler``.
    The closure's qualname is ``_ClosureMaker.register.<locals>.handler``."""

    def register(self):
        def handler(*args, **kwargs):
            yield from ()
        return handler


class _Decoy:
    """A plugin registered under the name ``_ClosureMaker`` (the closure's outer
    class name) that *does* expose a ``handler`` attribute. A resolver that
    misreads the closure as the method ``_ClosureMaker.handler`` would wrongly
    bind to this instead of returning the closure."""

    def handler(self, *args, **kwargs):
        yield from ()


class _MethodPlugin:
    """A normal plugin whose class-body method is registered directly."""

    def on_event(self, *args, **kwargs):
        yield from ()


class _RecordingLogger:
    def __init__(self):
        self.errors = []

    def error(self, msg, *a, **k):
        self.errors.append(msg % a if a else msg)

    def info(self, *a, **k):
        pass


# (module filename, plugin class, resolver method, resolver takes a hook_ptr arg)
CASES = [
    ("syscalls.py", "Syscalls", "_resolve_syscall_callback", False),
    ("uprobes.py", "Uprobes", "_resolve_callback", True),
    ("kprobes.py", "Kprobes", "_resolve_callback", True),
]
CASE_IDS = [c[1] for c in CASES]


def _make(igloo_ko_isf, filename, clsname):
    """Import the real API module (real consts via the ISF) and build the plugin
    without its PANDA-heavy ``__init__``, wiring only what the resolver touches."""
    mod, mgr = load_module(str(APIS / filename), real_isf=igloo_ko_isf)
    cls = getattr(mod, clsname)
    inst = cls.__new__(cls)
    inst._hooks = {}
    inst.logger = _RecordingLogger()
    return inst, mgr


def _resolve(inst, method, takes_hook_ptr, f, is_method):
    fn = getattr(inst, method)
    # hook_ptr 0 is absent from the empty _hooks map, so the cache-update branch
    # is skipped and only the classification path is exercised.
    return fn(f, is_method, 0) if takes_hook_ptr else fn(f, is_method)


# --- the regression, across all three probe APIs ---------------------------- #
@pytest.mark.parametrize("filename,clsname,method,hp", CASES, ids=CASE_IDS)
def test_nested_closure_hook_is_neither_dropped_nor_misbound(
        igloo_ko_isf, filename, clsname, method, hp):
    inst, mgr = _make(igloo_ko_isf, filename, clsname)
    handler = _ClosureMaker().register()
    assert "<locals>" in handler.__qualname__     # sanity: this is the shape that broke

    # Register a decoy under the closure's outer class name that *has* a "handler"
    # attribute. Pre-fix: syscalls -> None (drop); uprobes/kprobes -> decoy.handler
    # (wrong bind). Either way, not the closure. Pass is_method=True (the worst
    # case the old heuristic produced) so the resolver's guard is what's tested.
    mgr._ClosureMaker = _Decoy()

    resolved = _resolve(inst, method, hp, handler, True)

    assert resolved is handler
    assert inst.logger.errors == []


@pytest.mark.parametrize("filename,clsname,method,hp", CASES, ids=CASE_IDS)
def test_real_plugin_method_still_binds(igloo_ko_isf, filename, clsname, method, hp):
    """Guard against over-correction: a genuine class-body plugin method (qualname
    without "<locals>") must still resolve to the bound method on the instance."""
    inst, mgr = _make(igloo_ko_isf, filename, clsname)
    target = _MethodPlugin()
    mgr._MethodPlugin = target                    # getattr(plugins, "_MethodPlugin")

    resolved = _resolve(inst, method, hp, _MethodPlugin.on_event, True)

    assert getattr(resolved, "__self__", None) is target
    assert getattr(resolved, "__func__", None) is _MethodPlugin.on_event


# --- syscalls decorator: is_method is recorded at registration -------------- #
def test_syscalls_decorator_flags_closure_as_not_a_method(igloo_ko_isf):
    """Cover the *other* fix site: the ``@syscall`` decorator stores ``is_method``
    in the hook config at registration time, and it must be False for a closure."""
    mod, mgr = load_module(str(APIS / "syscalls.py"), real_isf=igloo_ko_isf)
    s = mod.Syscalls.__new__(mod.Syscalls)
    s._pending_hooks = []
    handler = _ClosureMaker().register()

    s.syscall("ioctl")(handler)

    hook_config = s._pending_hooks[-1][0]
    assert hook_config["callback"] is handler
    assert hook_config["is_method"] is False
