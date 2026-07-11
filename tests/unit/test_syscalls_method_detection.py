"""Regression coverage for syscall-hook callback classification in
``pyplugins/apis/syscalls.py``.

The ``Syscalls.syscall`` decorator has to tell three kinds of callable apart:

* a **bound method** (``func.__self__`` set),
* an **unbound plugin method** captured at class-definition time (qualname
  ``Plugin.method``) — which must be re-resolved to the bound method on the live
  plugin instance at event time, and
* a **nested closure** (qualname ``Outer.method.<locals>.handler``) — which is a
  plain function and must be used *as-is*.

The original heuristic classified anything with a dotted ``__qualname__`` as a
method. A closure's qualname always contains ``<locals>`` and dots, so it was
misclassified; ``_resolve_syscall_callback`` then tried
``getattr(plugins, "Outer")`` / ``hasattr(instance, "handler")``, failed, logged
``"Could not find method handler on instance"`` and returned ``None`` — silently
dropping the hook. This is exactly the path the ``breakpoint syscall`` CLI takes,
because ``HookLogger.register_syscall`` wraps every action in a nested ``handler``
closure.

These tests drive the *real* module (behind the ``hyper.consts`` FFI-enum
boundary, so they need the real ISF fixture) with a null ``plugins`` bound.
"""
from pathlib import Path

import pytest

from penguin.testing import load_module

REPO_ROOT = Path(__file__).resolve().parents[2]
SYSCALLS = str(REPO_ROOT / "pyplugins" / "apis" / "syscalls.py")


# --- module-level stand-ins ------------------------------------------------- #
# Defined at module scope on purpose: a real Penguin plugin is a module-level
# class, so its methods have qualname "Plugin.method" (no "<locals>"), while a
# handler closure created *inside* one of its methods has "<locals>" in its
# qualname. Defining these inside a test function would inject an extra
# "<locals>" into every qualname and mask the distinction under test.

class _ClosureMaker:
    """Stands in for ``HookLogger``: a method that returns a nested closure,
    just like ``register_syscall`` does with its ``handler``."""

    def register(self):
        def handler(regs, proto, sc, *args):   # nested closure -> "<locals>"
            yield from ()
        return handler


class _MethodPlugin:
    """Stands in for a normal plugin whose class-body method is registered
    directly as a syscall callback."""

    def on_syscall(self, regs, proto, sc, *args):
        yield from ()


class _RecordingLogger:
    def __init__(self):
        self.errors = []

    def error(self, msg, *a, **k):
        self.errors.append(msg % a if a else msg)

    def info(self, *a, **k):
        pass


def _make_syscalls(igloo_ko_isf):
    """Import the real ``apis.syscalls`` (real consts via the ISF) and build a
    ``Syscalls`` instance without its PANDA-heavy ``__init__``, wiring only the
    attributes the decorator and resolver touch."""
    mod, mgr = load_module(SYSCALLS, real_isf=igloo_ko_isf)
    s = mod.Syscalls.__new__(mod.Syscalls)
    s._pending_hooks = []
    s._hooks = {}
    s.logger = _RecordingLogger()
    return s, mgr


# --- the regression: a closure hook must not be treated as a method --------- #
def test_nested_closure_hook_is_not_classified_as_method(igloo_ko_isf):
    s, _ = _make_syscalls(igloo_ko_isf)
    handler = _ClosureMaker().register()
    assert "<locals>" in handler.__qualname__     # sanity: this is the shape that broke

    s.syscall("ioctl")(handler)

    hook_config = s._pending_hooks[-1][0]
    assert hook_config["callback"] is handler
    assert hook_config["is_method"] is False

    # With is_method False the resolver returns the closure unchanged (the hook
    # fires) rather than trying — and failing — to bind it to a plugin instance.
    assert s._resolve_syscall_callback(handler, hook_config["is_method"]) is handler


def test_resolver_does_not_drop_closure_even_if_flagged_a_method(igloo_ko_isf):
    """Defense in depth: even if a caller passes ``is_method=True`` for a closure,
    the resolver must return the closure (not ``None``) and log no
    "Could not find method" error — the exact failure the user hit."""
    s, mgr = _make_syscalls(igloo_ko_isf)
    handler = _ClosureMaker().register()
    # Make the pre-fix error path deterministic: a real instance is resolvable by
    # class name but has no "handler" attribute, so the old code logged + dropped.
    mgr._ClosureMaker = _ClosureMaker()

    resolved = s._resolve_syscall_callback(handler, True)

    assert resolved is handler
    assert s.logger.errors == []


# --- positive control: a genuine plugin method still resolves --------------- #
def test_plugin_method_hook_still_resolves_to_bound_method(igloo_ko_isf):
    s, mgr = _make_syscalls(igloo_ko_isf)
    instance = _MethodPlugin()
    mgr._MethodPlugin = instance                  # getattr(plugins, "_MethodPlugin")

    # Registered unbound (as at class-definition time): qualname "_MethodPlugin.on_syscall".
    s.syscall("ioctl")(_MethodPlugin.on_syscall)
    hook_config = s._pending_hooks[-1][0]
    assert hook_config["is_method"] is True

    resolved = s._resolve_syscall_callback(_MethodPlugin.on_syscall, True)
    assert resolved.__self__ is instance
    assert resolved.__func__ is _MethodPlugin.on_syscall
