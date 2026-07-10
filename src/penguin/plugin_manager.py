"""
plugin_manager.py - IGLOO Plugin Manager for Penguin

This module provides the IGLOOPluginManager and Plugin base class for the Penguin emulation environment.

It is responsible for:

- Discovering, loading, and unloading plugin classes.
- Managing plugin lifecycles and dependencies.
- Providing a singleton ``plugins`` object for global plugin access.
- Registering, subscribing, and publishing plugin events.
- Supporting Penguin Plugin interfaces.
- Providing utility functions for plugin name resolution and file discovery.

Arguments
---------
- ``panda``: The active emulator compatibility object.
- ``args`` (``dict``): Dictionary of arguments and configuration for plugins.

Plugin Interface
----------------
Plugins should subclass :class:`Plugin` and will be automatically discovered and managed.
Plugins can register, subscribe, and publish events using the ``plugins`` singleton::

    plugins.register(plugin_instance, "event_name")
    plugins.subscribe(other_plugin, "event_name", callback)
    plugins.publish(plugin_instance, "event_name", *args, **kwargs)

Plugins can be loaded by name or class, and arguments can be passed via the plugin manager.

Overall Purpose
---------------
The plugin manager provides a flexible, extensible, and event-driven system for managing plugins in the
Penguin emulation environment, enabling modular analysis, automation, and extension of the emulation workflow.
"""

import ast
import collections
import os
import sys
from os.path import join, isfile, basename, splitext, isdir
from contextlib import contextmanager
from penguin import getColoredLogger
import shutil
from typing import List, Dict, Union, Callable, Tuple, Optional, Any, Type, TypeVar, Iterator
import glob
import re
import importlib
import inspect
import datetime
import functools

from pydantic import BaseModel, ConfigDict, ValidationError

# Forward reference for type annotations
T = TypeVar('T', bound='Plugin')
PluginManagerType = TypeVar('PluginManagerType', bound='IGLOOPluginManager')


def resolve_bound_method_from_class(f: Callable, manager: Any = None) -> Callable:
    """
    Resolve a method from a class given a function reference.

    :param f: The function reference to resolve.
    :type f: Callable

    :return: The resolved method or the original function if not found.
    :rtype: Callable
    """
    if hasattr(f, '__qualname__') and '.' in f.__qualname__ and not hasattr(f, '__self__'):
        class_name = f.__qualname__.split('.')[0]
        method_name = f.__qualname__.split('.')[-1]

        # Use provided manager or fall back to global singleton
        mgr = manager if manager is not None else plugins

        # Use getattr with default to avoid crashing if plugin isn't loaded yet
        instance = getattr(mgr, class_name, None)
        if instance and hasattr(instance, method_name):
            return getattr(instance, method_name)
    return f


class ArgsBox:
    __slots__ = ('args',)

    def __init__(self, args: Dict[str, Any]) -> None:
        """
        Initialize ArgsBox with a dictionary of arguments.

        :param args: Dictionary of arguments.
        :type args: Dict[str, Any]
        """
        super().__setattr__('args', args)

    def __getitem__(self, key: str) -> Any:
        return self.args[key]

    def __getattr__(self, key: str) -> Any:
        if key == 'args':
            return super().__getattribute__('args')
        try:
            return self.args[key]
        except KeyError:
            raise AttributeError(f"ArgsBox has no attribute '{key}'")

    def __setitem__(self, key: str, value: Any) -> None:
        if key == 'args':
            super().__setattr__('args', value)
        else:
            self.args[key] = value

    def __setattr__(self, key: str, value: Any) -> None:
        if key == 'args':
            super().__setattr__('args', value)
        else:
            self.args[key] = value

    def get(self, key: str, default: Any = None) -> Any:
        return self.args.get(key, default)

    def get_bool(self, key: str, default: bool = False) -> bool:
        """
        Get a boolean argument value by name.

        :param key: The argument name.
        :type key: str
        :param default: Default value if the argument is not set.
        :type default: bool

        :return: The argument value interpreted as a boolean.
        :rtype: bool
        """
        if key not in self.args:
            return default
        x = interpret_bool(self.args[key])
        if x is not None:
            return x
        raise ValueError(f"Unsupported arg type: {type(self.args[key])}")

    def __contains__(self, key: str) -> bool:
        return key in self.args

    def __repr__(self) -> str:
        return f"ArgsBox({self.args!r})"


class PluginArgs(BaseModel):
    """
    Base class for declaring a plugin's accepted arguments.

    Declare a nested ``Args`` class inheriting from ``PluginArgs`` on a plugin to
    opt into argument validation, defaults, schema/docs generation, and the
    first-class top-level config syntax (``pluginname: {...}``). Plugins that do
    not declare ``Args`` keep the legacy behavior: any args are accepted and no
    defaults are applied.

    Example::

        class Kmods(Plugin):
            class Args(PluginArgs):
                allowlist: list[str] = []
                quiet: bool = Field(False, description="Reduce logging verbosity")
    """

    model_config = ConfigDict(extra="forbid")


class Plugin:
    """
    Base class for all IGLOO plugins.

    Plugins should inherit from this class to be managed by the plugin manager.
    Provides argument access, logging, and emulator compatibility object access.
    """

    # Opt-in argument schema. None means "legacy" (accept any args, no defaults).
    Args: Optional[Type[PluginArgs]] = None

    @classmethod
    def declares_args(cls) -> bool:
        """True if this class declares its own ``Args`` schema (not inherited)."""
        a = cls.__dict__.get("Args")
        return isinstance(a, type) and issubclass(a, PluginArgs)

    def __preinit__(self, plugins: 'IGLOOPluginManager', args: Dict[str, Any]) -> None:
        """
        Internal initialization method called by the plugin manager before ``__init__``.

        :param plugins: The plugin manager instance.
        :type plugins: IGLOOPluginManager
        :param args: Dictionary of arguments for this plugin.
        :type args: Dict
        """
        self.plugins = plugins
        self.panda = plugins.panda
        cls = type(self)
        if cls.declares_args():
            args_model = cls.__dict__["Args"]
            # Only feed declared fields to the (extra="forbid") model; global
            # args like outdir/conf/proj_dir must not reach it. (Unknown user-
            # supplied keys are caught earlier, at config load, via the static
            # AST check; here we just validate types/values of declared args.)
            declared = {k: v for k, v in args.items() if k in args_model.model_fields}
            try:
                validated = args_model(**declared)
            except ValidationError as e:
                from penguin.penguin_config.errors import format_validation_error
                self.logger = getColoredLogger(f"plugins.{camel_to_snake(self.name)}")
                self.logger.error(
                    "\n" + format_validation_error(
                        e, root_model=args_model,
                        header=f"Invalid arguments for plugin '{self.name}':",
                    )
                )
                sys.exit(1)
            merged = dict(args)
            merged.update(validated.model_dump())  # fill in declared defaults
            self.args = ArgsBox(merged)
            self._args_model = validated
        else:
            self.args = ArgsBox(args)
        logname = camel_to_snake(self.name)
        self.logger = getColoredLogger(f"plugins.{logname}")

    def ensure_init(self):
        """Ensure that the plugin is fully initialized before use."""
        pass

    def on_snapshot(self, tag: str) -> None:
        """Hook called after a VM snapshot is saved.

        Override to persist any host-side state that must be reproduced when
        the snapshot is later restored. No-op by default. Plugins may also
        subscribe to the Snapshot plugin's ``on_snapshot`` event instead.
        """
        pass

    def on_restore(self, tag: str) -> None:
        """Second restore phase — **actuate**. No-op by default.

        Runs after *every* plugin's :meth:`load_state` (see the two-phase
        contract there), so sibling state restored in phase one is already
        visible. This is where side effects belong: re-publish events, replay
        recorded work, re-establish bridges, and re-write output files (the run's
        ``out_dir`` is wiped on a restore run, so files must be rewritten here).

        **No-double-actuation rule.** Only re-actuate ground truth that *no other
        plugin saved*. If some other plugin will replay state you also observe
        (e.g. the VPN bridge re-publishes ``on_bind`` for every service it
        restores), do **not** re-emit it here — instead restore your view of it
        *silently* by applying it in :meth:`load_state` (phase one), so the
        upstream replay lands on already-restored state and is absorbed. Getting
        this wrong double-actuates (re-runs scans, re-triggers analysis).
        """
        pass

    def save_state(self):
        """Return **JSON-serialisable** host-side state to bundle with a
        snapshot, or None to carry nothing (default; also the way to opt out).

        A VM snapshot captures the guest, not host-side plugin state, and a
        cross-process restore starts a fresh ``./penguin run`` whose ``out_dir``
        is wiped — so in-memory state *and* output-dir files are lost unless
        returned here. Only ``proj_dir``-backed state (e.g. NVRAM's
        ``nvram_state.yaml``) self-heals without this.

        Return only JSON types (dict/list/str/int/float/bool/None) — the value
        is ``json.dump``\\ ed to the host sidecar, so sets/tuples/bytes must be
        converted (``set`` -> list, ``bytes`` -> base64) and threads / ffi
        handles / file objects must be dropped. Include a version field in your
        dict if the shape may change across releases (a sidecar can outlive the
        penguin version that wrote it). The value is handed back to
        :meth:`load_state` on restore.
        """
        return None

    def load_state(self, data) -> None:
        """First restore phase — **apply data, do not actuate**. No-op by default.

        Receives exactly what :meth:`save_state` returned. Restore your own
        attributes here (counters, dedup sets, records) but perform **no side
        effects** — no publishing, no replay, no file writes; those belong in
        :meth:`on_restore`.

        The split is deliberate: the framework runs ``load_state`` for *all*
        plugins before *any* plugin's :meth:`on_restore`, so data applied here is
        visible to siblings during their actuation phase. A downstream consumer
        that must absorb an upstream replay (see the no-double-actuation rule on
        :meth:`on_restore`) therefore restores its dedup/seen state *here*, so it
        is already in place when the upstream replay fires.
        """
        pass

    def reset_state(self) -> None:
        """Reserved seam — reset host-side state to a pristine baseline.

        Intended for fork / restore-many (restoring one save point repeatedly),
        where each restore needs a clean slate (fresh counters, port maps). **Not
        invoked by any caller today** — once-and-continue restore never calls it.
        Do not rely on it running; it exists so restore-many can be wired later
        without changing the contract.
        """
        pass

    @property
    def name(self) -> str:
        """
        Returns the name of this plugin, which is its class name.

        :return: The class name of this plugin.
        :rtype: str
        """
        return self.__class__.__name__

    def get_arg(self, arg_name: str) -> Any:
        """
        Get an argument value by name.

        :param arg_name: The argument name.
        :type arg_name: str

        :return: The argument value or None if not set.
        :rtype: Any
        """
        if arg_name in self.args:
            return self.args[arg_name]

        return None

    def get_arg_bool(self, arg_name: str, default: bool = False) -> bool:
        """
        Returns True if the argument is set and has a truthy value.

        :param arg_name: The name of the argument to retrieve.
        :type arg_name: str

        :param default: The default value to return if the argument is not set.
        :type arg_name: bool

        :return: True if the argument exists and has a truthy value, False otherwise.
        :rtype: bool

        :raises ValueError: If the argument exists but has an unsupported type.
        """
        if arg_name not in self.args:
            return default
        if (x := interpret_bool(self.args[arg_name])) is not None:
            return x

        raise ValueError(f"Unsupported arg type: {type(self.args[arg_name])}")


class ScriptingPlugin(Plugin):
    """
    A plugin that loads and executes a Python script as its ``__init__``.

    The script will have access to ``plugins`` and ``self`` (the plugin instance).
    """
    script: str | None = None

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        import runpy
        self.script_path = self.script
        self.logger.info(f"ScriptingPlugin loading script: {self.script_path}")
        if not hasattr(self, 'args'):
            self.args = {}
        self.init_globals = {
            "plugins": self.plugins,
            "logger": self.logger,
            "panda": self.panda,
            "args": ArgsBox(self.args),
        }
        self.module = runpy.run_path(self.script_path, init_globals=self.init_globals)

    @property
    def name(self) -> str:
        """
        Returns the name of this plugin, which is its class name.

        :return: The class name of this plugin.
        :rtype: str
        """
        if hasattr(self, "script_path"):
            return basename(self.script_path).split('.')[0]
        else:
            return super().name

    def uninit(self) -> None:
        """
        Uninitialize the plugin, if needed.

        This method can be overridden by subclasses to perform cleanup.
        """
        if hasattr(self, "module") and self.module.get("uninit", None) is not None:
            self.module["uninit"]()


def interpret_bool(val: Any) -> bool:
    """
    Interpret a value as a boolean, supporting bool, str, and int types.

    :param val: The value to interpret.
    :type val: Any

    :return: The interpreted boolean value.
    :rtype: bool

    :raises ValueError: If the value has an unsupported type.
    """
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.lower() in ['true', 'y', '1']
    if isinstance(val, int):
        return val != 0


# 2. Pre-compile Regexes
RE_SNAKE_1 = re.compile(r'(.)([A-Z][a-z]+)')
RE_SNAKE_2 = re.compile(r'([a-z0-9])([A-Z])')


@functools.lru_cache(maxsize=128)
def camel_to_snake(name: str) -> str:
    """
    Convert CamelCase to snake_case.

    :param name: The CamelCase string to convert
    :type name: str

    :return: The converted snake_case string
    :rtype: str
    """
    s1 = RE_SNAKE_1.sub(r'\1_\2', name)
    return RE_SNAKE_2.sub(r'\1_\2', s1).lower()


def snake_to_camel(name: str) -> str:
    """
    Convert snake_case to CamelCase.

    :param name: The snake_case string to convert
    :type name: str

    :return: The converted CamelCase string
    :rtype: str
    """
    return ''.join(word.capitalize() for word in name.split('_'))


def gen_search_locations(plugin_name: str, proj_dir: str,
                         plugin_path: str) -> List[str]:
    """
    Generate a list of possible file paths to look for a plugin.

    :param plugin_name: The name of the plugin to search for
    :type plugin_name: str
    :param proj_dir: The project directory
    :type proj_dir: str
    :param plugin_path: The plugin path
    :type plugin_path: str

    :return: List of possible file paths to search for the plugin
    :rtype: List[str]
    """
    search_locations = [
        join(plugin_path, '**', plugin_name),
        join(plugin_path, '**', plugin_name + ".py"),
        join(proj_dir, plugin_name),
        join(proj_dir, plugin_name + ".py"),
        join(proj_dir, "plugins", plugin_name),
        join(proj_dir, "plugins", plugin_name + ".py"),
        join(proj_dir, "plugins.d", plugin_name),
        join(proj_dir, "plugins.d", plugin_name + ".py"),
    ]
    return search_locations


def _find_file(g: List[str]) -> Optional[str]:
    """Helper function to find the first matching file from a list of patterns"""
    for f in g:
        if '*' in f:
            p = glob.glob(f, recursive=True)
            if len(p) == 1:
                if isfile(p[0]) and not isdir(p[0]):
                    return p[0]
            elif len(p) > 1:
                raise ValueError(f"Multiple files found for {f}: {p}")
        else:
            if isfile(f) and not isdir(f):
                return f
    return None


def find_plugin_by_name(plugin_name: str, proj_dir: str,
                        plugin_path: str) -> Tuple[str, bool]:
    """
    Find a plugin file by name, trying various naming conventions.

    :param plugin_name: The name of the plugin to find
    :type plugin_name: str
    :param proj_dir: The project directory
    :type proj_dir: str
    :param plugin_path: The plugin path
    :type plugin_path: str

    :return: Tuple of (file_path, is_local_plugin)
    :rtype: Tuple[str, bool]

    :raises ValueError: If the plugin cannot be found
    """
    plugin_name_possibilities = [plugin_name,
                                 plugin_name.lower(),
                                 camel_to_snake(plugin_name)]
    if '_' in plugin_name:
        plugin_name_possibilities.append(snake_to_camel(plugin_name))
    for pn in plugin_name_possibilities:
        if o := _find_file(gen_search_locations(pn, proj_dir, plugin_path)):
            return o, o.startswith(proj_dir)
    raise ValueError(
        f"Plugin not found: with name={plugin_name} and plugin_path={plugin_path}"
    )


def find_local_plugins(plugin_names: List[str], proj_dir: str) -> List[str]:
    """
    Find all local plugin files for a given list of plugin names.

    :param plugin_names: List of plugin names to search for.
    :type plugin_names: List[str]
    :param proj_dir: The project directory.
    :type proj_dir: str

    :return: List of valid local file paths for the discovered plugins.
    :rtype: List[str]
    """
    local_paths = []
    for plugin_name in plugin_names:
        plugin_name_possibilities = [plugin_name,
                                     plugin_name.lower(),
                                     camel_to_snake(plugin_name)]
        if '_' in plugin_name:
            plugin_name_possibilities.append(snake_to_camel(plugin_name))

        for pn in plugin_name_possibilities:
            search_locations = [
                join(proj_dir, pn),
                join(proj_dir, pn + ".py"),
                join(proj_dir, "plugins", pn),
                join(proj_dir, "plugins", pn + ".py"),
            ]
            if o := _find_file(search_locations):
                local_paths.append(o)
                break  # Found the local plugin, move to next plugin_name

    return local_paths


class _IntrospectionStub:
    """
    A recursive no-op stand-in for the plugin manager, used only while importing
    a plugin module for introspection. Class- and module-body code such as
    ``@plugins.syscalls.syscall(...)`` resolves to harmless no-ops, so the module
    imports without a live emulator/manager and we can read declared ``Args``.
    """

    def __getattr__(self, _):
        return self

    def __call__(self, *a, **k):
        # Behave as a decorator factory and a decorator: @x(...) and @x.
        if len(a) == 1 and not k and callable(a[0]):
            return a[0]
        return self

    def __getitem__(self, _):
        return self

    # Behave as an empty container too, so class-body code that does
    # ``len(plugins.x)``, ``for y in plugins.x``, ``if plugins.x`` etc. against
    # the stub gets harmless no-op results instead of a TypeError.
    def __len__(self):
        return 0

    def __iter__(self):
        return iter(())

    def __bool__(self):
        return False

    def __contains__(self, _):
        return False


@contextmanager
def _plugin_root_on_path(plugin_path: str):
    """
    Temporarily put ``plugin_path`` on ``sys.path`` so that introspection imports
    of plugins that reference sibling packages (``import hyper``, ``from apis
    import ...``) resolve the same way they do at runtime. Restores ``sys.path``
    on exit. A no-op if the path is missing or already present.
    """
    root = os.path.realpath(plugin_path) if plugin_path else None
    added = bool(root and isdir(root) and root not in sys.path)
    if added:
        sys.path.insert(0, root)
    try:
        yield
    finally:
        if added:
            try:
                sys.path.remove(root)
            except ValueError:
                pass


def _exec_plugin_module(path, singleton, panda):
    """
    Import a plugin module under a throwaway name with ``singleton`` bound as the
    ``plugins`` object (both as a module global and as ``penguin.plugins``, so
    ``from penguin import plugins`` resolves to it) and return its ``Plugin``
    subclasses WITHOUT instantiating them. Raises on import failure.
    """
    import penguin  # lazy to avoid an import cycle

    realpath = os.path.realpath(path)
    spec = importlib.util.spec_from_file_location("plugin_introspect", realpath)
    if spec is None:
        raise ValueError(f"Unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    module.__dict__.update({
        "plugins": singleton,
        "logger": getColoredLogger("plugins.introspect"),
        "panda": panda,
        "args": ArgsBox({}),
    })
    saved = getattr(penguin, "plugins", None)
    penguin.plugins = singleton
    try:
        spec.loader.exec_module(module)
    finally:
        penguin.plugins = saved
    out = []
    for name, cls in inspect.getmembers(module, inspect.isclass):
        if issubclass(cls, Plugin) and cls is not Plugin and cls is not ScriptingPlugin:
            out.append((name, cls))
    return tuple(out)


@functools.lru_cache(maxsize=None)
def _import_plugin_classes(path: str) -> Tuple[Tuple[str, type], ...]:
    """
    Import a plugin module for introspection with the ``plugins`` singleton
    neutralized by a no-op stub, so plugins that wire callbacks in their
    class/module body still import cleanly without a live emulator/manager.

    Cached by real path. This is the standalone path (CLI ``penguin schema``,
    config-load first-class detection); plugins whose import needs real runtime
    state (e.g. ``hyper.consts`` calling ``plugins.kffi.get_enum_dict``) will
    raise here. Inside a live run, use :func:`_import_plugin_classes_live`.
    """
    return _exec_plugin_module(path, _IntrospectionStub(), None)


def _import_plugin_classes_live(path, manager, panda):
    """
    Like :func:`_import_plugin_classes` but binds the real ``manager`` and
    ``panda`` during import, so plugins that read live runtime state at import
    time (kernel-FFI enums, etc.) resolve. Not cached (manager/panda are
    process state). Used by introspection that runs inside a real penguin
    process, e.g. the docgen plugin.
    """
    return _exec_plugin_module(path, manager, panda)


def plugin_declared_arg_fields(name: str, proj_dir: str,
                               plugin_path: str) -> Optional[set]:
    """
    Statically determine whether plugin ``name`` declares an ``Args`` schema, and
    if so the set of field names it declares — **without importing the module**.

    Parses the plugin file with ``ast`` and looks for a nested
    ``class Args(PluginArgs)``. Returns the declared field names (possibly empty)
    if found, else ``None``. Because it never executes plugin code, it is safe to
    call during config load in the run's own process (unlike importing, which
    drags in sibling/third-party modules — see ``_exec_plugin_module``).
    """
    try:
        path, _ = find_plugin_by_name(name, proj_dir, plugin_path)
    except ValueError:
        return None
    try:
        with open(path, "r") as f:
            tree = ast.parse(f.read(), filename=path)
    except (OSError, SyntaxError):
        return None
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ClassDef) and node.name == "Args"):
            continue
        declares = any(
            (isinstance(b, ast.Name) and b.id == "PluginArgs")
            or (isinstance(b, ast.Attribute) and b.attr == "PluginArgs")
            for b in node.bases
        )
        if not declares:
            continue
        fields = set()
        for stmt in node.body:
            if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                fields.add(stmt.target.id)
            elif isinstance(stmt, ast.Assign):
                fields.update(t.id for t in stmt.targets if isinstance(t, ast.Name))
        # model_config / dunders are pydantic machinery, not user-facing fields.
        return {f for f in fields if f != "model_config" and not f.startswith("_")}
    return None


# A statically-extracted plugin argument. ``default`` is one of:
#   None                      -> required (no default), or default unknown
#   ("literal", value)        -> a literal default we could evaluate (e.g. 3, [], False)
#   ("src", "source text")    -> a non-literal default, kept as source (e.g. a factory)
# ``required`` is True when the field has no usable default. ``type`` is the
# annotation rendered back to source (e.g. "Optional[List[str]]"), or None.
ArgSpec = collections.namedtuple("ArgSpec", "name type default required description")


def _ast_field_default(node):
    """Classify a default-value AST node into the ``ArgSpec.default`` form."""
    try:
        return ("literal", ast.literal_eval(node))
    except (ValueError, SyntaxError, TypeError):
        return ("src", ast.unparse(node))


def _ast_is_field_call(node) -> bool:
    """True if ``node`` is a pydantic ``Field(...)`` call (``Field`` or ``x.Field``)."""
    return isinstance(node, ast.Call) and (
        (isinstance(node.func, ast.Name) and node.func.id == "Field")
        or (isinstance(node.func, ast.Attribute) and node.func.attr == "Field")
    )


def _ast_parse_field_call(call):
    """
    Extract ``(default, required, description)`` from a ``Field(...)`` call node.

    Mirrors pydantic's rules closely enough for docs: a positional first arg or a
    ``default=`` keyword sets the default (``...`` means required); ``default_factory``
    means not-required with a non-literal default; a bare ``Field()`` is required.
    """
    default = None
    required = False
    description = None
    has_default = has_factory = False

    if call.args:  # Field(<default>, ...)
        default_node = call.args[0]
        has_default = True
    else:
        default_node = None
    for kw in call.keywords:
        if kw.arg == "default":
            default_node = kw.value
            has_default = True
        elif kw.arg == "default_factory":
            has_factory = True
            factory_node = kw.value
        elif kw.arg == "description" and isinstance(kw.value, ast.Constant) \
                and isinstance(kw.value.value, str):
            description = kw.value.value

    if has_default:
        if isinstance(default_node, ast.Constant) and default_node.value is Ellipsis:
            required = True
        else:
            default = _ast_field_default(default_node)
    elif has_factory:
        # Not required; the value comes from a factory we can't evaluate statically.
        default = ("src", f"{ast.unparse(factory_node)}()")
    else:
        required = True  # bare Field() with no default is required
    return default, required, description


def _ast_arg_specs_from_classdef(node) -> List[ArgSpec]:
    """Build the list of :data:`ArgSpec` for an ``class Args(PluginArgs)`` node."""
    specs = []
    for stmt in node.body:
        if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            name = stmt.target.id
            annotation = stmt.annotation
            value = stmt.value
        elif isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 \
                and isinstance(stmt.targets[0], ast.Name):
            name = stmt.targets[0].id
            annotation = None
            value = stmt.value
        else:
            continue
        if name == "model_config" or name.startswith("_"):
            continue

        type_str = ast.unparse(annotation) if annotation is not None else None
        default = None
        required = False
        description = None
        if value is None:
            required = True  # annotation-only (`x: int`) -> required
        elif _ast_is_field_call(value):
            default, required, description = _ast_parse_field_call(value)
        elif isinstance(value, ast.Constant) and value.value is Ellipsis:
            required = True
        else:
            default = _ast_field_default(value)
        specs.append(ArgSpec(name, type_str, default, required, description))
    return specs


def _ast_find_args_classdef(tree):
    """Return the first ``class Args(PluginArgs)`` ClassDef node in ``tree``, or None."""
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ClassDef) and node.name == "Args"):
            continue
        if any(
            (isinstance(b, ast.Name) and b.id == "PluginArgs")
            or (isinstance(b, ast.Attribute) and b.attr == "PluginArgs")
            for b in node.bases
        ):
            return node
    return None


def plugin_declared_arg_specs(name: str, proj_dir: str,
                              plugin_path: str) -> Optional[List[ArgSpec]]:
    """
    Return the declared :data:`ArgSpec`s for plugin ``name`` via ``ast``, without
    importing it — the rich counterpart to :func:`plugin_declared_arg_fields`.

    Returns the (possibly empty) spec list if the plugin declares an ``Args``
    schema, else ``None`` (plugin not found, unparseable, or no ``Args``).
    """
    try:
        path, _ = find_plugin_by_name(name, proj_dir, plugin_path)
    except ValueError:
        return None
    try:
        with open(path, "r") as f:
            tree = ast.parse(f.read(), filename=path)
    except (OSError, SyntaxError):
        return None
    node = _ast_find_args_classdef(tree)
    return _ast_arg_specs_from_classdef(node) if node is not None else None


def discover_declaring_plugins_static(plugin_path: str
                                      ) -> Tuple[List[Tuple[str, List[ArgSpec]]], List[str]]:
    """
    Like :func:`discover_declaring_plugins`, but reads each plugin's declared
    ``Args`` via ``ast`` **without importing** — so runtime-dependent plugins
    (kernel-FFI enums, sibling imports, a live emulator) are covered too, exactly
    as config-load arg validation already does.

    :return: ``(found, skipped)`` where ``found`` is a sorted list of
        ``(config_name, [ArgSpec])`` and ``skipped`` lists files that failed to
        parse. Lower-fidelity than the imported model (types/defaults are rendered
        from source, not pydantic), but complete without a runtime.
    """
    found: List[Tuple[str, List[ArgSpec]]] = []
    skipped: List[str] = []
    for path in sorted(glob.glob(join(plugin_path, "**", "*.py"), recursive=True)):
        if "__pycache__" in path or basename(path).startswith("_"):
            continue
        try:
            with open(path, "r") as f:
                tree = ast.parse(f.read(), filename=path)
        except (OSError, SyntaxError):
            skipped.append(path)
            continue
        args_node = _ast_find_args_classdef(tree)
        if args_node is not None:
            found.append((splitext(basename(path))[0], _ast_arg_specs_from_classdef(args_node)))
    # De-dup by config name (first wins) and sort for stable output.
    seen = set()
    deduped = []
    for name, specs in sorted(found, key=lambda x: x[0]):
        if name in seen:
            continue
        seen.add(name)
        deduped.append((name, specs))
    return deduped, sorted(skipped)


def get_plugin_class(name: str, proj_dir: str, plugin_path: str) -> Optional[type]:
    """
    Resolve a plugin name to its ``Plugin`` subclass without instantiating it,
    or None if it cannot be discovered/imported. Best effort and side-effect
    tolerant: any failure returns None so callers never regress config load.
    """
    try:
        path, _ = find_plugin_by_name(name, proj_dir, plugin_path)
    except ValueError:
        return None
    try:
        with _plugin_root_on_path(plugin_path):
            classes = _import_plugin_classes(path)
    except Exception:
        return None
    # Prefer a class whose name matches the requested plugin; else the first.
    for cname, cls in classes:
        if cname.lower() == name.lower() or camel_to_snake(cname) == name.lower():
            return cls
    return classes[0][1] if classes else None


def get_plugin_args_model(name: str, proj_dir: str, plugin_path: str) -> Optional[Type[PluginArgs]]:
    """
    Return the declared ``Args`` model for plugin ``name``, or None if the plugin
    can't be found, can't be imported, or doesn't declare an ``Args`` schema.
    """
    cls = get_plugin_class(name, proj_dir, plugin_path)
    if cls is not None and cls.declares_args():
        return cls.__dict__["Args"]
    return None


def discover_declaring_plugins(plugin_path: str, manager=None, panda=None
                               ) -> Tuple[List[Tuple[str, Type[PluginArgs]]], List[str]]:
    """
    Walk ``plugin_path`` and return every plugin that declares an ``Args`` schema.

    :param manager: If given (the live ``plugins`` singleton from inside a real
        penguin process), imports run with the real runtime bound instead of the
        no-op stub, so plugins that read runtime state at import time (kernel-FFI
        enums via ``plugins.kffi``, etc.) resolve and aren't skipped. Pass it
        from the docgen plugin for full coverage; omit it for best-effort
        standalone enumeration.
    :param panda: The live emulator/panda object to bind alongside ``manager``.

    :return: ``(found, skipped)`` where ``found`` is a sorted list of
        ``(config_name, args_model)`` (``config_name`` is the file stem users put
        in ``plugins:``) and ``skipped`` is a sorted list of files that could not
        be imported. With ``manager`` unset, many runtime-dependent plugins land
        in ``skipped``.
    """
    found: List[Tuple[str, Type[PluginArgs]]] = []
    skipped: List[str] = []
    with _plugin_root_on_path(plugin_path):
        for path in sorted(glob.glob(join(plugin_path, "**", "*.py"), recursive=True)):
            if "__pycache__" in path or basename(path).startswith("_"):
                continue
            try:
                if manager is not None:
                    classes = _import_plugin_classes_live(path, manager, panda)
                else:
                    classes = _import_plugin_classes(path)
            except Exception:
                skipped.append(path)
                continue
            stem = splitext(basename(path))[0]
            for _cname, cls in classes:
                if cls.declares_args():
                    found.append((stem, cls.__dict__["Args"]))
    # De-dup by config name (first wins) and sort for stable output.
    seen = set()
    deduped = []
    for name, model in sorted(found, key=lambda x: x[0]):
        if name in seen:
            continue
        seen.add(name)
        deduped.append((name, model))
    return deduped, sorted(skipped)


class IGLOOPluginManager:
    """
    Singleton class that manages the loading, unloading, and interaction with plugins.

    Provides event registration, subscription, publishing, and plugin lifecycle management.
    """
    plugin_cbs: Dict[Plugin, Dict[str, List[Callable]]]
    registered_cbs: Dict[Tuple[Plugin, str], Callable]
    aliases: Dict[str, str]
    plugins: Dict[str, Plugin]

    def __new__(cls) -> 'IGLOOPluginManager':
        """
        Singleton pattern implementation.

        :return: The singleton instance of IGLOOPluginManager.
        :rtype: IGLOOPluginManager
        """
        if not hasattr(cls, 'instance'):
            cls.instance = super(IGLOOPluginManager, cls).__new__(cls)
        return cls.instance

    def initialize(self, panda: Any, args: Dict[str, Any]) -> None:
        """
        Initialize the plugin manager with an emulator compatibility object and arguments.

        :param panda: Emulator compatibility object exposed to plugins as self.panda.
        :type panda: Any
        :param args: Dictionary of arguments.
        :type args: Dict[str, Any]
        """
        self.panda = panda
        self.args = args
        self.logger = getColoredLogger("penguin.plugin_manger")

        self.plugin_cbs: Dict[Plugin, Dict[str, List[Callable]]] = {}
        self.registered_cbs: Dict[Tuple[Plugin, str], Callable] = {}
        self.aliases: Dict[str, str] = {}
        self.plugins: Dict[str, Plugin] = {}
        self._plugin_name_map: Dict[str, Plugin] = {}  # Lowercase name -> instance

    def load(self, pluginclasses: Union[Type[T], List[Type[T]], Tuple[str, List[str]]],
             args: Dict[str, Any] = None) -> None:
        """
        Load one or more plugin classes.

        :param pluginclasses: Plugin class(es) or (file, classnames) tuple.
        :type pluginclasses: Union[Type[T], List[Type[T]], Tuple[str, List[str]]]
        :param args: Arguments to pass to the plugins.
        :type args: Dict[str, Any], optional
        """
        if args is None:
            args = {}

        pluginpath = None
        if isinstance(pluginclasses, tuple):
            # Tuple: use self.load_plugin_class to load the requested classes from
            # the provided file
            pluginpath, clsnames = pluginclasses
            pluginclasses = self.load_plugin_class(pluginpath, clsnames)

        elif not isinstance(pluginclasses, list):
            # Single element: make it a list with one item
            pluginclasses = [pluginclasses]

        # This is a little tricky - we can't just instantiate
        # an instance of the object- it may use self.get_arg
        # in its init method. To allow this behavior, we create
        # the object, use the __preinit__ function defined above
        # and then ultimately call the __init__ method
        # See https://stackoverflow.com/a/6384982/2796854

        for pluginclass in pluginclasses:
            # If Plugin is in scope it should not be treated as a plugin
            if pluginclass is Plugin:
                continue
            elif isinstance(pluginclass, Plugin) or issubclass(pluginclass, Plugin):
                pass
            else:
                continue

            name = pluginclass.__name__

            self.plugins[name] = pluginclass.__new__(pluginclass)
            self.plugins[name].__preinit__(self, args)
            num_args = len(
                inspect.signature(
                    self.plugins[name].__init__).parameters)
            if num_args == 1:
                self.plugins[name].__init__(self.panda)
            else:
                self.plugins[name].__init__()
            self.plugins[name].load_time = datetime.datetime.now()
            # Update fast lookup map
            self._plugin_name_map[name.lower()] = self.plugins[name]
            # 5. Pre-cache attributes during load
            if not hasattr(self, name):
                setattr(self, name, self.plugins[name])
            if not hasattr(self, name.lower()):
                setattr(self, name.lower(), self.plugins[name])

    def load_plugin(self, plugin_name: str, extra_args: Dict[str, Any] = None) -> None:
        """
        Load a plugin by name.

        :param plugin_name: Name of the plugin to load.
        :type plugin_name: str

        :raises ValueError: If plugin loading fails.
        """
        if self.get_plugin_by_name(plugin_name):
            return

        # Check if the plugin is disabled explicitly before loading
        details = self.args["plugins"]
        plugin_args = details.get(plugin_name, {})

        if plugin_args.get("enabled", True) is False:
            self.logger.debug(f"Plugin {plugin_name} is disabled")
            return

        self.logger.debug(f"Loading plugin: {plugin_name}")
        path, local_plugin = find_plugin_by_name(
            plugin_name, self.args["proj_dir"], self.args["plugin_path"])

        args = dict(self.args)

        for k, v in plugin_args.items():
            # Extend the args with everything from the config that isn't in our
            # special args
            if k in ["enabled"]:
                continue
            if k in args.keys():
                if args[k] != v:
                    raise ValueError(
                        f"Config for {plugin_name} overwrites argument {k} {args[k]} -> {v}")
                continue
            self.logger.debug(f"Setting {plugin_name} arg: {k} to {v}")
            args[k] = v
        if extra_args:
            for k, v in extra_args.items():
                if k in args.keys():
                    if args[k] != v:
                        self.logger.error(
                            f"Extra arg for {plugin_name} overwrites argument {k} {args[k]} -> {v}")
                    continue
                self.logger.debug(f"Setting extra arg for {plugin_name}: {k} to {v}")
                args[k] = v
        try:
            plugins_loaded = self.load_all(path, args)
        except SyntaxError as e:
            self.logger.error(f"Syntax error loading pyplugin: {e}")
            raise ValueError(f"Failed to load plugin: {plugin_name}") from e
        if len(plugins_loaded) == 0:
            with open(join(self.args["outdir"], "plugin_errors.txt"), "a") as f:
                f.write(f"Failed to load plugin: {plugin_name}")
            raise ValueError(f"Failed to load plugin: {plugin_name}")
        if len(plugins_loaded) == 1:
            # If the plugin name is different from the file name, add an alias
            loaded_plugin_name = plugins_loaded[0]
            base_fname = splitext(basename(path))[0]
            if base_fname != loaded_plugin_name:
                self.aliases[base_fname] = loaded_plugin_name
        if local_plugin:
            shutil.copy2(path, self.args["outdir"])

    def load_plugins(self, conf_plugins: List[str]) -> None:
        """
        Load multiple plugins from a list of names.

        :param conf_plugins: List of plugin names to load.
        :type conf_plugins: List[str]
        """
        for plugin in conf_plugins:
            self.load_plugin(plugin)

    def get_plugin_by_name(self, plugin_name: str) -> Union[Plugin, None]:
        """
        Retrieve a loaded plugin by name.

        :param plugin_name: Name of the plugin.
        :type plugin_name: str

        :return: The plugin instance if found, else None.
        :rtype: Plugin or None
        """
        # Resolve alias if present
        if plugin_name in self.aliases:
            plugin_name = self.aliases[plugin_name]
        # Fast lookup using lowercased name
        return self._plugin_name_map.get(plugin_name.lower(), None)

    def __contains__(self, plugin: str) -> bool:
        """
        Check if a plugin is loaded by name.

        :param plugin: Plugin name.
        :type plugin: str

        :return: True if loaded, False otherwise.
        :rtype: bool
        """
        return self.get_plugin_by_name(plugin) is not None

    def __getitem__(self, plugin: str) -> Plugin:
        """
        Get a plugin by name, loading it if necessary.

        :param plugin: Plugin name.
        :type plugin: str

        :return: The plugin instance.
        :rtype: Plugin
        """
        if not self.get_plugin_by_name(plugin):
            self.load_plugin(plugin)
        return self.get_plugin_by_name(plugin)

    def __getattr__(self, plugin: str) -> Plugin:
        """
        Attribute access for plugins by name or class name.

        :param plugin: Plugin name or class name.
        :type plugin: str

        :return: The plugin instance.
        :rtype: Plugin
        """
        # First try by plugin name (existing behavior)
        p = self.get_plugin_by_name(plugin)
        if p:
            setattr(self, plugin, p)
            return p
        try:
            self.load_plugin(plugin)
            p = self.get_plugin_by_name(plugin)
            if p:
                setattr(self, plugin, p)
                return p
        except ValueError:
            pass

        # Then try by class name - search through all plugins
        for plugin_name, plugin_instance in self.plugins.items():
            if plugin_instance.__class__.__name__ == plugin:
                return plugin_instance

        # If not found by either method, try to load it
        return self[plugin]

    def load_all(self, plugin_file: str,
                 args: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Load all Plugin classes from a Python file. If no Plugin classes are found, load as ScriptingPlugin.

        :param plugin_file: Path to the Python file.
        :type plugin_file: str
        :param args: Arguments to pass to the Plugin.
        :type args: Optional[Dict[str, Any]]

        :return: List of Plugin class names loaded from the file.
        :rtype: List[str]

        :raises ValueError: If the plugin file cannot be loaded.
        """
        spec = importlib.util.spec_from_file_location(
            "plugin_file", plugin_file)
        if spec is None:
            # Likely an invalid path
            raise ValueError(f"Unable to load {plugin_file}")

        module = importlib.util.module_from_spec(spec)
        # Prepare a logger for the script/module
        script_logger = getColoredLogger(f"plugins.{camel_to_snake(basename(plugin_file).split('.')[0])}")
        module.__dict__.update({
            "plugins": self,
            "logger": script_logger,
            "panda": self.panda,
            "args": ArgsBox(args or {}),
        })
        spec.loader.exec_module(module)

        names = []
        plugin_classes = []
        for name, cls in inspect.getmembers(
                module, lambda x: inspect.isclass(x)):
            if not issubclass(cls, Plugin) or cls == Plugin:
                continue
            # Imported base classes (e.g. InitPlugin) are not plugins of this file
            if cls.__name__ == "InitPlugin" and cls.__module__ == "penguin.init_plugin":
                continue
            plugin_classes.append((name, cls))

        if not plugin_classes:
            # No Plugin classes found, load as ScriptingPlugin
            name = basename(plugin_file).split('.')[0]
            DynamicScriptingPlugin = type(
                name,
                (ScriptingPlugin,),
                {"script": plugin_file}
            )
            plugin_classes.append((name, DynamicScriptingPlugin))

        for name, cls in plugin_classes:
            cls.__name__ = name
            self.load(cls, args)
            names.append(name)

            # Create alias from class name to plugin instance for method
            # resolution
            if name in self.plugins:
                class_name = cls.__name__
                plugin_instance_name = name
                if class_name != plugin_instance_name:
                    self.aliases[class_name] = plugin_instance_name
                # Update fast lookup map for alias
                self._plugin_name_map[class_name.lower()] = self.plugins[name]
        return names

    def unload(self, pluginclass: Union[Type[Plugin], str]) -> None:
        """
        Unload a plugin by class or name.

        :param pluginclass: Plugin class or name.
        :type pluginclass: Union[Type[Plugin], str]

        :raises ValueError: If the argument is not a loaded plugin.
        """
        if isinstance(pluginclass, str) and pluginclass in self.plugins:
            pluginclass = self.plugins[pluginclass]

        if not issubclass(type(pluginclass), Plugin):
            raise ValueError(
                f"Unload expects a name of a loaded pyplugin or a Plugin instance. Got {pluginclass} with plugin list: {self.plugins}")

        # Call uninit method if it's present
        if callable(getattr(pluginclass, "uninit", None)):
            pluginclass.uninit()

    def unload_all(self) -> None:
        """
        Unload all loaded plugins in reverse order of load time.
        """
        # unload in reverse order of load time
        plugin_list = {
            k: v for k,
            v in sorted(
                self.plugins.items(),
                key=lambda x: x[1].load_time)}
        while plugin_list:
            name, cls = plugin_list.popitem()
            self.unload(cls)

    def register(self, plugin: Plugin, event: str,
                 register_notify: Callable[[str, Callable[..., None]], None] = None) -> None:
        """
        Register a plugin event for callbacks.

        :param plugin: The plugin instance.
        :type plugin: Plugin
        :param event: Event name.
        :type event: str
        :param register_notify: Optional callback for registration notification.
        :type register_notify: Callable, optional
        """
        self.plugin_cbs[plugin] = self.plugin_cbs.get(plugin, {})
        self.plugin_cbs[plugin][event] = self.plugin_cbs[plugin].get(event, [])
        if register_notify is not None:
            self.registered_cbs[(plugin, event)] = register_notify

    def subscribe(self, plugin: Plugin, event: str,
                  callback: Callable[..., None] = None) -> Callable | None:
        """
        Subscribe a callback to a plugin event. Can also be used as a decorator if callback is not provided.

        :param plugin: The plugin instance.
        :type plugin: Plugin
        :param event: Event name.
        :type event: str
        :param callback: Callback function.
        :type callback: Callable, optional

        Usage::

            @plugins.subscribe(plugin, "event_name")
            def handler(...):
                ...

            # or

            plugins.subscribe(plugin, "event_name", handler)
        """
        if callback is None:
            def decorator(cb):
                if plugin not in self.plugin_cbs:
                    raise Exception(
                        f"Attempt to subscribe to unregistered plugin: {plugin}")
                elif event not in self.plugin_cbs[plugin]:
                    raise Exception(
                        f"Attempt to subscribe to unregistered event: {event} for plugin {plugin}")
                self.plugin_cbs[plugin][event].append(cb)
                if (plugin, event) in self.registered_cbs:
                    self.registered_cbs[(plugin, event)](event, cb)
                return cb
            return decorator

        if plugin not in self.plugin_cbs:
            raise Exception(
                f"Attempt to subscribe to unregistered plugin: {plugin}")
        elif event not in self.plugin_cbs[plugin]:
            raise Exception(
                f"Attempt to subscribe to unregistered event: {event} for plugin {plugin}")
        self.plugin_cbs[plugin][event].append(callback)

        if (plugin, event) in self.registered_cbs:
            self.registered_cbs[(plugin, event)](event, callback)

    def publish(self, plugin: Plugin, event: str, *args: Any, **kwargs: Any) -> None:
        """
        Publish an event to all registered callbacks for a plugin event.

        :param plugin: The plugin instance.
        :type plugin: Plugin
        :param event: Event name.
        :type event: str
        :param args: Positional arguments for callbacks.
        :param kwargs: Keyword arguments for callbacks.
        """
        if plugin not in self.plugin_cbs:
            raise Exception(
                f"Attempt to publish to unregistered plugin: {plugin}")
        elif event not in self.plugin_cbs[plugin]:
            raise Exception(
                f"Attempt to publish to unregistered event: {event} for plugin {plugin}")
        for cb in self.plugin_cbs[plugin][event]:
            # Handle unbound method: cb is a function, but its __qualname__
            # contains a dot
            if not hasattr(cb, '__self__') and hasattr(cb, '__qualname__') and '.' in cb.__qualname__:
                cb = resolve_bound_method_from_class(cb, manager=self)
            cb(*args, **kwargs)

    def portal_publish(self, plugin: Plugin, event: str, *args: Any, **kwargs: Any) -> Iterator:
        """
        Publish an event to all registered callbacks for a plugin event, handling generators properly.

        :param plugin: The plugin instance.
        :type plugin: Plugin
        :param event: Event name.
        :type event: str
        :param args: Positional arguments for callbacks.
        :param kwargs: Keyword arguments for callbacks.
        """
        if plugin not in self.plugin_cbs:
            raise Exception(
                f"Attempt to publish to unregistered plugin: {plugin}")
        elif event not in self.plugin_cbs[plugin]:
            raise Exception(
                f"Attempt to publish to unregistered event: {event} for plugin {plugin}")

        for cb in self.plugin_cbs[plugin][event]:
            if not hasattr(cb, '__self__') and hasattr(cb, '__qualname__') and '.' in cb.__qualname__:
                cb = resolve_bound_method_from_class(cb, manager=self)
            result = cb(*args, **kwargs)
            if isinstance(result, Iterator):
                yield from result
            # For non-generator callbacks, we don't need to do anything with
            # the result

    @property
    def resources(self) -> str:
        """
        Returns the path to the plugin resources directory.

        :return: Path to the resources directory.
        :rtype: str
        """
        return join(self.args["plugin_path"], "resources")

    def get_arg(self, arg_name: str) -> Any:
        """
        Get an argument value by name.

        :param arg_name: The argument name.
        :type arg_name: str

        :return: The argument value or None if not set.
        :rtype: Any
        """
        if arg_name in self.args:
            return self.args[arg_name]

        return None

    def get_arg_bool(self, arg_name: str, default: bool = False) -> bool:
        """
        Returns True if the argument is set and has a truthy value.

        :param arg_name: The name of the argument to retrieve.
        :type arg_name: str

        :param default: The default value to return if the argument is not set.
        :type arg_name: bool

        :return: True if the argument exists and has a truthy value, False otherwise.
        :rtype: bool

        :raises ValueError: If the argument exists but has an unsupported type.
        """
        if arg_name not in self.args:
            return default
        if (x := interpret_bool(self.args[arg_name])) is not None:
            return x

        raise ValueError(f"Unsupported arg type: {type(self.args[arg_name])}")


# singleton pattern for the plugin manager
plugins: IGLOOPluginManager = IGLOOPluginManager()
