"""
penguin.init_plugin
===================

Base class and helpers for init-time (config generation) plugins.

Init plugins run during ``penguin init`` (and ``penguin refresh``), before any
emulation exists, inside the fakeroot config-generation subprocess. They are
ordinary pyplugins (subclasses of :class:`penguin.plugin_manager.Plugin`) with
``panda=None``, so they get the plugin manager, logging, args, and inter-plugin
access (``self.plugins.X``) for free.

An init plugin can do either or both of:

- expose shared analysis results as :func:`cached_analysis` methods, computed
  lazily and exactly once no matter how many other plugins (or threads) access
  them, e.g. ``self.plugins.ArchId.arch``;
- produce a config patch by setting ``patch_name`` and implementing
  :meth:`InitPlugin.patch`, rendered to ``<proj>/static_patches/<patch_name>.yaml``.

Plugins run concurrently. There is no declared dependency graph: a plugin that
touches another plugin's cached analysis simply blocks until it is computed.
Circular accesses raise ``InitAnalysisCycleError`` instead of deadlocking.
"""

from __future__ import annotations

import os
import tarfile
import threading
from pathlib import Path
from typing import Any, ClassVar, Dict, NamedTuple, Optional

from .plugin_manager import Plugin

# Default patch-render position for plugins that don't set one. Built-in
# penguin patches use 10..990; user plugins default to rendering after (and
# therefore overriding) all built-ins.
DEFAULT_ORDER = 1000


class InitAnalysisCycleError(RuntimeError):
    """Raised when cached analyses circularly depend on each other."""


class _AnalysisState:
    __slots__ = ("lock", "done", "value", "exc")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.done = False
        self.value = None
        self.exc: Optional[BaseException] = None


# Global wait-for bookkeeping for deadlock detection across threads.
# _computing maps an analysis key to the thread currently computing it;
# _waiting_on maps a thread to the analysis key it is blocked on.
_dep_lock = threading.Lock()
_computing: Dict[int, threading.Thread] = {}
_waiting_on: Dict[threading.Thread, int] = {}


class cached_analysis:
    """
    Descriptor: thread-safe, compute-once property for shared analysis results.

    The first accessor computes the value on its own thread; concurrent
    accessors block until it is ready. A circular access — directly re-entrant
    or through a chain of plugins across threads — raises
    :class:`InitAnalysisCycleError` instead of deadlocking. Exceptions are
    cached and re-raised for every subsequent accessor so a failed analysis
    fails all of its consumers consistently.

    Usage::

        class ArchId(InitPlugin):
            @cached_analysis
            def arch(self) -> str:
                ...  # expensive, runs once
    """

    def __init__(self, func) -> None:
        self.func = func
        self.attrname: Optional[str] = None
        self.__doc__ = func.__doc__

    def __set_name__(self, owner, name: str) -> None:
        self.attrname = name

    def _state(self, instance) -> _AnalysisState:
        with _dep_lock:
            states = instance.__dict__.setdefault("_cached_analysis_states", {})
            state = states.get(self.attrname)
            if state is None:
                state = states[self.attrname] = _AnalysisState()
            return state

    def _check_deadlock(self, key: int, instance) -> None:
        """While holding _dep_lock, walk the wait-for graph from key; raise if
        it leads back to the current thread."""
        cur = threading.current_thread()
        k = key
        seen = set()
        while k is not None and k not in seen:
            seen.add(k)
            t = _computing.get(k)
            if t is None:
                return
            if t is cur:
                raise InitAnalysisCycleError(
                    f"analysis cycle detected while computing "
                    f"{type(instance).__name__}.{self.attrname}"
                )
            k = _waiting_on.get(t)

    def __get__(self, instance, owner=None):
        if instance is None:
            return self
        state = self._state(instance)

        if state.done:
            if state.exc is not None:
                raise state.exc
            return state.value

        key = id(state)
        cur = threading.current_thread()
        with _dep_lock:
            self._check_deadlock(key, instance)
            _waiting_on[cur] = key
        try:
            with state.lock:
                if not state.done:
                    with _dep_lock:
                        _computing[key] = cur
                        # No longer blocked - we're the one computing now
                        _waiting_on.pop(cur, None)
                    try:
                        state.value = self.func(instance)
                    except BaseException as e:  # noqa: BLE001 - cache and re-raise
                        state.exc = e
                    finally:
                        state.done = True
                        with _dep_lock:
                            _computing.pop(key, None)
        finally:
            with _dep_lock:
                _waiting_on.pop(cur, None)

        if state.exc is not None:
            raise state.exc
        return state.value


class FileEntry(NamedTuple):
    """One file from the extracted filesystem, as seen by os.walk."""

    path: str        # absolute path in the extracted tree
    rel: str         # path relative to the fs root, with a leading /
    name: str        # basename
    is_file: bool    # regular file (after following symlinks)
    is_symlink: bool
    executable: bool


class FileIndex:
    """
    A single os.walk pass over the extracted filesystem, shared by all init
    plugins via ``ctx.file_index`` so each doesn't re-walk (and re-stat) the
    whole tree. Semantics match the walks it replaces: only file entries (no
    directories), symlinks not followed into.
    """

    def __init__(self, root: str | Path) -> None:
        self.root = str(root)
        entries = []
        for r, _dirs, files in os.walk(self.root):
            for fn in files:
                p = os.path.join(r, fn)
                entries.append(FileEntry(
                    path=p,
                    rel="/" + os.path.relpath(p, self.root),
                    name=fn,
                    is_file=os.path.isfile(p),
                    is_symlink=os.path.islink(p),
                    executable=os.access(p, os.X_OK),
                ))
        self.entries = entries

    def files(self):
        """Regular files (symlink targets resolved)."""
        return (e for e in self.entries if e.is_file)

    def executables(self):
        return (e for e in self.entries if e.is_file and e.executable)


class InitContext:
    """
    Shared, read-mostly context handed to every init plugin.

    :ivar fs_archive: path to the project's ``base/fs.tar.gz``
    :ivar extracted_fs: directory the filesystem is extracted into (temporary,
        removed after the run)
    :ivar proj_dir: the project directory results are written into
    :ivar static_dir: ``proj_dir/static`` (analysis results)
    :ivar patch_dir: ``proj_dir/static_patches`` (rendered patches)
    :ivar options: CLI/runner options (free-form dict)
    """

    def __init__(
        self,
        fs_archive: str | Path,
        extracted_fs: str | Path,
        proj_dir: str | Path,
        static_dir: str | Path,
        patch_dir: str | Path,
        options: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.fs_archive = Path(fs_archive)
        self.extracted_fs = Path(extracted_fs)
        self.proj_dir = Path(proj_dir)
        self.static_dir = Path(static_dir)
        self.patch_dir = Path(patch_dir)
        self.options: Dict[str, Any] = options or {}

        self._archive_files = None
        self._archive_lock = threading.Lock()
        self._file_index: Optional[FileIndex] = None
        self._file_index_lock = threading.Lock()
        self._patches: Optional[Dict[str, tuple]] = None

    @property
    def archive_files(self) -> list:
        """All tar members of :attr:`fs_archive`, read once and shared."""
        with self._archive_lock:
            if self._archive_files is None:
                with tarfile.open(self.fs_archive) as tar:
                    self._archive_files = tar.getmembers()
            return self._archive_files

    @property
    def file_index(self) -> FileIndex:
        """A shared one-pass :class:`FileIndex` over :attr:`extracted_fs`."""
        with self._file_index_lock:
            if self._file_index is None:
                self._file_index = FileIndex(self.extracted_fs)
            return self._file_index

    def patches_snapshot(self) -> Dict[str, tuple]:
        """
        The accumulated ``{patch_name: (patch_dict, enabled)}`` map.

        Only available to plugins with ``consumes_patches = True`` (they run in
        a post phase after all other patches are generated).
        """
        if self._patches is None:
            raise RuntimeError(
                "patches_snapshot() is only available to plugins with "
                "consumes_patches = True"
            )
        return {k: (v[0], v[1]) for k, v in self._patches.items()}


class InitPlugin(Plugin):
    """
    Base class for init-time plugins.

    Class attributes:

    - ``patch_name``: set to produce a patch file (``static_patches/<patch_name>.yaml``).
    - ``order``: position of this plugin's patch in the generated config's
      ``patches:`` list. Later patches override earlier ones on conflicting
      keys. Built-ins use 10..990; the default (1000) renders user patches
      after all built-ins.
    - ``fatal``: if True, an exception from this plugin aborts config
      generation entirely (e.g. unknown architecture).
    - ``consumes_patches``: if True, run in a post phase after all other
      patches are generated; ``ctx.patches_snapshot()`` becomes available.
    - ``serializer``: how :meth:`static_result` is persisted under
      ``static/<ClassName>.*`` — ``"yaml"`` (default) or ``"json_xz"``.

    Instances may set ``self.enabled = False`` (e.g. in ``__init__`` or
    ``patch()``) to generate their patch file but leave it out of the config's
    ``patches:`` list.

    The runner assigns ``self.ctx`` (an :class:`InitContext`) to every loaded
    init plugin before execution starts, so cached analyses can use it too.
    """

    patch_name: ClassVar[Optional[str]] = None
    order: ClassVar[int] = DEFAULT_ORDER
    fatal: ClassVar[bool] = False
    consumes_patches: ClassVar[bool] = False
    serializer: ClassVar[str] = "yaml"

    enabled: bool = True
    ctx: InitContext  # assigned by InitPluginRunner before execution

    def patch(self, ctx: InitContext) -> Optional[dict]:
        """
        Produce this plugin's config patch as a dict (or None/empty for no
        patch). Only meaningful if ``patch_name`` is set.
        """
        return None

    def static_result(self) -> Any:
        """
        Analysis result to persist to ``static/<ClassName>.yaml`` (or
        ``.json.xz``). Return None (default) to persist nothing.
        """
        return None
