"""
penguin.init_runner
===================

Executes init plugins (see :mod:`penguin.init_plugin`) to produce a project's
static analysis results and config patches.

Execution model:

- all selected plugin classes are loaded up-front (serially, on the calling
  thread) through the IGLOO plugin manager with ``panda=None``;
- every plugin's work (``patch()`` + ``static_result()``) is submitted to a
  thread pool; shared analyses are lazy ``cached_analysis`` attributes, so
  cross-plugin data dependencies serialize naturally on first access;
- plugins with ``consumes_patches = True`` run afterwards, sequentially in
  ``(order, patch_name)`` order, with ``ctx.patches_snapshot()`` available;
- the rendered ``patches:`` list order is ``(order, patch_name)`` — stable and
  independent of execution timing, because later patches override earlier ones
  when the config is loaded.

Failure model: no individual plugin failure stops config generation. An
exception is logged, recorded in ``static/manifest.yaml``, and the run
continues without that plugin's outputs; a failed cached analysis fails every
plugin that consumes it (each recorded the same way). A summary of failures is
logged at the end of the run.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import lzma
import os
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

import yaml

from penguin import getColoredLogger

from .init_plugin import InitContext, InitPlugin

logger = getColoredLogger("penguin.init_runner")

MANIFEST_NAME = "manifest.yaml"


def _norm_name(name: str) -> str:
    """Normalize a plugin name for CLI matching: ArchId == arch_id == archid."""
    return name.lower().replace("_", "")


def discover_init_plugins(
    search_dirs,
    disable=(),
) -> List[Type[InitPlugin]]:
    """
    Find InitPlugin subclasses in .py files under the given directories
    (searched recursively, in order — a class found in a later directory
    shadows a same-named class from an earlier one, so project-local plugins
    override built-ins).

    Files are imported via the introspection path (no live plugin manager
    needed); only classes *defined* in each file are considered, so imported
    bases like InitPlugin are ignored. A file that fails to import is skipped
    with a warning rather than aborting init.

    :param search_dirs: directories to scan, lowest to highest precedence.
    :param disable: plugin class names to exclude (case/underscore-insensitive).
    :return: plugin classes sorted by class name.
    """
    from .plugin_manager import _import_plugin_classes

    found: Dict[str, tuple] = {}  # class name -> (cls, source file)
    for d in search_dirs:
        d = Path(d)
        if not d.is_dir():
            continue
        for f in sorted(d.rglob("*.py")):
            if f.name == "__init__.py" or f.name.startswith("."):
                continue
            try:
                classes = _import_plugin_classes(str(f))
            except Exception as e:  # noqa: BLE001 - a broken file shouldn't kill init
                logger.warning(f"Failed to import init plugin file {f}: {e}")
                continue
            for name, cls in classes:
                if not issubclass(cls, InitPlugin) or cls is InitPlugin:
                    continue
                if cls.__module__ != "plugin_introspect":
                    # Imported into the file, not defined in it
                    continue
                if name in found and found[name][1] != str(f):
                    logger.info(
                        f"Init plugin {name} from {f} shadows the one from {found[name][1]}"
                    )
                found[name] = (cls, str(f))

    disabled = {_norm_name(x) for x in disable}
    result = []
    for name in sorted(found):
        cls, src = found[name]
        if _norm_name(name) in disabled:
            logger.info(f"Init plugin {name} disabled")
            continue
        result.append(cls)
    return result


def _to_plain(data):
    """Recursively convert defaultdicts (and friends) to plain dicts for YAML."""
    if isinstance(data, dict):
        return {k: _to_plain(v) for k, v in data.items()}
    if isinstance(data, (list, tuple)):
        return [_to_plain(v) for v in data]
    return data


def _is_empty_patch(data) -> bool:
    """Mirror the historic render_patches skip logic: drop patches with no
    content so we don't write empty files."""
    if data is None:
        return True
    if isinstance(data, dict):
        return not data or all(not v for v in data.values())
    if isinstance(data, list):
        return len(data) == 0
    return False


class InitPluginRunner:
    """
    Run a set of init plugin classes against an extracted filesystem.

    :param plugin_classes: InitPlugin subclasses to run.
    :param ctx: shared :class:`InitContext`.
    :param manager: plugin manager to load through (defaults to the
        process-wide singleton).
    :param jobs: thread pool size (defaults to ``os.cpu_count()``).
    """

    def __init__(
        self,
        plugin_classes: List[Type[InitPlugin]],
        ctx: InitContext,
        manager=None,
        jobs: Optional[int] = None,
        skip=(),
    ) -> None:
        """
        :param skip: plugin names whose patch()/static_result() should NOT be
            executed. The plugins are still loaded, so their cached analyses
            remain available to (and are computed on demand by) selected
            plugins; their existing on-disk outputs are left untouched.
        """
        if manager is None:
            from .plugin_manager import plugins as default_manager
            manager = default_manager
        self.manager = manager
        self.classes = list(plugin_classes)
        self.ctx = ctx
        self.jobs = jobs or os.cpu_count() or 4
        self.skip = {_norm_name(s) for s in skip}
        self.manifest: Dict[str, dict] = {}
        self._manifest_lock = threading.Lock()
        # patch_name -> plugin name, filled as patches are collected
        self._patch_owner: Dict[str, str] = {}

    # ----- loading ----------------------------------------------------------

    def load_plugins(self, extra_args: Optional[Dict[str, Any]] = None) -> List[InitPlugin]:
        """Initialize the manager (panda=None) and load every plugin class.
        Returns the loaded instances in input order."""
        args: Dict[str, Any] = {
            "plugins": {},
            "conf": {},
            "proj_dir": str(self.ctx.proj_dir),
            "outdir": str(self.ctx.proj_dir),
            "plugin_path": self.ctx.options.get("plugin_path", ""),
            "verbose": self.ctx.options.get("verbose", False),
        }
        if extra_args:
            args.update(extra_args)

        self.manager.initialize(None, args)

        force_enable = {_norm_name(x) for x in self.ctx.options.get("enable", ())}

        instances = []
        for cls in self.classes:
            self.manager.load(cls, args)
            inst = self.manager.plugins[cls.__name__]
            inst.ctx = self.ctx
            if _norm_name(inst.name) in force_enable:
                inst.enabled = True
            instances.append(inst)
        return instances

    # ----- execution --------------------------------------------------------

    def run(self) -> Dict[str, tuple]:
        """
        Execute all plugins and return ``{patch_name: (patch_dict, enabled)}``
        ordered by ``(order, patch_name)``. Persists static results, patch
        files, and the manifest as a side effect.
        """
        instances = self.load_plugins()
        selected = [p for p in instances if _norm_name(p.name) not in self.skip]

        main_phase = [p for p in selected if not p.consumes_patches]
        post_phase = sorted(
            (p for p in selected if p.consumes_patches),
            key=lambda p: (p.order, p.patch_name or "", p.name),
        )

        results: Dict[str, dict] = {}  # plugin name -> {"patch": ..., "static": ...}

        with ThreadPoolExecutor(max_workers=self.jobs) as pool:
            futures = {pool.submit(self._run_plugin, p): p for p in main_phase}
            for fut, plugin in futures.items():
                results[plugin.name] = fut.result()  # _run_plugin never raises

        patches = self._collect_patches(main_phase, results)

        # Post phase: sequential, in render order, each seeing all prior patches
        self.ctx._patches = patches
        for plugin in post_phase:
            outcome = self._run_plugin(plugin)
            results[plugin.name] = outcome
            self._merge_patch(patches, plugin, outcome)
        self.ctx._patches = None

        # Deterministic render order, independent of completion order
        ordered = dict(
            sorted(patches.items(), key=lambda kv: (kv[1][2], kv[0]))
        )
        # Strip the order component before handing back (data, enabled)
        ordered = {k: (v[0], v[1]) for k, v in ordered.items()}

        self._write_manifest()
        self._log_failures()
        self._log_timings()
        return ordered

    def _log_failures(self) -> None:
        """One prominent end-of-run summary; details live in the manifest."""
        failed = sorted(
            name for name, e in self.manifest.items() if e.get("status") == "failed"
        )
        if failed:
            logger.error(
                f"{len(failed)} init plugin(s) failed and were skipped: "
                f"{', '.join(failed)} (details in static/{MANIFEST_NAME})"
            )

    def _log_timings(self) -> None:
        """Per-plugin durations, slowest first (visible with --verbose)."""
        timed = sorted(
            ((e.get("duration", 0), name) for name, e in self.manifest.items()),
            reverse=True,
        )
        total = sum(d for d, _ in timed)
        logger.debug(f"init plugin durations (sum {total:.2f}s of work):")
        for duration, name in timed:
            logger.debug(f"  {duration:8.3f}s  {name}")

    def _collect_patches(self, plugins_run, results) -> Dict[str, tuple]:
        """Build {patch_name: (data, enabled, order)} from main-phase results,
        in (order, name) order so post-phase consumers see a stable view."""
        patches: Dict[str, tuple] = {}
        for plugin in sorted(
            plugins_run, key=lambda p: (p.order, p.patch_name or "", p.name)
        ):
            outcome = results.get(plugin.name) or {}
            self._merge_patch(patches, plugin, outcome)
        return patches

    def _merge_patch(self, patches: Dict[str, tuple], plugin: InitPlugin, outcome: dict) -> None:
        data = outcome.get("patch")
        if plugin.patch_name and data:
            patches[plugin.patch_name] = (data, plugin.enabled, plugin.order)
            self._patch_owner[plugin.patch_name] = plugin.name
            if not plugin.enabled:
                logger.info(f"{plugin.patch_name} patch generated but disabled")

    def _run_plugin(self, plugin: InitPlugin) -> dict:
        """Run one plugin's static_result() and patch(). Returns an outcome
        dict; exceptions are captured, never raised."""
        entry = {
            "source": self._source_of(plugin),
            "patch_name": plugin.patch_name,
            "order": plugin.order,
            "status": "ok",
        }
        outcome: dict = {"patch": None, "static": None, "error": None}
        start = time.monotonic()
        try:
            outcome["static"] = plugin.static_result()
            if outcome["static"]:
                entry["static_file"] = self._persist_static(plugin, outcome["static"])
            outcome["patch"] = plugin.patch(self.ctx)
        except Exception as e:  # noqa: BLE001 - no plugin failure stops init
            outcome["error"] = e
            entry["status"] = "failed"
            entry["error"] = f"{type(e).__name__}: {e}"
            logger.error(f"init plugin {plugin.name} failed (continuing without it): {e}")
        finally:
            entry["duration"] = round(time.monotonic() - start, 4)
            entry["enabled"] = plugin.enabled
            with self._manifest_lock:
                self.manifest[plugin.name] = entry
        return outcome

    @staticmethod
    def _source_of(plugin: InitPlugin) -> Optional[str]:
        try:
            return inspect.getfile(type(plugin))
        except (TypeError, OSError):
            return None

    # ----- persistence ------------------------------------------------------

    def _persist_static(self, plugin: InitPlugin, data: Any) -> str:
        """Write one plugin's static result; returns the file name written."""
        self.ctx.static_dir.mkdir(exist_ok=True, parents=True)
        if plugin.serializer == "json_xz":
            path = self.ctx.static_dir / f"{plugin.name}.json.xz"
            with lzma.open(path, "wt", encoding="utf-8") as f:
                json.dump(data, f)
        else:
            path = self.ctx.static_dir / f"{plugin.name}.yaml"
            with open(path, "w") as f:
                yaml.dump(_to_plain(data), f)
        return path.name

    def render_patches(
        self,
        patches: Dict[str, tuple],
        previous_manifest: Optional[Dict[str, dict]] = None,
    ) -> Dict[str, list]:
        """
        Write non-empty patches to ``patch_dir/<name>.yaml`` (including
        disabled ones, matching historic behavior).

        When ``previous_manifest`` is given (refresh), a patch file whose
        on-disk content no longer matches the hash penguin recorded when it
        generated it is treated as user-edited: it is preserved and the new
        content is written next to it as ``<name>.yaml.new``.

        Returns ``{"written": [...], "preserved": [...]}`` patch names.
        """
        prev_hashes = {}
        for entry in (previous_manifest or {}).values():
            if entry.get("patch_file") and entry.get("patch_sha256"):
                prev_hashes[entry["patch_file"]] = entry["patch_sha256"]

        self.ctx.patch_dir.mkdir(exist_ok=True, parents=True)
        outcome = {"written": [], "preserved": []}
        for name, (data, _enabled) in patches.items():
            plain = _to_plain(data)
            if _is_empty_patch(plain):
                continue
            fname = f"{name}.yaml"
            target = self.ctx.patch_dir / fname
            if previous_manifest is not None and target.exists():
                recorded = prev_hashes.get(fname)
                current = _sha256_file(target)
                if recorded is not None and recorded != current:
                    logger.warning(
                        f"{target} was edited since penguin generated it; "
                        f"writing new content to {fname}.new instead"
                    )
                    target = self.ctx.patch_dir / f"{fname}.new"
                    outcome["preserved"].append(name)
                elif recorded is None:
                    logger.warning(
                        f"No generation record for {fname} (pre-migration "
                        "project?); overwriting"
                    )
            with open(target, "w") as f:
                yaml.dump(plain, f, default_flow_style=False)
            if target.name == fname:
                outcome["written"].append(name)
            # Record ownership so future refreshes can detect user edits
            owner = self._patch_owner.get(name)
            if owner and owner in self.manifest:
                self.manifest[owner]["patch_file"] = fname
                self.manifest[owner]["patch_sha256"] = _sha256_file(
                    self.ctx.patch_dir / fname
                ) if (self.ctx.patch_dir / fname).exists() else None
        self._write_manifest()
        return outcome

    def merge_previous_manifest(self, previous: Dict[str, dict]) -> None:
        """Carry forward manifest entries for plugins that did not run this
        time (refresh with a skip set)."""
        for name, entry in previous.items():
            self.manifest.setdefault(name, entry)

    def _write_manifest(self) -> None:
        self.ctx.static_dir.mkdir(exist_ok=True, parents=True)
        with open(self.ctx.static_dir / MANIFEST_NAME, "w") as f:
            yaml.dump({"plugins": _to_plain(self.manifest)}, f)


def load_manifest(static_dir: str | Path) -> Dict[str, dict]:
    """Read static/manifest.yaml; empty dict if absent or unreadable."""
    path = Path(static_dir, MANIFEST_NAME)
    if not path.is_file():
        return {}
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        return data.get("plugins", {}) or {}
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Could not read {path}: {e}")
        return {}


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()
