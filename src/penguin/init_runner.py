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

Failure model: an exception from a ``fatal`` plugin (or one of its analyses)
aborts the run by re-raising it (``penguin.gen_config.main`` turns that into
the project's ``result`` file). Non-fatal failures are logged, recorded in
``static/manifest.yaml``, and the run continues without that plugin's patch.
"""

from __future__ import annotations

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
    ) -> None:
        if manager is None:
            from .plugin_manager import plugins as default_manager
            manager = default_manager
        self.manager = manager
        self.classes = list(plugin_classes)
        self.ctx = ctx
        self.jobs = jobs or os.cpu_count() or 4
        self.manifest: Dict[str, dict] = {}
        self._manifest_lock = threading.Lock()

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

        instances = []
        for cls in self.classes:
            self.manager.load(cls, args)
            inst = self.manager.plugins[cls.__name__]
            inst.ctx = self.ctx
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

        main_phase = [p for p in instances if not p.consumes_patches]
        post_phase = sorted(
            (p for p in instances if p.consumes_patches),
            key=lambda p: (p.order, p.patch_name or "", p.name),
        )

        results: Dict[str, dict] = {}  # plugin name -> {"patch": ..., "static": ...}
        fatal_exc: Optional[BaseException] = None

        with ThreadPoolExecutor(max_workers=self.jobs) as pool:
            futures = {pool.submit(self._run_plugin, p): p for p in main_phase}
            for fut, plugin in futures.items():
                outcome = fut.result()  # _run_plugin never raises
                results[plugin.name] = outcome
                if outcome.get("error") is not None and plugin.fatal:
                    fatal_exc = fatal_exc or outcome["error"]

        if fatal_exc is not None:
            self._write_manifest()
            raise fatal_exc

        patches = self._collect_patches(main_phase, results)

        # Post phase: sequential, in render order, each seeing all prior patches
        self.ctx._patches = patches
        for plugin in post_phase:
            outcome = self._run_plugin(plugin)
            results[plugin.name] = outcome
            if outcome.get("error") is not None and plugin.fatal:
                self._write_manifest()
                raise outcome["error"]
            self._merge_patch(patches, plugin, outcome)
        self.ctx._patches = None

        # Deterministic render order, independent of completion order
        ordered = dict(
            sorted(patches.items(), key=lambda kv: (kv[1][2], kv[0]))
        )
        # Strip the order component before handing back (data, enabled)
        ordered = {k: (v[0], v[1]) for k, v in ordered.items()}

        self._write_manifest()
        return ordered

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

    @staticmethod
    def _merge_patch(patches: Dict[str, tuple], plugin: InitPlugin, outcome: dict) -> None:
        data = outcome.get("patch")
        if plugin.patch_name and data:
            patches[plugin.patch_name] = (data, plugin.enabled, plugin.order)
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
        except Exception as e:  # noqa: BLE001 - recorded per-plugin
            outcome["error"] = e
            entry["status"] = "failed"
            entry["error"] = f"{type(e).__name__}: {e}"
            if plugin.fatal:
                logger.error(f"init plugin {plugin.name} failed fatally: {e}")
            else:
                logger.warning(f"init plugin {plugin.name} failed (skipped): {e}")
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

    def render_patches(self, patches: Dict[str, tuple]) -> None:
        """Write non-empty patches to ``patch_dir/<name>.yaml`` (including
        disabled ones, matching historic behavior)."""
        self.ctx.patch_dir.mkdir(exist_ok=True, parents=True)
        for name, (data, _enabled) in patches.items():
            plain = _to_plain(data)
            if _is_empty_patch(plain):
                continue
            with open(self.ctx.patch_dir / f"{name}.yaml", "w") as f:
                yaml.dump(plain, f, default_flow_style=False)

    def _write_manifest(self) -> None:
        self.ctx.static_dir.mkdir(exist_ok=True, parents=True)
        with open(self.ctx.static_dir / MANIFEST_NAME, "w") as f:
            yaml.dump({"plugins": _to_plain(self.manifest)}, f)
