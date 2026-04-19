import os
import importlib.util
import inspect
import sys
from typing import List, Type, Dict
from penguin import getColoredLogger
from .static_plugin import StaticPlugin, StaticAnalysisPlugin, ConfigPatcherPlugin
from graphlib import TopologicalSorter

logger = getColoredLogger("penguin.static_plugin_manager")

class StaticPluginManager:
    """
    Manages loading and resolving dependencies for static plugins.
    """
    def __init__(self, plugin_dirs: List[str]):
        self.plugin_dirs = plugin_dirs
        self.plugins: Dict[str, Type[StaticPlugin]] = {}
        self.plugin_hashes: Dict[str, str] = {}
        self.load_plugins()

    def _hash_file(self, filepath: str) -> str:
        import hashlib
        hasher = hashlib.sha256()
        try:
            with open(filepath, 'rb') as afile:
                buf = afile.read()
                hasher.update(buf)
        except Exception as e:
            logger.error(f"Error hashing {filepath}: {e}")
        return hasher.hexdigest()

    def load_plugins(self):
        """
        Dynamically loads all plugins in the specified directories.
        """
        for plugin_dir in self.plugin_dirs:
            if not os.path.exists(plugin_dir):
                logger.warning(f"Plugin directory {plugin_dir} does not exist.")
                continue

            for root, _, files in os.walk(plugin_dir):
                for file in files:
                    if file.endswith('.py') and file != '__init__.py':
                        filepath = os.path.join(root, file)
                        self._load_plugin_file(filepath)

    def _load_plugin_file(self, filepath: str):
        # Determine the package name based on the directory structure
        # assuming pyplugins/static_analysis or pyplugins/config_patchers
        # e.g., if filepath is /app/pyplugins/static_analysis/arch_id.py
        # package will be pyplugins.static_analysis
        abs_filepath = os.path.abspath(filepath)
        path_parts = abs_filepath.split(os.sep)

        # Try to find 'pyplugins' in the path to determine the package hierarchy
        if 'pyplugins' in path_parts:
            idx = path_parts.index('pyplugins')
            pkg_parts = path_parts[idx:-1]
            package_name = '.'.join(pkg_parts)
            module_base = os.path.splitext(os.path.basename(filepath))[0]
            module_name = f"{package_name}.{module_base}"
        else:
            module_name = os.path.splitext(os.path.basename(filepath))[0]
            package_name = ''

        spec = importlib.util.spec_from_file_location(module_name, filepath)
        if spec and spec.loader:
            try:
                module = importlib.util.module_from_spec(spec)
                module.__package__ = package_name
                sys.modules[module_name] = module
                spec.loader.exec_module(module)

                for name, cls in inspect.getmembers(module, inspect.isclass):
                    # Check if it's a subclass of StaticPlugin but not the base class itself
                    if issubclass(cls, StaticPlugin) and cls not in (StaticPlugin, StaticAnalysisPlugin, ConfigPatcherPlugin):
                        # Ensure we don't load classes from imported modules (e.g. if they import the base classes)
                        if cls.__module__ == module_name:
                            self.plugins[name] = cls
                            self.plugin_hashes[name] = self._hash_file(filepath)
                            logger.debug(f"Loaded static plugin: {name}")
            except Exception as e:
                logger.error(f"Failed to load static plugin from {filepath}: {e}")

    def get_ordered_plugins(self) -> List[Type[StaticPlugin]]:
        """
        Returns a list of loaded plugin classes ordered by their dependencies.
        """
        graph = {}
        for name, cls in self.plugins.items():
            depends_on = getattr(cls, 'depends_on', [])
            graph[name] = set(depends_on)

        sorter = TopologicalSorter(graph)
        try:
            # We want deterministic ordering, but TopologicalSorter may output nodes
            # in an arbitrary order if they have the same depth.
            # While Python's graphlib.TopologicalSorter maintains insertion order internally,
            # we should sort keys alphabetically before building the graph to ensure determinism.

            # To strictly control the order, we can prepare the graph with sorted keys
            sorted_graph = {k: graph[k] for k in sorted(graph.keys())}
            sorter = TopologicalSorter(sorted_graph)

            ordered_names = list(sorter.static_order())
            # Some dependencies might not be plugins themselves (or not loaded),
            # so we only yield the ones we actually loaded.
            return [self.plugins[name] for name in ordered_names if name in self.plugins]
        except Exception as e:
            logger.error(f"Failed to resolve plugin dependencies: {e}")
            return []

    def get_state_hash(self) -> str:
        """
        Returns a single hash representing the state of all loaded plugins.
        """
        import hashlib
        hasher = hashlib.sha256()
        # Sort keys to ensure consistent hashing
        for name in sorted(self.plugin_hashes.keys()):
            hasher.update(self.plugin_hashes[name].encode('utf-8'))
        return hasher.hexdigest()
