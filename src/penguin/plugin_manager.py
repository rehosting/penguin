"""
# plugin_manager.py - IGLOO Plugin Manager for Penguin

This module provides the IGLOOPluginManager and Plugin base class for the Penguin emulation environment.
It is responsible for:

- Discovering, loading, and unloading plugin classes.
- Managing plugin lifecycles and dependencies.
- Providing a singleton `plugins` object for global plugin access.
- Registering, subscribing, and publishing plugin events.
- Supporting both legacy PyPlugin and new Plugin interfaces.
- Providing utility functions for plugin name resolution and file discovery.

## Arguments
- `panda` (`Panda`): The Panda emulation object.
- `args` (`dict`): Dictionary of arguments and configuration for plugins.

## Plugin Interface
- Plugins should subclass `Plugin` and will be automatically discovered and managed.
- Plugins can register, subscribe, and publish events using the `plugins` singleton:

```python
plugins.register(plugin_instance, "event_name")
plugins.subscribe(other_plugin, "event_name", callback)
plugins.publish(plugin_instance, "event_name", *args, **kwargs)
```

- Plugins can be loaded by name or class, and arguments can be passed via the plugin manager.

## Overall Purpose
The plugin manager provides a flexible, extensible, and event-driven system for managing plugins in the
Penguin emulation environment, enabling modular analysis, automation, and extension of the emulation workflow.
"""

from os.path import join, isfile, basename, splitext
from penguin import getColoredLogger
from pandare2 import PyPlugin, Panda
import shutil
from typing import List, Dict, Union, Callable, Tuple, Optional, Any, Type, TypeVar, Iterator
import glob
import re
import importlib
import inspect
import datetime

# Forward reference for type annotations
T = TypeVar('T', bound='Plugin')
PluginManagerType = TypeVar('PluginManagerType', bound='IGLOOPluginManager')


class Plugin:
    """
    Base class for all IGLOO plugins.
    Plugins should inherit from this class to be managed by the plugin manager.
    Provides argument access, logging, and Panda instance access.
    """

    def __preinit__(self, plugins: 'IGLOOPluginManager', args: Dict) -> None:
        """
        Internal initialization method called by the plugin manager before __init__.
        Args:
            plugins (IGLOOPluginManager): The plugin manager instance.
            args (Dict): Dictionary of arguments for this plugin.
        """
        self.plugins = plugins
        self.args = args
        logname = camel_to_snake(self.name)
        self.logger = getColoredLogger(f"plugins.{logname}")

    @property
    def name(self) -> str:
        """
        Returns the name of this plugin, which is its class name.
        Returns:
            str: The class name of this plugin.
        """
        return self.__class__.__name__

    @property
    def panda(self) -> Panda:
        """
        Returns the Panda instance associated with this plugin.
        Returns:
            Panda: The Panda instance.
        """
        return self.plugins.panda

    @panda.setter
    def panda(self, panda: Panda) -> None:
        """
        Setter for Panda instance (for compatibility, does nothing).
        Args:
            panda (Panda): The Panda instance.
        """
        pass

    def get_arg(self, arg_name: str) -> Any:
        """
        Get an argument value by name.
        Args:
            arg_name (str): The argument name.
        Returns:
            Any: The argument value or None if not set.
        """
        if arg_name in self.args:
            return self.args[arg_name]

        return None

    def get_arg_bool(self, arg_name: str) -> bool:
        """
        Returns True if the argument is set and has a truthy value.
        Args:
            arg_name (str): The name of the argument to retrieve.
        Returns:
            bool: True if the argument exists and has a truthy value, False otherwise.
        Raises:
            ValueError: If the argument exists but has an unsupported type.
        """
        if arg_name not in self.args:
            # Argument name unset - it's false
            return False

        arg_val = self.args[arg_name]
        if isinstance(arg_val, bool):
            # If it's a Python bool already, just return it
            return arg_val

        if isinstance(arg_val, str):
            # string of true/y/1 is True
            return arg_val.lower() in ['true', 'y', '1']

        if isinstance(arg_val, int):
            # Nonzero is True
            return arg_val != 0

        # If it's not a string, int, or bool something is weird
        raise ValueError(f"Unsupported arg type: {type(arg_val)}")


def gen_search_locations(plugin_name: str, proj_dir: str,
                         plugin_path: str) -> List[str]:
    """
    @private
    Generate a list of possible file paths to look for a plugin.

    Args:
        plugin_name: The name of the plugin to search for
        proj_dir: The project directory
        plugin_path: The plugin path

    Returns:
        List of possible file paths to search for the plugin
    """
    search_locations = [
        join(plugin_path, '**', plugin_name),
        join(plugin_path, '**', plugin_name + ".py"),
        join(proj_dir, plugin_name),
        join(proj_dir, plugin_name + ".py"),
        join(proj_dir, "plugins", plugin_name),
        join(proj_dir, "plugins", plugin_name + ".py"),
    ]
    return search_locations


def camel_to_snake(name: str) -> str:
    """
    @private
    Convert CamelCase to snake_case.

    Args:
        name: The CamelCase string to convert

    Returns:
        The converted snake_case string
    """
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def snake_to_camel(name: str) -> str:
    """
    @private
    Convert snake_case to CamelCase.

    Args:
        name: The snake_case string to convert

    Returns:
        The converted CamelCase string
    """
    return ''.join(word.capitalize() for word in name.split('_'))


def find_plugin_by_name(plugin_name: str, proj_dir: str,
                        plugin_path: str) -> Tuple[str, bool]:
    """
    @private
    Find a plugin file by name, trying various naming conventions.

    Args:
        plugin_name: The name of the plugin to find
        proj_dir: The project directory
        plugin_path: The plugin path

    Returns:
        Tuple of (file_path, is_local_plugin)

    Raises:
        ValueError: If the plugin cannot be found
    """
    def find_file(g: List[str]) -> Optional[str]:
        """Helper function to find the first matching file from a list of patterns"""
        for f in g:
            if '*' in f:
                p = glob.glob(f, recursive=True)
                if len(p) == 1:
                    return p[0]
                elif len(p) > 1:
                    raise ValueError(f"Multiple files found for {f}: {p}")
            else:
                if isfile(f):
                    return f
        return None

    plugin_name_possibilities = [plugin_name,
                                 plugin_name.lower(),
                                 camel_to_snake(plugin_name)]
    if '_' in plugin_name:
        plugin_name_possibilities.append(snake_to_camel(plugin_name))
    for pn in plugin_name_possibilities:
        if o := find_file(gen_search_locations(pn, proj_dir, plugin_path)):
            return o, o.startswith(proj_dir)

    raise ValueError(
        f"Plugin not found: with name={plugin_name} and plugin_path={plugin_path}"
    )


class IGLOOPluginManager:
    """
    Singleton class that manages the loading, unloading, and interaction with plugins.
    Provides event registration, subscription, publishing, and plugin lifecycle management.
    """
    def __new__(cls) -> 'IGLOOPluginManager':
        """
        Singleton pattern implementation.
        Returns:
            IGLOOPluginManager: The singleton instance of IGLOOPluginManager.
        """
        if not hasattr(cls, 'instance'):
            cls.instance = super(IGLOOPluginManager, cls).__new__(cls)
        return cls.instance

    def initialize(self, panda: Panda, args: Dict[str, Any]) -> None:
        """
        Initialize the plugin manager with a Panda instance and arguments.
        Args:
            panda (Panda): The Panda instance.
            args (Dict[str, Any]): Dictionary of arguments.
        """
        self.panda = panda
        self.args = args
        self.logger = getColoredLogger("penguin.plugin_manger")

        self.plugin_cbs: Dict[Plugin, Dict[str, List[Callable]]] = {}
        self.registered_cbs: Dict[Tuple[Plugin, str], Callable] = {}
        self.aliases: Dict[str, str] = {}
        self.plugins: Dict[str, Plugin] = {}

    def load(self, pluginclasses: Union[Type[T], List[Type[T]],
             Tuple[str, List[str]]], args: Dict[str, Any] = None) -> None:
        """
        Load one or more plugin classes.
        Args:
            pluginclasses (Union[Type[T], List[Type[T]], Tuple[str, List[str]]]): Plugin class(es) or (file, classnames) tuple.
            args (Dict[str, Any], optional): Arguments to pass to the plugins.
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
            if pluginclass is PyPlugin or pluginclass is Plugin:
                continue
            elif isinstance(pluginclass, Plugin) or issubclass(pluginclass, Plugin):
                pass
            elif isinstance(pluginclass, PyPlugin) or issubclass(pluginclass, PyPlugin):
                self.logger.warning(
                    f"Loading a PyPlugin subclass {pluginclass}. This is deprecated, please Plugin instead (from penguin import Plugin)"
                )
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

    def load_plugin(self, plugin_name: str) -> None:
        """
        Load a plugin by name.
        Args:
            plugin_name (str): Name of the plugin to load.
        Raises:
            ValueError: If plugin loading fails.
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
        Args:
            conf_plugins (List[str]): List of plugin names to load.
        """
        for plugin in conf_plugins:
            self.load_plugin(plugin)

    def get_plugin_by_name(self, plugin_name: str) -> Union[Plugin, None]:
        """
        Retrieve a loaded plugin by name.
        Args:
            plugin_name (str): Name of the plugin.
        Returns:
            Plugin or None: The plugin instance if found, else None.
        """
        if plugin_name in self.aliases:
            plugin_name = self.aliases[plugin_name]
        for p, i in self.plugins.items():
            if plugin_name.lower() == p.lower():
                return i

    def __contains__(self, plugin: str) -> bool:
        """
        Check if a plugin is loaded by name.
        Args:
            plugin (str): Plugin name.
        Returns:
            bool: True if loaded, False otherwise.
        """
        return self.get_plugin_by_name(plugin) is not None

    def __getitem__(self, plugin: str) -> Plugin:
        """
        Get a plugin by name, loading it if necessary.
        Args:
            plugin (str): Plugin name.
        Returns:
            Plugin: The plugin instance.
        """
        if not self.get_plugin_by_name(plugin):
            self.load_plugin(plugin)
        return self.get_plugin_by_name(plugin)

    def __getattr__(self, plugin: str) -> Plugin:
        """
        Attribute access for plugins by name or class name.
        Args:
            plugin (str): Plugin name or class name.
        Returns:
            Plugin: The plugin instance.
        """
        # First try by plugin name (existing behavior)
        plugin_by_name = self.get_plugin_by_name(plugin)
        if plugin_by_name:
            return plugin_by_name

        # Then try by class name - search through all plugins
        for plugin_name, plugin_instance in self.plugins.items():
            if plugin_instance.__class__.__name__ == plugin:
                return plugin_instance

        # If not found by either method, try to load it
        return self[plugin]

    def load_all(self, plugin_file: str,
                 args: Optional[Dict[str, Any]] = None) -> List[str]:
        """
        Load all Plugin classes from a Python file.
        Args:
            plugin_file (str): Path to the Python file.
            args (Optional[Dict[str, Any]]): Arguments to pass to the Plugin.
        Returns:
            List[str]: List of Plugin class names loaded from the file.
        Raises:
            ValueError: If the plugin file cannot be loaded.
        """
        spec = importlib.util.spec_from_file_location(
            "plugin_file", plugin_file)
        if spec is None:
            # Likely an invalid path
            raise ValueError(f"Unable to load {plugin_file}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        names = []
        for name, cls in inspect.getmembers(
                module, lambda x: inspect.isclass(x)):
            if not issubclass(cls, Plugin) or cls == Plugin:
                if not issubclass(cls, PyPlugin) or cls == PyPlugin:
                    continue
            cls.__name__ = name
            self.load(cls, args)
            names.append(name)

            # Create alias from class name to plugin instance for method
            # resolution
            if name in self.plugins:
                # Add the class name as an alias to the plugin instance
                # This allows syscalls plugin to find instances by class name
                class_name = cls.__name__
                plugin_instance_name = name  # The key used in self.plugins
                if class_name != plugin_instance_name:
                    self.aliases[class_name] = plugin_instance_name

        return names

    def unload(self, pluginclass: Union[Type[Plugin], Type[PyPlugin]]) -> None:
        """
        Unload a plugin by class or name.
        Args:
            pluginclass (Union[Type[Plugin], Type[PyPlugin], str]): Plugin class or name.
        Raises:
            ValueError: If the argument is not a loaded plugin.
        """
        if isinstance(pluginclass, str) and pluginclass in self.plugins:
            pluginclass = self.plugins[pluginclass]

        if not issubclass(type(pluginclass), PyPlugin) and not issubclass(
                type(pluginclass), Plugin):
            raise ValueError(
                f"Unload expects a name of a loaded pyplugin or a PyPlugin instance. Got {pluginclass} with plugin list: {self.plugins}")

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
        Args:
            plugin (Plugin): The plugin instance.
            event (str): Event name.
            register_notify (Callable, optional): Optional callback for registration notification.
        """
        self.plugin_cbs[plugin] = self.plugin_cbs.get(plugin, {})
        self.plugin_cbs[plugin][event] = self.plugin_cbs[plugin].get(event, [])
        if register_notify is not None:
            self.registered_cbs[(plugin, event)] = register_notify

    def subscribe(self, plugin: Plugin, event: str,
                  callback: Callable[..., None] = None):
        """
        Subscribe a callback to a plugin event. Can also be used as a decorator if callback is not provided.

        Args:
            plugin (Plugin): The plugin instance.
            event (str): Event name.
            callback (Callable, optional): Callback function.

        Usage:
            @plugins.subscribe(plugin, "event_name")
            def handler(...): ...

            or

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

    def publish(self, plugin: Plugin, event: str, *args, **kwargs):
        """
        Publish an event to all registered callbacks for a plugin event.
        Args:
            plugin (Plugin): The plugin instance.
            event (str): Event name.
            *args: Positional arguments for callbacks.
            **kwargs: Keyword arguments for callbacks.
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
            if hasattr(cb, '__qualname__') and '.' in cb.__qualname__ and not hasattr(
                    cb, '__self__'):
                class_name = cb.__qualname__.split('.')[0]
                method_name = cb.__qualname__.split('.')[-1]
                try:
                    instance = getattr(self, class_name)
                    if instance and hasattr(instance, method_name):
                        bound_method = getattr(instance, method_name)
                        bound_method(*args, **kwargs)
                        continue
                except AttributeError:
                    # Could not find instance or method, fall through to normal
                    # call
                    pass
            cb(*args, **kwargs)

    def portal_publish(self, plugin: Plugin, event: str, *args, **kwargs):
        """
        Publish an event to all registered callbacks for a plugin event, handling generators properly.
        Args:
            plugin (Plugin): The plugin instance.
            event (str): Event name.
            *args: Positional arguments for callbacks.
            **kwargs: Keyword arguments for callbacks.
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
            if hasattr(cb, '__qualname__') and '.' in cb.__qualname__ and not hasattr(
                    cb, '__self__'):
                class_name = cb.__qualname__.split('.')[0]
                method_name = cb.__qualname__.split('.')[-1]
                try:
                    instance = getattr(self, class_name)
                    if instance and hasattr(instance, method_name):
                        bound_method = getattr(instance, method_name)
                        result = bound_method(*args, **kwargs)
                        if isinstance(result, Iterator):
                            yield from result
                        continue
                except AttributeError:
                    # Could not find instance or method, fall through to normal
                    # call
                    pass
            result = cb(*args, **kwargs)
            if isinstance(result, Iterator):
                yield from result
            # For non-generator callbacks, we don't need to do anything with
            # the result

    @property
    def resources(self) -> str:
        """
        Returns the path to the plugin resources directory.
        Returns:
            str: Path to the resources directory.
        """
        return join(self.args["plugin_path"], "resources")


    def get_arg(self, arg_name: str) -> Any:
        """
        Get an argument value by name.
        Args:
            arg_name (str): The argument name.
        Returns:
            Any: The argument value or None if not set.
        """
        if arg_name in self.args:
            return self.args[arg_name]

        return None

    def get_arg_bool(self, arg_name: str) -> bool:
        """
        Returns True if the argument is set and has a truthy value.
        Args:
            arg_name (str): The name of the argument to retrieve.
        Returns:
            bool: True if the argument exists and has a truthy value, False otherwise.
        Raises:
            ValueError: If the argument exists but has an unsupported type.
        """
        if arg_name not in self.args:
            # Argument name unset - it's false
            return False

        arg_val = self.args[arg_name]
        if isinstance(arg_val, bool):
            # If it's a Python bool already, just return it
            return arg_val

        if isinstance(arg_val, str):
            # string of true/y/1 is True
            return arg_val.lower() in ['true', 'y', '1']

        if isinstance(arg_val, int):
            # Nonzero is True
            return arg_val != 0

        # If it's not a string, int, or bool something is weird
        raise ValueError(f"Unsupported arg type: {type(arg_val)}")


# singleton pattern for the plugin manager
plugins = IGLOOPluginManager()
