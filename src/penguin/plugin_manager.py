from os.path import join, isfile, basename, splitext
from penguin import getColoredLogger
from pandare2 import PyPlugin, Panda
import shutil
from typing import List, Dict, Union, Callable, Tuple
import glob
import re
import importlib
import inspect
import datetime


class Plugin:
    def __preinit__(self, plugins: IGLOOPluginManager, args:Union[dict, None]) -> None:
        self.plugins = plugins
        self.args = args
        logname = camel_to_snake(self.name)
        self.logger = getColoredLogger(f"plugins.{logname}")

    @property
    def name(self) -> str:
        return self.__class__.__name__
    
    @property
    def panda(self) -> Panda:
        '''
        Returns the Panda instance associated with this plugin.
        '''
        return self.plugins.panda
    
    @panda.setter
    def panda(self, panda: Panda) -> None:
        '''
        This does not set anything, but it makes sure code can be backwards 
        compatible with the old PyPlugin interface.
        '''
        pass
    
    def get_arg(self, arg_name: str):
        '''
        Returns either the argument as a string or None if the argument
        wasn't passed (arguments passed in bool form (i.e., set but with no value)
        instead of key/value form will also return None).
        '''
        if arg_name in self.args:
            return self.args[arg_name]

        return None

    def get_arg_bool(self, arg_name: str) -> bool:
        '''
        Returns True if the argument is set and has a truthy value
        '''

        if arg_name not in self.args:
            # Argument name unset - it's false
            return False

        arg_val = self.args[arg_name]
        if isinstance(arg_val, bool):
            # If it's a python bol already, just return it
            return arg_val

        if isinstance(arg_val, str):
            # string of true/y/1  is True
            return arg_val.lower() in ['true', 'y', '1']

        if isinstance(arg_val, int):
            # Nonzero is True
            return arg_val != 0

        # If it's not a string, int, or bool something is weird
        raise ValueError(f"Unsupported arg type: {type(arg_val)}")
    

def gen_search_locations(plugin_name: str, proj_dir: str, plugin_path: str) -> List[str]:
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
    # Convert CamelCase to snake_case
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def snake_to_camel(name: str) -> str:
    # Convert snake_case to CamelCase
    return ''.join(word.capitalize() for word in name.split('_'))


def find_plugin_by_name(plugin_name: str, proj_dir: str, plugin_path: str) -> Tuple[str, bool]:

    def find_file(g):
        for f in g:
            if '*' in f:
                p = glob.glob(f, recursive=True)
                if len(p) == 1:
                    return p[0]
            else:
                if isfile(f):
                    return f

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
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(IGLOOPluginManager, cls).__new__(cls)
        return cls.instance

    def initialize(self, panda: Panda, args: Dict[str, str]) -> None:
        self.panda = panda
        self.args = args
        self.logger = getColoredLogger("penguin.plugin_manger")

        self.plugin_cbs = {}
        self.registered_cbs = {}
        self.aliases = {}
        self.plugins = {}
    
    def load(self, pluginclasses: List[Union[Plugin, PyPlugin]], args:dict = None) -> None:
        '''
        pluginclasses can either be an uninstantiated python class, a list of such classes,
        or a tuple of (path_to_module.py, [classnames]) where classnames is a list of
        clases subclasses which subclass Plugin.

        Each plugin class will be stored in self.plugins under the class name
        '''
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
            num_args = len(inspect.signature(self.plugins[name].__init__).parameters)
            if num_args == 1:
                self.plugins[name].__init__(self.panda)
            else:
                self.plugins[name].__init__()
            self.plugins[name].load_time = datetime.datetime.now()

    def load_plugin(self, plugin_name: str) -> None:
        if self.get_plugin_by_name(plugin_name):
            return
        self.logger.debug(f"Loading plugin: {plugin_name}")
        path, local_plugin = find_plugin_by_name(plugin_name, self.args["proj_dir"], self.args["plugin_path"])

        args = dict(self.args)
        details = self.args["plugins"]
        plugin_args = details.get(plugin_name, {})

        if plugin_args.get("enabled", True) is False:
            self.logger.debug(f"Plugin {plugin_name} is disabled")
            return

        for k, v in plugin_args.items():
            # Extend the args with everything from the config that isn't in our special args
            if k in ["enabled"]:
                continue
            if k in args.keys():
                if args[k] != v:
                    raise ValueError(f"Config for {plugin_name} overwrites argument {k} {args[k]} -> {v}")
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
        for plugin in conf_plugins:
            self.load_plugin(plugin)

    def get_plugin_by_name(self, plugin_name: str) -> Union[Plugin, None]:
        if plugin_name in self.aliases:
            plugin_name = self.aliases[plugin_name]
        for p, i in self.plugins.items():
            if plugin_name.lower() == p.lower():
                return i

    def __contains__(self, plugin: str) -> bool:
        return self.get_plugin_by_name(plugin) is not None

    def __getitem__(self, plugin: str) -> Plugin:
        if not self.get_plugin_by_name(plugin):
            self.load_plugin(plugin)
        return self.get_plugin_by_name(plugin)

    def __getattr__(self, plugin: str) -> Plugin:
        return self[plugin]
    
    def load_all(self, plugin_file, args=None) -> List[str]:
        '''
        Given a path to a python file, load every Plugin defined in that file
        by identifying all classes that subclass Plugin and passing them to
        self.load()

        Args:
            plugin_file (str): A path specifying a Python file from which Plugin classes should be loaded
            args (dict): Optional. A dictionary of arguments to pass to the Plugin

        Returns:
            String list of Plugin class names loaded from the plugin_file
        '''
        spec = importlib.util.spec_from_file_location("plugin_file", plugin_file)
        if spec is None:
            # Likely an invalid path
            raise ValueError(f"Unable to load {plugin_file}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        names = []
        for name, cls in inspect.getmembers(module, lambda x: inspect.isclass(x)):
            if not issubclass(cls, Plugin) or cls == Plugin:
                if not issubclass(cls, PyPlugin) or cls == PyPlugin:
                    continue
            cls.__name__ = name
            self.load(cls, args)
            names.append(name)
        return names

    def unload(self, pluginclass: List[Union[Plugin, PyPlugin]]) -> None:
        '''
        Given an instance of a PyPlugin or its name, unload it
        '''

        if isinstance(pluginclass, str) and pluginclass in self.plugins:
            pluginclass = self.plugins[pluginclass]

        if not isinstance(pluginclass, PyPlugin):
            raise ValueError(f"Unload expects a name of a loaded pyplugin or a PyPlugin instance. Got {pluginclass} with plugin list: {self.plugins}")

        # Call uninit method if it's present
        if callable(getattr(pluginclass, "uninit", None)):
            pluginclass.uninit()

    def unload_all(self) -> None:
        '''
        Unload all PyPlugins
        '''
        # unload in reverse order of load time
        plugin_list = {k:v for k,v in sorted(self.plugins.items(), key=lambda x: x[1].load_time)}
        while plugin_list:
            name, cls = plugin_list.popitem()
            self.unload(cls)

    def register(self, plugin: Plugin, event: str,
                 register_notify: Callable[[str, Callable[..., None]], None] = None) -> None:
        self.plugin_cbs[plugin] = self.plugin_cbs.get(plugin, {})
        self.plugin_cbs[plugin][event] = self.plugin_cbs[plugin].get(event, [])
        if register_notify:
            self.registered_cbs[(plugin, event)] = register_notify

    def subscribe(self, plugin: Plugin, event: str, callback: Callable[..., None]) -> None:
        if plugin not in self.plugin_cbs:
            raise Exception(f"Attempt to subscribe to unregistered plugin: {plugin}")
        elif event not in self.plugin_cbs[plugin]:
            raise Exception(f"Attempt to subscribe to unregistered event: {event} for plugin {plugin}")
        self.plugin_cbs[plugin][event].append(callback)

        if (plugin, event) in self.registered_cbs:
            self.registered_cbs[(plugin, event)](event, callback)

    def publish(self, plugin: Plugin, event: str, *args, **kwargs):
        if plugin not in self.plugin_cbs:
            raise Exception(f"Attempt to publish to unregistered plugin: {plugin}")
        elif event not in self.plugin_cbs[plugin]:
            raise Exception(f"Attempt to publish to unregistered event: {event} for plugin {plugin}")
        for cb in self.plugin_cbs[plugin][event]:
            cb(*args, **kwargs)

    @property
    def resources(self) -> str:
        return join(self.args["plugin_path"], "resources")


# singleton pattern for the plugin manager
plugins = IGLOOPluginManager()
