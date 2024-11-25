from os.path import join, isfile, basename, splitext
from penguin import getColoredLogger
from pandare import PyPlugin, Panda
import shutil
from typing import List, Dict, Union, Callable
import glob
import re


def gen_search_locations(plugin_name: str, proj_dir: str, plugin_path: str):
    search_locations = [
        join(plugin_path, '**', plugin_name),
        join(plugin_path, '**', plugin_name + ".py"),
        join(proj_dir, plugin_name),
        join(proj_dir, plugin_name + ".py"),
        join(proj_dir, "plugins", plugin_name),
        join(proj_dir, "plugins", plugin_name + ".py"),
    ]
    return search_locations


def camel_to_snake(name):
    # Convert CamelCase to snake_case
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def snake_to_camel(name):
    # Convert snake_case to CamelCase
    return ''.join(word.capitalize() for word in name.split('_'))


def find_plugin_by_name(plugin_name: str, proj_dir: str, plugin_path: str):

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

    def initialize(self, panda: Panda, args: Dict[str, str]):
        self.panda = panda
        self.args = args
        self.logger = getColoredLogger("penguin.plugin_manger")

        self.plugin_cbs = {}
        self.registered_cbs = {}
        self.aliases = {}

    def load_plugin(self, plugin_name: str):
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
            plugins_loaded = self.panda.pyplugins.load_all(path, args)
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

    def load_plugins(self, conf_plugins: List[str]):
        for plugin in conf_plugins:
            self.load_plugin(plugin)

    def get_plugin_by_name(self, plugin_name: str) -> Union[PyPlugin, None]:
        if plugin_name in self.aliases:
            plugin_name = self.aliases[plugin_name]
        for p, i in self.panda.pyplugins.plugins.items():
            if plugin_name.lower() == p.lower():
                return i

    def __contains__(self, plugin: str) -> bool:
        return self.get_plugin_by_name(plugin) is not None

    def __getitem__(self, plugin: str) -> PyPlugin:
        if not self.get_plugin_by_name(plugin):
            self.load_plugin(plugin)
        return self.get_plugin_by_name(plugin)

    def __getattr__(self, plugin: str) -> PyPlugin:
        return self[plugin]

    def register(self, plugin: PyPlugin, event: str,
                 register_notify: Callable[[str, Callable[..., None]], None] = None):
        self.plugin_cbs[plugin] = self.plugin_cbs.get(plugin, {})
        self.plugin_cbs[plugin][event] = self.plugin_cbs[plugin].get(event, [])
        if register_notify:
            self.registered_cbs[(plugin, event)] = register_notify

    def subscribe(self, plugin: PyPlugin, event: str, callback: Callable[..., None]):
        if plugin not in self.plugin_cbs:
            raise Exception(f"Attempt to subscribe to unregistered plugin: {plugin}")
        elif event not in self.plugin_cbs[plugin]:
            raise Exception(f"Attempt to subscribe to unregistered event: {event} for plugin {plugin}")
        self.plugin_cbs[plugin][event].append(callback)

        if (plugin, event) in self.registered_cbs:
            self.registered_cbs[(plugin, event)](event, callback)

    def publish(self, plugin: PyPlugin, event: str, *args, **kwargs):
        if plugin not in self.plugin_cbs:
            raise Exception(f"Attempt to publish to unregistered plugin: {plugin}")
        elif event not in self.plugin_cbs[plugin]:
            raise Exception(f"Attempt to publish to unregistered event: {event} for plugin {plugin}")
        for cb in self.plugin_cbs[plugin][event]:
            cb(*args, **kwargs)

    @property
    def resources(self):
        return join(self.args["plugin_path"], "resources")


# singleton pattern for the plugin manager
plugins = IGLOOPluginManager()
