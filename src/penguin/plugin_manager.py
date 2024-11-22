from os.path import join, isfile
from penguin import getColoredLogger
from pandare import PyPlugin, Panda
import shutil
from typing import List, Dict, Union, Callable

def find_plugin_by_name(plugin_name: str, proj_dir: str, plugin_path: str):
    search_locations = [
        join(plugin_path, plugin_name),
        join(plugin_path, plugin_name + ".py"),
        join(plugin_path, plugin_name.lower()),
        join(plugin_path, plugin_name.lower() + ".py"),
        join(proj_dir, plugin_name),
        join(proj_dir, plugin_name + ".py"),
        join(proj_dir, plugin_name.lower()),
        join(proj_dir, plugin_name.lower() + ".py"),
        join(proj_dir, "plugins", plugin_name),
        join(proj_dir, "plugins", plugin_name + ".py"),
        join(proj_dir, "plugins", plugin_name.lower()),
        join(proj_dir, "plugins", plugin_name.lower() + ".py"),
    ]
    
    for p in search_locations:
        if isfile(p):
            return p, p.startswith(proj_dir)

    raise ValueError(
        f"Plugin not found: with name={plugin_name} and plugin_path={plugin_path}"
    )

class IGLOOPluginManager:
    def __new__(cls):
        if not hasattr(cls, 'instance'):
            cls.instance = super(IGLOOPluginManager, cls).__new__(cls)
        return cls.instance
    
    def initialize(self, panda: Panda, args: Dict[str,str]):
        self.panda = panda
        self.args = args
        self.logger = getColoredLogger("penguin.plugin_manger")
        
        
        self.plugin_cbs = {}
        self.registered_cbs = {}
        
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
            if len(self.panda.pyplugins.load_all(path, args)) == 0:
                with open(join(self.args["outdir"], "plugin_errors.txt"), "a") as f:
                    f.write(f"Failed to load plugin: {plugin_name}")
                raise ValueError(f"Failed to load plugin: {plugin_name}")
        except SyntaxError as e:
            self.logger.error(f"Syntax error loading pyplugin: {e}")
            raise ValueError(f"Failed to load plugin: {plugin_name}") from e
        if local_plugin:
            shutil.copy2(path, self.args["outdir"])
    
    def load_plugins(self, conf_plugins: List[str]):
        for plugin in conf_plugins:
            self.load_plugin(plugin)
                
    def get_plugin_by_name(self, plugin_name: str) -> Union[PyPlugin, None]:
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
        
    
# singleton pattern for the plugin manager
plugins = IGLOOPluginManager()

