# Plugins

Plugins are a way to extend the functionality of penguin.

## The Plugin Class

All plugins should inherit from the `Plugin` base class provided by `penguin`. This class provides useful methods and properties for plugin development:

- `self.get_arg(arg_name)`: Retrieve a plugin argument by name, or None if not set.
- `self.get_arg_bool(arg_name)`: Retrieve a plugin argument as a boolean (interprets common true/false values).
- `self.logger`: A logger instance for the plugin, automatically named for the plugin class.
- `self.plugins`: Reference to the plugin manager, allowing access to other plugins (e.g., `self.plugins.other_plugin`).
- `self.name`: The name of the plugin (class name).

The plugin manager will automatically instantiate your plugin and call its `__init__` method. You do not need to handle argument parsing or plugin registration manually.

Example:

```python
from penguin import Plugin

class MyPlugin(Plugin):
    def __init__(self):
        self.logger.info(f"Initializing {self.name}")
        foo = self.get_arg("foo")
        if self.get_arg_bool("debug"):
            self.logger.setLevel("DEBUG")
```

## Plugin Arguments

In your config.yaml file, you can specify arguments for your plugin. These arguments are passed to the plugin and can be accessed using the `get_arg` or `get_arg_bool` methods. For example, if you have a plugin that takes a `foo` argument, you can specify it in your config.yaml file like this:

```yaml
plugins:
    pluginA:
        argumentA: valueA
```

Then, in your plugin, you can access the argument like this:

```python
from penguin import Plugin

class PluginA(Plugin):
    def __init__(self):
        self.argumentA = self.get_arg("argumentA")
```

## Plugin File Locations and Discovery

Plugins can be placed in several locations, and the plugin manager will search for them using common naming conventions. When you reference a plugin by name, the manager will look for files matching the plugin name (in CamelCase, snake_case, or lowercase) in the following locations:

- The directory specified by your `plugin_path` (recursively, including subdirectories)
- The project directory (`proj_dir`)
- A `plugins/` subdirectory inside your project directory

Supported file extensions are `.py` (Python source files). For example, a plugin named `MyPlugin` can be found as any of the following:

- `myplugin.py` or `MyPlugin.py` in your plugin path or project directory
- `plugins/myplugin.py` or `plugins/MyPlugin.py` in your project directory

This flexible search allows you to organize plugins as needed for your project. You do not need to specify the full path—just the plugin name.

## The Plugin Manager

The Plugin Manager manages plugin lifecycle and inter-plugin interaction. It is accessible through the `penguin.plugins` object.

### Plugin Interaction

Plugins can interact with each other through the `penguin.plugins` object. This object is a namespace that exposes plugin instances as attributes. For example, if you have a plugin named `pluginA` and a plugin named `pluginB`, you can access `pluginB` from `pluginA` like this:

```python
from penguin import Plugin, plugins

class PluginA(Plugin):
    def __init__(self):
        plugins.pluginB.do_something()
```

### Auto-Loading Plugins

If a plugin references another plugin via the Plugin Manager and that plugin is not specified in the config, the Plugin Manager will automatically load it. This allows for a more flexible plugin architecture where plugins can be added and removed without changing the config file.

```python
from penguin import Plugin, plugins

class PluginA(Plugin):
    def __init__(self):
        plugins.pluginB.do_something()
```

### Publish/Subscribe Model

Plugins can also interact with each other through a publish/subscribe model. This allows plugins to subscribe to events and publish events. This is useful for plugins that need to interact with each other but don't have a direct dependency. For example, if you have a plugin that needs to know when a new process is created, you can subscribe to the `process_created` event like this:

```python
from penguin import Plugin, plugins

class ProcessCreatedDetector(Plugin):
    def __init__(self):
        plugins.register(self, "process_created", register_notify=self.notify_subscribed)
    
    def notify_subscribed(self, event, cb):
        print(f"New subscriber to event {event} with {cb}")

    def some_analysis(self):
        print(f"New process created: {process.name}")
        args = (arg1, arg2, arg3)
        plugins.publish(self, "process_created", *args)
```

Here the `ProcessCreatedDetector` plugin lets the plugin manager know that it will publish events called "process_created" and optionally chooses to be notified every time a plugin subscribes to this event. The notification here can be important as effort is wasted publishing events if no subscribers exist.

After creating the terms of its publication it does some analysis in `some_analysis` and determines that a new process has been created. It then publishes the event "process_created" with the arguments `arg1`, `arg2`, and `arg3`. Any plugin that has subscribed to this event will be notified and can take action based on the arguments passed.

Next, we have a plugin that subscribes to the event "process_created":

```python
from penguin import Plugin, plugins

class ProcessSubscriber(Plugin):
    def __init__(self):
        plugins.subscribe(self, "process_created", self.process_created)

    def process_created(self, *args):
        print(f"New process created with args: {args}")
```