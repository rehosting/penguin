# PyPlugins

PyPlugins are a way to extend the functionality of penguin. They are built on the PyPANDA core functionality and extend that functionality. [pandare documentation])(https://docs.panda.re/)

## Plugin Arguments

In your config.yaml file, you can specify arguments for your plugin. These arguments are passed to the plugin as a dictionary. For example, if you have a plugin that takes a `foo` argument, you can specify it in your config.yaml file like this:

```yaml
plugins:
    pluginA:
        argumentA: valueA
```

Then, in your plugin, you can access the argument like this:

```python
from pandare import PyPlugin

class PluginA(PyPlugin):
    def __init__(self, config):
        self.argumentA = self.get_arg("argumentA")
```


## The Plugin Manager

The Plugin Manager manages plugin lifecycle and inter-plugin interaction. It is accessible through the `penguin.plugins` object.

### Plugin Interaction

Plugins can interact with each other through the `penguin.plugins` object. This object is a dictionary that maps plugin names to plugin objects. For example, if you have a plugin named `pluginA` and a plugin named `pluginB`, you can access `pluginB` from `pluginA` like this:

```python
from pandare import PyPlugin
from penguin import plugins

class PluginA(PyPlugin):
    def __init__(self, config):
        plugins.pluginB.do_something()
```

### Auto-Loading Plugins

As we saw in our previous example PluginA can interact with PluginB via the Plugin Manager. Additionally, we know that the plugin manager will load each plugin with the appropriate config. However, what happens if plugin A needs plugin B and plugin B is not specified in our config?

```python
from pandare import PyPlugin
from penguin import plugins

class PluginA(PyPlugin):
    def __init__(self, config):
        plugins.pluginB.do_something()
```

In this case, the Plugin Manager will automatically load PluginB. Each reference to a new plugin will automatically trigger the loading of that plugin. This allows for a more flexible plugin architecture where plugins can be added and removed without changing the config file.

### Publish/Subscribe model

Plugins can also interact with each other through a publish/subscribe model. This allows plugins to subscribe to events and publish events. This is useful for plugins that need to interact with each other but don't have a direct dependency. For example, if you have a plugin that needs to know when a new process is created, you can subscribe to the `process_created` event like this:

```python
from pandare import PyPlugin
from penguin import plugins

class ProcessCreatedDetector(PyPlugin):
    def __init__(self, config):
        plugins.register(self, "process_created", register_notify=self.notify_subscribed)
    
    def notify_subscribed(self, event, cb):
        print(f"New subscriber to event {event} with {cb}")

    def some_analysis(self):
        print(f"New process created: {process.name}")
        args = (arg1, arg2, arg3)
        plugins.publish(self, "process_created", *args)
```

Here the `ProcessCreatedDetector` plugin lets the plugin manager that it will publish events called "process_created" and optionally chooses to be notified every time a plugin subscribes to this event. The notification here can be important as effort is wasted publishing events if no subscribers exist.

After creating the terms of its publication it does some analysis in `some_analysis` and determines that a new process has been created. It then publishes the event "process_created" with the arguments `arg1`, `arg2`, and `arg3`. Any plugin that has subscribed to this event will be notified and can take action based on the arguments passed.


Next, we have a plugin that subscribes to the event "process_created":

```python
from pandare import PyPlugin
from penguin import plugins

class ProcessSubscriber(PyPlugin):
    def __init__(self, config):
        plugins.subscribe(self, "process_created", self.process_created)

    def process_created(self, *args):
        print(f"New process created with args: {args}")
```