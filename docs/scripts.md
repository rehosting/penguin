# Scripting Plugins in Penguin

Penguin supports both class-based plugins and scripting plugins. Scripting plugins allow you to write simple, top-level Python scripts that interact with the plugin manager and the emulation environment, without needing to define a class. This is useful for quick automation, prototyping, or when you want to use decorators and plugin APIs without boilerplate.

> **How scripting plugins work:**
> When you load a script as a plugin, the script's top-level code is executed as if it were inside the `__init__` method of a special `ScriptingPlugin` class. This means all global code runs at plugin load time, decorators are registered, and any setup logic is performed immediately. The script is managed by the plugin manager just like a class-based plugin.

## Key Differences: Plugins vs. Scripts

| Feature                | Class-based Plugin                | Scripting Plugin (Script)         |
|------------------------|-----------------------------------|-----------------------------------|
| Structure              | Subclass `Plugin`                 | Plain Python script               |
| Entry Point            | `__init__` method                 | Top-level code (runs in `__init__` of ScriptingPlugin) |
| Arguments              | `self.get_arg("foo")`            | `args` global                      |
| Decorators             | Use as `@self.plugins.syscalls...`| Use as `@plugins.syscalls...`     |
| Unload/cleanup         | `uninit()` method                 | Define `uninit()` function        |
| Access to manager      | `self.plugins` or `import`        | `plugins` global or `import`      |
| Access to logger       | `self.logger`                     | `logger` global                   |

- Scripting plugins are loaded and managed just like class-based plugins. If a `.py` file does not define a `Plugin` subclass, it is loaded as a scripting plugin.
- The script's top-level code is executed at load time, and the `plugins` object is available for decorators and API calls.
- The `logger` global is automatically injected and named for the script file, so you can use `logger.info(...)` directly in your script.
- You can define an `uninit()` function in your script for cleanup, which will be called when the plugin is unloaded.

## Example: Scripting Plugin

```python
# Example scripting plugin for Penguin
# This script demonstrates how to use scripting plugins with the Penguin plugin manager.
# It uses the global 'plugins' object for API access and the injected 'logger' for logging.
# No class definition is needed; top-level code is executed at load time.
# The 'uninit' function will be called automatically when the plugin is unloaded.

logger.info("Initializing scripting_test.py")
outdir = args.outdir
getpid_ran = False

@plugins.syscalls.syscall("on_sys_getpid_enter")
def getpid_enter(*args):
    """
    This function is registered as a syscall callback for 'on_sys_getpid_enter'.
    It writes a message to a file the first time it is called.
    """
    global getpid_ran
    if getpid_ran:
        return
    logger.info("Received getpid_enter syscall")
    
    with open(f"{outdir}/scripting_test.txt", "w") as f:
        f.write("Hello from scripting_test.py\n")
    getpid_ran = True

def uninit():
    """
    This function is called when the scripting plugin is unloaded.
    It appends a message to the output file, or writes a failure message if the syscall was never triggered.
    """
    logger.info("Got uninit() call")
    if getpid_ran:
        with open(f"{outdir}/scripting_test.txt", "a") as f:
            f.write("Unloading scripting_test.py\n")
    else:
        with open(f"{outdir}/scripting_test.txt", "w") as f:
            f.write("FAIL: scripting_test.py was never run\n")
```

## Example: Class-based Plugin

```python
from penguin import Plugin, plugins

class ClassExample(Plugin):
    def __init__(self):
        self.getpid_ran = False
        self.logger.info(f"Initializing {self.name}")
        self.outdir = self.get_arg("outdir")
        plugins.syscalls.syscall("on_sys_getpid_enter")(self.getpid_enter)

    # Alternatively: you can also use the decorator directly
    # instead of plugins.syscalls.syscall in __init__
    # @plugins.syscalls.syscall("on_sys_getpid_enter")
    def getpid_enter(self, *args):
        if self.getpid_ran:
            return
        self.logger.info("Received getpid_enter syscall")
        with open(f"{self.outdir}/scripting_test.txt", "w") as f:
            f.write("Hello from scripting_test.py\n")
        self.getpid_ran = True

    def uninit(self):
        self.logger.info("Got uninit() call")
        if self.getpid_ran:
            with open(f"{self.outdir}/class_example.txt", "a") as f:
                f.write("Unloading class_example.py\n")
        else:
            with open(f"{self.outdir}/class_example.txt", "w") as f:
                f.write("FAIL: class_example.py was never run\n")
```

## When to Use Scripting Plugins
- For quick experiments, automation, or glue code.
- When you want to use decorators or plugin APIs without class boilerplate.
- When you don't need advanced features like a logger or inheritance.

## When to Use Class-based Plugins
- For reusable, modular, or complex plugins.
- When you need a logger, inheritance, or advanced plugin lifecycle management.

Both plugin types are fully supported and can be mixed in the same project.
