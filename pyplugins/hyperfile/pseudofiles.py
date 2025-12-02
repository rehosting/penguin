import inspect
from penguin import plugins, Plugin
from hyperfile.models.base import DevFile, ProcFile, SysFile
from hyperfile.models.read import ReadZero, ReadExternalVFS, ReadExternalLegacy, ReadConstBuf, ReadEmpty, ReadFromFile
from hyperfile.models.write import WriteDiscard, WriteExternalVFS, WriteExternalLegacy, WriteToFile
from hyperfile.models.ioctl import (
    IoctlDispatcher, 
    IoctlReturnConst, 
    IoctlExternalVFS, 
    IoctlExternalLegacy,
    IoctlZero,
    IoctlPluginVFS,
    IoctlPluginLegacy,
)


class Pseudofiles(Plugin):
    def __init__(self):
        self.config = self.get_arg("conf")
        self._populate_hf_config()

    # 1. MAPPING LEGACY NAMES TO NEW CLASSES
    # --------------------------------------
    read_models = {
        "zero": ReadZero,
        "empty": ReadEmpty,
        "const_buf": ReadConstBuf,
        "from_file": ReadFromFile,
        "return_const": ReadConstBuf, # Legacy compatibility
        # "default": ReadDefault # If you implement a default error mixin
    }

    write_models = {
        "discard": WriteDiscard,
        "to_file": WriteToFile,
        # "default": WriteUnhandledMixin
    }

    ioctl_models = {
        "return_const": IoctlZero,
        "zero": IoctlReturnConst,
        # "symex": IoctlSymexMixin, # If you implement symex later
    }

    def _translate_kwargs(self, domain, raw_config):
        """
        Converts schema keys (filename, plugin) to Mixin keys (read_filepath, write_plugin).
        domain: 'read', 'write', or 'ioctl'
        """
        new_kwargs = {}
        
        # 1. Handle Plugins (collision prone)
        if "plugin" in raw_config:
            new_kwargs[f"{domain}_plugin"] = raw_config["plugin"]
        
        if "function" in raw_config:
            new_kwargs[f"{domain}_function"] = raw_config["function"]

        # 2. Handle Filenames (collision prone)
        if "filename" in raw_config:
            if domain == "read":
                # For const_map_file or from_file
                new_kwargs["read_filepath"] = raw_config["filename"]
            elif domain == "write":
                new_kwargs["write_filepath"] = raw_config["filename"]

        # 3. Handle 'val' (generic value)
        if "val" in raw_config:
            if domain == "read":
                # const_buf uses 'buffer' internally in ReadBufWrapper
                new_kwargs["buffer"] = raw_config["val"]
            elif domain == "ioctl":
                new_kwargs["ioctl_retval"] = raw_config["val"]
        
        # 4. Pass through non-conflicting keys (pad, size, etc)
        # Careful: 'size' might be used by both read maps and base file props.
        # Usually BaseFile consumes 'size' via kwargs last, so it's okay to pass through.
        for k, v in raw_config.items():
            if k not in ["plugin", "function", "filename", "val", "model"]:
                new_kwargs[k] = v
                
        return new_kwargs
    
    def _detect_plugin_style(self, plugin_name, func_name, type_hint):
        """
        Introspects the target plugin function to determine if it matches 
        the legacy signature or the new VFS signature.
        """
        plugin = getattr(plugins, plugin_name, None)
        if not plugin:
            raise ValueError(f"Plugin '{plugin_name}' not found/loaded.")
        
        func = getattr(plugin, func_name, None)
        if not func:
            raise ValueError(f"Function '{func_name}' not found in plugin '{plugin_name}'.")

        sig = inspect.signature(func)
        params = list(sig.parameters.values())
        
        # Filter out 'self' if it's a bound method, though inspect usually handles this.
        # We count positional arguments.
        
        # SIGNATURE HEURISTICS based on your previous code:
        # Read Legacy:  (self, filename, user_buf, size, offset, details=...) -> 5 args + optional
        # Read VFS:     (ptregs, file, user_buf, size, loff) -> 5 args (no details kwarg usually)
        
        # Write Legacy: (self, fname, user_buf, size, loff, buf, details) -> 6 args
        # Write VFS:    (ptregs, file, user_buf, size, loff) -> 5 args

        # Ioctl Legacy: (self, filename, cmd, arg, details) -> 4 args
        # Ioctl VFS:    (ptregs, file, cmd, arg) -> 4 args

        # Since arg counts overlap, we look for specific naming conventions 
        # or the presence of 'details'/'kwargs' which legacy heavily relied on.
        
        param_names = [p.name for p in params]
        
        if type_hint == "read":
            if "details" in param_names or "filename" in param_names:
                return ReadExternalLegacy
            return ReadExternalVFS
            
        elif type_hint == "write":
            if "details" in param_names or "buf" in param_names:
                 # Legacy took the buffer content as an arg ('buf')
                return WriteExternalLegacy
            return WriteExternalVFS
            
        elif type_hint == "ioctl":
            if "details" in param_names:
                return IoctlExternalLegacy
            return IoctlExternalVFS
            
        return None

    def _detect_plugin_style_ioctl(self, plugin_name, func_name):
        """
        Inspects plugin to see if it uses legacy signature for IOCTL.
        Returns: 'legacy' or 'vfs'
        """
        plugin = getattr(plugins, plugin_name, None)
        if not plugin: return 'vfs' 
        func = getattr(plugin, func_name, None)
        if not func: return 'vfs'

        sig = inspect.signature(func)
        params = [p.name for p in sig.parameters.values()]
        
        if "details" in params or "filename" in params:
            return 'legacy'
        return 'vfs'

    def _create_ioctl_handler(self, details):
        """
        Creates a specific Handler object for one ioctl entry.
        """
        model = details.get("model", "return_const")
        
        if model == "return_const":
            val = details.get("val", 0)
            return IoctlReturnConst(val)
        
        elif model == "from_plugin":
            plugin_name = details.get("plugin")
            func_name = details.get("function", "ioctl")
            
            style = self._detect_plugin_style_ioctl(plugin_name, func_name)
            
            if style == "legacy":
                return IoctlPluginLegacy(plugin_name, func_name, details)
            else:
                return IoctlPluginVFS(plugin_name, func_name)
        
        # Fallback
        return IoctlReturnConst(0)

    def _resolve_mixin(self, domain, conf):
        """
        Determines the correct Mixin class to use.
        If model == 'from_plugin', performs introspection.
        """
        model_name = conf.get("model", "default") # e.g. "zero", "from_plugin"
        
        # 1. Handle Standard Models
        if model_name != "from_plugin":
            if domain == "read":
                return self.read_models.get(model_name, ReadZero)
            elif domain == "write":
                return self.write_models.get(model_name, WriteDiscard)
            elif domain == "ioctl":
                return self.ioctl_models.get(model_name, IoctlZero) # TODO FIX

        # 2. Handle "from_plugin"
        plugin_name = conf.get("plugin")
        # Default function names if not provided
        default_funcs = {"read": "read", "write": "write", "ioctl": "ioctl"}
        func_name = conf.get("function", default_funcs[domain])

        return self._detect_plugin_style(plugin_name, func_name, domain)

    def _create_dynamic_class(self, filename, details, BaseClass):
        read_conf = details.get("read", {})
        write_conf = details.get("write", {})
        ioctl_conf = details.get("ioctl", {})
        
        # Resolve Classes
        R_Mixin = self._resolve_mixin("read", read_conf)
        W_Mixin = self._resolve_mixin("write", write_conf)
        
        # Resolve Ioctl Handlers
        handlers_map = {}
        for cmd_key, cmd_details in ioctl_conf.items():
            if cmd_key != "*":
                try:
                    cmd_key = int(cmd_key)
                except ValueError:
                    pass 
            handlers_map[cmd_key] = self._create_ioctl_handler(cmd_details)

        # Translate Args (as defined in previous turn)
        r_kwargs = self._translate_kwargs("read", read_conf)
        w_kwargs = self._translate_kwargs("write", write_conf)
        
        # Assemble
        safe_name = f"Gen_{filename.replace('/', '_')}"
        bases = (R_Mixin, W_Mixin, IoctlDispatcher, BaseClass)
        
        all_kwargs = {**r_kwargs, **w_kwargs}
        all_kwargs['ioctl_handlers'] = handlers_map
        all_kwargs['path'] = filename
        all_kwargs['fs'] = BaseClass.FS

        return type(safe_name, bases, {})(**all_kwargs)

    def _force_removal(self, filename):
        self.config["static_files"][filename] = {"type": "delete"}

    def _populate_hf_config(self):
        if not self.config or "pseudofiles" not in self.config:
            return

        for filename, details in self.config.get("pseudofiles", {}).items():
            
            # Determine Base Class and Registerer based on path prefix
            if filename.startswith("/proc/"):
                BaseClass = ProcFile
                registrar = plugins.procfs.register_proc
            elif filename.startswith("/dev/"):
                BaseClass = DevFile
                registrar = plugins.devfs.register_devfs
                self._force_removal(filename)
            elif filename.startswith("/sys/"):
                # Sysfs uses show/store, so read/write mixins might need 
                # the SysfsAdapterMixin we discussed earlier, or SysFile needs 
                # to map read->show internally.
                BaseClass = SysFile 
                registrar = plugins.sysfs.register_sysfs
            else:
                self.logger.warning(f"Unknown path type for {filename}, skipping.")
                continue
            # Create the object
            instance = self._create_dynamic_class(filename, details, BaseClass)

            # Register it
            # Note: Some legacy configs might have specific devfs major/minors
            # defined in 'details'. You can extract them and pass them here.
            registrar(instance, path=filename)
            
            self.logger.debug(f"Dynamically registered {filename} as {instance.__class__.__name__}")
