import importlib.util
import inspect
import os
from pydantic import Field
from penguin import plugins, Plugin, PluginArgs, getColoredLogger
from penguin.plugin_manager import find_plugin_by_name
from hyperfile.models.base import DevFile, ProcFile, SysFile, SysfsBridge, SysctlFile, VFSFile
from hyperfile.models.read import (
    ReadConstBuf,
    ReadConstMap,
    ReadConstMapFile,
    ReadDefault,
    ReadEmpty,
    ReadExternalLegacy,
    ReadExternalVFS,
    ReadFromFile,
    ReadOne,
    ReadZero,
)
from hyperfile.models.write import WriteDefault, WriteExternalVFS, WriteExternalLegacy, WriteToFile
from hyperfile.models.ioctl import (
    IoctlDispatcher,
    IoctlReturnConst,
    IoctlExternalVFS,
    IoctlExternalLegacy,
    IoctlZero,
    IoctlPluginVFS,
    IoctlPluginLegacy,
)
from hyperfile.models.poll import PollAlwaysReady, PollExternalVFS


class _LegacyDevSeekCompat:
    """Seek fallback for legacy dictionary-backed /dev pseudofiles with known size.

    Provides only ``lseek``; the always-ready poll fallback lives in
    :class:`~hyperfile.models.poll.PollAlwaysReady` so a known-size node can
    keep seek support while still modelling poll() in a data-aware way.
    """

    def lseek(self, ptregs, file, offset, whence):
        offset_val = int(offset)
        whence_val = int(whence)
        size = int(getattr(self, "SIZE", 0))

        cur = yield from plugins.kffi.read_field(file, "struct file", "f_pos")
        cur_val = int(cur)

        if whence_val == 0:  # SEEK_SET
            new_offset = offset_val
        elif whence_val == 1:  # SEEK_CUR
            new_offset = cur_val + offset_val
        elif whence_val == 2:  # SEEK_END
            new_offset = size + offset_val
        else:
            ptregs.retval = -22
            return

        if new_offset < 0 or new_offset > size:
            ptregs.retval = -22
            return

        yield from plugins.kffi.write_field(file, "struct file", "f_pos", new_offset)
        ptregs.retval = new_offset


class Pseudofiles(Plugin):
    class Args(PluginArgs):
        disable_tracking: bool = Field(
            default=False,
            description="If true, do not initialize the pseudofile_tracker plugin alongside pseudofiles.",
        )

    def __init__(self):
        self.config = self.get_arg("conf")
        if not self.get_arg_bool("disable_tracking"):
            plugins.pseudofile_tracker.ensure_init()
        self._populate_hf_config()

    # 1. MAPPING LEGACY NAMES TO NEW CLASSES
    # --------------------------------------
    read_models = {
        "zero": ReadZero,
        "one": ReadOne,
        "empty": ReadEmpty,
        "const_buf": ReadConstBuf,
        "const_map": ReadConstMap,
        "const_map_file": ReadConstMapFile,
        "from_file": ReadFromFile,
        "return_const": ReadConstBuf,  # Legacy compatibility
        "default": ReadDefault,
    }

    write_models = {
        "discard": WriteDefault,
        "to_file": WriteToFile,
        "default": WriteDefault,
    }

    ioctl_models = {
        "return_const": IoctlReturnConst,
        "zero": IoctlZero,
        # "symex": IoctlSymexMixin, # If you implement symex later
    }

    poll_models = {
        "always_ready": PollAlwaysReady,
    }

    # Built-in single-object backing classes, referenced by bare name in the
    # file-level `plugin:` key. User backings use the `file:ClassName` form
    # instead (resolved via the pyplugin search path).
    backing_models = {}

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
                new_kwargs["filename"] = raw_config["filename"]
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
            raise ValueError(
                f"Function '{func_name}' not found in plugin '{plugin_name}'.")

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

        elif type_hint == "poll":
            # Poll has no buffer/details distinction; only the VFS signature
            # (ptregs, file, poll_table_struct) is supported.
            return PollExternalVFS

        return None

    def _detect_plugin_style_ioctl(self, plugin_name, func_name):
        """
        Inspects plugin to see if it uses legacy signature for IOCTL.
        Returns: 'legacy' or 'vfs'
        """
        plugin = getattr(plugins, plugin_name, None)
        if not plugin:
            return 'vfs'
        func = getattr(plugin, func_name, None)
        if not func:
            return 'vfs'

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

        elif model == "zero":
            return IoctlReturnConst(0)

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

    def _normalize_ioctl_conf(self, ioctl_conf):
        """
        Accept both legacy whole-operation ioctl models:
            ioctl:
              model: from_plugin
              plugin: foo
        and command-map models:
            ioctl:
              "*":
                model: return_const
                val: 0
        """
        if not ioctl_conf:
            return {}
        if "model" in ioctl_conf:
            return {"*": ioctl_conf}
        return ioctl_conf

    def _resolve_mixin(self, domain, conf):
        """
        Determines the correct Mixin class to use.
        If model == 'from_plugin', performs introspection.
        """
        model_name = conf.get("model", "default")  # e.g. "zero", "from_plugin"

        # 1. Handle Standard Models
        if model_name != "from_plugin":
            if domain == "read":
                return self.read_models.get(model_name, ReadDefault)
            elif domain == "write":
                return self.write_models.get(model_name, WriteDefault)
            elif domain == "ioctl":
                return self.ioctl_models.get(model_name, IoctlZero)
            elif domain == "poll":
                return self.poll_models.get(model_name, PollAlwaysReady)

        # 2. Handle "from_plugin"
        plugin_name = conf.get("plugin")
        # Default function names if not provided
        default_funcs = {"read": "read", "write": "write", "ioctl": "ioctl", "poll": "poll"}
        func_name = conf.get("function", default_funcs[domain])

        return self._detect_plugin_style(plugin_name, func_name, domain)

    def _resolve_known_size(self, filename, details, read_conf):
        if "size" in details and details["size"] is not None:
            try:
                return int(details["size"])
            except (TypeError, ValueError):
                return None

        model_name = read_conf.get("model", "default")

        if model_name in ("const_buf", "return_const"):
            val = read_conf.get("val", b"")
            if isinstance(val, bytes):
                return len(val)
            return len(str(val).encode("utf-8"))

        if model_name == "empty":
            return 0

        if model_name == "zero":
            return 1

        if model_name in ("const_map", "const_map_file"):
            size = read_conf.get("size")
            try:
                return int(size)
            except (TypeError, ValueError):
                return None

        if model_name == "from_file":
            host_path = read_conf.get("filename")
            if not host_path:
                return None

            proj_dir = plugins.get_arg("proj_dir")
            if not os.path.isabs(host_path) and proj_dir:
                host_path = os.path.join(proj_dir, host_path)

            if os.path.exists(host_path):
                return os.path.getsize(host_path)
            return None

        return None

    def _get_compat_bases(self, filename, details):
        """Seek (lseek) compat for known-size /dev nodes.

        Poll is resolved separately (see ``_resolve_poll_mixin``) so a
        known-size node can keep seek support while still answering poll() in a
        data-aware way.
        """
        if not filename.startswith("/dev/"):
            return []

        read_conf = details.get("read", {})
        known_size = self._resolve_known_size(filename, details, read_conf)
        if known_size is not None:
            details.setdefault("size", known_size)
            return [_LegacyDevSeekCompat]
        return []

    @staticmethod
    def _overrides_poll(cls):
        """True if ``cls`` provides its own poll() (not the VFSFile stub).

        A backing class with no ``poll`` at all counts as "does not override",
        so a /dev node falls back to the legacy always-ready poll.
        """
        meth = getattr(cls, "poll", None)
        if meth is None:
            return False
        base_meth = getattr(VFSFile, "poll", None)
        return getattr(meth, "__code__", None) is not getattr(base_meth, "__code__", None)

    def _resolve_poll_mixin(self, filename, details):
        """Resolve the poll mixin + its kwargs for the per-domain form.

        - explicit ``poll:`` domain -> the resolved poll mixin,
        - else /dev with no poll config -> PollAlwaysReady (legacy fallback),
        - else (e.g. /proc/sys) -> None (falls through to the VFSFile stub).
        """
        poll_conf = details.get("poll", {})
        if poll_conf:
            return self._resolve_mixin("poll", poll_conf), self._translate_kwargs("poll", poll_conf)
        if filename.startswith("/dev/"):
            return PollAlwaysReady, {}
        return None, {}

    def _import_backing_module(self, path):
        mod_name = f"pseudofile_backing_{os.path.splitext(os.path.basename(path))[0]}"
        spec = importlib.util.spec_from_file_location(mod_name, path)
        module = importlib.util.module_from_spec(spec)
        # Mirror plugin_manager.load_all: inject the common globals so a backing
        # file can use `plugins`/`logger` without importing them explicitly.
        module.__dict__.update({
            "plugins": plugins,
            "logger": getColoredLogger(f"plugins.{mod_name}"),
        })
        spec.loader.exec_module(module)
        return module

    def _resolve_backing_class(self, ref):
        """Resolve a file-level ``plugin:`` backing reference to a class.

        ``file:ClassName`` finds ``file.py`` on the pyplugin search path and
        pulls ``ClassName`` from it; a bare name resolves against the built-in
        ``backing_models`` registry.
        """
        if ":" in ref:
            file_token, cls_name = ref.split(":", 1)
            path, _ = find_plugin_by_name(
                file_token,
                plugins.get_arg("proj_dir") or "",
                plugins.get_arg("plugin_path") or "",
            )
            module = self._import_backing_module(path)
            cls = getattr(module, cls_name, None)
            if cls is None:
                raise ValueError(
                    f"Backing class '{cls_name}' not found in '{file_token}' ({path})")
            return cls
        if ref in self.backing_models:
            return self.backing_models[ref]
        raise ValueError(
            f"Unknown pseudofile backing '{ref}' "
            "(use 'file:ClassName' to reference a user class)")

    def _create_backing_class(self, filename, details, BaseClass, backing_ref):
        """Build a node whose whole fop surface is owned by one backing class."""
        BackingClass = self._resolve_backing_class(backing_ref)

        safe_name = f"Gen_{filename.replace('/', '_')}"
        bases = list(self._get_compat_bases(filename, details))
        # Legacy always-ready fallback only when the backing doesn't model poll.
        if filename.startswith("/dev/") and not self._overrides_poll(BackingClass):
            bases.append(PollAlwaysReady)
        bases.append(BackingClass)
        if BaseClass is SysFile:
            bases.append(SysfsBridge)
        bases.append(BaseClass)

        all_kwargs = {'path': filename, 'fs': getattr(BaseClass, 'FS', None)}
        # Forward top-level file properties (size, mode, name, ...); the
        # per-domain read/write/ioctl/poll keys and the backing ref itself are
        # owned by the backing class, not passed through.
        for key, val in details.items():
            if key not in ("read", "write", "ioctl", "poll", "plugin"):
                all_kwargs[key] = val

        return type(safe_name, tuple(bases), {})(**all_kwargs)

    def _create_dynamic_class(self, filename, details, BaseClass):
        # First-class single-object backing: one class owns read/write/ioctl/poll.
        backing_ref = details.get("plugin")
        if backing_ref:
            return self._create_backing_class(filename, details, BaseClass, backing_ref)

        read_conf = details.get("read", {})
        write_conf = details.get("write", {})
        ioctl_conf = self._normalize_ioctl_conf(details.get("ioctl", {}))

        # Resolve Classes
        R_Mixin = self._resolve_mixin("read", read_conf)
        W_Mixin = self._resolve_mixin("write", write_conf)
        P_Mixin, p_kwargs = self._resolve_poll_mixin(filename, details)

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
        bases = list(self._get_compat_bases(filename, details))
        if P_Mixin is not None:
            bases.append(P_Mixin)
        bases.extend([R_Mixin, W_Mixin, IoctlDispatcher])

        if BaseClass is SysFile:
            bases.append(SysfsBridge)
        bases.append(BaseClass)

        all_kwargs = {**r_kwargs, **w_kwargs, **p_kwargs}
        all_kwargs['ioctl_handlers'] = handlers_map
        all_kwargs['path'] = filename
        all_kwargs['fs'] = getattr(BaseClass, 'FS', None)

        # --- Compatibility bridge for SysctlFile ---
        # If the old config uses a const_buf read mixin to set a static sysctl value,
        # map it to INITIAL_VALUE so the C driver can natively handle it.
        if BaseClass is SysctlFile and "buffer" in r_kwargs:
            all_kwargs["INITIAL_VALUE"] = str(r_kwargs["buffer"])

        # Capture top-level file properties (size, mode, etc.)
        for key, val in details.items():
            if key not in ("read", "write", "ioctl", "poll", "plugin"):
                all_kwargs[key] = val
        # -----------------------------------------------------------------

        return type(safe_name, tuple(bases), {})(**all_kwargs)

    def _populate_hf_config(self):
        if not self.config or "pseudofiles" not in self.config:
            return

        for filename, details in self.config.get("pseudofiles", {}).items():
            # Ignore MTD devices; they are handled natively by mtd.py and portal_mtd.c
            if filename.startswith("/dev/mtd") or filename == "/proc/mtd":
                self.logger.debug(
                    f"Ignoring {filename} in pseudofiles (deferred to native MTD subsystem)")
                plugins.mtd.ensure_init()
                continue

            # Determine Base Class and Registerer based on path prefix
            if filename.startswith("/proc/sys/"):
                BaseClass = SysctlFile
                registrar = plugins.sysctl.register_sysctl
            elif filename.startswith("/proc/"):
                BaseClass = ProcFile
                registrar = plugins.procfs.register_proc
            elif filename.startswith("/dev/"):
                BaseClass = DevFile
                registrar = plugins.devfs.register_devfs
            elif filename.startswith("/sys/"):
                # Sysfs uses show/store, so read/write mixins might need
                # the SysfsAdapterMixin we discussed earlier, or SysFile needs
                # to map read->show internally.
                BaseClass = SysFile
                registrar = plugins.sysfs.register_sysfs
            else:
                self.logger.warning(
                    f"Unknown path type for {filename}, skipping.")
                continue
            # Create the object
            instance = self._create_dynamic_class(filename, details, BaseClass)

            # Register it
            # Note: Some legacy configs might have specific devfs major/minors
            # defined in 'details'. You can extract them and pass them here.
            registrar(instance, path=filename)

            self.logger.debug(
                f"Dynamically registered {filename} as {instance.__class__.__name__}")
