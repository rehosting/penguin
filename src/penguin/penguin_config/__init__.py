import dataclasses
import hashlib
import sys
import os
import typing
from copy import deepcopy
from typing import Annotated, Any, Dict, List, Literal, Optional, Union
from types import NoneType
import shutil
import textwrap
from collections import defaultdict

import click
import jsonschema
try:
    from penguin.common import yaml, CoreDumper, CoreLoader, style_config_for_dump
except ImportError:
    from yamlcore import CoreLoader, CoreDumper
    import yaml

    def style_config_for_dump(obj, _key=None):
        return obj
from pydantic import BaseModel, Field, RootModel, ValidationError
from pydantic.config import ConfigDict

import penguin
from .errors import format_validation_error
from . import templating
try:
    from penguin.common import patch_config
    from penguin.dropin_compile import compile_init_c_dropin
    from penguin.utils import construct_empty_fs
    from penguin.utils import get_kernel
except ImportError:
    pass
from pathlib import Path

from . import versions
from . import structure


logger = penguin.getColoredLogger("config")


def _jsonify_dict(d):
    """
    Recursively walk a nested dict and stringify all the keys

    This is required for jsonschema.validate() to succeed,
    since JSON requires keys to be strings.
    """
    return {
        str(k): _jsonify_dict(v) if isinstance(v, dict) else v for k, v in d.items()
    }


def _validate_config_schema(config, is_dump, path=None, origin_map=None):
    """Validate config with Pydantic"""
    try:
        validated_model = structure.Main(**config)
    except ValidationError as e:
        logger.error(
            "\n" + format_validation_error(e, config_path=path, origin_map=origin_map)
        )
        sys.exit(1)

    if is_dump:
        validated_model.model_dump(exclude_none=True)
    else:
        config.clear()
        config.update(validated_model.model_dump(exclude_none=True))

    jsonschema.validate(
        instance=_jsonify_dict(config),
        schema=structure.Main.model_json_schema(),
    )


def _validate_config_ptrace(config):
    """Check for ptrace-related conflicts, such as using multiple tools to debug the same process"""

    err = False

    fields = {
        tool: config["core"].get(tool)
        for tool in ("strace", "ltrace", "gdbserver")
    }

    is_init_strace = fields["strace"] is True
    is_init_ltrace = fields["ltrace"] is True

    fields = {
        tool: info if isinstance(info, bool) else set(info)
        for tool, info in fields.items()
        if info
    }

    if is_init_strace and is_init_ltrace:
        err = True
        logger.error("core.strace and core.ltrace are mutually exclusive")

    indiv_debug_procs = defaultdict(set)
    for tool, info in fields.items():
        if isinstance(info, set):
            for proc in info:
                indiv_debug_procs[proc].add(tool)

    for proc, tools in indiv_debug_procs.items():
        for tool in tools:
            if not config["core"].get("guest_cmd"):
                err = True
                logger.error(f"debugging {proc} with core.{tool} requires core.guest_cmd")
            if not config["core"].get("shared_dir"):
                err = True
                logger.error(f"debugging {proc} with core.{tool} requires core.shared_dir to store logs")
            if is_init_strace or is_init_ltrace:
                err = True
                logger.error(f"debugging {proc} with core.{tool} is mutually exclusive with full-system strace/ltrace")
        if len(tools) > 1:
            err = True
            logger.error(f"attempt to debug {proc} with more than one tool: {', '.join(tools)}")

    if err:
        sys.exit(1)


def _validate_config_options(config):
    """Do custom checks for config option compatibility"""

    if config["core"].get("ltrace", False) and config["core"]["arch"].startswith("mips64"):
        logger.error("ltrace does not support mips64")
        sys.exit(1)

    _validate_config_ptrace(config)


def _validate_config_version(config, path):
    """Check if config is too old, and show changes and ask to auto-fix"""

    latest_version = penguin.defaults.default_version
    assert latest_version == len(versions.CHANGELOG)

    v = config["core"]["version"]
    if v == "1.0.0":
        v = 1
    changes = versions.CHANGELOG[v:]

    if len(changes) != 0:
        logger.error(
            f"Config version {v} is too old for latest PENGUIN."
            f" The latest version is {latest_version}."
        )
        s = ["# Changelog"]
        for version in changes:
            def format_paragraph(s):
                return "\n\n".join(
                    textwrap.fill(p, break_long_words=False)
                    for p in textwrap.dedent(s).strip().split("\n\n")
                )
            example_config = version.example_old_config
            example_old_text = yaml.dump(example_config).strip()
            version.auto_fix(example_config),
            example_new_text = yaml.dump(example_config).strip()
            s += [
                f"## Version {version.num}",
                "### Changes in new version",
                format_paragraph(version.change_description),
                "### Fix guide",
                format_paragraph(version.fix_guide),
                "For example, change",
                example_old_text,
                "to",
                example_new_text,
            ]
        logger.info("\n" + "\n\n".join(s) + "\n")

        if click.confirm("Automatically apply fixes?", default=True):
            path_old = f"{path}.old"
            shutil.copyfile(path, path_old)
            for version in changes:
                version.auto_fix(config)
                config["core"]["version"] = version.num
            dump_config(config, path)
            logger.info(
                "Config updated."
                f" Backup saved to '{path_old}'."
                " Try running PENGUIN again."
            )
        sys.exit(1)


def _validate_config(config, is_dump=False, path=None, origin_map=None):
    _validate_config_schema(config, is_dump, path=path, origin_map=origin_map)
    _validate_config_options(config)


def _default_plugin_path(raw):
    """Resolve the plugin search path from a raw config dict."""
    core = raw.get("core") if isinstance(raw, dict) else None
    if isinstance(core, dict) and core.get("plugin_path"):
        return core["plugin_path"]
    return structure.Core.model_fields["plugin_path"].default


def _reserved_sections():
    """Top-level config keys that are NOT plugins (reserved schema sections)."""
    return set(structure.Main.model_fields.keys())


def _promote_first_class_plugins(raw, proj_dir, plugin_path):
    """
    Move first-class top-level plugin entries (``pluginname: {...}``) into
    ``raw["plugins"][pluginname]`` in place.

    Only keys that resolve to a plugin declaring an ``Args`` schema are promoted;
    any other unknown top-level key is left alone so the schema's extra="forbid"
    still catches typos. Raises ValueError on a top-level/``plugins:`` conflict.

    .. deprecated::
        The first-class top-level form is deprecated. It makes the set of valid
        top-level keys depend on which plugins happen to declare ``Args``, which
        is ambiguous to read and risks shadowing if a plugin name ever collides
        with a reserved section. Configure plugins under ``plugins:`` instead.
        Promotion still works for now but logs a warning and may be removed in a
        future release.
    """
    if not isinstance(raw, dict):
        return raw
    from penguin.plugin_manager import plugin_declared_arg_fields

    reserved = _reserved_sections()
    for key in [k for k in raw.keys() if k not in reserved]:
        # Detect declaring plugins statically (AST); importing here would run
        # plugin code in the run's own process and corrupt the live plugins.
        if plugin_declared_arg_fields(key, proj_dir, plugin_path) is None:
            continue  # not a declaring plugin -> leave for extra="forbid"
        plugins = raw.setdefault("plugins", {})
        if not isinstance(plugins, dict):
            continue
        if key in plugins:
            raise ValueError(
                f"plugin '{key}' is configured both at the top level and under "
                f"'plugins:'; use only one"
            )
        logger.warning(
            "Plugin '%s' is configured at the top level (first-class syntax). "
            "This form is deprecated and may be removed; move it under the "
            "'plugins:' section (plugins.%s) instead.",
            key, key,
        )
        plugins[key] = raw.pop(key)
    return raw


def _validate_plugin_args(config, proj_dir, plugin_path):
    """
    Catch unknown argument keys for each enabled declaring plugin, statically.

    Field names are read from the plugin's declared ``Args`` via AST (no import,
    so this is safe in the run's own process). Type/value validation of the
    declared args happens later, against the real Pydantic model, in
    ``Plugin.__preinit__`` at plugin load (before the guest boots).
    """
    from penguin.plugin_manager import plugin_declared_arg_fields

    reserved = {"enabled", "depends_on", "description", "version"}
    had_error = False
    for name, pargs in (config.get("plugins") or {}).items():
        if isinstance(pargs, dict) and pargs.get("enabled", True) is False:
            continue
        fields = plugin_declared_arg_fields(name, proj_dir, plugin_path)
        if fields is None:
            continue  # legacy / non-declaring plugin -> no validation (BC)
        unknown = sorted(
            k for k in (pargs or {}) if k not in reserved and k not in fields
        )
        if unknown:
            had_error = True
            valid = ", ".join(sorted(fields)) or "(none)"
            logger.error(
                f"Unknown argument(s) for plugin '{name}': {', '.join(unknown)}. "
                f"Valid arguments: {valid}."
            )
    if had_error:
        sys.exit(1)


def load_unpatched_config(path):
    '''
    Load a configuration without applying any patches. No validation.
    '''
    with open(path, "r") as f:
        config = yaml.load(f, Loader=CoreLoader)
    return config


# In-guest interpreters an init.d drop-in shebang can safely target. The boot
# runner (src/resources/init.sh) execs each executable file in /igloo/init.d
# directly, so the kernel needs a shebang whose interpreter actually exists in
# the guest. The guest shell is busybox at /igloo/utils/sh (init.sh:1) and, when
# staged, Python is the closure wrapper at /igloo/utils/python3 -- a firmware's
# own /bin/sh or /usr/bin/python may not resolve in a minimal rootfs.
_GUEST_SHELL_INTERP = "/igloo/utils/sh"
_GUEST_PYTHON_INTERP = "/igloo/utils/python3"

# Shebang interpreter basenames we recognize and remap to the guest equivalent.
# NB: busybox is deliberately absent -- it is a multi-call binary whose applet
# is the *second* token (``#!/bin/busybox awk``), so remapping it to the shell
# would silently drop the applet. A shebang already pointing under /igloo/
# resolves in-guest and is left untouched (see _resolve_init_dropin).
_SHELL_SHEBANG_INTERPS = frozenset({"sh", "bash", "ash", "dash"})
_PYTHON_SHEBANG_INTERPS = frozenset({"python", "python2", "python3"})


def _shebang_parts(first_line):
    """Return (interpreter_path, interpreter_basename) for a shebang line.

    Resolves ``#!/usr/bin/env python3`` to ``(python3, python3)`` (the env
    argument). Returns ``(None, None)`` when the line is not a shebang.
    """
    if not first_line.startswith("#!"):
        return (None, None)
    parts = first_line[2:].strip().split()
    if not parts:
        return (None, None)
    interp = parts[0]
    base = os.path.basename(interp)
    if base == "env" and len(parts) > 1:
        interp = parts[1]
        base = os.path.basename(parts[1])
    return (interp, base)


def _resolve_init_dropin(host_path, filename, python_interp=None):
    """Decide how an ``init.d/`` drop-in that is neither ``.c`` nor ``.h`` installs.

    Uncompiled scripts -- ``.sh``, ``.py``, or an extension-less file carrying a
    shell/python shebang -- are first-class init scripts: the boot runner execs
    each executable file in ``/igloo/init.d`` directly, so the shebang must point
    at an interpreter that exists in the guest (see the module-level notes on
    ``/igloo/utils/sh`` / ``/igloo/utils/python3``). A missing or foreign
    shell/python shebang is normalized to the guest interpreter (with a warning)
    and the rewritten body installed as an ``inline_file``. Anything we do not
    recognize as such a script -- a prebuilt binary, a ``.conf``/``.txt``, a text
    file with a deliberate non-shell/non-python shebang -- is left verbatim,
    preserving the historical behavior for non-script drop-ins.

    ``python_interp`` is the guest Python interpreter path (``/igloo/utils/python3``)
    when a Python interpreter is staged for the target, else None. When None,
    ``.py`` and python-shebang drop-ins are left verbatim (the shell half of this
    feature ships independently of in-guest Python).

    Returns ``(kind, payload)``:
      ``("verbatim", None)``    -> install ``host_path`` unchanged as a ``host_file``
      ``("inline", contents)``  -> install ``contents`` as an ``inline_file`` (0755)
      ``("need_python", None)`` -> a Python drop-in but ``python_interp`` is None;
                                   the caller should fail the build with a clear
                                   message rather than install a script that dies
                                   at boot.
    """
    ext = Path(filename).suffix
    python_kind = False
    if ext == ".sh":
        target = _GUEST_SHELL_INTERP
    elif ext == ".py":
        target = python_interp
        python_kind = True
    elif ext == "":
        target = None  # extension-less: decide from the shebang below
    else:
        # Some other extension (.conf, .txt, ...): not a script we manage.
        return ("verbatim", None)

    try:
        raw = Path(host_path).read_bytes()
    except OSError:
        return ("verbatim", None)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        # Binary content (e.g. a prebuilt ELF dropped in extension-less): never
        # rewrite. A non-UTF-8 .sh/.py is almost certainly a mistake, but we
        # still won't corrupt it -- install verbatim.
        return ("verbatim", None)

    head, _, tail = text.partition("\n")
    interp_path, interp_base = _shebang_parts(head)

    if ext == "":
        # Only claim an extension-less file if it looks like a shell/python
        # script; otherwise leave it exactly as before.
        if interp_base in _SHELL_SHEBANG_INTERPS:
            target = _GUEST_SHELL_INTERP
        elif interp_base in _PYTHON_SHEBANG_INTERPS:
            target = python_interp
            python_kind = True
        else:
            return ("verbatim", None)

    if python_kind and python_interp is None:
        # A Python drop-in with no in-guest interpreter staged for this target:
        # let the caller fail loudly instead of installing a boot-time failure.
        return ("need_python", None)

    if target is None:
        return ("verbatim", None)

    # A shebang already pointing under /igloo/ resolves inside the guest (e.g.
    # the target itself, or a deliberate '#!/igloo/utils/busybox awk -f'): trust
    # it and install verbatim, no copy needed.
    if interp_path is not None and interp_path.startswith("/igloo/"):
        return ("verbatim", None)

    if head.startswith("#!"):
        logger.warning(
            f"init.d drop-in {filename}: rewriting shebang {head.strip()!r} to "
            f"'#!{target}' so it resolves inside the guest")
        body = tail
    else:
        logger.warning(
            f"init.d drop-in {filename}: no shebang found; prepending "
            f"'#!{target}' so the boot runner can exec it")
        body = text
    return ("inline", f"#!{target}\n{body}")


def _guest_python_interp(config):
    """Return the in-guest Python interpreter path (``/igloo/utils/python3``) if
    a Python interpreter is staged for the target architecture, else None.

    The penguin-tools tool closure ships a per-arch ``manifest.json`` mapping
    tool -> in-store exe (see live_image._stage_tool_closure); a ``python3`` key
    means an interpreter is available for this arch. Missing closure / manifest
    (e.g. host unit tests, arches without one) -> None.
    """
    import json
    from penguin.defaults import static_dir
    from penguin.utils import get_arch_subdir
    try:
        manifest = os.path.join(
            static_dir, "closures", get_arch_subdir(config), "manifest.json")
        with open(manifest) as f:
            tools = json.load(f)
    except (OSError, ValueError, KeyError):
        return None
    return "/igloo/utils/python3" if "python3" in tools else None


def load_config(proj_dir, path, validate=True, resolved_kernel=None, verbose=False):
    """Load penguin config from path"""
    with open(path, "r") as f:
        config = yaml.load(f, Loader=CoreLoader)

    # Render Jinja2 meta-variables ({{ arch }}, {{ core.* }}, user vars:, and the
    # late-bound {{ kernel_version }}) per-file, before merging. main_ctx is
    # reused so patches resolve against the main config's core/arch/vars.
    try:
        config, main_ctx = templating.render_config(config, where=os.path.basename(path))
    except templating.TemplateError as e:
        logger.error(str(e))
        sys.exit(1)

    # Resolve plugin search path once and use it for first-class promotion of
    # both the main config and every patch layer.
    plugin_path = _default_plugin_path(config)
    config = _promote_first_class_plugins(config, proj_dir, plugin_path)
    config = structure.Patch(**config)

    # 1. Initialize the empty map to track our provenance
    origin_map = {}

    # look for files called patch_*.yaml in the same directory as the config file
    if config.core.auto_patching:
        patch_files = list(Path(proj_dir).glob("patch_*.yaml"))
        patches_dir = Path(proj_dir, "patches")
        if patches_dir.exists():
            patch_files += list(patches_dir.glob("*.yaml"))
        if patch_files:
            if config.patches is None:
                config.patches = structure.Patches(root=[])
            elif config.patches.root is None:
                config.patches.root = []
            for patch_file in patch_files:
                config.patches.root.append(str(patch_file))
    if config.patches is not None and config.patches.root is not None:
        patch_list = config.patches.root
        for patch in patch_list:
            # patches are loaded relative to the main config file
            patch_relocated = Path(proj_dir, patch)
            if patch_relocated.exists():
                with open(patch_relocated, "r") as f:
                    patch_data = yaml.load(f, Loader=CoreLoader)
                try:
                    patch_data = templating.substitute(
                        patch_data,
                        templating.build_context(patch_data, extra=main_ctx),
                        where=os.path.basename(str(patch_relocated)),
                    )
                except templating.TemplateError as e:
                    logger.error(str(e))
                    sys.exit(1)
                patch_data = _promote_first_class_plugins(patch_data, proj_dir, plugin_path)
                patch_data = structure.Patch(**patch_data)

                # 2. Pass the origin map and the patch name down into the merger
                config = patch_config(
                    logger=logger,
                    base_config=config,
                    patch=patch_data,
                    patch_name=str(patch_relocated),  # Give it a name to log
                    origin_map=origin_map,           # Pass the state map
                    verbose=verbose
                )
            else:
                logger.error(f"patch file {patch} not found, ignoring")

    config = config.model_dump()
    # `vars` is load-time metadata only; drop it so it never reaches the run.
    config.pop("vars", None)

    # Normalize the architecture to its canonical name (e.g. intel64 -> x86_64,
    # arm64 -> aarch64) so all downstream consumers and the realized config use a
    # single spelling. arch may have been set by a patch, so do this on the merged
    # value. Unknown values are left as-is for schema validation to report.
    from penguin import arch_registry
    _arch = config.get("core", {}).get("arch")
    if _arch is not None and arch_registry.is_known(_arch):
        config["core"]["arch"] = arch_registry.normalize_arch(_arch)

    # Backwards compat: `timeout` used to be a core-plugin arg (plugins.core.timeout).
    # It is now the top-level core.timeout option. Migrate an old-style value so
    # existing configs keep working, preferring an explicit core.timeout.
    _legacy_core = (config.get("plugins") or {}).get("core")
    if isinstance(_legacy_core, dict) and "timeout" in _legacy_core:
        legacy_timeout = _legacy_core.pop("timeout")
        if config["core"].get("timeout") is None:
            logger.warning(
                "plugins.core.timeout is deprecated; use core.timeout instead. "
                "Migrating the value for this run."
            )
            config["core"]["timeout"] = legacy_timeout

    if config["core"].get("guest_cmd", False) is True:
        guesthopper_name = arch_registry.spec(config["core"]["arch"]).canonical
        guesthopper_dir = "/igloo_static/guesthopper"
        try:
            from penguin.utils import resolve_arch_asset
            guesthopper_name = resolve_arch_asset(
                config["core"]["arch"], guesthopper_dir, prefix="guesthopper."
            )
        except Exception:
            pass
        config["static_files"]["/igloo/utils/guesthopper"] = dict(
            type="host_file",
            host_path=f"{guesthopper_dir}/guesthopper.{guesthopper_name}",
            mode=0o755,
        )
        config["static_files"]["/igloo/init.d/guesthopper"] = dict(
            type="inline_file",
            contents="RUST_LOG=info /igloo/utils/guesthopper --shell /igloo/utils/sh &",
            mode=0o755,
        )

    # Stage the guest-side `penguest` Python binding (draft 16) so in-guest
    # Python -- and `.py` init.d drop-ins -- can `import penguest` to reach the
    # host over the portalcall ABI. Files land under /igloo/pylib, which the
    # in-guest python3 wrapper puts on PYTHONPATH (live_image._stage_tool_closure).
    # setdefault so a user/patch override of any path still wins.
    from penguin.defaults import penguest_src_dir
    if os.path.isdir(penguest_src_dir):
        for root, _dirs, files in os.walk(penguest_src_dir):
            for fname in sorted(files):
                if not fname.endswith(".py"):
                    continue
                src = os.path.join(root, fname)
                rel = os.path.relpath(src, penguest_src_dir).replace(os.sep, "/")
                config["static_files"].setdefault(f"/igloo/pylib/penguest/{rel}", {
                    "type": "host_file",
                    "host_path": src,
                    "mode": 0o644,
                })

    # Project drop-ins are applied after patches so the user's per-project
    # files always win over inherited base configs and patch layers.
    guest_python = _guest_python_interp(config)
    for dropin_dir in ("init.d", "source.d"):
        host_dir = os.path.join(proj_dir, dropin_dir)
        if not os.path.isdir(host_dir):
            continue
        for filename in sorted(os.listdir(host_dir)):
            if filename.startswith("."):
                continue
            host_path = os.path.join(host_dir, filename)
            if not os.path.isfile(host_path):
                continue
            if dropin_dir == "init.d" and filename.endswith(".h"):
                continue
            entry = None
            if dropin_dir == "init.d" and filename.endswith(".c"):
                static_host_path = compile_init_c_dropin(proj_dir, host_dir, host_path, config)
                guest_path = f"/igloo/{dropin_dir}/{Path(filename).stem}"
                entry = {"type": "host_file", "host_path": static_host_path, "mode": 0o755}
            else:
                guest_path = f"/igloo/{dropin_dir}/{filename}"
                # Uncompiled init.d scripts (.sh/.py/extension-less) get their
                # shebang normalized to an in-guest interpreter; source.d/ and
                # non-script drop-ins are installed verbatim.
                kind, payload = ("verbatim", None)
                if dropin_dir == "init.d":
                    kind, payload = _resolve_init_dropin(
                        host_path, filename, python_interp=guest_python)
                if kind == "need_python":
                    raise ValueError(
                        f"init.d drop-in {host_path} is a Python script, but no "
                        f"in-guest Python interpreter is staged for arch "
                        f"{config['core'].get('arch')!r}. Rebuild the penguin "
                        "image with a python3 tool closure for this architecture, "
                        "or remove the .py drop-in.")
                if kind == "inline":
                    entry = {"type": "inline_file", "contents": payload, "mode": 0o755}
                else:
                    entry = {"type": "host_file", "host_path": host_path, "mode": 0o755}
            if guest_path in config["static_files"]:
                logger.warning(
                    f"drop-in {host_path} is overriding existing static_files entry "
                    f"{guest_path} (previously set by a patch or base config)"
                )
            config["static_files"][guest_path] = entry

    startup_script = config["core"].get("startup_script")
    if startup_script:
        guest_path = "/igloo/init.d/zz_startup_script"
        if guest_path in config["static_files"]:
            logger.warning(
                f"core.startup_script is overriding existing static_files entry "
                f"{guest_path} (previously set by a patch, base config, or drop-in)"
            )
        config["static_files"][guest_path] = {
            "type": "inline_file",
            "contents": "#!/igloo/utils/sh\n" + startup_script,
            "mode": 0o755,
        }

    plugins_dir = os.path.join(proj_dir, "plugins.d")
    if os.path.isdir(plugins_dir):
        if not isinstance(config.get("plugins"), dict):
            config["plugins"] = {}
        for filename in sorted(os.listdir(plugins_dir)):
            if not filename.endswith(".py"):
                continue
            host_path = os.path.join(plugins_dir, filename)
            if not os.path.isfile(host_path):
                continue
            plugin_name = filename[:-3]
            sidecar = os.path.join(plugins_dir, f"{plugin_name}.yaml")
            args: Dict[str, Any] = {}
            if os.path.isfile(sidecar):
                with open(sidecar, "r") as f:
                    loaded = yaml.load(f, Loader=CoreLoader)
                if isinstance(loaded, dict):
                    args = loaded
                else:
                    logger.debug(
                        f"plugins.d sidecar {sidecar} is not a dict (got {type(loaded).__name__}); "
                        f"using empty args for plugin {plugin_name}"
                    )
            if plugin_name in config["plugins"]:
                logger.warning(
                    f"drop-in plugin {host_path} is overriding existing plugins entry "
                    f"'{plugin_name}' (previously set by a patch or base config)"
                )
            config["plugins"][plugin_name] = args

    # Use pre-resolved kernel if provided, otherwise resolve it
    if resolved_kernel:
        config["core"]["kernel"] = resolved_kernel
    else:
        config["core"]["kernel"] = get_kernel(config, proj_dir)

    # Second templating pass: now that the kernel is resolved, fill in any
    # {{ kernel_version }} references that were deferred in the first pass.
    # Kernel paths look like /igloo_static/kernels/<VERSION>/<file>.
    resolved_kpath = config["core"].get("kernel") or ""
    kernel_version = os.path.basename(os.path.dirname(resolved_kpath)) if resolved_kpath else ""
    config = templating.resolve_kernel_version(config, kernel_version)

    # when loading a patch we don't need a completely valid config
    if validate:
        _validate_config(config, path=path, origin_map=origin_map)
        _validate_plugin_args(config, proj_dir, _default_plugin_path(config))
        _validate_config_version(config, path)
        # Not required in schema as to allow for patches, but these really are required
        if config["core"].get("arch", None) is None:
            raise ValueError("No core.arch specified in config")

        if config["core"].get("fs", None) is None:
            if Path(proj_dir, "base/fs.tar.gz").exists():
                config["core"]["fs"] = "./base/fs.tar.gz"
            else:
                if verbose:
                    logger.info("No core.fs specified in config - using empty fs - most likely a test")
                config["core"]["fs"] = "./base/empty_fs.tar.gz"
                empty_fs_path = os.path.join(proj_dir, "./base/empty_fs.tar.gz")
                if not os.path.exists(empty_fs_path):
                    construct_empty_fs(empty_fs_path)
    return config


def dump_config(config, path):
    """
    Write penguin config to path
    TODO: If we have a config that includes patches we should validate *after* patches.
    For now we allow empty arch and kernel with patches filling them in later, but
    validation doesn't check this
    """
    _validate_config(config)
    # Wrap ints for readable rendering (octal modes, hex addresses) without
    # mutating the caller's config; validation above ran on the originals.
    styled = style_config_for_dump(config)
    with open(path, "w") as f:
        f.write(
            "# yaml-language-server: $schema=https://github.com/rehosting/penguin/releases/latest/download/config_schema.yaml\n"
        )
        yaml.dump(styled, f, sort_keys=False, default_flow_style=False, width=None, Dumper=CoreDumper)


def hash_yaml_config(config: dict):
    """
    Given a config dict, generate a hash
    """
    target = config
    if "meta" in config:
        # We want to ignore the 'meta' field because it's an internal detail
        config2 = deepcopy(config)
        del config2["meta"]
        target = config2
    return hashlib.md5(str(target).encode()).hexdigest()
