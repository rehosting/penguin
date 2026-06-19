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
    from penguin.plugin_manager import get_plugin_args_model

    reserved = _reserved_sections()
    for key in [k for k in raw.keys() if k not in reserved]:
        if get_plugin_args_model(key, proj_dir, plugin_path) is None:
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
    """Validate each enabled plugin's args against its declared ``Args`` model."""
    from penguin.plugin_manager import get_plugin_args_model

    reserved = {"enabled", "depends_on", "description", "version"}
    had_error = False
    for name, pargs in (config.get("plugins") or {}).items():
        if isinstance(pargs, dict) and pargs.get("enabled", True) is False:
            continue
        model = get_plugin_args_model(name, proj_dir, plugin_path)
        if model is None:
            continue  # legacy / non-declaring plugin -> no validation (BC)
        candidate = {k: v for k, v in (pargs or {}).items() if k not in reserved}
        try:
            model(**candidate)
        except ValidationError as e:
            had_error = True
            logger.error(
                "\n" + format_validation_error(
                    e, root_model=model,
                    header=f"Invalid arguments for plugin '{name}':",
                )
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

    # Project drop-ins are applied after patches so the user's per-project
    # files always win over inherited base configs and patch layers.
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
            if dropin_dir == "init.d" and filename.endswith(".c"):
                static_host_path = compile_init_c_dropin(proj_dir, host_dir, host_path, config)
                guest_path = f"/igloo/{dropin_dir}/{Path(filename).stem}"
            else:
                static_host_path = host_path
                guest_path = f"/igloo/{dropin_dir}/{filename}"
            if guest_path in config["static_files"]:
                logger.warning(
                    f"drop-in {host_path} is overriding existing static_files entry "
                    f"{guest_path} (previously set by a patch or base config)"
                )
            config["static_files"][guest_path] = {
                "type": "host_file",
                "host_path": static_host_path,
                "mode": 0o755,
            }

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
