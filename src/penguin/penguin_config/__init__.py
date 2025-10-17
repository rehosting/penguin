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
import yaml
from yamlcore import CoreLoader
from pydantic import BaseModel, Field, RootModel
from pydantic.config import ConfigDict

import penguin
try:
    from penguin.common import patch_config
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


def _validate_config_schema(config, is_dump):
    """Validate config with Pydantic"""
    validated_model = structure.Main(**config)

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


def _validate_config(config, is_dump=False):
    _validate_config_schema(config, is_dump)
    _validate_config_options(config)


def load_unpatched_config(path):
    '''
    Load a configuration without applying any patches. No validation.
    '''
    with open(path, "r") as f:
        config = yaml.load(f, Loader=CoreLoader)
    return config


def load_config(proj_dir, path, validate=True, resolved_kernel=None):
    """Load penguin config from path"""
    with open(path, "r") as f:
        config = yaml.load(f, Loader=CoreLoader)
    config = structure.Patch(**config)
    # look for files called patch_*.yaml in the same directory as the config file
    if config.core.auto_patching:
        patch_files = list(Path(proj_dir).glob("patch_*.yaml"))
        patches_dir = Path(proj_dir, "patches")
        if patches_dir.exists():
            patch_files += list(patches_dir.glob("*.yaml"))
        if patch_files:
            if config.patches.root is None:
                config.patches.root = []
            for patch_file in patch_files:
                config.patches.root.append(str(patch_file))
    if config.patches.root is not None:
        patch_list = config.patches.root
        for patch in patch_list:
            # patches are loaded relative to the main config file
            patch_relocated = Path(proj_dir, patch)
            if patch_relocated.exists():
                # TODO: If we're missing a patch we should warn, but this happens 3-4x
                # and that's too verbose.
                with open(patch_relocated, "r") as f:
                    patch = yaml.load(f, Loader=CoreLoader)
                patch = structure.Patch(**patch)
                config = patch_config(logger, config, patch)
    config = config.model_dump()
    if config["core"].get("guest_cmd", False) is True:
        config["static_files"]["/igloo/utils/guesthopper"] = dict(
            type="host_file",
            host_path="/igloo_static/guesthopper/guesthopper."+config["core"]["arch"],
            mode=0o755,
        )
        config["static_files"]["/igloo/init.d/guesthopper"] = dict(
            type="inline_file",
            contents="RUST_LOG=info /igloo/utils/guesthopper --shell /igloo/utils/busybox &",
            mode=0o755,
        )
    # Use pre-resolved kernel if provided, otherwise resolve it
    if resolved_kernel:
        config["core"]["kernel"] = resolved_kernel
    else:
        config["core"]["kernel"] = get_kernel(config, proj_dir)

    # when loading a patch we don't need a completely valid config
    if validate:
        _validate_config(config)
        _validate_config_version(config, path)
        # Not required in schema as to allow for patches, but these really are required
        if config["core"].get("arch", None) is None:
            raise ValueError("No core.arch specified in config")

        if config["core"].get("fs", None) is None:
            if Path(proj_dir, "base/fs.tar.gz").exists():
                config["core"]["fs"] = "./base/fs.tar.gz"
            else:
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
    with open(path, "w") as f:
        f.write(
            "# yaml-language-server: $schema=https://github.com/rehosting/penguin/releases/latest/download/config_schema.yaml\n"
        )
        yaml.dump(config, f, sort_keys=False, default_flow_style=False, width=None)


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
