"""
Config-mutation writers — express an agent's config changes as a reviewable patch.

Rather than editing ``config.yaml`` in place, every mutation deep-merges into a single
``patch_90_mcp.yaml`` in the project directory. Penguin auto-discovers ``patch_*.yaml``
(when ``core.auto_patching`` is on, the default) and merges it into the validated config,
so the agent's changes are: (a) applied without touching the base config, (b) all in one
auditable file, and (c) trivially reverted (``reset_patch``). The ``90`` prefix orders it
after lower-numbered hand-authored patches.

Dependency-free (pyyaml + stdlib). Each function returns the resulting patch dict so the
caller/agent can see the new state.
"""

from __future__ import annotations

import os
from typing import Any, Optional

import yaml

PATCH_NAME = "patch_90_mcp.yaml"

_HEADER = (
    "# Managed by the Penguin MCP server (penguin.mcp). Each tool call deep-merges here.\n"
    "# Safe to edit or delete by hand; `reset_patch` removes it.\n"
)


def _patch_path(proj_dir: str) -> str:
    return os.path.join(proj_dir, PATCH_NAME)


def _load(proj_dir: str) -> dict:
    path = _patch_path(proj_dir)
    if os.path.exists(path):
        with open(path) as f:
            return yaml.safe_load(f) or {}
    return {}


def _deep_merge(dst: dict, src: dict) -> dict:
    """Recursively merge src into dst (dicts merge; lists union-append; scalars overwrite)."""
    for k, v in src.items():
        if isinstance(v, dict) and isinstance(dst.get(k), dict):
            _deep_merge(dst[k], v)
        elif isinstance(v, list) and isinstance(dst.get(k), list):
            for item in v:
                if item not in dst[k]:
                    dst[k].append(item)
        else:
            dst[k] = v
    return dst


def _apply(proj_dir: str, fragment: dict) -> dict:
    if not os.path.isdir(proj_dir):
        raise ValueError(f"project dir does not exist: {proj_dir}")
    patch = _deep_merge(_load(proj_dir), fragment)
    with open(_patch_path(proj_dir), "w") as f:
        f.write(_HEADER)
        yaml.safe_dump(patch, f, sort_keys=False, default_flow_style=False)
    return patch


# --- individual mutations -------------------------------------------------------------

def set_env(proj_dir: str, key: str, value: Any) -> dict:
    """Set an environment variable / boot arg (e.g. ``igloo_init``, a model string)."""
    return _apply(proj_dir, {"env": {key: value}})


def set_nvram(proj_dir: str, key: str, value: Any) -> dict:
    """Seed an initial NVRAM key/value."""
    return _apply(proj_dir, {"nvram": {key: value}})


def set_uboot_env(proj_dir: str, key: str, value: str) -> dict:
    """Seed a U-Boot env var (served via fw_getenv by the ``uboot`` plugin)."""
    return _apply(proj_dir, {"uboot_env": {key: value}})


def add_netdev(proj_dir: str, name: str) -> dict:
    """Declare a network interface the firmware expects (e.g. ``egiga0``, ``vlan1``)."""
    return _apply(proj_dir, {"netdevs": [name]})


def block_signal(proj_dir: str, signum: int) -> dict:
    """Block a signal guest-wide (supported: 6/9/15/17)."""
    return _apply(proj_dir, {"blocked_signals": [int(signum)]})


def add_pseudofile(
    proj_dir: str,
    path: str,
    read: Optional[dict] = None,
    write: Optional[dict] = None,
    ioctl: Optional[dict] = None,
) -> dict:
    """Create/model a pseudofile. With no models, just makes the path exist (``{}``).

    Example models: read={"model": "const_buf", "val": "hello"},
    write={"model": "discard"}, ioctl={"*": {"model": "return_const", "val": 0}}.
    """
    spec: dict = {}
    if read is not None:
        spec["read"] = read
    if write is not None:
        spec["write"] = write
    if ioctl is not None:
        spec["ioctl"] = ioctl
    return _apply(proj_dir, {"pseudofiles": {path: spec}})


def add_static_file(proj_dir: str, path: str, spec: dict) -> dict:
    """Add a pre-boot filesystem edit. ``spec`` is the action dict, e.g.
    {"type": "symlink", "target": "/igloo/utils/exit0.sh"} or
    {"type": "inline_file", "contents": "...", "mode": 0o755}.
    """
    return _apply(proj_dir, {"static_files": {path: spec}})


# --- inspection / lifecycle -----------------------------------------------------------

def show_patch(proj_dir: str) -> dict:
    """Return the current MCP-managed patch (the accumulated agent changes)."""
    path = _patch_path(proj_dir)
    if not os.path.exists(path):
        return {"patch": {}, "exists": False}
    return {"patch": _load(proj_dir), "exists": True, "path": path}


def reset_patch(proj_dir: str) -> dict:
    """Delete the MCP-managed patch (revert all agent changes)."""
    path = _patch_path(proj_dir)
    existed = os.path.exists(path)
    if existed:
        os.remove(path)
    return {"removed": existed}
