"""
FastMCP server exposing Penguin's rehosting loop as MCP tools (Phase 1).

Runs inside the Penguin container; launched by ``penguin mcp`` (stdio transport).
Tool groups:
  * lifecycle  — ``run`` (executes a single emulation run, returns a health summary)
  * mutate     — set_env / set_nvram / set_uboot_env / add_netdev / add_pseudofile /
                 add_static_file / block_signal / show_patch / reset_patch
  * diagnose   — health / missing_env / pseudofile_failures / netbinds / console / db

This module imports the ``mcp`` package, so it is only loaded when serving (the
``diagnostics`` and ``mutations`` modules stay dependency-free and unit-testable).
"""

from __future__ import annotations

import os
from typing import Any, Optional

from mcp.server.fastmcp import FastMCP

from . import diagnostics as diag
from . import mutations as mut

app = FastMCP("penguin")


def _alloc_results_dir(proj_dir: str) -> str:
    """Allocate the next ``results/N`` dir and repoint ``results/latest`` (mirrors the CLI)."""
    base = os.path.join(proj_dir, "results")
    os.makedirs(base, exist_ok=True)
    nums = [int(d) for d in os.listdir(base) if d.isdigit() and os.path.isdir(os.path.join(base, d))]
    idx = max(nums) + 1 if nums else 0
    latest = os.path.join(base, "latest")
    if os.path.islink(latest):
        os.unlink(latest)
    try:
        os.symlink(f"./{idx}", latest)
    except OSError:
        pass
    return os.path.join(base, str(idx))


# --- lifecycle ------------------------------------------------------------------------

@app.tool()
def run(project_dir: str, timeout: Optional[int] = None) -> dict:
    """Run one emulation of the project (applies config + auto-merged patches) and return
    the results dir plus a health summary. This is the core loop step after mutations."""
    from penguin.__main__ import run_from_config  # lazy: heavy import path

    if not os.path.isdir(os.path.join(project_dir, "base")):
        return {"error": f"{project_dir} has no base/ (run `penguin init` first)"}
    config_path = os.path.join(project_dir, "config.yaml")
    if not os.path.exists(config_path):
        return {"error": f"no config.yaml in {project_dir}"}
    out = _alloc_results_dir(project_dir)
    try:
        run_from_config(project_dir, config_path, out, timeout=timeout)
    except Exception as e:  # surface, don't crash the server
        return {"error": f"run failed: {e}", "results_dir": out}
    summary = diag.read_health(results_dir=out)
    return {"results_dir": out, **summary}


# --- mutate ---------------------------------------------------------------------------

@app.tool()
def set_env(project_dir: str, key: str, value: Any) -> dict:
    """Set an env var / boot arg (e.g. igloo_init). Tip: value 'DYNVALDYNVALDYNVAL'
    discovers the expected value via env_cmp.txt on the next run."""
    return mut.set_env(project_dir, key, value)


@app.tool()
def set_nvram(project_dir: str, key: str, value: Any) -> dict:
    """Seed an initial NVRAM key/value."""
    return mut.set_nvram(project_dir, key, value)


@app.tool()
def set_uboot_env(project_dir: str, key: str, value: str) -> dict:
    """Seed a U-Boot env var (served via fw_getenv by the uboot plugin)."""
    return mut.set_uboot_env(project_dir, key, value)


@app.tool()
def add_netdev(project_dir: str, name: str) -> dict:
    """Declare a network interface the firmware expects (e.g. egiga0, vlan1)."""
    return mut.add_netdev(project_dir, name)


@app.tool()
def block_signal(project_dir: str, signum: int) -> dict:
    """Block a signal guest-wide to stop a service being killed (supported: 6/9/15/17)."""
    return mut.block_signal(project_dir, signum)


@app.tool()
def add_pseudofile(
    project_dir: str,
    path: str,
    read: Optional[dict] = None,
    write: Optional[dict] = None,
    ioctl: Optional[dict] = None,
) -> dict:
    """Create/model a /dev /proc /sys pseudofile. No models = just make it exist.
    e.g. ioctl={"*": {"model": "return_const", "val": 0}}."""
    return mut.add_pseudofile(project_dir, path, read=read, write=write, ioctl=ioctl)


@app.tool()
def add_static_file(project_dir: str, path: str, spec: dict) -> dict:
    """Add a pre-boot FS edit, e.g. spec={"type":"symlink","target":"/igloo/utils/exit0.sh"}."""
    return mut.add_static_file(project_dir, path, spec)


@app.tool()
def show_patch(project_dir: str) -> dict:
    """Show the accumulated MCP-managed config patch (all changes made this session)."""
    return mut.show_patch(project_dir)


@app.tool()
def reset_patch(project_dir: str) -> dict:
    """Revert all MCP-managed config changes (delete patch_90_mcp.yaml)."""
    return mut.reset_patch(project_dir)


# --- diagnose -------------------------------------------------------------------------

@app.tool()
def health(project_dir: str = None, results_dir: str = None) -> dict:
    """End-of-run health summary (score components, panic flag, counts)."""
    return diag.read_health(results_dir=results_dir, proj_dir=project_dir)


@app.tool()
def missing_env(project_dir: str = None, results_dir: str = None) -> dict:
    """Env vars / cmdline keys the firmware read but the config didn't provide."""
    return diag.read_missing_env(results_dir=results_dir, proj_dir=project_dir)


@app.tool()
def pseudofile_failures(project_dir: str = None, results_dir: str = None) -> dict:
    """Missing/unmodeled /dev /proc /sys files the firmware touched, with op counts."""
    return diag.read_pseudofile_failures(results_dir=results_dir, proj_dir=project_dir)


@app.tool()
def netbinds(project_dir: str = None, results_dir: str = None) -> dict:
    """Listening sockets the guest opened (the success signal)."""
    return diag.read_netbinds(results_dir=results_dir, proj_dir=project_dir)


@app.tool()
def console(
    project_dir: str = None, results_dir: str = None, pattern: str = None, max_lines: int = 100
) -> dict:
    """console.log lines matching a regex (or the tail). Grep for panics, segfaults, errors."""
    return diag.grep_console(
        results_dir=results_dir, proj_dir=project_dir, pattern=pattern, max_lines=max_lines
    )


@app.tool()
def db_query(
    sql: str, project_dir: str = None, results_dir: str = None, limit: int = 100
) -> dict:
    """Read-only SELECT over plugins.db (syscall/exec events). JOIN syscall→event for procname."""
    return diag.query_db(sql, results_dir=results_dir, proj_dir=project_dir, limit=limit)


@app.tool()
def missing_files(
    project_dir: str = None, results_dir: str = None, procname: str = None, limit: int = 30
) -> dict:
    """Files a process tried to open/stat that returned ENOENT (what pseudofiles to add)."""
    return diag.missing_files(
        results_dir=results_dir, proj_dir=project_dir, procname=procname, limit=limit
    )


def serve(transport: str = "stdio") -> None:
    """Entry point for `penguin mcp`."""
    app.run(transport=transport)
