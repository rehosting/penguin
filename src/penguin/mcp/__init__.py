"""
Penguin MCP server (Phase 1) — a Model Context Protocol adapter for AI-led rehosting.

This package exposes Penguin's rehosting loop to an LLM agent as discrete tools instead
of "hand-edit YAML, reboot the VM, grep multi-KB result files". It runs **inside the
Penguin container** (where it has direct access to the project tree, the run entry point,
and the SQLite event DB) and speaks MCP over stdio (`penguin mcp`).

Layout:
- ``diagnostics`` — dependency-free readers that parse ``results/N/`` artifacts into JSON.
- ``mutations``   — dependency-free writers that express config changes as a reviewable
                    ``patch_90_mcp.yaml`` (auto-merged by Penguin's ``auto_patching``).
- ``server``      — the FastMCP server wiring those + ``run`` into MCP tools (imports the
                    ``mcp`` package; only loaded by the ``penguin mcp`` subcommand).

Phase 1 = lifecycle (run) + config-mutation patch-writers + structured diagnostics.
Phase 2 (not yet) = live control via the ``remotectrl`` socket + guest interaction.
"""

from . import diagnostics, mutations

__all__ = ["diagnostics", "mutations"]
