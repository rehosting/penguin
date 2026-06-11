# Penguin MCP server (Phase 1)

A [Model Context Protocol](https://modelcontextprotocol.io) adapter that lets an LLM agent
drive Penguin's rehosting loop through discrete tools instead of hand-editing YAML and
grepping raw result files. It runs **inside the Penguin container** and speaks MCP over
stdio.

## Run it

```sh
penguin mcp            # stdio transport; launch under your MCP client / agent
```

The wrapper launches this in-container, so the server has direct access to the project
tree, the run entry point, and `plugins.db`.

## Tools

**Lifecycle**
- `run(project_dir, timeout?)` — execute one emulation (config + auto-merged patches) and
  return the new `results/N` dir plus a health summary.

**Config mutations** (each deep-merges into a single reviewable `patch_90_mcp.yaml`,
auto-merged by Penguin's `auto_patching`; revert with `reset_patch`)
- `set_env`, `set_nvram`, `set_uboot_env`, `add_netdev`, `block_signal`,
  `add_pseudofile`, `add_static_file`, `show_patch`, `reset_patch`

**Structured diagnostics** (parsed JSON, not file dumps)
- `health`, `missing_env`, `pseudofile_failures`, `netbinds`, `console(pattern)`,
  `db_query(sql)`, `missing_files(procname)`

## Design notes

- `diagnostics.py` and `mutations.py` are dependency-free (pyyaml + stdlib) and unit-tested
  (`tests/unit_tests/test_mcp.py`) — they need neither a container nor the `mcp` package.
- `server.py` is the only module that imports `mcp` (FastMCP); it's loaded by `penguin mcp`.
- Mutations never touch `config.yaml`; they live in one patch file so changes are auditable
  and reversible — matching the "prefer patches" discipline.

## Not yet (Phase 2)

Live control via the `remotectrl` Unix socket (add uprobes/syscall hooks, toggle plugins on
a *running* guest, no reboot) and guest interaction (`guest_cmd`, VPN-bridge reachability).
