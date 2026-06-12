# Init plugins

The plugins in this directory run during `penguin init` (inside the fakeroot
config-generation subprocess, before any emulation exists). Together they
analyze the extracted root filesystem and generate the project's initial
`config.yaml`, `static/` analysis results, and `static_patches/` config
patches.

## How they differ from runtime pyplugins

Init plugins are ordinary pyplugins (`self.plugins`, `self.logger`, args,
`penguin schema` all work), with three differences:

- they run with `panda = None` — there is no emulator;
- they are all discovered and run automatically (no `plugins:` config section
  is needed — there is no config yet);
- execution is concurrent in a thread pool.

## Writing one

```python
from penguin.init_plugin import InitContext, InitPlugin, cached_analysis

class MyAnalysis(InitPlugin):
    @cached_analysis            # computed once, shared with every consumer
    def interesting_files(self) -> list[str]:
        return [str(p) for p in self.ctx.extracted_fs.rglob("*.conf")]

    def static_result(self):    # optional: persisted to static/MyAnalysis.yaml
        return self.interesting_files

class MyPatch(InitPlugin):
    patch_name = "vendor.custom"   # produces static_patches/vendor.custom.yaml

    def patch(self, ctx: InitContext) -> dict | None:
        arch = self.plugins.ArchId.arch          # blocks until computed once
        confs = self.plugins.MyAnalysis.interesting_files
        return {"nvram": {"detected_arch": arch}} if confs else None
```

Key attributes (all optional):

| Attribute | Default | Meaning |
|---|---|---|
| `patch_name` | `None` | Set to produce a patch file. |
| `order` | `1000` | Position in the config's `patches:` list. Later patches override earlier ones; built-ins use 10–990, so user plugins override built-ins by default. |
| `enabled` | `True` | If `False` (settable per-instance, e.g. in `patch()`), the patch file is written but left out of the config's `patches:` list. |
| `fatal` | `False` | If `True`, an exception aborts config generation entirely. |
| `consumes_patches` | `False` | Run after all other patchers, with `ctx.patches_snapshot()` available. |
| `serializer` | `"yaml"` | `"json_xz"` to persist `static_result()` compressed. |

`self.ctx` (an `InitContext`) provides `extracted_fs`, `fs_archive`,
`archive_files` (parsed tar members, read once), `proj_dir`, and `options`.

Dependencies between plugins are implicit: accessing another plugin's
`@cached_analysis` attribute computes it on first use and reuses it afterward
(concurrent accessors block; circular accesses raise instead of deadlocking).
There is no ordering to declare — only `order`, which controls patch override
precedence, never execution order.

## Where plugins are discovered

In precedence order (later shadows earlier, by class name):

1. `<plugin_path>/init/` — these built-ins,
2. `<project>/plugins.d/` — project-local plugins,
3. directories passed via `penguin init --init-plugin-path DIR`.

`penguin init --disable NAME` skips a plugin entirely; `--enable NAME`
force-enables a disabled-by-default patch (e.g. `--enable root_shell`).
Per-plugin results, timings, and failures are recorded in
`static/manifest.yaml`. A failing plugin is skipped with a warning (unless
`fatal`); a failing analysis fails every plugin that consumes it.

## Constraints

- File basenames must be unique across all of `pyplugins/` (the plugin
  manager's recursive lookup rejects ambiguous names) — enforced by
  `tests/unit_tests/test_init_discovery.py`.
- Don't call `plugins.load_plugin()` from `patch()`/analyses — all loading
  happens on the main thread before execution.
