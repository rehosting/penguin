# CLAUDE.md — Penguin

This is the Penguin repo inside an IGLOO worktree workspace. The workspace
overview lives at `../CLAUDE.md`; this file covers Penguin specifically.

Penguin is a configuration-based firmware rehosting framework (NDSS BAR 2025).
The user writes a YAML `config.yaml` describing the target; Penguin generates
or refines that config and runs the firmware under PANDA-QEMU with a stack of
pyplugins providing analysis, intervention, and instrumentation.

## Entry points

- **`./penguin`** — host bash wrapper (~700 lines). Handles Docker
  orchestration, path rewriting (`./projects/foo` → `/host_projects/foo`
  inside the container), networking (auto-allocates a `192.168.x.0/24` bridge
  per run), and UID/GID mapping. Wrapper-only flags (before subcommands):
  - `--build` — rebuild the container image. Picks up files from
    `local_packages/` (see `../CLAUDE.md` for the contract).
  - `--pydev` — live-mount `src/` → `/pkg` and `pyplugins/` → `/pandata`
    inside the container and `pip install -e` Penguin before each run. Use
    this when iterating on Python code.
  - `--image NAME`, `--name NAME`, `--subnet [CIDR|none]`,
    `--extra_docker_args ...`, `--verbose`, `--wrapper-help`.

- **`src/penguin/`** — Python package and CLI. Major modules:
  - `__main__.py` — Click CLI: `init`, `run`, `explore`, `ga_explore`,
    `patch_explore`, `minimize`, `guest_cmd`, `pack`, `unpack`, `docs`,
    `shell`.
  - `penguin_config/` — config loading and schema.
    `structure.py` is the Pydantic schema (single source of truth);
    `versions/v2.py` holds the config changelog and auto-migration;
    `__init__.py` loads YAML, applies patches and drop-ins, and validates.
    `gen_docs.py` regenerates `docs/schema_doc.md`.
  - `static_analyses.py` — pre-emulation analysis (init programs, symbols,
    NVRAM keys, env vars).
  - `penguin_prep.py` / `penguin_run.py` — pre-run setup and single-run
    execution via `PandaRunner`.
  - `plugin_manager.py` — pyplugin discovery and lifecycle.
  - `gen_config.py` / `gen_image.py` — config and kernel/FS image generation.
  - `manager.py`, `graph_search.py`, `genetic.py`, `patch_search.py`,
    `patch_minimizer.py` — multi-iteration search/refinement strategies.

- **`pyplugins/`** — built-in Penguin pyplugins, grouped by intent:
  `actuation/`, `analysis/`, `core/`, `hyper/`, `hyperfile/`,
  `interventions/`, `loggers/`, `wrappers/`, `apis/`, `compat/`, `docgen/`,
  `testing/`. Each is a Python class inheriting from `penguin.Plugin`.
  See `docs/pyplugin_architecture.md` and `docs/plugins.md`.

- **`pengutils/`** — utility library (not pyplugins). Event types, DB helpers,
  guest_cmd helpers, breakpoint helpers used by plugins and CLI commands.

- **`guest-utils/`** — guest-side tools shipped into the firmware: `native/`
  (C helpers), `ltrace/`, `scripts/`. These are compiled and packaged into
  the Docker image at `/igloo_static/`.

- **`Dockerfile`** — multi-stage build (Rust builder, base, downloader,
  installer). The local-packages override block sits around lines 599–665.
  Pinned dependency versions are ARGs at the top.

## Dev iteration loop

```sh
./penguin --pydev run path/to/myfw_project   # edit src/ or pyplugins/ → re-run
./penguin --build run ...                    # changed local_packages/ or Dockerfile → rebuild
./penguin --build --pydev run ...            # both
```

`--pydev` reinstalls the package on each run, so changes to `src/penguin/` and
`pyplugins/` apply without a rebuild. Use `--build` only when you change the
Dockerfile or drop a new file into `local_packages/`.

When developing a sibling-repo dependency (busybox, hyperfs, kernels, PANDA,
etc.), build that repo's artifact, drop the resulting tarball / `.deb` / `.whl`
into `local_packages/`, and rebuild. The Dockerfile auto-detects each file
and uses it instead of the pinned release. Remove the file when finished so
later builds return to the pinned version.

## Plugin authoring

A pyplugin is a Python class extending `penguin.Plugin` with hooks like
`__init__`, `on_run`, `on_stop`, plus PyPANDA callbacks decorated with
`@panda.cb_*`. Args come from `config.yaml`'s `plugins:` section and are
read via `self.get_arg("...")` / `self.get_arg_bool("...")`.

Plugin discovery order (`docs/pyplugin_architecture.md`):
1. `plugins.d/` inside the active project directory (local plugins).
2. `/pyplugins` inside the container (built-in plugins, mounted from
   `pyplugins/` in `--pydev` mode).
3. Any path on the `plugin_path` config key.

Local prototyping pattern: drop `myplugin.py` into your rehosting project's
`plugins.d/`, then enable it in `config.yaml` with
`plugins: { myplugin: { args... } }`.

PANDA-plugin vs PyPANDA-plugin vs Penguin-pyplugin:
- **PANDA plugin** — native C/C++ compiled into the QEMU process. Plugin
  work is being migrated into the `qemu/` fork (`panda-re/qemu`); older
  plugins still live in `panda-ng/plugins/` but new ones should go in `qemu/`.
  You don't edit these from Penguin.
- **PyPANDA plugin** — Python wrapper exposing PANDA callbacks. The CLI
  imports `from pandare import Panda`; the runtime currently comes from the
  `pandare2-*.whl` published by `panda-ng/`, which Penguin ships in its image.
- **Penguin pyplugin** — Penguin's higher-level orchestration: holds state,
  reads config, may use PyPANDA callbacks internally but also exposes
  hypercalls, guest-cmd actions, event APIs, etc. **This is what you
  write to add behavior to Penguin.**

## Config schema and project layout

A rehosting project directory looks like:

```
projects/myfw/
  config.yaml              # main config (user-editable)
  base/
    fs.tar.gz              # rootfs from fw2tar
    env.yaml               # static-analysis env vars
    nvram.csv              # identified NVRAM keys
    initial_config.yaml    # auto-generated backup
  static/                  # optional: hand-curated files dropped into the FS
  init.d/, source.d/       # optional: init drop-ins (shell or C compiled in)
  plugins.d/               # optional: local plugins + their YAML args
  patch_*.yaml             # optional: config patches (auto-merged)
  results/0, results/1...  # per-run output
  results/latest -> 0      # symlink to most recent run
```

Major config sections (see `docs/schema_doc.md` for the full reference, which
is generated from `src/penguin/penguin_config/structure.py`):

- `core` — arch, kernel, fs path, strace/ltrace, timeout, plugin_path.
- `env` — kernel boot args, `igloo_init` selection.
- `static_files` — pre-boot FS modifications.
- `pseudofiles` — `/dev`, `/proc`, `/sys` modeling (read/write/ioctl handlers).
- `nvram` — initial key-value pairs.
- `netdevs` — network device names.
- `plugins` — pyplugin args.

Patches: any `patch_*.yaml` in the project root is auto-merged into
`config.yaml` at load time (`config_patchers.py`). Drop-ins under `init.d/`,
`source.d/`, `plugins.d/` are auto-discovered.

## Tests

- `tests/unit_tests/` — small targets exercised in CI. `test_target/` and
  `basic_target/` are the main fixtures.
- `tests/comprehensive/` — full rehosting scenarios under `combined/`, `env/`,
  `multiinit/`, `pseudofile/`, `search/`, `search_min/`. Runner is
  `tests/comprehensive/test.sh`; expects to be invoked inside the container.

Run from inside the workspace:
```sh
./penguin --pydev shell                    # drops into a container shell
# then, inside:
cd /pandata/../tests/comprehensive && ./test.sh
```

## Useful commands

```sh
./penguin --wrapper-help                   # all wrapper flags
./penguin run --help                       # subcommand options
./penguin docs                             # browse markdown docs inside container
./penguin init path/to/rootfs.tar.gz       # bootstrap a new project from a fs tarball
./penguin run projects/myfw                # single run
./penguin explore projects/myfw/config.yaml  # multi-iteration graph search
```

## Things worth knowing

- The wrapper runs **on the host**, not in the container; everything else
  runs inside the Docker image. Filesystem paths are rewritten at the
  container boundary — use `--verbose` to see the exact mappings.
- `--cap-add=NET_BIND_SERVICE` is set so guests can bind low ports.
- `local_packages/*` and `results/`, `projects/`, `*.tar.gz`, `*.qcow` are all
  gitignored — they're build/output artifacts, not source.
- Config schema is the source of truth: when adding a config option, change
  `src/penguin/penguin_config/structure.py` and regenerate `docs/schema_doc.md`
  via `python -m penguin.penguin_config.gen_docs` (or equivalent).
- Penguin's `Dockerfile` ARG block pins every external dependency version.
  When bumping a sibling repo's release tag, update the corresponding ARG.
