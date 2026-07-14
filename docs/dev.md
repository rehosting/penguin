# Penguin Development Guide

## Installation and `./penguin` usage

After cloning this repository you can use the local `./penguin` script
to build your container and to run Penguin.

To build the image you can run:
```sh
./penguin --build
```

`--build` builds the image from the Nix flake (`nix build .#dockerImage`),
loads it into your container engine, and runs it. It requires `nix` on your
host (with flakes enabled); see [nix.md](nix.md) for the full Nix build
reference. With no `--image`, `--build` builds and runs `localhost/penguin:dev`
so it never shadows the pinned `rehosting/penguin:latest`.

You can view all the wrapper arguments that may assist with development by running
```sh
./penguin --wrapper-help
```

The penguin wrapper arguments go before penguin commands (e.g. `run`, `init`), but
can be combined, for example the following command will rebuild your container
and then run the configuration in `projects/myfw/config.yaml`

```sh
./penguin --build run projects/myfw
```

Note that the standard `penguin` wrapper command that we recommend users install
supports these development options, so you can use these wrapper flags even if
the `penguin` command is installed for a user or system.

## Iterating on Penguin's Python code

There are two loops, fastest first. Neither rebuilds the image.

### Host-only logic + unit tests — `nix develop` (no container at all)

For plugin *host-side* logic, config/schema work, `gen_docs`, linting, and the
`tests/unit/` suite, drop into the dev shell: it's the exact interpreter the
image runs (`pythonEnv`, all runtime deps) with the live `src/`, `pengutils/`,
and `pyplugins/` trees on `PYTHONPATH`, so `import penguin` resolves to your
worktree — edits take effect immediately, no build, no boot.

```sh
nix develop            # then, inside the shell:
python3 -m pytest tests/unit/ pengutils/    # host-side tests in seconds
python3 -m penguin ...                       # host tooling against live sources
```

This can't run emulation (PANDA-QEMU, `/igloo_static`, and the guest tools only
exist inside the image) — use it for everything that doesn't need a guest boot.

### Plugin behavior in a running guest — `--dev` (no rebuild)

To iterate against a *real boot* without rebuilding, use `--dev`: it
bind-mounts the live Python trees (`src/ -> /pkg`, `pengutils/ -> /pengutils`,
`pyplugins/ -> /pyplugins`) and prepends them to `PYTHONPATH` (the image is an
immutable `python3.withPackages` env with no pip, so this overlays the live tree
rather than reinstalling). Edits apply on the next `run` — no rebuild, no
root/pip step. (`--pydev` still works as a deprecated alias.)

```sh
./penguin --dev run projects/myfw     # edit src/, pengutils/, or pyplugins/ -> re-run
./penguin --build --dev run ...        # rebuild the image too (only if a baked-in dep changed)
```

By default `--dev` finds the worktree to overlay by walking up from the
current directory for a `src/penguin/` dir (falling back to the cwd), so it
works from a subdirectory. To overlay a checkout elsewhere — e.g. when the
installed `penguin` command runs from outside the repo — point it explicitly:

```sh
./penguin --dev --dev-root /abs/path/to/penguin run projects/myfw
PENGUIN_DEV_ROOT=/abs/path/to/penguin penguin --dev run projects/myfw
```

Precedence: `--dev-root` > `PENGUIN_DEV_ROOT` > auto-detect > cwd. A root
that isn't a penguin worktree (no `src/penguin/`) fails loudly instead of
silently mounting empty directories.

**What's live vs. not** (`--dev` prints this on startup):

- **Live** — `src/` (the `penguin` package *and* `src/resources/`: init scripts,
  `source.d/`, `static_keys`, … via `PENGUIN_RESOURCES=/pkg/resources`),
  `pengutils/`, and `pyplugins/`.
- **Not live — needs `--build`** — anything baked into the image: `/igloo_static`
  (kernels, `igloo_driver`, the guest tools busybox/console/guesthopper/vpnguin/
  libnvram, native helpers, musl sysroots) and the qemu fork. For a local
  sibling-repo checkout, combine with `--override-input` (see below).

## Dependency development

Penguin's dependencies (the PANDA-QEMU fork, kernels, igloo-driver,
penguin-tools, the firmware-extraction stack, …) are pinned as **Nix flake
inputs** in `flake.nix`, not downloaded at build time. To prototype a change to
one of them, point its input at your local checkout for a build:

```sh
./penguin --image penguin:dev --build ...   # uses flake.nix as-is
# or build the image directly against a local sibling-repo checkout:
nix build .#dockerImage \
  --override-input penguin-qemu path:/abs/path/to/qemu \
  --accept-flake-config
docker load < result
```

To make the change permanent, edit that input's `url` in `flake.nix` and run
`nix flake update <input>`. See [nix.md](nix.md#dependency-overrides-replacing-local_packages)
for the input list and more detail.

# Example: local kernel development

Clone the kernel builder and make your changes:

```sh
$ git clone --recurse-submodules git@github.com:rehosting/linux_builder.git && cd linux_builder
$ # Edit some files in linux/ (not shown)
$ # Build kernels-latest.tar.gz, e.g. for just 4.10 + armel
$ ./build.sh --versions 4.10 --targets armel
```

Then build the penguin image against that local artifact by overriding the
`kernels` input:

```sh
$ cd ../penguin
$ nix build .#dockerImage \
    --override-input kernels path:/abs/path/to/linux_builder/kernels-latest.tar.gz \
    --accept-flake-config
$ docker load < result
```

This builds an image with your kernel without needing to tag a new release of
the dependency on GitHub. When you are finished, build without the
`--override-input` to return to the pinned version.
