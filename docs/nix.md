# Building Penguin with Nix

The `rehosting/penguin` image is built from a **Nix flake** (`flake.nix` at the
repo root). There is no Dockerfile — the flake is the sole build path.

The flake produces a reproducible image: every dependency (the Python
environment, the PANDA-QEMU fork, `/igloo_static`, the firmware-extraction
stack, clang-20) is pinned by `flake.lock`, so two builds of the same commit
yield the same closure. It replaces what the old multi-stage Dockerfile did
with `apt` + `pip` + release downloads.

## Prerequisites

- **Nix** with flakes enabled (`experimental-features = nix-command flakes`).
- The flake declares the shared **Cachix** substituter
  (`rehosting-tools.cachix.org`) in its `nixConfig`, so a first build pulls the
  heavy artifacts (cross toolchains, the qemu fork) from the cache instead of
  compiling them. Accept it when prompted, or pass
  `--accept-flake-config`.

A cold build with no cache hits is expensive (it cross-compiles guest helpers
for ~14 arches and pulls the qemu closure); with Cachix it is mostly downloads.

## Build and run the image

The quickest path — `nix run` streams the image straight into your local
Docker/Podman daemon (no multi-GB tarball realised in the store), tagged by the
**nix build** rather than a shared `:latest`:

```sh
# Build + load into docker/podman, tagged rehosting/penguin:<nix-build-hash>
nix run --accept-flake-config .          # (or `nix run .#load`)
# ...
# Loaded rehosting/penguin:zpfmbzp06f6pwf5yw9l4sfknyxjbwzdn
# Run it with, e.g.:  ./penguin --image rehosting/penguin:<hash> run projects/your_fw
```

The tag is the image's layer-closure hash, so each distinct build loads under
its own unique, reproducible reference: same inputs → same tag, any change → a
new tag, and builds never clobber each other on `:latest`. The command prints
the exact `--image` reference to run.

Alternatively, build a tarball first (e.g. to inspect it or push it), then load:

```sh
# Build the image (result is a docker-loadable tarball, tagged :latest)
nix build .#dockerImage --accept-flake-config

# Load it into the local Docker daemon as rehosting/penguin:latest
docker load < result

# Run with the normal wrapper, pointing at the loaded tag
./penguin --image rehosting/penguin:latest run projects/your_fw
```

`nix build .#dockerImage` emits a `dockerTools.buildLayeredImage` tarball; the
image is named `rehosting/penguin:latest`, layered on `ubuntu:22.04` (so it
keeps a normal FHS userland + `apt`), with the Nix-built components on top.
`nix run`/`.#load` instead uses the streaming variant
(`dockerImageStreamHashed`, `streamLayeredImage` with `tag = null`) — same
layers, but piped directly into the engine and content-hash-tagged.

The `./penguin` wrapper's `--build` flag does the above for you — it runs
`nix build .#dockerImage`, loads the result into your container engine, and
retags it to the run image (`localhost/penguin:dev` by default, or whatever
`--image` selects). It uses `buildLayeredImage` rather than the streaming
variant on purpose: the per-layer tarballs are cached in the store, so a warm
rebuild only re-tars the layers that actually changed (fast dev inner loop),
whereas `nix run`/`.#load` re-streams the whole image each time:

```sh
./penguin --build run projects/your_fw   # rebuild from the flake, then run
```

## Flake outputs

Built for both `x86_64-linux` and `aarch64-linux`. Build any with
`nix build .#<name>`:

| Output | What it is |
|--------|------------|
| `dockerImage` | the full `rehosting/penguin:latest` image tarball |
| `dockerImageStream` | streaming variant of `dockerImage` (`nix run .#dockerImageStream \| docker load`); no store tarball, still `:latest` |
| `dockerImageStreamHashed` | streaming image tagged by the nix build hash (`:` `<hash>`), backing `nix run` / `.#load` |
| `docsImage` | `rehosting/penguin:docs` — the runtime image plus the sphinx toolchain + texlive, used by the docs release job |
| `pythonEnv` *(default)* | the interpreter the image runs: penguin + all runtime deps |
| `penguin` | the penguin Python package alone |
| `pengutils` | the `pengutils` helper package |
| `penguinQemu` | the PANDA-QEMU fork staged as the `/usr/local` overlay |
| `iglooStatic` | the assembled `/igloo_static` tree (kernels, driver, guest utils) |
| `nativeHelpersTree` | the cross-built guest native helpers, `out/<arch>/<bin>` |
| `muslHeaders` | per-arch musl headers for the drop-in sysroots |
| `vhostDeviceVsock` | the static `vhost-device-vsock` host backend |

Inspect without building the whole image, e.g. `nix build .#iglooStatic` then
`find result/`.

## How the pieces fit together

### The qemu seam

The PANDA-QEMU fork is the one input most likely to change. It is consumed as
**its own flake**, pinned by release tag:

```nix
inputs.penguin-qemu.url = "github:rehosting/qemu/v0.0.12";
```

We use the flake's `penguin-qemu` *package* output (not a `fetchurl` of the
release tarball): the Nix-built `libqemu-system-*.so` / `qemu-img` carry
`/nix/store` rpaths, so consuming the package drags its runtime closure
(glibc, pixman, libfdt, glib, slirp) into the image — a plain tarball would
leave those dangling. It also ships CFFI env modules built against this flake's
CPython (3.13), so they match penguin's interpreter.

**To move to a new qemu release** (after it is tagged and released):

```sh
# edit flake.nix: inputs.penguin-qemu.url = "github:rehosting/qemu/vX.Y.Z";
nix flake update penguin-qemu --accept-flake-config
nix build .#dockerImage --accept-flake-config   # re-validate
```

The qemu fork's `build.sh` controls which system targets ship via
`PENGUIN_SYSTEM_ARCHES`. The library name must match what penguin's
`arch_registry` resolves — e.g. the x86_64 guest needs
`libqemu-system-x86_64.so` (shipped from qemu **v0.0.12**; earlier releases
only had the `intel64` alias).

### Guest native helpers — dynamic vs. static

`nix/mk-native-helpers.nix` cross-compiles `guest-utils/native/*.c` per arch,
mirroring that directory's `Makefile` **per-binary** link rules. This
distinction is load-bearing, not cosmetic:

- `test_nvram`, `uprobes_test`, `proc_mtd_dynamic` are built **dynamic**, with
  an explicit `--dynamic-linker=/igloo/dylibs/ld-musl-<arch>.so.1`
  (`proc_mtd_dynamic` also links `-ldl`). These rely on `LD_PRELOAD` /
  `dlsym` at runtime. **A statically linked binary silently ignores
  `LD_PRELOAD`**, so e.g. `lib_inject.so`'s constructor never fires — the
  guest boots but the injected behavior is missing, with no error.
- `test_executable` is static but **unstripped**; everything else is
  `-s -static`.

If a helper "builds fine" but behaves wrong at runtime, diff its ELF against
the Docker image's copy (`readelf -h/-l/-d`): a wrong static-vs-dynamic choice
or a missing `INTERP` is invisible until the guest runs.

### `/igloo_static`

`nix/mk-igloo-static.nix` assembles `/igloo_static` from the pinned kernel,
igloo-driver, and penguin-tools release tarballs plus the `guest-utils` source,
reproducing the Dockerfile's per-arch symlink staging. The result is
golden-diffed against the Docker image's tree.

### Writable paths

The image is otherwise immutable, but qemu writes its `snapshot=on` drive
overlay under `/var/tmp`, so `nix/mk-image.nix` materializes a writable
`/var/tmp` (and `/tmp`, `/root`). Without it the guest fails to launch with
"Could not open temporary file '/var/tmp/vl.XXXXXX'".

## Architecture coverage

The flake builds every bootable **system** target — **12** distinct arches:

```
armel  aarch64  mipsel  mipseb  mips64el  mips64eb
powerpc  powerpc64  powerpc64le  riscv64  loongarch64  x86_64
```

`powerpc64el` is an accepted *alias* of `powerpc64le` (same `ppc64-softmmu`
library), so it is not a separate build. `x86_64` and `intel64` likewise share
one compiled module.

## CI integration

`.github/workflows/build.yaml` validates the flake on every PR **alongside**
the Docker build:

- **`build_container_nix`** — runs `nix build .#dockerImage` (via
  `rehosting/ci/actions/nix-setup`, pulling from the `rehosting-tools` Cachix
  cache), loads it, and pushes the image under a `<sha>-nix` tag. The Docker
  `build_container` job is untouched and still pushes `<sha>`.
- **`run_tests_nix`** — runs the full `basic_target` + `test_target` suites
  against the `<sha>-nix` image across all 12 system arches. This includes
  `powerpc` (32-bit BE) and `powerpc64le`, which the flake ships but the legacy
  qemu `.deb` does not — the Docker matrix stays at its original 10.

## Updating pinned inputs

All external artifacts are flake inputs pinned in `flake.lock`:

```sh
nix flake metadata                         # show every input + its pin
nix flake update <input> --accept-flake-config   # bump one (e.g. kernels, igloo-driver)
nix flake update --accept-flake-config            # bump all
```

Inputs include `penguin-qemu`, `kernels`, `igloo-driver`, `penguin-tools`,
`musl-src`, `ltrace-src`, `vhost-device`, and `fw2tar` (whose closure supplies
the firmware-extraction stack). Re-run `nix build .#dockerImage` after any bump.

## Dependency overrides (replacing `local_packages/`)

The old Dockerfile let you drop a prebuilt artifact into `local_packages/` to
override a pinned dependency. The flake has no such mechanism — dependencies are
pinned as flake inputs, so to test a local change to a sibling repo (qemu,
kernels, igloo-driver, …) point its input at your checkout:

```sh
# Build against a local qemu checkout instead of the pinned release:
nix build .#dockerImage --override-input penguin-qemu path:/abs/path/to/qemu --accept-flake-config
```

For a permanent change, edit the input's `url` in `flake.nix` and
`nix flake update <input>` (see [Updating pinned inputs](#updating-pinned-inputs)).

## Not yet covered

- A Nix **devShell** for the `--pydev` live-edit loop is not yet implemented.
  `./penguin --pydev` still mounts `src/`→`/pkg` and `pip install -e`s over the
  image for iterating on `src/` and `pyplugins/`; for a from-scratch image
  rebuild use `./penguin --build` (which runs `nix build .#dockerImage`).
