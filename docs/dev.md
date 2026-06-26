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

For fast iteration on `src/` and `pyplugins/` without rebuilding the image, use
`--pydev`, which live-mounts your source over the image and reinstalls it before
each run:

```sh
./penguin --pydev run projects/myfw     # edit src/ or pyplugins/ -> re-run
./penguin --build --pydev run ...        # rebuild the image too
```

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
