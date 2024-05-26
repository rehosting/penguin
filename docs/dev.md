# Penguin Development Guide

## Installation and `./penguin` usage

After cloning this repository you can use the local `./penguin` script
to build your container and to run Penguin.

To build the container you can run:
```sh
./penguin --build
```

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

## Dependency Development

If you wish to prototype changes to a Penguin dependency, you can develop the
dependency locally, build the artifacts, and then modify the Penguin Dockerfile
to use the local artifacts instead of pulling them from GitHub.

For example, the following workflow shows how to test modifications to the Penguin
Linux kernel.

### Example: Local kernel development

First clone and update the Linux kernel repo

```sh
$ git clone --recurse-submodules  git@github.com:rehosting/linux_builder.git && cd linux_builder
$ # Edit some files in linux/4.10 (not shown)
```

Then build the artifacts - note you don't have to build all kernels if you just wish to test
with a single architecture.

```sh
$ # Build kernels-latest.tar.gz, for example with just 4.10 and armel
$ ./build.sh --versions 4.10 --targets armel
```

Next, copy the artifacts into your Penguin source directory.

```sh
$ cp kernels-latest.tar.gz ../penguin/
```

Finally, you'll update your Penguin Dockerfile to pull this dependency locally.
Find the commented code at the end of the Dockerfile that copies the relevant artifact
from your host and installs it into the container. Uncomment that code.

```Dockerfile
COPY kernels-latest.tar.gz /tmp
RUN rm -rf /igloo_static/kernels && \
    tar xvf /tmp/kernels-latest.tar.gz -C /igloo_static/
```

Now when you build your container, it will use this local version and allow you to use
or test your changes without needing to tag a new release of the dependency on GitHub.

```sh
./penguin --build ...
```

## Singularity

To run penguin under [singularity](https://docs.sylabs.io/guides/2.6/user-guide/introduction.html#welcome-to-singularity),
you'll need to build a docker container and convert it to a singularity image. You'll likely want to do
this for both fw2tar and penguin. After obtaining both containers (by pulling or building), you can generate
the singularity containers with:

```sh
sudo docker run -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd)/:/output \
    --privileged -t --rm quay.io/singularity/docker2singularity:v3.7.2 rehosting/penguin

sudo docker run -v /var/run/docker.sock:/var/run/docker.sock -v $(pwd)/:/output \
    --privileged -t --rm quay.io/singularity/docker2singularity:v3.7.2 rehosting/fw2tar
```

Then copy the two generated `.sif` files to your singularity environment.

Unfortunately you won't be able to use our wrapper scripts with the singularity containers, so you'll
need to directly manage shared directories and running the underlying commands. For example, you can run
fw2tar with:

#### Fw2tar with Singularity
```sh
# Launch container, mapping host directory with target firmware
singularity shell -B $(pwd):/host rehosting_fw2tar-*.sif

# Run full command
Singularity > fakeroot python3 /usr/local/bin/fw2tar /host/your_fw_name.bin
Best extractor: unblob (identical) archive at your_fw_name.rootfs.tar.gz

# Or use short command
Singularity > fakeroot_fw2tar /host/your_fw_name.bin
Best extractor: unblob (identical) archive at your_fw_name.rootfs.tar.gz
```

#### Penguin with Singularity
```sh
# Create base for project directories
mkdir -p projects

# Launch container, mapping target fw directory and a projects directory
singularity shell -e -B $(pwd):/host,$(pwd)/projects:/projects rehosting_penguin-*.sif

# When running penguin, use --output_base /project to ensure projects are created in the mapped directory
Singularity> penguin init /host/your_fw_name.rootfs.tar.gz --output_base /projects/
12:30:28 penguin INFO Creating project at generated path: /projects/your_fw_name
12:30:29 penguin.gen_confg INFO Generating new configuration for /host/your_fw_name.rootfs.tar.gz...
12:30:49 penguin.static INFO Selected 1540 default NVRAM entries from: libraries (1388), defaults (159)
12:30:50 penguin.gen_confg INFO Tailoring configuration for single-iteration: selecting init and configuring default catch-all ioctl models
12:30:50 penguin.gen_confg INFO         init set to: /sbin/preinit
12:30:50 penguin.gen_confg INFO Generated config at /projects/your_fw_name/config.yaml

# Run a config
Singularity> penguin run /projects/your_fw_name
12:30:29 penguin.gen_confg INFO Generating new configuration for /host/your_fw_name.rootfs.tar.gz...
12:30:49 penguin.static INFO Selected 1540 default NVRAM entries from: libraries (1388), defaults (159)
12:30:50 penguin.gen_confg INFO Tailoring configuration for single-iteration: selecting init and configuring default catch-all ioctl models
12:30:50 penguin.gen_confg INFO         init set to: /sbin/preinit
12:30:50 penguin.gen_confg INFO Generated config at /projects/your_fw_name/config.yaml

# Run a config
Singularity> penguin run /projects/your_fw_name
```

### Singularity with local development
Within an unprivileged environment where you run singularity, you can clone penguin and use mapped directories
to prototype modifications to local source code without rebuilding the full container.

For example:
```sh
git clone git@github.com:rehosting/penguin.git
singularity shell -B $(pwd):/host,$(pwd)/projects:/projects,penguin/src:/pkg,penguin/pyplugins:/pandata rehosting_penguin-*.sif
Singularity> pip install -e /pkg
Singularity> penguin init /host/your_fw.rootfs.tar.gz
```
