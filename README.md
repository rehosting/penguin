Penguin: Configuration Based Rehosting
====

Penguin can generate a project with a configuration for a firmware and
run a rehosting as specified in a config.

Before you start with Penguin, you'll need an archive of a firmware root filesystem. This is a tarball of the root
filesystem with permissions and ownership preserved. You can generate this with the [fw2tar](https://github.com/rehosting/fw2tar) utility or by hand.

```
fw2tar your_fw.bin
```

Once you have a root filesystem, you can generate an initial rehosting configuration
based on a static analysis of the filesystem. This initial configuration is stored
within a "project directory" which will hold the config, static analysis results, and
the output from every dynamic analysis you run.

To generate your initial configuration you'll use the `init` subcommand to penguin. This
will generate a configuration for the provided firmware root filesystem. By default the
configuration will be stored in `./projects/<firmware_name>/config.yaml. You can specify
a different output directory with the `--output` flag.

```
penguin init your_fw.rootfs.tar.gz --output projects/your_fw
```

Once you have created an initial configuration you can view and edit it if necessary.

To run a configuration, use the `run` subcommand. This will run the rehosting as specified
in the configuration file and report dynamic analysis results in a "results directory."
By default this directory will be within the project directory at 
`<project directory>/results/<auto-incrementing number>`.  You can also specify an output
directory with the `--output` flag and replace an existing directory with `--force`.

```
penguin run projects/your_fw/config.yaml --output projects/your_fw/results/0
```

Some dynamic analysis output will be logged into the results directory *during* the emulation, 
for example the file `console.log` within the directory will be updated as console output is 
produced from the guest. Other output will be generated after the emulation completes such
as information on pseudofiles accessed, network binds, and environment variables accessed.

To learn more about Penguin you can look in the [docs](docs/) directory or run the `docs`
subcommand to list available documentation files which you can then select to view with
the `--filename` flag. The `README.md` file contains an overview of the project while 
`schema_doc.md` contains details on the configuration file format and options.

```
penguin docs --filename schema_doc.md
```

For additional help, you can run any of the `penguin` subcommands with a `--help` flag.

# Installation

Penguin consists of two components, a container named `rehosting/penguin` and a wrapper
script `penguin` that runs your host machine.  The `penguin` wrapper script can be
installed from a pre-built container.

## Pull container and install `penguin`

First download the container from dockerhub (requires authentication).
```sh
docker login
docker pull rehosting/penguin
```

You can then install the `penguin` command system-wide or locally. These instructions will
be shown if you run `docker run rehosting/penguin`.


### System-wide install:
```sh
docker run rehosting/penguin penguin_install | sudo sh
```

### Local install:
```sh
docker run rehosting/penguin penguin_install.local | sh
```

## Local development from source

After cloning this repository you can use the local `./penguin` script to build your container and to run penguin.
To build the container you can run:
```sh
./penguin --build
```

You can view all the wrapper arguments that may assist with development by running
```sh
./penguin --wrapper-help
```

## Install `fw2tar` dependency

You should also install [fw2tar](https://github.com/rehosting/fw2tar) so you can convert 
firmware into the format penguin expects. This process is documented in the `fw2tar` repo,
but is nearly identical to the steps shown above - just pull the container and follow the
instructions shown when you run the container.

```sh
docker pull rehosting/fw2tar
docker run rehosting/fw2tar # Follow the instructions shown
```

# Additional documentation

* Typical workflow:           [docs/workflow.md](docs/workflow.md) - describes the end to end process of rehosting a firmware with penguin.
* Playbook:                   [docs/playbook.md](docs/playbook.md) - describes strategies to use for rehosting firmware that don't work out of the box.
* Plugin documentation:       [docs/plugins.md](docs/plugins.md) - describes each of the dynamic analysis plugins.
* Config file documentation:  [docs/schema_doc.md](docs/schema_doc.md) - describes the configuration file format.