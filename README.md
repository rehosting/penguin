Penguin: Configuration Based Rehosting
====

Penguin is a firmware rehosting tool designed to get your firmware up
and running in a virtual environment where you can interact with it
and closely monitor its behavior. Unlike other rehosting tools, Penguin
takes a **target-centric** approach to rehosting where the
specific details of each rehosting process are stored in a configuration
file that you can examine and edit as necessary.

There are typically four phases to rehosting a system with Penguin:

### Obtain target filesystem

Before you start with Penguin, you'll need an archive of a firmware root filesystem. This is a tarball of the root
filesystem with permissions and ownership preserved. You can generate this with the [fw2tar](https://github.com/rehosting/fw2tar) utility or by hand.

To install fw2tar (once you have penguin installed):
```
docker image tag rehosting/penguin rehosting/fw2tar

# global install
docker run rehosting/fw2tar fw2tar_install | sudo sh

# local install
docker run rehosting/fw2tar fw2tar_install.local | sh
```

To use fw2tar:
```
fw2tar your_fw.bin
```

### Generate initial configuration

Once you have a root filesystem, you can generate an initial rehosting configuration
based on a static analysis of the filesystem. This initial configuration is stored
within a "project directory" which will hold the config, static analysis results, and
the output from every dynamic analysis you run.

To generate your initial configuration you'll use the `init` subcommand to `penguin`. This
will generate a configuration for the provided firmware root filesystem. By default the
configuration will be stored in `./projects/<firmware_name>/config.yaml`. You can specify
a different output directory with the `--output` flag.

```
penguin init your_fw.rootfs.tar.gz --output projects/your_fw
```

Once you have created an initial configuration you can view and edit it if necessary.

### Run rehosting specified by configuration

To run a configuration, use the `run` subcommand. This will run the rehosting as specified
in the configuration file and report dynamic analysis results in a "results directory."
By default this directory will be within the project directory at 
`<project directory>/results/<auto-incrementing number>`.  You can also specify an output
directory with the `--output` flag and replace an existing directory with `--force`.

```
penguin run projects/your_fw/config.yaml --output projects/your_fw/results/0
```

### Refine rehosting configuration

While your rehosting is running, you can:
1. Connect to the **Penguin root shell** by running the `telnet` command printed in
Penguin's output. This command will give you interactive
shell access within the target firmware while it runs. From here you can interact
with the system and use standard debugging tools like `strace` and `gdbserver`.
2. Connect to network-listening guest services from your host machine using the
**Penguin VPN** which bridges connections from your host machine into the guest. Details
for each reachable service will be shown in Penguin's output.
3. Examine dynamic analysis output. In your results directory, a number of files will be
populated *while the system runs*, for example `console.log` which shows console output
produced by the guest.

After your rehosting terminates, additional output will be produced in your results
directory. For a full description of these outputs and the analyses creating them,
check out [docs/plugins.md](docs/plugins.md) which describes each of the dynamic
analysis plugins and the outputs they produce.

Once you have finished a run of a rehosting, consider the behavior you observed. If you
saw errors that you would like to fix, you can update your configuration to try addressing
the errors. An example of such an iterative workflow is shown in
[docs/workflow.md](docs/workflow.md).

# Installation

Penguin consists of two components, a container named `rehosting/penguin` and a wrapper
script `penguin` that runs your host machine.  The `penguin` wrapper script can be
installed from a pre-built container.

## Pull container and install `penguin`

First download the container from Docker Hub (requires authentication).
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

You can also build your penguin container from source and do local software development
by following the instructions in [docs/dev.md](docs/dev.md)

## Install `fw2tar` dependency

You should also install [fw2tar](https://github.com/rehosting/fw2tar) so you can convert 
firmware into the format penguin expects. This process is documented in the `fw2tar` repo,
but is nearly identical to the steps shown above - just pull the container and follow the
instructions shown when you run the container.

```sh
docker pull rehosting/fw2tar
docker run rehosting/fw2tar # Follow the instructions shown
```

# Learn more about Penguin

To learn more about Penguin you can look in the [docs](docs/) directory or run the `docs`
subcommand to list available documentation files which you can then select to view with
the `--filename` flag. The `README.md` file contains an overview of the project while 
`schema_doc.md` contains details on the configuration file format and options.

```
penguin docs --filename schema_doc.md
```

For additional help, you can run any of the `penguin` subcommands with a `--help` flag.


## Additional documentation

* Typical workflow:           [docs/workflow.md](docs/workflow.md) - describes the end to end process of rehosting a firmware with penguin.
* Playbook:                   [docs/playbook.md](docs/playbook.md) - describes strategies to use for rehosting firmware that don't work out of the box.
* Plugin documentation:       [docs/plugins.md](docs/plugins.md) - describes each of the dynamic analysis plugins.
* Config file documentation:  [docs/schema_doc.md](docs/schema_doc.md) - describes the configuration file format.
