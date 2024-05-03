Penguin: Configuration Based Rehosting
====

Given a tarball of a firmware's root filesystem, penguin generates a configuration file specifying
the rehosting process for the firmware. This configueration file can be refined by hand or automated
analyses to improve a rehosting.

There are two stages to running penguin:

## Project Creation: `init`

Initialize a penguin project with the `init` command. By default this will create a project folder in `./projects/firmware_name/` which
contains `config.yaml` specifying the rehosting as well as static analysis results. An `--output` argument can be passed to specify
another directory to store the project in.
```
./penguin init ./path/to/your_firmware.tar.gz
```

## Run configuration: `run`

Run the rehosting as specified by a given configuration. Note that configuration files can have arbitrary names, but must be stored
within a penguin project directory. By default output from a run will be stored within the project directory at `results/X` where `X` is
an auto-incrementing run number. An `--output` argument can be passed to specify another directory to store results in.

```
penguin run ./projects/your_firmware/config.yaml
```


# Installation

Penguin consists of two components, a container named `rehosting/penguin` and a wrapper script `penguin` that runs your host machine.
The `penguin` wrapper script can be installed from a pre-built container.

## Pull Container and install `penguin`

First download the container from dockerhub (requires authentication).
```sh
docker login
docker pull rehosting/penguin
```

You can then install the penguin command system-wide or locally:

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

# Rehosting Workflow

## Convert firmware blob to root filesystem archive

Install [fw2tar](https://github.com/rehosting/fw2tar) (or `docker pull rehosting/fw2tar`) and use it to convert a firmware blob into a root filesystem.

## Initialize project from root filesystem archive
```
./penguin init ./path/to/your_firmware.tar.gz
```

This will create a project in `./projects/your_firmware`. In this directory you can view and edit the generated `config.yaml` file.
You can also examine static analysis outputs in the `base` directory which has useful information, including:

* `image.qcow`: an immutable "base image" that stores the original firmware's filesystem with minimal modifications.
* `env.yaml`: a list of statically-identified environment variables you may later need to set
* `pseudofiles.yaml`: a list of statically-identified `/dev` and `/proc` files that you may later need to model.

## Run your configuration and collect output:
Run your initial configuration and store output in a directory called `test`:
```
penguin run projects/your_firmware/config.yaml --output projects/your_firmware/test
```

This rehosting will run until you terminate the command or the rehosting shuts down. Press Ctrl-C to gracefully shutdown the rehosting.
While the rehosting runs you will see some results in your output directory (e.g., `tail -f your_firmware/test/console.log` will trace the console output).
After the rehosting terminates, additional output will be produced. See the **Penguin Plugins** section below for an overview of the analysis output produced by the
various penguin plugins.

## Update configuration
You can modify a configuration file to try improving or chaning your rehosting.
A detailed guide of changes to make are listed in the **Penguin Playbook** section
below.

After you've modified your configuration, run the updated configuration and
specify a new output directory. Pick a better name than `second_try`, perhaps
something that describes what you changed (or drop the `--output` argument to get an auto-incrementing numerical directory in `[project_dir]/results`).

```
penguin run projects/your_firmware/config.yaml --output projects/your_firmware/changed_something
```

If this run doesn't panic, you can shut it down by typing `q` at the `(qemu)` prompt after a minute. Then examine the output and try refining it further.

You can also try connecting to network-listening services using the `vpn` plugin. More information is provided below in the docs for the `vpn` plugin


# Penguin Plugins
The following penguin plugins are currently supported. Each is documented below.
* `env`
* `health`
* `pseudofiles`
* `shell`
* `coverage`
* `vpn`
* `nmap`
* `zap`


## Env
The `env` plugin dynamically tracks linux environment variables accessed through
 `/proc/cmdline` and calls to `getenv`. It also tracks accesses to `/proc/mtd`
 as well as `/dev/mtdX` to identify accesses to u-boot environment variables.

In a config file, a user may add key-value pairs into the `env` filed to set new
values into the linux environment. Note that a number of required internal variables
(e.g., `root=/dev/vda`) will added to the system's arguments _after_ any arguments you specify here.

## Health
The `health` plugin tracks the system health over time. `health.csv` tracks counts
of various behaviors of interest over time while `health_final.yaml` just reports
these values at the end of execution.

The plugin also creates `health_procs.txt` as a sorted list of processes run and
`health_procs_with_args.txt` as a sorted list of processes with their arguments.

## Pseudofiles
This plugin tracks accesses and interactions with files in `/dev/` and `/proc/`.
In `pseudofiles_failures.yaml` details of failed interactions are reported.

Users can add pseudofiles and configure models for reads, writes, and IOCTLs on
these files by adding entries into the `pseudofiles` config section.

## Shell
This plugin tracks the behavior of shell scripts, capturing coverage in `shell_cov.csv`, environment variable values in `shell_env.csv` and a combined trace in `shell_cov_trace.csv`.

## Coverage
This plugin tracks the module and offset block level coverage of all binaries
in the system. These results are reported in `coverage.csv`.
The file `coverage_tree.csv` stores this information with parent/child
relationships to visualize as a tree. The file `coverage_transitions.csv`
records all context switches between processes.

## VPN
When running your container with sufficent privileges, this
plugin detects network binds and configures the IGLOO VPN to bridge
network connections to guest services. The details of network-listening guest
services are recorded in `vpn_netbinds.csv` while the details of what
host ports are bridged are recorded in `vpn_bridges.csv`.

For example, if `vpn_bridges.csv` contains:

```
procname,ipvn,domain,guest_ip,guest_port,host_port
lighttpd,ipv4,tcp,127.0.0.1,80,80
lighttpd,ipv4,tcp,192.168.0.1,80,48823
```

This means lighttpd started listeing on port 80 on the loopback interface as well as another IP address.
To talk to the service as if you were connecting via loopback, you'd connect to the relevant `host_port`, here 80.
To talk to the service as if you were connecting via the other IP address, you'd connect to the other `host_port`, here 48823.

Note these are ports within your container, not on your host. You can configure docker to bridge traffic between guest and host ports
or you can connect using command line tools from within your container.

## Nmap
This plugin runs nmap scans on all network-listening services.
It depends on the VPN plugin to establish network connections to guest services.
Logs are written to `nmap_{protocol}_{port}.log`

## ZAP
This plugin runs the [zap web application scanner](https://github.com/zaproxy/) to crawl and interact with guest
web applications listening on TCP port 80. Logs are written to `zap.log` and `zap_tcp_80.log`.

# Penguin Playbook

As you go through your rehosting loop, editing configs and seeing what happens when
they're run, you're trying to mitigate observed failures and improve system health.
There are three key choices you'll want to focus on at the start:

* init program selection
* pseudofile modeling
* kernel environment variables

## Init program selection
In a Linux-based system, the __init program__ is the first program (script or binary)
run by the kernel. This program is responsible for starting all other programs on
the system. If the wrong program is selected, it might crash, error, or even run
successfully and exit. An init program should never do any of these things: you want
your init program to run until the system shuts down.

**Penguin configs set the init program in the `env` section as the `igloo_init` field.**

Your initial rehosting configuration is automatically populated with a 
potentially-correct init binary. However this may be incorrect and you might
want to change it.

### When to change init
If you firmware kernel panics when init exits with a code of 0, you probably have
the wrong init binary. In this case towards the end of your `console.log` you'll
see a line like this:
```
[   63.581671] Kernel panic - not syncing: Attempted to kill init! exitcode=0x00000000 
```

If you instead see a similar line with a non-zero exit code, this could indicate
that you have the wrong init selected or that something else is going wrong causing
the correct init program to crash. You could either try another init or try
tracking down other failures and seeing what changes.


### Potential init programs to choose from
The static analysis that put results in `/results/your_fw/base/` will have created a
file called `init.yaml` with a list of likely init binaries found inside your firmware.
Note that this list isn't comprehensive (it's just finding executables that contain
`start` or `init`), but it will usually find the right binary.

### How to change init:
In your config file, change the `igloo_init` key under the `env` section:

```
env:
  igloo_init: /your/desired/init
```

## Pseudofile modeling
Unlike regular files stored on disk, files in `/proc` (procfs) and `/dev` (devtmpfs) aren't really a part of your filesystem. Instead these files just a way for user
space applications and the kernel to communicate. Through this interface applications
can learn about the hardware state of a system and interact with attached peripherals.

In the rehosting context, many changes will be visible here. Many hardware peripherals
a system expects to run with will no longer be present or, if they are present,
behave differently than expected. While many of these changes are acceptable, some
will be fatal and must be handled in your rehosting config.

### When to create pseudofile models
If you see errors in your `console.log` about missing devices or it seems like
services are crashing or failing to start, pseudofiles are a good place to begin
making changes.

### Potential pseudofiles to add
After each run, the `pseudofiles` plugin will populate the `pseudofiles_failures.yaml`
file in the output directory. The first layer of keys show the filenames that programs
tried and failed to access during execution. Within each of those values, you'll get
the name of the interaction as well as a count of the number of times it was attempted.

Note that you don't generally need to model every pseudofile you see here. These models
are generally low quality shims just trying to get a program to stop crashing. But if 
applications are behaving correctly when a pseudofile is missing, you may be better off
by leaving that alone instead of creating a model and trying to make it correct.

First, you'll see failed accesses to a pseudofile and add this file into your
config. Then, you can run with the new config and see if and how applications try to
interact with the newly added pseudofile.

### Modeling pseudofiles
Beyond allowing you to add pseudofiles into a system, penguin also allows
you to specify how `read`s, `write`s, and `ioctl`s of these files should be modeled.

After adding a pseudofile to a config and running it, you might see
guest applications try to interact with this newly created psueodfile. The
`pseudofiles` plugin will collect the details of these accesses in the `pseudofiles_modeled.yaml`.

In this file, you'll see keys of device paths with a list of interactions that
were modeled on that device. You'll see details for `read`s, `write`s, and `ioctl`s.

Each of these three behaviors can be modeled in various ways. By default, the `default`
model is used.

#### Read modeling

**default**: Return an empty string with return value `-EINVAL`.

**const_buf**: Given some string in `val` model the file as containing that data.

**const_map**: Given a list of constants, model the file as a large buffer with just the specified values set.
Arguments: `size` for total size, `pad` for what to place between values (byte value as int or a character).
Provide a dictionary in `vals` with keys as an integer offset into the buffer and values as strings or lists of byte values.

**const_map_file**: like const\_map, but adds a `filename` field. Will create this file on your host (container) if it doesn't exist with contents based on the const\_map details and then read from the host file.

**from_file**: Given a host (container) file path in `filename` read from that file

#### Write modeling

**default**: Return value `-EINVAL`

**discard**: Do nothing with the value and return as if the write was successful.

**to_file**: Given a host (container) file path in `filename` write to that file

#### IOCTL modeling
IOCTLs have a command number and each command can be modeled distinctly. A wildcard `*` can be used as a command number to indicate that all other ioctls should be modeled in a given way.

**default** Return `-ENOTTY`

**return_const**: Return the specified `val`

**return_symex**: Coming soon.

### How to model pseudofiles:
In your config file, you'll insert new keys udner `pseudofiles` for each file you want to model. By specifying a key (which must start with `/dev/` or `/proc/`), you'll
change the system so that a pseudofile is present at the specified location. If this is
all you wish to do, you'll specify the key as having a value of `{}`.
Otherwise, if you'd like to model the behavior of the pseudofile, you'll add one or more subkeys of `read`, `write,` and `ioctl` and specify the model details.

To just add `/dev/missing` into the filesystem:

```
pseudofiles:
  /dev/missing: {}
```

To actually model what happens once this device is accessed we could expand this so

* reads return the string hello world, 
* writes appear to work but actually do nothing, and
* IOCTLs all return 0


```
pseudofiles:
  /dev/missing:
    read:
        model: const_buf
        val: "hello world"
    write:
        model: discard
    ioctls:
        '*':
            model: return_const
            val: 0
```


## Kernel environment variables
Before the Linux kernel is launched, a bootloader typically sets up a system with some
initial state. There are two key sets of environment variables we may care about,
the first is much more common than the second.

**Linux kernel boot arguments**: these are arguments passed to the Linux kernel at
boot time. These control things such as where the root filesystem is and there
serial console configuration. A system's bootloader may be configured to pass
nonstandard arguments through these arguments.

The init program will be given many of these values in its environment while regular applications may examine these arguemnts by reading from `/proc/cmdline`.

**U-Boot Environment**: If the `U-Boot` bootloader is used, it may have its own set
of environment variables that can be passed through to the Linux kernel through
one of the `/dev/mtdX` devices (where X is a number).
These are typically stored with a hash followed by
null-terminated key=value pairs: `[crc32][key=value]\0[key=value]...`.

A mapping of MTD device names to the corresponding `/dev/mtdX` is available
at `/proc/mtd`. Applications may hardcode which MTD devices they try to
read from or dynamically search `/proc/mtd` to find which device a
given name corresponds to.

Typically a custom binary is used to access U-Boot environments with
support for getting and setting keys. These are foten based off the
open source [fw_env](https://github.com/ARM-software/u-boot/blob/master/tools/env/fw_env.c) program.

### When to set boot arguments
After running a configuration, examine `env_missing.yaml` to find a list of
environment variables that were searched for in `/proc/cmdline`.

If you're unsure of what values you might want to set a key to,
try the magic value `DYNVALDYNVALDYNVAL` in your config and run again.
Then examine the generated `env_cmp.txt` output file
which will report strings that this magic value was compared against.

Altneratively, you might want to search through the filesystem to identify which
binaries or scripts are parsing this environment variable and reverse enginner them
to determine a good value. For identifying such binaries, extract the `base/fs.tar` file and then `grep` through all files. For example, to find programs that reference
`myvar` you could do:

```
# Extract filesystem
mkdir /tmp/fs
tar xvf base/fs.tar -C /tmp/fs

# Find binaries and scripts that reference myvar
grep --binary 'myvar' /tmp/fs'
```

Matching binaries can be analyzed with a tool like Ghidra while scripts can be
analyzed with any text editor.

### How to set boot arguments:
In your config file add new values into the `env` section as key-value pairs.

```
env:
  my_env_name: my_value
```

### When to set U-Boot Environment variables
If you see output in `env_mtd.txt`, penguin detected an application searching
for an MTD device with a specified name. When you see this, you may wish to add
a new MTD device by adding an `mtdparts` env variable specifying values for the `0.flash` device. After this device name, you'll craft a comma-seperated list of `0xsize(name)` values. Your sizes should be multiples of 0x4000.

```
env:
    mtdparts: 0.flash:0x4000(yourname),0x8000(anothername)
```

After adding such an entry, the guest will be configured to have new MTD devices named `yourname` and `anothername` and new `/dev/mtdX` files will also be created.

Generally the values of `X` should correspond to the order in which you've specified these devices (e.g., `yourname` is `/dev/mtd0`, `anothername` is `/dev/mtd1`).
You can confirm this by connecting to the root shell and examining `/proc/mtd`
which will list the mapping from name to device file.

If you'd like to then control the contents of that mtd device, use the `pseudofiles`
plugin. If you'd like to create a valid u-boot environment with arbitrary key-value pairs, check out the `makeuboot.py` script.

Alternatively, if you add the variable `MTD_PLACEHOLDER` and set it to 1 in your config's `env`, penguin will automatically set up `/dev/mtdX` for all X in 1 to 10 with a placeholder value. When running in this mode, penguin will analyze accesses to these
devices and track variable names searched for. These names will be logged in the output
file `env_uboot.txt`

After setting these values, you'll need to customize `makeuboot.py` to generate a
valid uboot key-value store then customize your `pseudofile` config to pass this
file through on reads of the relevant device. Bringing this together, you might
create the file `/results/mtd.flash` (abusing the shared `results` directory to share
something that isn't a result) with `makeuboot.py` and then pass it through
to your firmware with a config with elements like this:

```
env:
    mtdparts: 0.flash:0x4000(flash)

pseudofiles:
    /dev/mtd0:
        read:
            model: from_file
            filename: /results/mtd.flash
        write:
            model: to_file
            filename: /results/mtd.flash
        ioctl:
            '*':
                model: return_const
                val: 0
```

## Advanced debugging
If you've tried selecting the correct init program, modeling psueodfiles, and
adding environment variables but things are still failing, you'll need to
try some more involved debugging.

First examine the console output for error messages that relate to processes
being killed, missing files, bad arguments, and so on. Examine scripts and binaries
as necessary.

Next examine output from other plugins. The `shell_cov_trace.csv` script may
be particularly useful as it shows each line from shell scripts executed in the
order they were run with concrete values listed along with each variable.
For example if a script `foo.sh` has a 10th line of  `if [ -e $myfile ]; then` and the `myfile` variable was set to `/root/myfile`, the log would show this as:

```
foo.sh:10,if [ -e $(myfile=>/root/myfile)]
```

Next enable the root shell by changing your config's `base` section's `root_shell`
value to be `true`. Then run your target and connect from another shell on your
host machine with:

```
docker exec -it [YOUR_CONTAINER_NAME] rootshell
```

After launching this, press enter a few times and perhaps wait ~10s.
You should then get a root prompt and be able to run shell commands.

From this shell you can try running `strace` on various guest
applications to see how they behave dynamically.
You can examine running processes with `ps aux` and then connect
strace to a running process with `strace -p [PID]` 

If your guest is kernel panicking and shutting down or you'd just like
more explicit control of what's being run, you can change your config
to skip running the right init program and instead just launch a shell
that doesn't exit by setting:

```
env:
    igloo_init: /igloo/utils/sh
``
