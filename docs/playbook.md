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
Penguin's initial static analysis writes its results to `<project_dir>/static/`.
The init candidates are the list in `static/InitFinder.yaml`, shortest path
first. `static/EnvFinder.yaml` carries the same list under its `igloo_init` key,
alongside the other environment variables the analysis suggests.
Note that this list isn't comprehensive (it's just finding executables that contain
`start` or `init`), but it will usually find the right binary.

### How to change init:
Set `env.igloo_init` **in a patch**, not in `config.yaml`:

```yaml
# patch_init.yaml
env:
  igloo_init: /your/desired/init
```

Then either drop that file into `<project_dir>/patches/` — every `*.yaml` there
is applied automatically, no `config.yaml` edit needed — or append it to the
`patches:` list in `config.yaml`.

Editing `env.igloo_init` in `config.yaml` **looks like it works and silently
does nothing**. `penguin init` records the init it picked in
`static_patches/base.yaml`, and patches are applied *on top of* `config.yaml`,
so the generated value wins and the guest goes on dispatching the original
init. Patches later in the list override earlier ones, which is why a user
patch has to come after `static_patches/base.yaml`.

## Pseudofile modeling
Unlike regular files stored on disk, files in `/proc` (procfs) and `/dev` (devtmpfs)
aren't really a part of your filesystem. Instead these files just a way for user
space applications and the kernel to communicate. Through this interface applications
can learn about the hardware state of a system and interact with attached peripherals.

In the rehosting context, many changes will be visible here. Many hardware peripherals
a system expects to run with will no longer be present or, if they are present,
behave differently than expected. While many of these changes are acceptable, some
will be fatal and must be handled in your rehosting config.

For the full set of models you can attach to a pseudofile — including stateful
registers, sequenced responses, ioctl struct-fills, and the seek/open/release
ops — see the [pseudofile model catalog](pseudofile_models.md).

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
model is used. The [docs/schema_doc.md](docs/schema_doc.md) contains auto-generated 
documentation for these fields which will always be the most up to date. However, the
following descriptions may be of value.

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
support for getting and setting keys. These are often based off the
open source [fw_env](https://github.com/ARM-software/u-boot/blob/master/tools/env/fw_env.c) program.

### When to set boot arguments
After running a configuration, examine `env_missing.yaml` to find a list of
environment variables that were searched for in `/proc/cmdline`.

If you're unsure of what values you might want to set a key to,
try the magic value `DYNVALDYNVALDYNVAL` in your config and run again.
Then examine the generated `env_cmp.txt` output file
which will report strings that this magic value was compared against.

Alteratively, you might want to search through the filesystem to identify which
binaries or scripts are parsing this environment variable and reverse engineer them
to determine a good value. For identifying such binaries, extract the
`<project_dir>/base/fs.tar` file and then `grep` through all files. For example,
to find programs that reference `myvar` you could do:

```
# Extract filesystem
mkdir /tmp/fs
tar xvf base/fs.tar -C /tmp/fs

# Find binaries and scripts that reference `myvar`
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
for an MTD device with a specified name; `env_uboot.txt` logs the U-Boot
variable names it went looking for. When you see this, give the guest a flash
device of that name.

Flash has its own subsystem, configured under `plugins.mtd.devices`. Each entry
is named, and that name is what the guest matches on in `/proc/mtd`:

```yaml
plugins:
  mtd:
    devices:
      flash:
        model: backing_file          # persists guest writes to the host file
        backing_file: ./flash.bin    # relative paths resolve inside the project
        personality:
          type: nor
```

Then, from the root shell, `/proc/mtd` lists the name-to-device mapping.

**Match on the name, not the index.** The kernel assigns `/dev/mtdN` numbers as
devices register, so a device named `flash` is not necessarily `/dev/mtd0`. Look
its node up by name:

```sh
MTD=$(grep flash /proc/mtd | cut -d: -f1)   # -> mtd3, say
cat /dev/$MTD
```

The available models (`zeros`, `const_buf`, `backing_file`), the `personality`
geometry fields and their defaults, and how to implement custom flash physics in
Python are documented in
[pseudofile_models.md](pseudofile_models.md#mtd-flash-devices).

Legacy `pseudofiles:` entries for `/dev/mtdN` are migrated into this subsystem
automatically, so older configs keep working — but new configs should use
`plugins.mtd.devices` directly.

## Stubbing library functions

When a program calls a library function that misbehaves under emulation (a
hardware probe, a licensing check, a NVRAM accessor), forcing that function to
return a constant is often enough to get past it. Declare it under
`lib_inject.stubs`:

```yaml
lib_inject:
  stubs:
    libvendor.so:
      hw_present: { return: 1 }
      "check_*":  { return: 0 }        # glob over exported symbols
    /lib/libc.so:
      memcpy: { guard_null_args: [0, 1], return: 0 }  # skip on NULL, else real
```

This compiles down to the injected library (a generated shim + a `--defsym`
alias), so it reuses the same build path as `lib_inject.aliases`/`extra`. See
[lib_inject.md](lib_inject.md) for the full reference, including globs,
return-type overrides, the `guard_null_args` call-through, and its limits.

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
value to be `true`. Then run your target and connect with `telnet as described
in the Penguin output to get a root shell.

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

```yaml
env:
    igloo_init: /igloo/utils/sh
```