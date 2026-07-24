# Penguin Configuration

Configuration file for config-file-based rehosting with IGLOO

## `core` Core configuration options

Core configuration options for this rehosting

### `core.arch` Architecture of guest

|||
|-|-|
|__Type__|`"armel"` or `"arm"` or `"armle"` or `"aarch64"` or `"arm64"` or `"mipsel"` or `"mipseb"` or `"mipsbe"` or `"mips64el"` or `"mips64eb"` or `"mips64be"` or `"powerpc"` or `"ppc"` or `"powerpc64"` or `"ppc64"` or `"powerpc64le"` or `"ppc64le"` or `"powerpc64el"` or `"ppc64el"` or `"riscv64"` or `"riscv"` or `"rv64"` or `"loongarch64"` or `"loongarch"` or `"la64"` or `"x86_64"` or `"intel64"` or `"amd64"` or `"x86-64"` or `"x64"` or null|
|__Default__|`null`|

Canonical name or an accepted alias (normalized at load, e.g. intel64 -> x86_64).

```yaml
x86_64
```

```yaml
armel
```

```yaml
aarch64
```

```yaml
mipsel
```

```yaml
mipseb
```

```yaml
mips64el
```

```yaml
powerpc64le
```

### `core.kernel` Path to kernel image

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
/igloo_static/kernels/zImage.armel
```

```yaml
/igloo_static/kernels/zImage.arm64
```

```yaml
/igloo_static/kernels/vmlinux.mipsel
```

```yaml
/igloo_static/kernels/vmlinux.mipseb
```

```yaml
/igloo_static/kernels/vmlinux.mips64el
```

```yaml
/igloo_static/kernels/vmlinux.mips64eb
```

### `core.fs` Project-relative path to filesystem tarball

|||
|-|-|
|__Type__|string or null|
|__Default__|`./base/fs.tar.gz`|


```yaml
base/fs.tar.gz
```

### `core.plugin_path` Path to search for PyPlugins

|||
|-|-|
|__Type__|string|
|__Default__|`/pyplugins`|


```yaml
/pyplugins
```

### `core.root_shell` Enable root shell

|||
|-|-|
|__Type__|boolean|
|__Default__|`false`|

Whether to enable a root shell into the guest

```yaml
false
```

```yaml
true
```

### `core.analysis_scope` Scope of per-process analysis

|||
|-|-|
|__Type__|boolean or string|
|__Default__|`firmware`|

Which processes the per-process analysis loggers capture. Affects the syscall/exec-derived loggers (syscalls, exec, read/write, ficd, interfaces) and busybox shell coverage; netbinds always reports for every process regardless of this setting. Recognized values: 'firmware' (default) captures only the firmware-under-analysis process subtree, excluding Penguin's own infrastructure (boot machinery and the vpnguin/console/guesthopper helpers); 'none' captures every process, including Penguin infrastructure; 'infra' inverts the firmware filter to capture only Penguin's own tools. Booleans are accepted for backward compatibility: true == 'firmware', false == 'none'. The field is a string so further interpretations can be added without a schema change.

```yaml
firmware
```

```yaml
none
```

```yaml
infra
```

### `core.strace` Enable strace

|||
|-|-|
|__Type__|boolean or list of string|
|__Default__|`false`|

If true, run strace for entire system starting from init. If names of programs, enable strace only for those programs.

```yaml
false
```

```yaml
true
```

```yaml
- lighttpd
```

### `core.ltrace` Enable ltrace

|||
|-|-|
|__Type__|boolean or list of string|
|__Default__|`false`|

If true, run ltrace for entire system starting from init. If names of programs, enable ltrace only for those programs.

```yaml
false
```

```yaml
true
```

```yaml
- lighttpd
```

### `core.gdbserver` Programs to run through gdbserver

|||
|-|-|
|__Default__|`{}`|

Mapping between names of programs and ports for gdbserver. When a program in this mapping is run, it will start paused with gdbserver attached, listening on the specified port.

```yaml
{}
```

```yaml
lighttpd: 9999
```

#### `core.gdbserver.<string>` Port

|||
|-|-|
|__Type__|integer|
|__Default__|`null`|


### `core.snapshot` Snapshot configuration

|||
|-|-|
|__Default__|`null`|

VM snapshot (savevm/loadvm) configuration.

    Snapshotting is *active* whenever ``save_at`` or ``boot_from`` is set — there
    is no separate enable flag. When active, the guest runs on a persistent
    qcow2 overlay (rather than the throwaway immutable overlay) so an internal VM
    snapshot can be saved and later restored. Saving a snapshot at a chosen point
    lets a later run boot directly from that state instead of re-booting the
    firmware.
    

#### `core.snapshot.backend` Snapshot backend

|||
|-|-|
|__Type__|`"internal"` or `"file"`|
|__Default__|`internal`|

'internal' stores the snapshot inside the qcow2 overlay (savevm/loadvm). 'file' (not yet implemented) writes a standalone migration file bundle.

```yaml
internal
```

```yaml
file
```

#### `core.snapshot.tag` Snapshot tag

|||
|-|-|
|__Type__|string|
|__Default__|`boot`|

Name of the internal VM snapshot to save and/or restore.

```yaml
boot
```

```yaml
post_init
```

#### `core.snapshot.save_at` When to save the snapshot

|||
|-|-|
|__Type__|`"readiness"` or `"manual"` or null|
|__Default__|`null`|

'readiness' saves once the guest reaches steady state; 'manual' arms the Snapshot plugin to save on request (via guest_cmd / hypercall). None disables saving.

```yaml
readiness
```

```yaml
manual
```

#### `core.snapshot.boot_from` Snapshot tag to boot from

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

If set, restore this internal snapshot at startup (-loadvm).

```yaml
boot
```

#### `core.snapshot.stop_after_save` End the run after saving

|||
|-|-|
|__Type__|boolean|
|__Default__|`false`|

Shut the guest down immediately after the snapshot is saved.

```yaml
false
```

```yaml
true
```

### `core.force_www` Try to force webserver start

|||
|-|-|
|__Type__|boolean|
|__Default__|`false`|

Whether to try forcing webserver start

```yaml
false
```

```yaml
true
```

### `core.cpu` CPU model

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Specify non-default QEMU CPU model

### `core.show_output` Write serial to stdout

|||
|-|-|
|__Type__|boolean|
|__Default__|`false`|

Whether to print QEMU serial output to stdout instead of writing to a log file

```yaml
false
```

```yaml
true
```

### `core.log_file` Penguin log file

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

If set, write penguin/plugin logger output to this file (relative paths resolve under the results dir).

```yaml
penguin.log
```

### `core.immutable` Enable immutable mode

|||
|-|-|
|__Type__|boolean|
|__Default__|`true`|

Whether to run the guest filesystem in immutable mode

```yaml
false
```

```yaml
true
```

### `core.network` Connect guest to network

|||
|-|-|
|__Type__|boolean|
|__Default__|`false`|

Whether to connect the guest to the network

```yaml
false
```

```yaml
true
```

### `core.shared_dir` Shared directory configuration

|||
|-|-|
|__Default__|`null`|

Host<->guest shared directory (9p) configuration.

    Accepted in ``core.shared_dir`` as ``true`` (enable with defaults), a string
    (shorthand for ``path``), or this object. Core dumps ride the same single
    mount (see ``core.core_dumps``); they do not need this feature enabled.
    

```yaml
true
```

```yaml
my_shared_directory
```

```yaml
msize: 131072
path: shared
```

#### `core.shared_dir.path` Results-relative share directory

|||
|-|-|
|__Type__|string|
|__Default__|`shared`|

Directory shared into the guest at /igloo/shared. Resolved under the run's results dir unless core.shared_dir.host_path is set.

```yaml
shared
```

```yaml
my_shared_directory
```

#### `core.shared_dir.host_path` Absolute host directory to share

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

If set, share this absolute host directory instead of a results-relative one (path is ignored).

```yaml
/data/fixtures
```

#### `core.shared_dir.msize` 9p msize override

|||
|-|-|
|__Type__|integer or null|
|__Default__|`null`|

Override the 9p transport buffer size. Unset uses the default 8MB with an automatic fallback to 128KB on memory-tight guests.

```yaml
8192000
```

```yaml
131072
```

### `core.core_dumps` Core dump configuration

|||
|-|-|
|__Default__|`null`|

Guest core-dump capture configuration.

    Accepted in ``core.core_dumps`` as ``true`` (enable with defaults), a string
    (shorthand for ``pattern``), or this object. When enabled, penguin points
    core_pattern at /igloo/core_dumps (a symlink into the shared mount) and
    brings that mount up even when core.shared_dir is unset.
    

```yaml
true
```

```yaml
/igloo/core_dumps/core_%e.%p
```

```yaml
lock: false
```

#### `core.core_dumps.lock` Lock core_pattern

|||
|-|-|
|__Type__|boolean|
|__Default__|`true`|

Install a sysctl pseudofile that eats guest writes to core_pattern so dumps can't be redirected. Set false to let the guest firmware keep its own core_pattern.

```yaml
true
```

```yaml
false
```

#### `core.core_dumps.pattern` core_pattern override

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Override the core_pattern string. Unset uses /igloo/core_dumps/core_%e.%p.

```yaml
/igloo/core_dumps/core_%e.%p.%t
```

### `core.version` Config format version

|||
|-|-|
|__Type__|`"1.0.0"` or `2`|

Version of the config file format

### `core.auto_patching` Enable automatic patching

|||
|-|-|
|__Type__|boolean|
|__Default__|`true`|

Whether to automatically apply patches named patch_*.yaml or from patches/*.yaml in the project directory

```yaml
false
```

```yaml
true
```

### `core.guest_cmd` Enable running commands in the guest

|||
|-|-|
|__Type__|boolean|
|__Default__|`false`|

When enabled, starts the guesthopper daemon in the guest that the host can use to run commands over vsock

```yaml
false
```

```yaml
true
```

### `core.execution_mode` Execution Mode

|||
|-|-|
|__Type__|`"qemu"` or `"kvm"`|
|__Default__|`qemu`|

The execution backend to use for the guest (qemu for TCG, kvm for hardware acceleration)

```yaml
qemu
```

```yaml
kvm
```

### `core.extra_qemu_args` Extra QEMU arguments

|||
|-|-|
|__Type__|string|
|__Patch merge behavior__|Concatenate strings separated by `' '`|
|__Default__|`null`|

A list of additional QEMU command-line arguments to use when booting the guest

```yaml
-vnc :0 -vga std -device usb-kbd -device usb-tablet
```

### `core.kernel_cmdline_append` Extra kernel command-line tokens

|||
|-|-|
|__Type__|string|
|__Patch merge behavior__|Concatenate strings separated by `' '`|
|__Default__|`null`|

Tokens appended verbatim to the kernel command line (-append). Use this to set real kernel parameters or anything you need on /proc/cmdline. Unlike `env`, these are never diverted to the early-boot env blob, so they always reach the kernel cmdline. They count against the per-arch COMMAND_LINE_SIZE budget (256 bytes on MIPS), so penguin warns/errors if they overflow it.

```yaml
nokaslr mem=256M
```

```yaml
igloo_debug=1
```

### `core.mem` Panda Memory Value

|||
|-|-|
|__Type__|string or null|
|__Default__|`2G`|

Allows users to customize memory allocation for guest

```yaml
16K
```

```yaml
512M
```

```yaml
1G
```

```yaml
2G
```

### `core.kernel_quiet` Whether to include quiet flag in kernel command line

|||
|-|-|
|__Type__|boolean|
|__Default__|`true`|

If true, the kernel command line will include the quiet flag, otherwise all kernel boot messages will be printed to the console

```yaml
false
```

```yaml
true
```

### `core.smp` Number of CPUs

|||
|-|-|
|__Type__|integer or null|
|__Default__|`1`|

Number of CPUs to emulate in the guest (Warning: This can break things)

```yaml
1
```

```yaml
2
```

```yaml
4
```

### `core.timeout` Run timeout (seconds)

|||
|-|-|
|__Type__|integer or null|
|__Default__|`null`|

If set, automatically shut the guest down after this many seconds. Overridden by the --timeout CLI flag. No timeout when unset.

```yaml
60
```

```yaml
300
```

### `core.graphics` Enable graphics

|||
|-|-|
|__Type__|boolean|
|__Default__|`false`|

Whether to enable graphics in the guest

```yaml
false
```

```yaml
true
```

### `core.startup_script` Inline guest startup script

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Shell script body dropped into /igloo/init.d to run during guest boot. Installed under a name that sorts after other init.d entries so it runs last. A '#!/igloo/utils/sh' shebang is prepended automatically.

```yaml
'ip link set eth0 up

  udhcpc -i eth0

  '
```

## `patches` Patches

|||
|-|-|
|__Type__|list of string|
|__Default__|`null`|

List of paths to patch files

## `vars` Template variables

|||
|-|-|
|__Type__|mapping from string to any or null|
|__Default__|`null`|

User-defined variables usable elsewhere via Jinja2 templating, e.g. `{{ myvar }}`. Alongside these, `{{ arch }}`, `{{ core.<field> }}`, and `{{ kernel_version }}` are available. This section is consumed at load time and does not appear in the realized config.

```yaml
libdir: /lib/{{ arch }}
webroot: /www
```

## `env` Environment

|||
|-|-|
|__Default__|`null`|

Environment variables to set in the guest

```yaml
VAR1: VAL1
VAR2: VAL2
```

```yaml
FOO: DYNVALDYNVALDYNVAL
PATH: /bin:/sbin
TMPDIR: /tmp
```

### `env.<string>` Value

|||
|-|-|
|__Type__|string|
|__Default__|`null`|

Value of the environment variable

```yaml
DYNVALDYNVALDYNVAL
```

## `pseudofiles` Pseudo-files

|||
|-|-|
|__Default__|`{}`|

Device files to emulate in the guest

### `pseudofiles.<string>` File emulation spec

How to emulate a device file

#### `pseudofiles.<string>.name` MTD name

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Name of an MTD device (ignored for non-mtd)

```yaml
flash
```

```yaml
uboot
```

#### `pseudofiles.<string>.size` File size

|||
|-|-|
|__Type__|integer or null|
|__Default__|`null`|

Size of the pseudofile to be reported by stat(). This must be specified for mmap() on the pseudofile to work.

```yaml
1
```

```yaml
4096
```

#### `pseudofiles.<string>.plugin` Single backing class

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Name of a single backing class that owns the whole file_operations surface (read/write/ioctl/poll) for this node. Reference a built-in backing by name, or a user class as 'file:ClassName' (the file is found via the normal pyplugin search path). When set, the per-domain read/write/ioctl/poll keys are ignored — the class owns them all.

```yaml
my_backing:SerialBacking
```

#### `pseudofiles.<string>.read` Read

|||
|-|-|
|__Default__|`null`|

How to handle reads from the file

##### `pseudofiles.<string>.read.<model=zero>` Read a zero


###### `pseudofiles.<string>.read.<model=zero>.model` Read modelling method (read a zero)

|||
|-|-|
|__Type__|`"zero"`|


###### `pseudofiles.<string>.read.<model=zero>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.read.<model=one>` Read a one


###### `pseudofiles.<string>.read.<model=one>.model` Read modelling method (read a one)

|||
|-|-|
|__Type__|`"one"`|


###### `pseudofiles.<string>.read.<model=one>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.read.<model=empty>` Read empty file


###### `pseudofiles.<string>.read.<model=empty>.model` Read modelling method (read empty file)

|||
|-|-|
|__Type__|`"empty"`|


###### `pseudofiles.<string>.read.<model=empty>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.read.<model=const_buf>` Read a constant buffer


###### `pseudofiles.<string>.read.<model=const_buf>.model` Read modelling method (read a constant buffer)

|||
|-|-|
|__Type__|`"const_buf"`|


###### `pseudofiles.<string>.read.<model=const_buf>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.read.<model=const_buf>.val` Pseudofile contents

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.read.<model=const_buf>.null_terminate` Append a NUL byte to the configured contents

|||
|-|-|
|__Type__|boolean|
|__Default__|`false`|


###### `pseudofiles.<string>.read.<model=const_buf>.nul_terminate` Alias for null_terminate

|||
|-|-|
|__Type__|boolean|
|__Default__|`false`|


##### `pseudofiles.<string>.read.<model=const_map>` Read a constant map


###### `pseudofiles.<string>.read.<model=const_map>.model` Read modelling method (read a constant map)

|||
|-|-|
|__Type__|`"const_map"`|


###### `pseudofiles.<string>.read.<model=const_map>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.read.<model=const_map>.pad` Byte for padding file

|||
|-|-|
|__Type__|string or integer|
|__Default__|`0`|


###### `pseudofiles.<string>.read.<model=const_map>.size` File size

|||
|-|-|
|__Type__|integer|
|__Default__|`65536`|


###### `pseudofiles.<string>.read.<model=const_map>.vals` Mapping from file offsets to data


###### `pseudofiles.<string>.read.<model=const_map>.vals.<integer>` Data to place in the file at an offset

|||
|-|-|
|__Type__|string or list of integer or list of string|
|__Default__|`null`|

When this is a list of integers, it treated as a byte array. When this is a list of strings, the strings are separated by null bytes.

##### `pseudofiles.<string>.read.<model=const_map_file>` Read a constant map with host file


###### `pseudofiles.<string>.read.<model=const_map_file>.model` Read modelling method (read a constant map with host file)

|||
|-|-|
|__Type__|`"const_map_file"`|


###### `pseudofiles.<string>.read.<model=const_map_file>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.read.<model=const_map_file>.filename` Path to host file to store constant map

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.read.<model=const_map_file>.pad` Byte for padding file

|||
|-|-|
|__Type__|string or integer|
|__Default__|`0`|


###### `pseudofiles.<string>.read.<model=const_map_file>.size` File size

|||
|-|-|
|__Type__|integer|
|__Default__|`65536`|


###### `pseudofiles.<string>.read.<model=const_map_file>.vals` Mapping from file offsets to data


###### `pseudofiles.<string>.read.<model=const_map_file>.vals.<integer>` Data to place in the file at an offset

|||
|-|-|
|__Type__|string or list of integer or list of string|
|__Default__|`null`|

When this is a list of integers, it treated as a byte array. When this is a list of strings, the strings are separated by null bytes.

##### `pseudofiles.<string>.read.<model=cycle>` Read a repeating buffer

Repeat the configured buffer forever (never reports EOF).

###### `pseudofiles.<string>.read.<model=cycle>.model` Read modelling method (read a repeating buffer)

|||
|-|-|
|__Type__|`"cycle"`|


###### `pseudofiles.<string>.read.<model=cycle>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.read.<model=cycle>.val` Buffer to repeat

|||
|-|-|
|__Type__|string|


##### `pseudofiles.<string>.read.<model=from_file>` Read from a host file


###### `pseudofiles.<string>.read.<model=from_file>.model` Read modelling method (read from a host file)

|||
|-|-|
|__Type__|`"from_file"`|


###### `pseudofiles.<string>.read.<model=from_file>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.read.<model=from_file>.filename` Path to host file

|||
|-|-|
|__Type__|string|


##### `pseudofiles.<string>.read.<model=stateful>` Read back what was written

Serve bytes from this node's write buffer, giving a read-after-write register. Pair with write model 'default' (or 'discard'/'record', which all record) so writes are stored.

###### `pseudofiles.<string>.read.<model=stateful>.model` Read modelling method (read back what was written)

|||
|-|-|
|__Type__|`"stateful"`|


###### `pseudofiles.<string>.read.<model=stateful>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.read.<model=stateful>.initial` Initial buffer contents

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


##### `pseudofiles.<string>.read.<model=sequence>` Read successive values

Return each entry of 'vals' on successive reads; the common 'busy... busy... ready' status pattern. Holds the last entry when exhausted unless 'cycle' wraps around.

###### `pseudofiles.<string>.read.<model=sequence>.model` Read modelling method (read successive values)

|||
|-|-|
|__Type__|`"sequence"`|


###### `pseudofiles.<string>.read.<model=sequence>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.read.<model=sequence>.vals` Ordered values to return

|||
|-|-|
|__Type__|list|


###### `pseudofiles.<string>.read.<model=sequence>.cycle` Wrap around when exhausted

|||
|-|-|
|__Type__|boolean|
|__Default__|`false`|


##### `pseudofiles.<string>.read.<model=from_plugin>` Read from a custom PyPlugin


###### `pseudofiles.<string>.read.<model=from_plugin>.model` Read modelling method (read from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.read.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.read.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.read.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`read`|


##### `pseudofiles.<string>.read.<model=default>` Default


###### `pseudofiles.<string>.read.<model=default>.model` Read modelling method (default)

|||
|-|-|
|__Type__|`"default"`|


###### `pseudofiles.<string>.read.<model=default>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.read.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.read.<model=custom>.model` Read modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.read.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.read.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


#### `pseudofiles.<string>.write` Write

|||
|-|-|
|__Default__|`null`|

How to handle writes to the file

##### `pseudofiles.<string>.write.<model=to_file>` Write to host file


###### `pseudofiles.<string>.write.<model=to_file>.model` Write modelling method (write to host file)

|||
|-|-|
|__Type__|`"to_file"`|


###### `pseudofiles.<string>.write.<model=to_file>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.write.<model=to_file>.filename` Path to host file

|||
|-|-|
|__Type__|string|


##### `pseudofiles.<string>.write.<model=from_plugin>` Read from a custom PyPlugin


###### `pseudofiles.<string>.write.<model=from_plugin>.model` Write modelling method (read from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.write.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.write.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.write.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`write`|


##### `pseudofiles.<string>.write.<model=discard>` Discard write


###### `pseudofiles.<string>.write.<model=discard>.model` Write modelling method (discard write)

|||
|-|-|
|__Type__|`"discard"`|


###### `pseudofiles.<string>.write.<model=discard>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.write.<model=return_const>` Return a constant on write

Return a fixed value (e.g. a byte count or a negative errno) without storing data.

###### `pseudofiles.<string>.write.<model=return_const>.model` Write modelling method (return a constant on write)

|||
|-|-|
|__Type__|`"return_const"`|


###### `pseudofiles.<string>.write.<model=return_const>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.write.<model=return_const>.const` Value to return from write()

|||
|-|-|
|__Type__|integer|


##### `pseudofiles.<string>.write.<model=unhandled>` Reject writes

Return -EINVAL for every write.

###### `pseudofiles.<string>.write.<model=unhandled>.model` Write modelling method (reject writes)

|||
|-|-|
|__Type__|`"unhandled"`|


###### `pseudofiles.<string>.write.<model=unhandled>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.write.<model=default>` Default


###### `pseudofiles.<string>.write.<model=default>.model` Write modelling method (default)

|||
|-|-|
|__Type__|`"default"`|


###### `pseudofiles.<string>.write.<model=default>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.write.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.write.<model=custom>.model` Write modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.write.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.write.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


#### `pseudofiles.<string>.ioctl` Ioctl

|||
|-|-|
|__Default__|`null`|

How to handle ioctl() calls

```yaml
'*':
  model: return_const
  val: 0
'1000':
  model: return_const
  val: 5
```

```yaml
'*':
  model: return_const
```

```yaml
function: ioctl_handler
model: from_plugin
plugin: my_plugin
```

##### `pseudofiles.<string>.ioctl.<model=return_const>` Return a constant


###### `pseudofiles.<string>.ioctl.<model=return_const>.model` ioctl modelling method (return a constant)

|||
|-|-|
|__Type__|`"return_const"`|


###### `pseudofiles.<string>.ioctl.<model=return_const>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.ioctl.<model=return_const>.val` Constant to return

|||
|-|-|
|__Type__|integer|
|__Default__|`0`|


##### `pseudofiles.<string>.ioctl.<model=zero>` Return zero


###### `pseudofiles.<string>.ioctl.<model=zero>.model` ioctl modelling method (return zero)

|||
|-|-|
|__Type__|`"zero"`|


###### `pseudofiles.<string>.ioctl.<model=zero>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.ioctl.<model=unhandled>` Reject ioctl

Return -ENOTTY (inappropriate ioctl for device).

###### `pseudofiles.<string>.ioctl.<model=unhandled>.model` ioctl modelling method (reject ioctl)

|||
|-|-|
|__Type__|`"unhandled"`|


###### `pseudofiles.<string>.ioctl.<model=unhandled>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.ioctl.<model=write_data>` Write a buffer to the arg pointer

Write a constant buffer to the user pointer in 'arg' (the common shape of an ioctl that fills a struct), then return 'val'.

###### `pseudofiles.<string>.ioctl.<model=write_data>.model` ioctl modelling method (write a buffer to the arg pointer)

|||
|-|-|
|__Type__|`"write_data"`|


###### `pseudofiles.<string>.ioctl.<model=write_data>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.ioctl.<model=write_data>.data` Bytes to write to *arg

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.ioctl.<model=write_data>.val` Value to return from ioctl()

|||
|-|-|
|__Type__|integer|
|__Default__|`0`|


##### `pseudofiles.<string>.ioctl.<model=from_plugin>` ioctl from a custom PyPlugin


###### `pseudofiles.<string>.ioctl.<model=from_plugin>.model` ioctl modelling method (ioctl from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.ioctl.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.ioctl.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.ioctl.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`ioctl`|


#### `pseudofiles.<string>.poll` Poll

|||
|-|-|
|__Default__|`null`|

How to answer poll()/select() on the file

##### `pseudofiles.<string>.poll.<model=always_ready>` Always report ready

Constant POLLIN|POLLRDNORM|POLLOUT|POLLWRNORM mask (legacy behavior).

###### `pseudofiles.<string>.poll.<model=always_ready>.model` Poll modelling method (always report ready)

|||
|-|-|
|__Type__|`"always_ready"`|


###### `pseudofiles.<string>.poll.<model=always_ready>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.poll.<model=blocking>` Never report ready (block the waiter)

Return a zero mask so poll()/select()/epoll parks the caller on the node's wait queue instead of spinning. Models an event-source device whose read() blocks until a hardware event that never occurs under emulation (e.g. an AVM-style /dev/watchdog). A write to the node wakes any parked waiter.

###### `pseudofiles.<string>.poll.<model=blocking>.model` Poll modelling method (never report ready (block the waiter))

|||
|-|-|
|__Type__|`"blocking"`|


###### `pseudofiles.<string>.poll.<model=blocking>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.poll.<model=periodic>` Report ready on a fixed cadence (heartbeat)

Report the node readable once every 'interval_ms', parking the waiter on the node's wait queue in between. An igloo_driver kernel timer drives the cadence, so a poll()/epoll(timeout=-1) main loop advances at a fixed rate instead of spinning (always_ready) or deadlocking (blocking). Models a device that delivers a periodic hardware event (e.g. an AVM-style /dev/watchdog heartbeat). Note the interval is in guest time, which runs slower than wall-clock under emulation.

###### `pseudofiles.<string>.poll.<model=periodic>.model` Poll modelling method (report ready on a fixed cadence (heartbeat))

|||
|-|-|
|__Type__|`"periodic"`|


###### `pseudofiles.<string>.poll.<model=periodic>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.poll.<model=periodic>.interval_ms` Heartbeat interval (guest milliseconds)

|||
|-|-|
|__Type__|integer|
|__Default__|`1000`|


##### `pseudofiles.<string>.poll.<model=from_plugin>` Poll from a custom PyPlugin

Data-aware poll: the plugin returns a poll mask reflecting actual readiness.

###### `pseudofiles.<string>.poll.<model=from_plugin>.model` Poll modelling method (poll from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.poll.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.poll.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.poll.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`poll`|


##### `pseudofiles.<string>.poll.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.poll.<model=custom>.model` Poll modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.poll.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.poll.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


#### `pseudofiles.<string>.lseek` Seek

|||
|-|-|
|__Default__|`null`|

How to handle lseek() on the file

##### `pseudofiles.<string>.lseek.<model=default>` Standard offset arithmetic

SEEK_SET/CUR/END against the node's reported size.

###### `pseudofiles.<string>.lseek.<model=default>.model` Seek modelling method (standard offset arithmetic)

|||
|-|-|
|__Type__|`"default"`|


###### `pseudofiles.<string>.lseek.<model=default>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.lseek.<model=unsupported>` Reject seeks

Return -ESPIPE (for pipe/stream-like nodes).

###### `pseudofiles.<string>.lseek.<model=unsupported>.model` Seek modelling method (reject seeks)

|||
|-|-|
|__Type__|`"unsupported"`|


###### `pseudofiles.<string>.lseek.<model=unsupported>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.lseek.<model=from_plugin>` lseek from a custom PyPlugin


###### `pseudofiles.<string>.lseek.<model=from_plugin>.model` Seek modelling method (lseek from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.lseek.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.lseek.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.lseek.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`lseek`|


##### `pseudofiles.<string>.lseek.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.lseek.<model=custom>.model` Seek modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.lseek.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.lseek.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


#### `pseudofiles.<string>.mmap` Mmap

|||
|-|-|
|__Default__|`null`|

How to handle mmap() on the file

##### `pseudofiles.<string>.mmap.<model=from_plugin>` mmap from a custom PyPlugin


###### `pseudofiles.<string>.mmap.<model=from_plugin>.model` Mmap modelling method (mmap from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.mmap.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.mmap.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.mmap.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`mmap`|


##### `pseudofiles.<string>.mmap.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.mmap.<model=custom>.model` Mmap modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.mmap.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.mmap.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


#### `pseudofiles.<string>.open` Open

|||
|-|-|
|__Default__|`null`|

How to handle open() on the file

##### `pseudofiles.<string>.open.<model=from_plugin>` open from a custom PyPlugin

Fire a plugin function when the guest opens this node.

###### `pseudofiles.<string>.open.<model=from_plugin>.model` Open modelling method (open from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.open.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.open.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.open.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`open`|


##### `pseudofiles.<string>.open.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.open.<model=custom>.model` Open modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.open.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.open.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


#### `pseudofiles.<string>.release` Release

|||
|-|-|
|__Default__|`null`|

How to handle release()/close() on the file

##### `pseudofiles.<string>.release.<model=from_plugin>` release from a custom PyPlugin

Fire a plugin function when the guest closes this node.

###### `pseudofiles.<string>.release.<model=from_plugin>.model` Release modelling method (release from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.release.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.release.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.release.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`release`|


##### `pseudofiles.<string>.release.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.release.<model=custom>.model` Release modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.release.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.release.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


#### `pseudofiles.<string>.compat_ioctl` Compat ioctl

|||
|-|-|
|__Default__|`null`|

How to handle 32-bit compat_ioctl() on the file

##### `pseudofiles.<string>.compat_ioctl.<model=same_as_ioctl>` Reuse the ioctl model

Route compat_ioctl through the same handlers as ioctl (the common driver pattern).

###### `pseudofiles.<string>.compat_ioctl.<model=same_as_ioctl>.model` compat_ioctl modelling method (reuse the ioctl model)

|||
|-|-|
|__Type__|`"same_as_ioctl"`|


###### `pseudofiles.<string>.compat_ioctl.<model=same_as_ioctl>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `pseudofiles.<string>.compat_ioctl.<model=from_plugin>` compat_ioctl from a custom PyPlugin


###### `pseudofiles.<string>.compat_ioctl.<model=from_plugin>.model` compat_ioctl modelling method (compat_ioctl from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.compat_ioctl.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.compat_ioctl.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.compat_ioctl.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`compat_ioctl`|


#### `pseudofiles.<string>.flush` Flush

|||
|-|-|
|__Default__|`null`|

How to handle flush() on the file

##### `pseudofiles.<string>.flush.<model=from_plugin>` flush from a custom PyPlugin


###### `pseudofiles.<string>.flush.<model=from_plugin>.model` Flush modelling method (flush from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.flush.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.flush.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.flush.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`flush`|


##### `pseudofiles.<string>.flush.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.flush.<model=custom>.model` Flush modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.flush.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.flush.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


#### `pseudofiles.<string>.fsync` Fsync

|||
|-|-|
|__Default__|`null`|

How to handle fsync() on the file

##### `pseudofiles.<string>.fsync.<model=from_plugin>` fsync from a custom PyPlugin


###### `pseudofiles.<string>.fsync.<model=from_plugin>.model` Fsync modelling method (fsync from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.fsync.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.fsync.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.fsync.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`fsync`|


##### `pseudofiles.<string>.fsync.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.fsync.<model=custom>.model` Fsync modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.fsync.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.fsync.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


#### `pseudofiles.<string>.fasync` Fasync

|||
|-|-|
|__Default__|`null`|

How to handle fasync() on the file

##### `pseudofiles.<string>.fasync.<model=from_plugin>` fasync from a custom PyPlugin


###### `pseudofiles.<string>.fasync.<model=from_plugin>.model` Fasync modelling method (fasync from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.fasync.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.fasync.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.fasync.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`fasync`|


##### `pseudofiles.<string>.fasync.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.fasync.<model=custom>.model` Fasync modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.fasync.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.fasync.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


#### `pseudofiles.<string>.lock` Lock

|||
|-|-|
|__Default__|`null`|

How to handle lock() on the file

##### `pseudofiles.<string>.lock.<model=from_plugin>` lock from a custom PyPlugin


###### `pseudofiles.<string>.lock.<model=from_plugin>.model` Lock modelling method (lock from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.lock.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.lock.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.lock.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`lock`|


##### `pseudofiles.<string>.lock.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.lock.<model=custom>.model` Lock modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.lock.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.lock.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


#### `pseudofiles.<string>.read_iter` Read iterator

|||
|-|-|
|__Default__|`null`|

How to handle read_iter() on the file

##### `pseudofiles.<string>.read_iter.<model=from_plugin>` read_iter from a custom PyPlugin


###### `pseudofiles.<string>.read_iter.<model=from_plugin>.model` Read iterator modelling method (read_iter from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.read_iter.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.read_iter.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.read_iter.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`read_iter`|


##### `pseudofiles.<string>.read_iter.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.read_iter.<model=custom>.model` Read iterator modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.read_iter.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.read_iter.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


#### `pseudofiles.<string>.write_iter` Write iterator

|||
|-|-|
|__Default__|`null`|

How to handle write_iter() on the file

##### `pseudofiles.<string>.write_iter.<model=from_plugin>` write_iter from a custom PyPlugin


###### `pseudofiles.<string>.write_iter.<model=from_plugin>.model` Write iterator modelling method (write_iter from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.write_iter.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.write_iter.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.write_iter.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`write_iter`|


##### `pseudofiles.<string>.write_iter.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.write_iter.<model=custom>.model` Write iterator modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.write_iter.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.write_iter.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


#### `pseudofiles.<string>.get_unmapped_area` Get unmapped area

|||
|-|-|
|__Default__|`null`|

How to handle get_unmapped_area() on the file

##### `pseudofiles.<string>.get_unmapped_area.<model=from_plugin>` get_unmapped_area from a custom PyPlugin


###### `pseudofiles.<string>.get_unmapped_area.<model=from_plugin>.model` Get unmapped area modelling method (get_unmapped_area from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.get_unmapped_area.<model=from_plugin>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.get_unmapped_area.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.get_unmapped_area.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`get_unmapped_area`|


##### `pseudofiles.<string>.get_unmapped_area.<model=custom>` Custom registered model

Use a model registered via @register_model in a loaded plugin. 'model_name' selects it; any extra keys are forwarded to the model.

###### `pseudofiles.<string>.get_unmapped_area.<model=custom>.model` Get unmapped area modelling method (custom registered model)

|||
|-|-|
|__Type__|`"custom"`|


###### `pseudofiles.<string>.get_unmapped_area.<model=custom>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

###### `pseudofiles.<string>.get_unmapped_area.<model=custom>.model_name` Registered model name

|||
|-|-|
|__Type__|string|


## `nvram` NVRAM

|||
|-|-|
|__Default__|`{}`|

NVRAM values to add to the guest

### `nvram.<string>` NVRAM value

|||
|-|-|
|__Type__|string or integer|
|__Default__|`null`|


## `netdevs` Network devices

|||
|-|-|
|__Type__|list of string|
|__Default__|`[]`|

Names for guest network interfaces

```yaml
- eth0
- eth1
```

```yaml
- ens33
- wlp3s0
```

## `uboot_env` U-Boot environment

|||
|-|-|
|__Default__|`{}`|

U-Boot environment variables to set in the guest

### `uboot_env.<string>` Value

|||
|-|-|
|__Type__|string|
|__Default__|`null`|

Value of the U-Boot environment variable

## `blocked_signals` List of blocked signals

|||
|-|-|
|__Type__|list of integer|
|__Default__|`[]`|

Signals numbers to block within the guest. Supported values are 6 (SIGABRT), 9 (SIGKILL), 15 (SIGTERM), and 17 (SIGCHLD).

## `lib_inject` Injected library configuration

Library functions to be intercepted

### `lib_inject.aliases` Injected library aliases

|||
|-|-|
|__Default__|`{}`|

Mapping between names of external library functions and names of functions defined in the injected library. This allows replacing arbitrary library functions with your own code.

```yaml
fputs: 'false'
nvram_load: nvram_init
```

#### `lib_inject.aliases.<string>` Injected library alias target

|||
|-|-|
|__Type__|string|
|__Default__|`null`|

This is the name of the target function that the alias points to.

```yaml
nvram_init
```

```yaml
'true'
```

```yaml
'false'
```

### `lib_inject.extra` Extra injected library code

|||
|-|-|
|__Type__|string|
|__Patch merge behavior__|Concatenate strings separated by `'\n'`|
|__Default__|`null`|

Custom source code for library functions to intercept and model

## `static_files` Static files

Files to create in the guest filesystem

```yaml
{}
```

```yaml
/path/to/file:
  contents: Hello world!
  type: file
```

```yaml
/path/to/symlink/source:
  target: /path/to/symlink/target
  type: symlink
```

```yaml
/dev/some_device:
  devtype: char
  major: 1
  minor: 2
  mode: 438
  type: dev
```

### `static_files.<string>` Static filesystem action

|||
|-|-|
|__Default__|`null`|


#### `static_files.<string>.<type=inline_file>` Add inline file

Add a file with contents specified inline in this config

##### `static_files.<string>.<type=inline_file>.type` Type of file action (add inline file)

|||
|-|-|
|__Type__|`"inline_file"`|


##### `static_files.<string>.<type=inline_file>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `static_files.<string>.<type=inline_file>.mode` Permissions of file

|||
|-|-|
|__Type__|integer|
|__Default__|`420`|


##### `static_files.<string>.<type=inline_file>.contents` Contents of file

|||
|-|-|
|__Type__|string|


##### `static_files.<string>.<type=inline_file>.patches` Binary patches to apply after this file is placed

|||
|-|-|
|__Type__|list of Binary patch entry|
|__Default__|`null`|

A list of binary edits applied to this file after it is staged into the guest, in a single host-side pass (same semantics as the standalone 'binary_patch' action). Each edit may verify the bytes currently at its offset (expect/on_mismatch) and record rationale (why/tag); every outcome is written to binary_patches.yaml in the run output. Overlapping write ranges are rejected. Cannot be combined with a glob source or destination (the patch target would be ambiguous).

###### `static_files.<string>.<type=inline_file>.patches.<item>` Binary patch entry

A single edit within a ``binary_patch`` action: bytes to write at one
    file offset, optionally guarded by an ``expect`` check. Multiple entries can
    target one file via the action's ``patches`` list; they are applied
    host-side to one buffer in a single pass, and overlapping write ranges are
    rejected.

###### `static_files.<string>.<type=inline_file>.patches.<item>.file_offset` File offset (integer)

|||
|-|-|
|__Type__|integer|


###### `static_files.<string>.<type=inline_file>.patches.<item>.hex_bytes` Bytes to write at offset (hex string)

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
DEADBEEF
```

```yaml
90 90
```

###### `static_files.<string>.<type=inline_file>.patches.<item>.asm` Assembly code to write at offset (runs through keystone)

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
nop
```

```yaml
'mov r0, #0xdeadbeef'
```

###### `static_files.<string>.<type=inline_file>.patches.<item>.mode` Assembly mode

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
arm
```

```yaml
thumb
```

###### `static_files.<string>.<type=inline_file>.patches.<item>.expect` Expected bytes at offset before patching (hex string)

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

If set, the current bytes at file_offset are compared against this hex string (over its own length, which may differ from the patch length) before the patch is written. If the bytes at the offset already equal the patch bytes, the patch is skipped (idempotent re-run); otherwise the on_mismatch policy applies.

```yaml
0102 0304
```

```yaml
DEADBEEF
```

###### `static_files.<string>.<type=inline_file>.patches.<item>.on_mismatch` Policy when 'expect' does not match

|||
|-|-|
|__Type__|`"fail"` or `"skip"` or `"warn"`|
|__Default__|`fail`|

fail: abort the run (default, safest). skip: leave the file unpatched and continue. warn: log a warning and write the patch anyway. Only meaningful when 'expect' is set.

###### `static_files.<string>.<type=inline_file>.patches.<item>.why` Rationale for this patch, recorded in the run's binary_patches.yaml

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
NOP out the secure-boot check
```

###### `static_files.<string>.<type=inline_file>.patches.<item>.tag` Label grouping related patches, recorded in the run's binary_patches.yaml

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
secureboot
```

#### `static_files.<string>.<type=host_file>` Copy host file

Copy a file from the host into the guest

##### `static_files.<string>.<type=host_file>.type` Type of file action (copy host file)

|||
|-|-|
|__Type__|`"host_file"`|


##### `static_files.<string>.<type=host_file>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `static_files.<string>.<type=host_file>.mode` Permissions of file

|||
|-|-|
|__Type__|integer|
|__Default__|`493`|


##### `static_files.<string>.<type=host_file>.host_path` Host path

|||
|-|-|
|__Type__|string|


##### `static_files.<string>.<type=host_file>.patches` Binary patches to apply after this file is placed

|||
|-|-|
|__Type__|list of Binary patch entry|
|__Default__|`null`|

A list of binary edits applied to this file after it is staged into the guest, in a single host-side pass (same semantics as the standalone 'binary_patch' action). Each edit may verify the bytes currently at its offset (expect/on_mismatch) and record rationale (why/tag); every outcome is written to binary_patches.yaml in the run output. Overlapping write ranges are rejected. Cannot be combined with a glob source or destination (the patch target would be ambiguous).

###### `static_files.<string>.<type=host_file>.patches.<item>` Binary patch entry

A single edit within a ``binary_patch`` action: bytes to write at one
    file offset, optionally guarded by an ``expect`` check. Multiple entries can
    target one file via the action's ``patches`` list; they are applied
    host-side to one buffer in a single pass, and overlapping write ranges are
    rejected.

###### `static_files.<string>.<type=host_file>.patches.<item>.file_offset` File offset (integer)

|||
|-|-|
|__Type__|integer|


###### `static_files.<string>.<type=host_file>.patches.<item>.hex_bytes` Bytes to write at offset (hex string)

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
DEADBEEF
```

```yaml
90 90
```

###### `static_files.<string>.<type=host_file>.patches.<item>.asm` Assembly code to write at offset (runs through keystone)

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
nop
```

```yaml
'mov r0, #0xdeadbeef'
```

###### `static_files.<string>.<type=host_file>.patches.<item>.mode` Assembly mode

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
arm
```

```yaml
thumb
```

###### `static_files.<string>.<type=host_file>.patches.<item>.expect` Expected bytes at offset before patching (hex string)

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

If set, the current bytes at file_offset are compared against this hex string (over its own length, which may differ from the patch length) before the patch is written. If the bytes at the offset already equal the patch bytes, the patch is skipped (idempotent re-run); otherwise the on_mismatch policy applies.

```yaml
0102 0304
```

```yaml
DEADBEEF
```

###### `static_files.<string>.<type=host_file>.patches.<item>.on_mismatch` Policy when 'expect' does not match

|||
|-|-|
|__Type__|`"fail"` or `"skip"` or `"warn"`|
|__Default__|`fail`|

fail: abort the run (default, safest). skip: leave the file unpatched and continue. warn: log a warning and write the patch anyway. Only meaningful when 'expect' is set.

###### `static_files.<string>.<type=host_file>.patches.<item>.why` Rationale for this patch, recorded in the run's binary_patches.yaml

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
NOP out the secure-boot check
```

###### `static_files.<string>.<type=host_file>.patches.<item>.tag` Label grouping related patches, recorded in the run's binary_patches.yaml

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
secureboot
```

#### `static_files.<string>.<type=dir>` Add directory


##### `static_files.<string>.<type=dir>.type` Type of file action (add directory)

|||
|-|-|
|__Type__|`"dir"`|


##### `static_files.<string>.<type=dir>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `static_files.<string>.<type=dir>.mode` Permissions of directory

|||
|-|-|
|__Type__|integer|
|__Default__|`493`|


#### `static_files.<string>.<type=symlink>` Add symbolic link


##### `static_files.<string>.<type=symlink>.type` Type of file action (add symbolic link)

|||
|-|-|
|__Type__|`"symlink"`|


##### `static_files.<string>.<type=symlink>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `static_files.<string>.<type=symlink>.target` Target linked path

|||
|-|-|
|__Type__|string|


#### `static_files.<string>.<type=dev>` Add device file


##### `static_files.<string>.<type=dev>.type` Type of file action (add device file)

|||
|-|-|
|__Type__|`"dev"`|


##### `static_files.<string>.<type=dev>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `static_files.<string>.<type=dev>.devtype` Type of device file

|||
|-|-|
|__Type__|`"char"` or `"block"`|


##### `static_files.<string>.<type=dev>.major` Major device number

|||
|-|-|
|__Type__|integer|


##### `static_files.<string>.<type=dev>.minor` Minor device number

|||
|-|-|
|__Type__|integer|


##### `static_files.<string>.<type=dev>.mode` Permissions of device file

|||
|-|-|
|__Type__|integer|
|__Default__|`438`|


#### `static_files.<string>.<type=delete>` Delete file


##### `static_files.<string>.<type=delete>.type` Type of file action (delete file)

|||
|-|-|
|__Type__|`"delete"`|


##### `static_files.<string>.<type=delete>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

#### `static_files.<string>.<type=move>` Move file


##### `static_files.<string>.<type=move>.type` Type of file action (move file)

|||
|-|-|
|__Type__|`"move"`|


##### `static_files.<string>.<type=move>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `static_files.<string>.<type=move>.from` File to be moved to the specified location

|||
|-|-|
|__Type__|string|


##### `static_files.<string>.<type=move>.mode` Permissions of target file

|||
|-|-|
|__Type__|integer or null|
|__Default__|`null`|


#### `static_files.<string>.<type=shim>` Shim file


##### `static_files.<string>.<type=shim>.type` Type of file action (shim file)

|||
|-|-|
|__Type__|`"shim"`|


##### `static_files.<string>.<type=shim>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `static_files.<string>.<type=shim>.target` Target file we want the shim to be symlinked to

|||
|-|-|
|__Type__|string|


#### `static_files.<string>.<type=binary_patch>` Patch binary file

Patch a binary file at one or more offsets. A single edit is given inline (file_offset + one of hex_bytes/asm); multiple edits to the same file go in the 'patches' list (applied together in one host-side pass, with overlapping write ranges rejected). Each edit may verify the bytes currently at its offset first (expect/on_mismatch) so the patch is idempotent and safe across firmware variants, and record rationale (why/tag); every edit's outcome is written to binary_patches.yaml in the run output.

##### `static_files.<string>.<type=binary_patch>.type` Type of file action (patch binary file)

|||
|-|-|
|__Type__|`"binary_patch"`|


##### `static_files.<string>.<type=binary_patch>.provenance` Model provenance

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Origin tag. Set 'default' for a synthesized stub (it reports its hits into pseudofiles_failures.yaml); leave unset for author-intentional models.

##### `static_files.<string>.<type=binary_patch>.file_offset` File offset (integer) — for a single inline edit; omit when using 'patches'

|||
|-|-|
|__Type__|integer or null|
|__Default__|`null`|


##### `static_files.<string>.<type=binary_patch>.hex_bytes` Bytes to write at offset (hex string)

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
DEADBEEF
```

```yaml
90 90
```

##### `static_files.<string>.<type=binary_patch>.asm` Assembly code to write at offset (runs through keystone)

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
nop
```

```yaml
'mov r0, #0xdeadbeef'
```

##### `static_files.<string>.<type=binary_patch>.mode` Assembly mode

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
arm
```

```yaml
thumb
```

##### `static_files.<string>.<type=binary_patch>.expect` Expected bytes at offset before patching (hex string)

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

If set, the current bytes at file_offset are compared against this hex string (over its own length, which may differ from the patch length) before the patch is written. If the bytes at the offset already equal the patch bytes, the patch is skipped (idempotent re-run); otherwise the on_mismatch policy applies.

```yaml
0102 0304
```

```yaml
DEADBEEF
```

##### `static_files.<string>.<type=binary_patch>.on_mismatch` Policy when 'expect' does not match

|||
|-|-|
|__Type__|`"fail"` or `"skip"` or `"warn"`|
|__Default__|`fail`|

fail: abort the run (default, safest). skip: leave the file unpatched and continue. warn: log a warning and write the patch anyway. Only meaningful when 'expect' is set.

##### `static_files.<string>.<type=binary_patch>.why` Rationale for this patch, recorded in the run's binary_patches.yaml

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
NOP out the secure-boot check
```

##### `static_files.<string>.<type=binary_patch>.tag` Label grouping related patches, recorded in the run's binary_patches.yaml

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
secureboot
```

##### `static_files.<string>.<type=binary_patch>.patches` Multiple edits to this file

|||
|-|-|
|__Type__|list of Binary patch entry|
|__Default__|`null`|

A list of edits applied to this one file in a single host-side pass. Use this instead of the inline file_offset/hex_bytes/asm fields when patching a binary at more than one offset. Overlapping write ranges are rejected.

###### `static_files.<string>.<type=binary_patch>.patches.<item>` Binary patch entry

A single edit within a ``binary_patch`` action: bytes to write at one
    file offset, optionally guarded by an ``expect`` check. Multiple entries can
    target one file via the action's ``patches`` list; they are applied
    host-side to one buffer in a single pass, and overlapping write ranges are
    rejected.

###### `static_files.<string>.<type=binary_patch>.patches.<item>.file_offset` File offset (integer)

|||
|-|-|
|__Type__|integer|


###### `static_files.<string>.<type=binary_patch>.patches.<item>.hex_bytes` Bytes to write at offset (hex string)

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
DEADBEEF
```

```yaml
90 90
```

###### `static_files.<string>.<type=binary_patch>.patches.<item>.asm` Assembly code to write at offset (runs through keystone)

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
nop
```

```yaml
'mov r0, #0xdeadbeef'
```

###### `static_files.<string>.<type=binary_patch>.patches.<item>.mode` Assembly mode

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
arm
```

```yaml
thumb
```

###### `static_files.<string>.<type=binary_patch>.patches.<item>.expect` Expected bytes at offset before patching (hex string)

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

If set, the current bytes at file_offset are compared against this hex string (over its own length, which may differ from the patch length) before the patch is written. If the bytes at the offset already equal the patch bytes, the patch is skipped (idempotent re-run); otherwise the on_mismatch policy applies.

```yaml
0102 0304
```

```yaml
DEADBEEF
```

###### `static_files.<string>.<type=binary_patch>.patches.<item>.on_mismatch` Policy when 'expect' does not match

|||
|-|-|
|__Type__|`"fail"` or `"skip"` or `"warn"`|
|__Default__|`fail`|

fail: abort the run (default, safest). skip: leave the file unpatched and continue. warn: log a warning and write the patch anyway. Only meaningful when 'expect' is set.

###### `static_files.<string>.<type=binary_patch>.patches.<item>.why` Rationale for this patch, recorded in the run's binary_patches.yaml

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
NOP out the secure-boot check
```

###### `static_files.<string>.<type=binary_patch>.patches.<item>.tag` Label grouping related patches, recorded in the run's binary_patches.yaml

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


```yaml
secureboot
```

## `plugins` Plugins


### `plugins.<string>` Plugin


|Field|Type|Default|Title|
|-|-|-|-|
|`description`|string or null|`null`|Plugin description|
|`depends_on`|string or null|`null`|Plugin dependency|
|`enabled`|boolean|`true`|Enable this plugin (default depends on plugin)|
|`version`|string or null|`null`|Plugin version|
## `init_plugins` Init plugins

|||
|-|-|
|__Default__|`null`|

The init plugins that generated this project (recorded by `penguin init`). Drives which plugins re-run on `penguin refresh`; newly available plugins are appended when they run.

### `init_plugins.<string>` Init plugin

One init plugin's record/settings in the init_plugins section.

#### `init_plugins.<string>.enabled` Run this init plugin during penguin refresh

|||
|-|-|
|__Type__|boolean|
|__Default__|`true`|

Set to false to skip this plugin entirely when re-running init analyses with `penguin refresh`.

## `network` Network Configuration

|||
|-|-|
|__Default__|`null`|

Configuration for networks to attach to guest

### `network.external` Set up NAT for outgoing connections

Configuration for NAT for external connections

#### `network.external.mac` MAC Address for external interface

|||
|-|-|
|__Type__|string or null|
|__Default__|`'52:54:00:12:34:56'`|

MAC Address for external network interface

#### `network.external.pcap` pcap file name

|||
|-|-|
|__Type__|boolean or null|
|__Default__|`null`|

Whether to capture traffic over the external net in a pcap file. The file will be called 'ext.pcap' in the output directory. Capture disabled if unset.


