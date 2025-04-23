# Penguin Configuration

Configuration file for config-file-based rehosting with IGLOO

## `core` Core configuration options

Core configuration options for this rehosting

### `core.arch` Architecture of guest

|||
|-|-|
|__Type__|`"armel"` or `"aarch64"` or `"mipsel"` or `"mipseb"` or `"mips64el"` or `"mips64eb"` or `"powerpc"` or `"powerpc64"` or `"powerpc64le"` or `"riscv64"` or `"loongarch64"` or `"intel64"` or null|
|__Default__|`null`|


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
mips64eb
```

```yaml
intel64
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

### `core.shared_dir` Project-relative path of shared directory

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

Share this directory as /igloo/shared in the guest.

```yaml
my_shared_directory
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

### `core.extra_qemu_args` Extra QEMU arguments

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|

A list of additional QEMU command-line arguments to use when booting the guest

```yaml
-vnc :0 -vga std -device usb-kbd -device usb-tablet
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

## `patches` Patches

|||
|-|-|
|__Type__|list of string|
|__Default__|`null`|

List of paths to patch files

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
|__Default__|`null`|

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


##### `pseudofiles.<string>.read.<model=empty>` Read empty file


###### `pseudofiles.<string>.read.<model=empty>.model` Read modelling method (read empty file)

|||
|-|-|
|__Type__|`"empty"`|


##### `pseudofiles.<string>.read.<model=const_buf>` Read a constant buffer


###### `pseudofiles.<string>.read.<model=const_buf>.model` Read modelling method (read a constant buffer)

|||
|-|-|
|__Type__|`"const_buf"`|


###### `pseudofiles.<string>.read.<model=const_buf>.val` Constant buffer

|||
|-|-|
|__Type__|string|

The string with the contents of the pseudofile

##### `pseudofiles.<string>.read.<model=const_map>` Read a constant map


###### `pseudofiles.<string>.read.<model=const_map>.model` Read modelling method (read a constant map)

|||
|-|-|
|__Type__|`"const_map"`|


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


####### `pseudofiles.<string>.read.<model=const_map>.vals.<integer>` Data to place in the file at an offset

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


####### `pseudofiles.<string>.read.<model=const_map_file>.vals.<integer>` Data to place in the file at an offset

|||
|-|-|
|__Type__|string or list of integer or list of string|
|__Default__|`null`|

When this is a list of integers, it treated as a byte array. When this is a list of strings, the strings are separated by null bytes.

##### `pseudofiles.<string>.read.<model=from_file>` Read from a host file


###### `pseudofiles.<string>.read.<model=from_file>.model` Read modelling method (read from a host file)

|||
|-|-|
|__Type__|`"from_file"`|


###### `pseudofiles.<string>.read.<model=from_file>.filename` Path to host file

|||
|-|-|
|__Type__|string|


##### `pseudofiles.<string>.read.<model=from_plugin>` Read from a custom PyPlugin


###### `pseudofiles.<string>.read.<model=from_plugin>.model` Read modelling method (read from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


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


###### `pseudofiles.<string>.write.<model=to_file>.filename` Path to host file

|||
|-|-|
|__Type__|string|


##### `pseudofiles.<string>.write.<model=from_plugin>` Read from a custom PyPlugin


###### `pseudofiles.<string>.write.<model=from_plugin>.model` Write modelling method (read from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


###### `pseudofiles.<string>.write.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


###### `pseudofiles.<string>.write.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`read`|


##### `pseudofiles.<string>.write.<model=discard>` Discard write


###### `pseudofiles.<string>.write.<model=discard>.model` Write modelling method (discard write)

|||
|-|-|
|__Type__|`"discard"`|


##### `pseudofiles.<string>.write.<model=default>` Default


###### `pseudofiles.<string>.write.<model=default>.model` Write modelling method (default)

|||
|-|-|
|__Type__|`"default"`|


#### `pseudofiles.<string>.ioctl` ioctl

|||
|-|-|
|__Default__|`{}`|

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

##### `pseudofiles.<string>.ioctl.<integer or "*">` Ioctl

|||
|-|-|
|__Default__|`null`|


###### `pseudofiles.<string>.ioctl.<integer or "*">.<model=return_const>` Return a constant


####### `pseudofiles.<string>.ioctl.<integer or "*">.<model=return_const>.model` ioctl modelling method (return a constant)

|||
|-|-|
|__Type__|`"return_const"`|


####### `pseudofiles.<string>.ioctl.<integer or "*">.<model=return_const>.val` Constant to return

|||
|-|-|
|__Type__|integer|


###### `pseudofiles.<string>.ioctl.<integer or "*">.<model=symex>` Symbolic execution


####### `pseudofiles.<string>.ioctl.<integer or "*">.<model=symex>.model` ioctl modelling method (symbolic execution)

|||
|-|-|
|__Type__|`"symex"`|


###### `pseudofiles.<string>.ioctl.<integer or "*">.<model=from_plugin>` ioctl from a custom PyPlugin


####### `pseudofiles.<string>.ioctl.<integer or "*">.<model=from_plugin>.model` ioctl modelling method (ioctl from a custom pyplugin)

|||
|-|-|
|__Type__|`"from_plugin"`|


####### `pseudofiles.<string>.ioctl.<integer or "*">.<model=from_plugin>.plugin` Name of the loaded PyPlugin

|||
|-|-|
|__Type__|string|


####### `pseudofiles.<string>.ioctl.<integer or "*">.<model=from_plugin>.function` Function to call

|||
|-|-|
|__Type__|string or null|
|__Default__|`read`|


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
|__Default__|`null`|

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
|__Default__|`null`|

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
|__Type__|string or null|
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


##### `static_files.<string>.<type=inline_file>.mode` Permissions of file

|||
|-|-|
|__Type__|integer|


##### `static_files.<string>.<type=inline_file>.contents` Contents of file

|||
|-|-|
|__Type__|string|


#### `static_files.<string>.<type=host_file>` Copy host file

Copy a file from the host into the guest

##### `static_files.<string>.<type=host_file>.type` Type of file action (copy host file)

|||
|-|-|
|__Type__|`"host_file"`|


##### `static_files.<string>.<type=host_file>.mode` Permissions of file

|||
|-|-|
|__Type__|integer|


##### `static_files.<string>.<type=host_file>.host_path` Host path

|||
|-|-|
|__Type__|string|


#### `static_files.<string>.<type=dir>` Add directory


##### `static_files.<string>.<type=dir>.type` Type of file action (add directory)

|||
|-|-|
|__Type__|`"dir"`|


##### `static_files.<string>.<type=dir>.mode` Permissions of directory

|||
|-|-|
|__Type__|integer|


#### `static_files.<string>.<type=symlink>` Add symbolic link


##### `static_files.<string>.<type=symlink>.type` Type of file action (add symbolic link)

|||
|-|-|
|__Type__|`"symlink"`|


##### `static_files.<string>.<type=symlink>.target` Target linked path

|||
|-|-|
|__Type__|string|


#### `static_files.<string>.<type=dev>` Add device file


##### `static_files.<string>.<type=dev>.type` Type of file action (add device file)

|||
|-|-|
|__Type__|`"dev"`|


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


```yaml
438
```

#### `static_files.<string>.<type=delete>` Delete file


##### `static_files.<string>.<type=delete>.type` Type of file action (delete file)

|||
|-|-|
|__Type__|`"delete"`|


#### `static_files.<string>.<type=move>` Move file


##### `static_files.<string>.<type=move>.type` Type of file action (move file)

|||
|-|-|
|__Type__|`"move"`|


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


##### `static_files.<string>.<type=shim>.target` Target file we want the shim to be symlinked to

|||
|-|-|
|__Type__|string|


## `plugins` Plugins


### `plugins.<string>` Plugin


#### `plugins.<string>.description` Plugin description

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|


#### `plugins.<string>.depends_on` Plugin dependency

|||
|-|-|
|__Type__|string|
|__Default__|`null`|


#### `plugins.<string>.enabled` Enable plugin

|||
|-|-|
|__Type__|boolean|
|__Default__|`true`|

Whether to enable this plugin (default depends on plugin)

#### `plugins.<string>.version` Plugin version

|||
|-|-|
|__Type__|string or null|
|__Default__|`null`|



