from typing import Annotated, Dict, List, Literal, Optional, Union, Any
from pydantic import BaseModel, Field, RootModel, model_validator
from pydantic.config import ConfigDict
from pydantic_core import PydanticUndefinedType, PydanticUndefined
import dataclasses
import typing
import jsonschema
import yaml
from yamlcore import CoreLoader
import sys
from pathlib import Path
import os
from copy import deepcopy
import hashlib

'''
We cannot import anything from penguin here as its used to generate the schema
in a self-contained context. If you need things from penguin import them in the
functions that use them.
'''

ENV_MAGIC_VAL = "DYNVALDYNVALDYNVAL"


def _newtype(class_name, type_, title, description=None, default=None, examples=None):
    return type(
        class_name,
        (RootModel,),
        dict(
            __doc__=description,
            model_config=ConfigDict(
                title=title,
                default=default,
                json_schema_extra=examples and dict(examples=examples),
            ),
            __annotations__=dict(root=type_),
        ),
    )


def _variant(discrim_val, title, description, discrim_key, discrim_title, fields):
    return type(
        discrim_val,
        (BaseModel,),
        dict(
            model_config=ConfigDict(title=title, extra="forbid"),
            __doc__=description,
            __annotations__={
                discrim_key: Annotated[
                    Literal[discrim_val],
                    Field(title=f"{discrim_title} ({title.lower()})"),
                ],
            }
            | {key: Annotated[type, field] for key, type, field in fields},
        ),
    )


def _union(class_name, title, description, discrim_key, discrim_title, variants):
    variants = tuple(
        _variant(discrim_key=discrim_key, discrim_title=discrim_title, **v)
        for v in variants
    )
    return _newtype(
        class_name=class_name,
        type_=Annotated[Union[variants], Field(discriminator=discrim_key)],
        title=title,
        description=description,
    )


class Core(BaseModel):
    """Core configuration options for this rehosting"""

    model_config = ConfigDict(title="Core configuration options", extra="forbid")

    arch: Annotated[
        Optional[Literal["armel", "aarch64", "mipsel", "mipseb", "mips64el", "mips64eb", "intel64"]],
        Field(
            None,
            title="Architecture of guest",
            examples=["armel", "aarch64", "mipsel", "mipseb", "mips64el", "mips64eb", "intel64"],
        ),
    ]
    kernel: Annotated[
        Optional[str],
        Field(
            None,
            title="Path to kernel image",
            examples=[
                "/igloo_static/kernels/zImage.armel",
                "/igloo_static/kernels/zImage.arm64",
                "/igloo_static/kernels/vmlinux.mipsel",
                "/igloo_static/kernels/vmlinux.mipseb",
                "/igloo_static/kernels/vmlinux.mips64el",
                "/igloo_static/kernels/vmlinux.mips64eb",
            ],
        ),
    ]

    @model_validator(mode="before")
    def set_kernel_default(cls, values):
        arch = values.get("arch")
        kernel = values.get("kernel")
        if kernel is None and arch is not None:
            if arch == "armel":
                values["kernel"] = "/igloo_static/kernels/4.10/zImage.armel"
            elif arch == "aarch64":
                values["kernel"] = "/igloo_static/kernels/4.10/zImage.arm64"
            elif arch == "intel64":
                values["kernel"] = "/igloo_static/kernels/4.10/bzImage.x86_64"
            else:
                values["kernel"] = f"/igloo_static/kernels/4.10/vmlinux.{arch}"
        return values

    fs: Annotated[
        Optional[str],
        Field(
            "./base/fs.tar.gz",
            title="Project-relative path to filesystem tarball",
            examples=["base/fs.tar.gz"],
        ),
    ]
    plugin_path: Annotated[
        str,
        Field("/pyplugins", title="Path to search for PyPlugins", examples=["/pyplugins"]),
    ]
    root_shell: Annotated[
        bool,
        Field(
            False,
            title="Enable root shell",
            description="Whether to enable a root shell into the guest",
            examples=[False, True],
        ),
    ]
    strace: Annotated[
        bool,
        Field(
            False,
            title="Enable stracing init process",
            description="Whether to enable strace",
            examples=[False, True],
        ),
    ]
    ltrace: Annotated[
        bool,
        Field(
            False,
            title="Enable ltracing init process",
            description="Whether to enable ltrace",
            examples=[False, True],
        ),
    ]
    force_www: Annotated[
        bool,
        Field(
            False,
            title="Try to force webserver start",
            description="Whether to try forcing webserver start",
            examples=[False, True],
        ),
    ]
    cpu: Annotated[
        Optional[str],
        Field(
            None,
            title="CPU model",
            description="Specify non-default QEMU CPU model",
        ),
    ]
    show_output: Annotated[
        bool,
        Field(
            False,
            title="Write serial to stdout",
            description="Whether to print QEMU serial output to stdout instead of writing to a log file",
            examples=[False, True],
        ),
    ]
    immutable: Annotated[
        bool,
        Field(
            True,
            title="Enable immutable mode",
            description="Whether to run the guest filesystem in immutable mode",
            examples=[False, True],
        ),
    ]
    network: Annotated[
        bool,
        Field(
            False,
            title="Connect guest to network",
            description="Whether to connect the guest to the network",
            examples=[False, True],
        ),
    ]
    shared_dir: Annotated[
        Optional[str],
        Field(
            None,
            title="Project-relative path of shared directory",
            description="Share this directory as /igloo/shared in the guest.",
            examples=["my_shared_directory"],
        ),
    ]
    version: Annotated[
        Literal["1.0.0", 2],
        Field(
            title="Config format version",
            description="Version of the config file format",
        ),
    ]
    auto_patching: Annotated[
        bool,
        Field(
            True,
            title="Enable automatic patching",
            description="Whether to automatically apply patches named patch_*.yaml or from patches/*.yaml in the project directory",
            examples=[False, True],
        ),
    ]
    guest_cmd: Annotated[
        bool,
        Field(
            False,
            title="Enable running commands in the guest",
            description="When enabled, starts the guesthopper daemon in the guest that the host can use to run commands over vsock",
            examples=[False, True],
        ),
    ]
    extra_qemu_args: Annotated[
        Optional[str],
        Field(
            None,
            title="Extra QEMU arguments",
            description="A list of additional QEMU command-line arguments to use when booting the guest",
            examples=["-vnc :0 -vga std -device usb-kbd -device usb-tablet"],
        ),
    ]
    mem: Annotated[
        Optional[str],
        Field(
            "2G",
            title="Panda Memory Value",
            description="Allows users to customize memory allocation for guest",
            examples=["16K", "512M", "1G", "2G"],
            ),
    ]


EnvVal = _newtype(
    class_name="EnvVal",
    type_=str,
    title="Value",
    description="Value of the environment variable",
    examples=[ENV_MAGIC_VAL],
)


Env = _newtype(
    class_name="Env",
    type_=dict[str, EnvVal],
    title="Environment",
    description="Environment variables to set in the guest",
    examples=[
        dict(
            VAR1="VAL1",
            VAR2="VAL2",
        ),
        dict(
            PATH="/bin:/sbin",
            TMPDIR="/tmp",
            FOO=ENV_MAGIC_VAL,
        ),
    ],
)
NetDevs = Field(
    default=None,
    title="Network devices",
    description="Names for guest network interfaces",
    examples=[["eth0", "eth1"], ["ens33", "wlp3s0"]],
)

BlockedSignalsField = Field(
    default=None,
    title="List of blocked signals",
    description="Signals numbers to block within the guest. Supported values are 6 (SIGABRT), 9 (SIGKILL), 15 (SIGTERM), and 17 (SIGCHLD).",
    example=[[9], [9, 15]],
)


ConstMapVal = _newtype(
    class_name="ConstMapVal",
    type_=Union[str, tuple[int], tuple[str]],
    title="Data to place in the file at an offset",
    description="When this is a list of integers, it treated as a byte array. When this is a list of strings, the strings are separated by null bytes.",
)


_const_map_fields = (
    ("pad", Union[str, int], Field(0, title="Byte for padding file")),
    ("size", int, Field(0x10000, title="File size", ge=0)),
    ("vals", dict[int, ConstMapVal], Field(title="Mapping from file offsets to data")),
)


Read = _union(
    class_name="Read",
    title="Read",
    description="How to handle reads from the file",
    discrim_key="model",
    discrim_title="Read modelling method",
    variants=(
        dict(
            discrim_val="zero",
            title="Read a zero",
            description=None,
            fields=(),
        ),
        dict(
            discrim_val="empty",
            title="Read empty file",
            description=None,
            fields=(),
        ),
        dict(
            discrim_val="const_buf",
            title="Read a constant buffer",
            description=None,
            fields=(
                (
                    "val",
                    str,
                    Field(
                        title="Constant buffer",
                        description="The string with the contents of the pseudofile",
                    ),
                ),
            ),
        ),
        dict(
            discrim_val="const_map",
            title="Read a constant map",
            description=None,
            fields=_const_map_fields,
        ),
        dict(
            discrim_val="const_map_file",
            title="Read a constant map with host file",
            description=None,
            fields=(
                (
                    "filename",
                    str,
                    Field(title="Path to host file to store constant map"),
                ),
            )
            + _const_map_fields,
        ),
        dict(
            discrim_val="from_file",
            title="Read from a host file",
            description=None,
            fields=(("filename", str, Field(title="Path to host file")),),
        ),
        dict(
            discrim_val="from_plugin",
            title="Read from a custom PyPlugin",
            description=None,
            fields=(
                ("plugin", str, Field(title="Name of the loaded PyPlugin")),
                ("function", Optional[str], Field(title="Function to call", default="read")),
            ),
        ),
        dict(
            discrim_val="default",
            title="Default",
            description=None,
            fields=(),
        ),
    ),
)


Write = _union(
    class_name="Write",
    title="Write",
    description="How to handle writes to the file",
    discrim_key="model",
    discrim_title="Write modelling method",
    variants=(
        dict(
            discrim_val="to_file",
            title="Write to host file",
            description=None,
            fields=(("filename", str, Field(title="Path to host file")),),
        ),
        dict(
            discrim_val="from_plugin",
            title="Read from a custom PyPlugin",
            description=None,
            fields=(
                ("plugin", str, Field(title="Name of the loaded PyPlugin")),
                ("function", Optional[str], Field(title="Function to call", default="read")),
            ),
        ),
        dict(
            discrim_val="discard",
            title="Discard write",
            description=None,
            fields=(),
        ),
        dict(
            discrim_val="default",
            title="Default",
            description=None,
            fields=(),
        ),
    ),
)


IoctlCommand = _union(
    class_name="IoctlCommand",
    title="Ioctl",
    description=None,
    discrim_key="model",
    discrim_title="ioctl modelling method",
    variants=(
        dict(
            discrim_val="return_const",
            title="Return a constant",
            description=None,
            fields=(("val", int, Field(title="Constant to return")),),
        ),
        dict(
            discrim_val="symex",
            title="Symbolic execution",
            description=None,
            fields=(),
        ),
        dict(
            discrim_val="from_plugin",
            title="ioctl from a custom PyPlugin",
            description=None,
            fields=(
                ("plugin", str, Field(title="Name of the loaded PyPlugin")),
                ("function", Optional[str], Field(title="Function to call", default="read")),
            ),
        )
    ),
)


Star = Literal["*"]

Ioctls = _newtype(
    class_name="Ioctls",
    type_=Dict[Union[int, Star], IoctlCommand],
    title="ioctl",
    description="How to handle ioctl() calls",
    default=dict(),
    examples=[
        {
            "*": dict(
                model="return_const",
                val=0,
            ),
            "1000": dict(
                model="return_const",
                val=5,
            ),
        },
        {
            "*": dict(
                model="return_const",
            ),
        },
        {
            "model": "from_plugin",
            "plugin": "my_plugin",
            "function": "ioctl_handler",
        },
    ],
)


class Pseudofile(BaseModel):
    """How to emulate a device file"""

    model_config = ConfigDict(title="File emulation spec", extra="forbid")

    name: Annotated[
        Optional[str],
        Field(
            None,
            title="MTD name",
            description="Name of an MTD device (ignored for non-mtd)",
            examples=["flash", "uboot"],
        ),
    ]
    size: Annotated[
        Optional[int],
        Field(
            None,
            title="File size",
            description="Size of the pseudofile to be reported by stat(). This must be specified for mmap() on the pseudofile to work.",
            examples=[1, 0x1000],
        ),
    ]
    read: Optional[Read] = None
    write: Optional[Write] = None
    ioctl: Optional[Ioctls] = None


Pseudofiles = _newtype(
    class_name="Pseudofiles",
    type_=dict[str, Pseudofile],
    title="Pseudo-files",
    description="Device files to emulate in the guest",
)

Patches = _newtype(
    class_name="Patches",
    type_=list[str],
    title="Patches",
    description="List of paths to patch files",
)


NVRAM = _newtype(
    class_name="NVRAM",
    type_=dict[
        str,
        _newtype(class_name="NVRAMVal", type_=Union[str, int], title="NVRAM value"),
    ],
    title="NVRAM",
    description="NVRAM values to add to the guest",
    default=dict(),
)

UBootEnv = _newtype(
    class_name="UBootEnv",
    type_=dict[
        str,
        _newtype(
            class_name="UBootEnvVal",
            type_=str,
            title="Value",
            description="Value of the U-Boot environment variable",
        ),
    ],
    title="U-Boot environment",
    description="U-Boot environment variables to set in the guest",
    default=dict(),
)


LibInjectAliasTarget = _newtype(
    class_name="LibInjectAliasTarget",
    type_=str,
    title="Injected library alias target",
    description="This is the name of the target function that the alias points to.",
    examples=["nvram_init", "true", "false"],
)

LibInjectAliases = _newtype(
    class_name="LibInjectAliases",
    type_=dict[str, LibInjectAliasTarget],
    title="Injected library aliases",
    description="Mapping between names of external library functions and names of functions defined in the injected library. This allows replacing arbitrary library functions with your own code.",
    default=dict(),
    examples=[
        dict(fputs="false", nvram_load="nvram_init"),
    ],
)


class LibInject(BaseModel):
    """Library functions to be intercepted"""

    model_config = ConfigDict(title="Injected library configuration", extra="forbid")

    aliases: Annotated[
        Optional[LibInjectAliases],
        Field(
            None,
            title="Function names to alias to existing library function shims",
            descriptions="Mapping between new names (e.g., my_nvram_get) and existing library function shims (e.g., nvram_get)",
        ),
    ]

    extra: Annotated[
        Optional[str],
        Field(
            None,
            title="Extra injected library code",
            description="Custom source code for library functions to intercept and model",
        ),
    ]


StaticFileAction = _union(
    class_name="StaticFileAction",
    title="Static filesystem action",
    description=None,
    discrim_key="type",
    discrim_title="Type of file action",
    variants=(
        dict(
            discrim_val="inline_file",
            title="Add inline file",
            description="Add a file with contents specified inline in this config",
            fields=(
                ("mode", int, Field(title="Permissions of file")),
                ("contents", str, Field(title="Contents of file")),
            ),
        ),
        dict(
            discrim_val="host_file",
            title="Copy host file",
            description="Copy a file from the host into the guest",
            fields=(
                ("mode", int, Field(title="Permissions of file")),
                ("host_path", str, Field(title="Host path")),
            ),
        ),
        dict(
            discrim_val="dir",
            title="Add directory",
            description=None,
            fields=(("mode", int, Field(title="Permissions of directory")),),
        ),
        dict(
            discrim_val="symlink",
            title="Add symbolic link",
            description=None,
            fields=(("target", str, Field(title="Target linked path")),),
        ),
        dict(
            discrim_val="dev",
            title="Add device file",
            description=None,
            fields=(
                (
                    "devtype",
                    Literal["char", "block"],
                    Field(title="Type of device file"),
                ),
                ("major", int, Field(title="Major device number")),
                ("minor", int, Field(title="Minor device number")),
                (
                    "mode",
                    int,
                    Field(title="Permissions of device file", examples=[0o666]),
                ),
            ),
        ),
        dict(
            discrim_val="delete",
            title="Delete file",
            description=None,
            fields=(),
        ),
        dict(
            discrim_val="move",
            title="Move file",
            description=None,
            fields=(
                (
                    "from",
                    str,
                    Field(title="File to be moved to the specified location"),
                ),
            ),
        ),
        dict(
            discrim_val="shim",
            title="Shim file",
            description=None,
            fields=(
                (
                    "target",
                    str,
                    Field(title="Target file we want the shim to be symlinked to"),
                ),
            ),
        ),
    ),
)


class StaticFiles(RootModel):
    """Files to create in the guest filesystem"""

    root: dict[str, StaticFileAction]
    model_config = ConfigDict(
        title="Static files",
        json_schema_extra=dict(
            examples=[
                {},
                {
                    "/path/to/file": dict(
                        type="file",
                        contents="Hello world!",
                    )
                },
                {
                    "/path/to/symlink/source": dict(
                        type="symlink",
                        target="/path/to/symlink/target",
                    )
                },
                {
                    "/dev/some_device": dict(
                        type="dev",
                        devtype="char",
                        major=1,
                        minor=2,
                        mode=0o666,
                    )
                },
            ]
        ),
    )


class Plugin(BaseModel):
    model_config = ConfigDict(title="Plugin", extra="allow")

    description: Annotated[Optional[str], Field(None, title="Plugin description")]
    depends_on: Annotated[str, Field(None, title="Plugin dependency")]
    enabled: Annotated[
        bool,
        Field(
            True,
            title="Enable plugin",
            description="Whether to enable this plugin (default depends on plugin)",
        ),
    ]
    version: Annotated[Optional[str], Field(None, title="Plugin version")]


class Main(BaseModel):
    """Configuration file for config-file-based rehosting with IGLOO"""

    model_config = ConfigDict(title="Penguin Configuration", extra="forbid")

    core: Core
    patches: Optional[Patches] = None
    env: Env
    pseudofiles: Pseudofiles
    nvram: NVRAM
    netdevs: List[str] = NetDevs
    uboot_env: Optional[UBootEnv] = None
    blocked_signals: List[int] = BlockedSignalsField
    lib_inject: LibInject
    static_files: StaticFiles
    plugins: Annotated[dict[str, Plugin], Field(title="Plugins")]


def _jsonify_dict(d):
    """
    Recursively walk a nested dict and stringify all the keys

    This is required for jsonschema.validate() to succeed,
    since JSON requires keys to be strings.
    """
    return {
        str(k): _jsonify_dict(v) if isinstance(v, dict) else v for k, v in d.items()
    }


def _validate_config_schema(config, is_dump):
    """Validate config with Pydantic"""
    validated_model = Main(**config)

    if is_dump:
        validated_model.model_dump(exclude_none=True)
    else:
        config.clear()
        config.update(validated_model.model_dump(exclude_none=True))
        config.update(validated_model.model_dump(exclude_none=True))

    jsonschema.validate(
        instance=_jsonify_dict(config),
        schema=Main.model_json_schema(),
    )


def _validate_config_options(config):
    """Do custom checks for config option compatibility"""

    import penguin

    logger = penguin.getColoredLogger("config")

    if config["core"].get("ltrace", False) and config["core"].get("arch", "").startswith(
        "mips64"
    ):
        logger.error("ltrace does not support mips64")
        sys.exit(1)


def _validate_config(config, is_dump=False):
    _validate_config_schema(config, is_dump)
    _validate_config_options(config)


def load_unpatched_config(path):
    '''
    Load a configuration without applying any patches. No validation.
    '''
    with open(path, "r") as f:
        config = yaml.load(f, Loader=CoreLoader)
    return config


def load_config(proj_dir, path, validate=True):
    """Load penguin config from path"""
    with open(path, "r") as f:
        config = yaml.load(f, Loader=CoreLoader)
    # look for files called patch_*.yaml in the same directory as the config file
    if config["core"].get("auto_patching", False) is True:
        patch_files = list(Path(proj_dir).glob("patch_*.yaml"))
        patches_dir = Path(proj_dir, "patches")
        if patches_dir.exists():
            patch_files += list(patches_dir.glob("*.yaml"))
        if patch_files:
            if config.get("patches", None) is None:
                config["patches"] = []
            for patch_file in patch_files:
                config["patches"].append(str(patch_file))
    if config.get("patches", None) is not None:
        patch_list = config["patches"]
        for patch in patch_list:
            # patches are loaded relative to the project directory
            patch_relocated = Path(proj_dir, patch)
            if patch_relocated.exists():
                # TODO: If we're missing a patch we should warn, but this happens 3-4x
                # and that's too verbose.
                from penguin.common import patch_config
                config = patch_config(config, patch_relocated)
    # when loading a patch we don't need a completely valid config
    if validate:
        _validate_config(config)
        # Not required in schema as to allow for patches, but these really are required
        if config["core"].get("arch", None) is None:
            raise ValueError("No core.arch specified in config")

        if config["core"]["fs"] == "./base/empty_fs.tar.gz":
            empty_fs_path = os.path.join(proj_dir, "./base/empty_fs.tar.gz")
            if not os.path.exists(empty_fs_path):
                from penguin.utils import construct_empty_fs
                construct_empty_fs(empty_fs_path)
    return config


def dump_config(config, path):
    """
    Write penguin config to path
    TODO: If we have a config that includes patches we should validate *after* patches.
    For now we allow empty arch and kernel with patches filling them in later, but
    validation doesn't check this
    """
    _validate_config(config, True)
    with open(path, "w") as f:
        f.write(
            "# yaml-language-server: $schema=https://rehosti.ng/igloo/config_schema.yaml\n"
        )
        yaml.dump(config, f, sort_keys=False, default_flow_style=False, width=None)


def hash_yaml_config(config: dict):
    """
    Given a config dict, generate a hash
    """
    target = config
    if "meta" in config:
        # We want to ignore the 'meta' field because it's an internal detail
        config2 = deepcopy(config)
        del config2["meta"]
        target = config2
    return hashlib.md5(str(target).encode()).hexdigest()

