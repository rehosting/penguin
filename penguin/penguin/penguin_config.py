from typing import Optional, Union, Literal, Annotated, Dict

from pydantic import BaseModel, RootModel, Field
from pydantic.config import ConfigDict


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
                json_schema_extra=examples and dict(examples=examples)
            ),
            __annotations__=dict(root=type_),
        )
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
                    Field(title=f"{discrim_title} ({title.lower()})")
                ],
            } | { key: Annotated[type, field] for key, type, field in fields },
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
    model_config = ConfigDict(title="Core configuration options", extra="forbid")

    arch: Annotated[
        Literal["armel", "mipsel", "mipseb", "mips64eb"],
        Field(
            title="Architecture of guest",
            examples=["armel", "mipsel", "mipseb", "mips64eb"],
        ),
    ]
    kernel: Annotated[
        str,
        Field(
            title="Path to kernel image",
            examples=[
                "/igloo_static/kernels/zImage.armel",
                "/igloo_static/kernels/vmlinux.mipsel",
                "/igloo_static/kernels/vmlinux.mipseb",
                "/igloo_static/kernels/vmlinux.mips64eb",
            ],
        ),
    ]
    fs: Annotated[
        str,
        Field(
            title="Path to filesystem tarball",
            examples=["/output/device_name/base/fs.tar"],
        ),
    ]
    plugin_path: Annotated[
        str,
        Field("/pandata", title="Path to search for PyPlugins", examples=["/pandata"]),
    ]
    qcow: Annotated[
        str,
        Field(
            title="Path to filesystem qcow file",
            examples=["/output/device_name/base/image.qcow"],
        ),
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
            False,
            title="Host path of shared directory",
            description="Share this directory as /igloo/shared in the guest.",
            examples=["/shared"],
        ),
    ]
    version: Annotated[
        Literal["1.0.0"],
        Field(
            title="Config format version",
            description="Version of the config file format",
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
NetDevs = _newtype(
    class_name="NetDevs",
    type_=list[str],
    title="Network Devices",
    description="Names for guest network interfaces",
    examples=[
        ["eth0",
         "eth1"],
        ["ens33",
         "wlp3s0"]
    ],
)

BlockedSignals = _newtype(
    class_name="BlockedSignals",
    type_=list[str],
    title="Signals to block",
    description="Signals numbers to block within guest",
    examples=[
        [15],
        [9, 14],
    ],
)

ConstMapVal = _newtype(
    class_name="ConstMapVal",
    type_=Union[
        str,
        _newtype(class_name="ByteArray", type_=tuple[int], title="Byte array"),
        _newtype(class_name="StringArray", type_=tuple[str], title="String array to be joined by null bytes"),
    ],
    title="Data to place in the file at an offset",
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
                ("val", str, Field(
                    title="Constant buffer",
                    description="The string with the contents of the pseudofile"
                )),
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
                ("filename", str, Field(title="Path to host file to store constant map")),
            ) + _const_map_fields,
        ),
        dict(
            discrim_val="from_file",
            title="Read from a host file",
            description=None,
            fields=(
                ("filename", str, Field(title="Path to host file")),
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
            fields=(
                ("filename", str, Field()),
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
    title=None,
    description=None,
    discrim_key="model",
    discrim_title="ioctl modelling method",
    variants=(
        dict(
            discrim_val="return_const",
            title="Return a constant",
            description=None,
            fields=(
                ("val", int, Field(title="Constant to return")),
            ),
        ),
        dict(
            discrim_val="symex",
            title="Symbolic execution",
            description=None,
            fields=(),
        ),
    ),
)


Ioctls = _newtype(
    class_name="Ioctls",
    type_=Dict[Union[int, str], IoctlCommand], # TODO: str should only allow for "*" but we need a custom validator for that
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
            examples=["flash","uboot"],
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


NVRAM = _newtype(
    class_name="NVRAM",
    type_=dict[
        str,
        _newtype(
            class_name="NVRAMVal",
            type_=Union[str, int],
            title="NVRAM value"
        ),
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
            fields=(
                ("mode", int, Field(title="Permissions of directory")),
            ),
        ),
        dict(
            discrim_val="symlink",
            title="Add symbolic link",
            description=None,
            fields=(
                ("target", str, Field(title="Target linked path")),
            ),
        ),
        dict(
            discrim_val="dev",
            title="Add device file",
            description=None,
            fields=(
                ("devtype", Literal["char", "block"], Field(title="Type of device file")),
                ("major", int, Field(title="Major device number")),
                ("minor", int, Field(title="Minor device number")),
                ("mode", int, Field(title="Permissions of device file", examples=[0o666])),
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
                ("from", str, Field(title="File to be moved to the specified location")),
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

    description: Annotated[str, Field(title="Plugin description")]
    depends_on: Annotated[str, Field(None, title="Plugin dependency")]
    enabled: Annotated[
        bool,
        Field(
            None,
            title="Enable plugin",
            description="Whether to enable this plugin (default depends on plugin)",
        ),
    ]
    version: Annotated[str, Field(title="Plugin version")]


class Main(BaseModel):
    """Configuration file for config-file-based rehosting with IGLOO"""
    model_config = ConfigDict(title="Penguin Configuration", extra="forbid")

    core: Core
    env: Env
    pseudofiles: Pseudofiles
    nvram: NVRAM
    netdevs: Optional[NetDevs] = None
    uboot_env: Optional[UBootEnv] = None
    blocked_signals: Optional[BlockedSignals] = None
    static_files: StaticFiles
    plugins: Annotated[dict[str, Plugin], Field(title="Plugins")]


if __name__ == "__main__":
    import yaml
    print(yaml.dump(Main.model_json_schema(), indent=2))
