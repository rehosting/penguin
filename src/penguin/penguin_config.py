import dataclasses
import hashlib
import sys
import os
import typing
from copy import deepcopy
from typing import Annotated, Any, Dict, List, Literal, Optional, Union

import jsonschema
import yaml
from yamlcore import CoreLoader
from pydantic import BaseModel, Field, RootModel
from pydantic.config import ConfigDict
from pydantic_core import PydanticUndefined, PydanticUndefinedType

try:
    from penguin.common import patch_config
    from penguin.utils import construct_empty_fs
except ImportError:
    pass
from pathlib import Path

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
        Literal["armel", "aarch64", "mipsel", "mipseb", "mips64eb", "intel64"],
        Field(
            title="Architecture of guest",
            examples=["armel", "aarch64", "mipsel", "mipseb", "mips64eb", "intel64"],
        ),
    ]
    kernel: Annotated[
        str,
        Field(
            title="Path to kernel image",
            examples=[
                "/igloo_static/kernels/zImage.armel",
                "/igloo_static/kernels/zImage.arm64",
                "/igloo_static/kernels/vmlinux.mipsel",
                "/igloo_static/kernels/vmlinux.mipseb",
                "/igloo_static/kernels/vmlinux.mips64eb",
            ],
        ),
    ]
    fs: Annotated[
        Union[str, None],
        Field(
            title="Project-relative path to filesystem tarball",
            examples=["base/fs.tar"],
        ),
    ]
    plugin_path: Annotated[
        str,
        Field("/pandata", title="Path to search for PyPlugins", examples=["/pandata"]),
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
        Literal["1.0.0"],
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

    description: Annotated[str, Field(None, title="Plugin description")]
    depends_on: Annotated[str, Field(None, title="Plugin dependency")]
    enabled: Annotated[
        bool,
        Field(
            None,
            title="Enable plugin",
            description="Whether to enable this plugin (default depends on plugin)",
        ),
    ]
    version: Annotated[str, Field(None, title="Plugin version")]


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


def _validate_config_schema(config):
    """Validate config with Pydantic"""
    Main(**config).model_dump()
    jsonschema.validate(
        instance=_jsonify_dict(config),
        schema=Main.model_json_schema(),
    )


def _validate_config_options(config):
    """Do custom checks for config option compatibility"""

    import penguin

    logger = penguin.getColoredLogger("config")

    if config["core"].get("ltrace", False) and config["core"]["arch"].startswith(
        "mips64"
    ):
        logger.error("ltrace does not support mips64")
        sys.exit(1)


def _validate_config(config):
    _validate_config_schema(config)
    _validate_config_options(config)


def load_config(path, validate=True):
    """Load penguin config from path"""
    with open(path, "r") as f:
        config = yaml.load(f, Loader=CoreLoader)
    config_folder = Path(path).parent
    # look for files called patch_*.yaml in the same directory as the config file
    if config["core"]["auto_patching"]:
        patch_files = list(config_folder.glob("patch_*.yaml"))
        patches_dir = Path(config_folder, "patches")
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
            # patches are loaded relative to the main config file
            patch_relocated = Path(config_folder, patch)
            config = patch_config(config, patch_relocated)
    # when loading a patch we don't need a completely valid config
    if validate:
        _validate_config(config)
        if config["core"].get("fs", None) is None:
            config["core"]["fs"] = "./base/empty_fs.tar.gz"
            empty_fs_path = os.path.join(config_folder, "./base/empty_fs.tar.gz")
            if not os.path.exists(empty_fs_path):
                construct_empty_fs(empty_fs_path)
    return config


def dump_config(config, path):
    """Write penguin config to path"""
    _validate_config(config)
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


def gen_docs_yaml_dump(x):
    """
    Convert `x` to YAML for use in generated docs.
    We can't use `yaml.dump(x)` alone for this, becuase it appends "\n...\n".
    """

    s = yaml.dump(x)
    term = "\n...\n"
    s = s[: -len(term)] if s.endswith(term) else s
    return s.strip()


def gen_docs_type_name(t):
    """Convert the Python type `t` to a string for use in generated docs."""

    og = typing.get_origin(t)
    args = typing.get_args(t)

    if t == Star:
        return '"*"'
    elif og is Union:
        return " or ".join(map(gen_docs_type_name, args))
    elif og is Literal:
        return " or ".join([f'`"{gen_docs_yaml_dump(a)}"`' for a in args])
    elif og in (list, tuple):
        return "list of " + gen_docs_type_name(args[0])
    elif t is int:
        return "integer"
    elif t is str:
        return "string"
    elif t is bool:
        return "boolean"
    elif t is type(None):
        return "null"
    else:
        raise ValueError(f"unknown type {t}")


def gen_docs_field(path, docs_field, include_type=True):
    """Generate docs for a single field of the config"""

    assert (
        docs_field.title is not None
    ), f"config option {path} has no title: {docs_field}"
    heading_hashes = "#" * (len(path) + 1)
    include_docs = docs_field.default is not PydanticUndefined
    path_prefix = f"`{'.'.join(path)}` " if path else ""
    out = ""
    out += f"{heading_hashes} {path_prefix}{docs_field.title}\n"
    if include_type or include_docs:
        out += "\n"
        out += "|||\n"
        out += "|-|-|\n"
    if include_type:
        out += f"|__Type__|{gen_docs_type_name(docs_field.type_)}|\n"
    if include_docs:
        out += f"|__Default__|`{gen_docs_yaml_dump(docs_field.default)}`|\n"
    out += "\n"
    if docs_field.description is not None:
        out += docs_field.description + "\n"
    out += "\n"
    for e in docs_field.examples:
        out += "```yaml\n"
        out += gen_docs_yaml_dump(e) + "\n"
        out += "```\n"
        out += "\n"
    return out


@dataclasses.dataclass(frozen=True)
class DocsField:
    """Information about a field of the config, for generating docs"""

    type_: type
    title: Optional[str]
    description: Optional[str]
    default: Union[PydanticUndefinedType, Any]
    examples: tuple[Any]

    def from_type(type_: type) -> "DocsField":
        """Create a `DocsField` from a Python type, which should probably inherit `BaseModel` or `RootModel`"""

        # Change Optional[Optional[... Optional[T] ...]] to T
        while (
            typing.get_origin(type_) is Union
            and len(typing.get_args(type_)) == 2
            and typing.get_args(type_)[1] is type(None)
        ):
            type_ = typing.get_args(type_)[0]

        if hasattr(type_, "model_config"):
            # Inherits BaseModel or RootModel
            title = type_.model_config["title"]
            description = type_.__doc__
            try:
                default = type_.model_config["default"]
            except KeyError:
                default = PydanticUndefined
            try:
                examples = type_.model_config["json_schema_extra"]["examples"]
            except (KeyError, TypeError):
                examples = []
        else:
            # Doesn't inherit BaseModel or RootModel, so make all values empty
            title = description = None
            default = PydanticUndefined
            examples = []
        return DocsField(type_, title, description, default, examples)

    def from_field(field) -> "DocsField":
        """Create a `DocsField` from a Pydantic `Field`"""

        return DocsField(
            field.annotation,
            field.title,
            field.description,
            field.default,
            field.examples or [],
        ).merge(DocsField.from_type(field.annotation))

    def merge(self, other: "DocsField") -> "DocsField":
        """Create a `DocsField` by combining two `DocsField`s, using the second to fill in gaps in the first"""
        return DocsField(
            self.type_,
            self.title or other.title,
            self.description or other.description,
            other.default if self.default is PydanticUndefined else self.default,
            self.examples + other.examples,
        )


def gen_docs(path=[], docs_field=DocsField.from_type(Main)):
    """Generate docs for config format starting from the field at the given path"""

    type_ = docs_field.type_
    type_origin = typing.get_origin(type_)
    type_args = typing.get_args(type_)

    # The first type argument that inherits `BaseModel`.
    # For example, if the type is `Optional[Env]`, this is `Env`
    first_model_arg = next(
        (a for a in type_args if hasattr(a, "model_fields")),
        None,
    )

    is_model = hasattr(type_, "model_fields")  # Type inherits `BaseModel`
    is_root_model = (
        is_model and "root" in type_.model_fields
    )  # Type inherits `RootModel`
    out = ""

    if is_root_model:
        # The type inherits `RootModel`. It is a newtype or a union.

        info = type_.model_fields["root"]
        discrim_key = info.discriminator
        ann = info.annotation
        og = typing.get_origin(ann)
        args = typing.get_args(ann)

        if isinstance(discrim_key, str):
            # The type is a tagged union
            assert og is Union

            # Generate docs for the union itself
            out += gen_docs_field(path=path, docs_field=docs_field, include_type=False)

            # Generate docs for each variant
            for variant in args:
                [discrim_val] = typing.get_args(
                    variant.model_fields[discrim_key].annotation
                )
                out += gen_docs(
                    path=path + [f"<{discrim_key}={discrim_val}>"],
                    docs_field=DocsField.from_type(variant),
                )
        else:
            # The type is a newtype.
            # Collect its metadata and try again with the underlying type.
            out += gen_docs(
                path=path,
                docs_field=DocsField.from_field(info).merge(docs_field),
            )
    elif is_model:
        # The type inherits `BaseModel` but not `RootModel`

        out += gen_docs_field(path=path, docs_field=docs_field, include_type=False)
        for name, info in type_.model_fields.items():
            out += gen_docs(
                path=path + [name],
                docs_field=DocsField.from_field(info),
            )
    elif type_origin is dict:
        # The type is `dict[T, U]`.

        # Generate docs for the dictionary itself
        out += gen_docs_field(path=path, docs_field=docs_field, include_type=False)

        # Generate docs for the value type
        key_type, val_type = typing.get_args(type_)
        key_type_str = gen_docs_type_name(key_type)
        out += gen_docs(
            path=path + [f"<{key_type_str}>"],
            docs_field=DocsField.from_type(val_type),
        )
    elif type_origin is Union and first_model_arg is not None:
        # The type is `Optional[T]`. Try again with just `T`.
        out += gen_docs(
            path=path,
            docs_field=DocsField.from_type(first_model_arg),
        )
    else:
        # The type does not inherit from `BaseModel` and it doesn't have an argument that does.
        # It is probably a primative type, like `str` or `bool`.
        # There is no more recursion to do for this field, so just generate docs for it.
        out += gen_docs_field(path, docs_field)

    return out


if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    sp = p.add_subparsers(required=True)

    sp.add_parser(
        "schema",
        help="Write JSON schema for config to stdout",
    ).set_defaults(func=lambda: print(yaml.dump(Main.model_json_schema(), indent=2)))

    sp.add_parser(
        "docs",
        help="Write generated config docs to stdout",
    ).set_defaults(func=lambda: print(gen_docs()))

    p.parse_args().func()
