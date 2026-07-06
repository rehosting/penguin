from typing import Annotated, Any, Dict, List, Literal, Optional, Union, ClassVar
from pydantic import BaseModel, Field, RootModel, field_validator, model_validator
from pydantic.config import ConfigDict
from pydantic.functional_validators import AfterValidator
from pydantic_partial import PartialModelMixin, create_partial_model

'''
We cannot import anything from penguin here as its used to generate the schema
in a self-contained context. If you need things from penguin import them in the
functions that use them.
'''

ENV_MAGIC_VAL = "DYNVALDYNVALDYNVAL"


def normalize_hex_string(value: str) -> str:
    """Normalize a user-supplied hex byte string: strip whitespace, allow an
    optional ``0x``/``0X`` prefix, and drop internal spaces. Returns lowercase
    hex with no separators. Raises ``ValueError`` if it is not valid hex or has
    an odd digit count. Shared by the schema validator and the patch applier so
    both accept exactly the same inputs."""
    s = value.strip()
    if s[:2].lower() == "0x":
        s = s[2:]
    s = s.replace(" ", "")
    # bytes.fromhex validates both the alphabet and the even-length requirement.
    bytes.fromhex(s)
    return s.lower()


def _validate_hex_string(value: Optional[str]) -> Optional[str]:
    if value is None:
        return value
    try:
        normalize_hex_string(value)
    except ValueError as e:
        raise ValueError(
            f"expected an even-length hex byte string (optionally 0x-prefixed, "
            f"spaces allowed), got {value!r}: {e}"
        )
    return value


# A hex byte string that is validated at config-load time (so a typo fails with
# a clear message instead of a raw fromhex error during image build). The
# original text is preserved; callers normalize with normalize_hex_string.
HexStr = Annotated[str, AfterValidator(_validate_hex_string)]


class StrSep(RootModel):
    root: str
    separator: ClassVar = None

    @classmethod
    def merge_behavior(cls):
        return f"Concatenate strings separated by `{repr(cls.separator)}`"

    def merge(self, other):
        return self.root + self.separator + other.root


class StrLines(StrSep):
    separator = "\n"


class StrSepSpace(StrSep):
    separator = " "


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


def _variant(discrim_val, title, description, discrim_key, discrim_title, fields, extra="forbid"):
    return type(
        discrim_val,
        (PartialModelMixin, BaseModel),
        dict(
            model_config=ConfigDict(title=title, extra=extra),
            __doc__=description,
            __annotations__={
                discrim_key: Annotated[
                    Literal[discrim_val],
                    Field(title=f"{discrim_title} ({title.lower()})"),
                ],
                "provenance": Annotated[
                    Optional[str],
                    Field(
                        None,
                        title="Model provenance",
                        description=(
                            "Origin tag. Set 'default' for a synthesized stub (it "
                            "reports its hits into pseudofiles_failures.yaml); leave "
                            "unset for author-intentional models."
                        ),
                    ),
                ],
            }
            | {key: Annotated[type, field] for key, type, field in fields},
        ),
    )


# Shared escape variant: select a model registered at runtime via
# @register_model (hyperfile.models.registry). Allows extra keys so the
# custom model's own constructor args validate.
_CUSTOM_VARIANT = dict(
    discrim_val="custom",
    title="Custom registered model",
    description=(
        "Use a model registered via @register_model in a loaded plugin. "
        "'model_name' selects it; any extra keys are forwarded to the model."
    ),
    fields=(("model_name", str, Field(title="Registered model name")),),
    extra="allow",
)


def _union(class_name, title, description, discrim_key, discrim_title, variants, allow_custom=False):
    if allow_custom:
        variants = tuple(variants) + (_CUSTOM_VARIANT,)
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


GDBServerProgramPort = _newtype(class_name="GDBServerProgramPort", type_=int, title="Port")
GDBServerPrograms = _newtype(
    class_name="GDBServerPrograms",
    type_=dict[str, GDBServerProgramPort],
    title="Programs to run through gdbserver",
    description=" ".join((
        "Mapping between names of programs and ports for gdbserver.",
        "When a program in this mapping is run,",
        "it will start paused with gdbserver attached, listening on the specified port.",
    )),
    default=dict(),
    examples=[dict(), dict(lighttpd=9999)],
)


class Snapshot(PartialModelMixin, BaseModel):
    """VM snapshot (savevm/loadvm) configuration.

    Snapshotting is *active* whenever ``save_at`` or ``boot_from`` is set — there
    is no separate enable flag. When active, the guest runs on a persistent
    qcow2 overlay (rather than the throwaway immutable overlay) so an internal VM
    snapshot can be saved and later restored. Saving a snapshot at a chosen point
    lets a later run boot directly from that state instead of re-booting the
    firmware.
    """

    model_config = ConfigDict(title="Snapshot configuration", extra="forbid")

    backend: Annotated[
        Literal["internal", "file"],
        Field(
            "internal",
            title="Snapshot backend",
            description=(
                "'internal' stores the snapshot inside the qcow2 overlay "
                "(savevm/loadvm). 'file' (not yet implemented) writes a "
                "standalone migration file bundle."
            ),
            examples=["internal", "file"],
        ),
    ]
    tag: Annotated[
        str,
        Field(
            "boot",
            title="Snapshot tag",
            description="Name of the internal VM snapshot to save and/or restore.",
            examples=["boot", "post_init"],
        ),
    ]
    save_at: Annotated[
        Optional[Literal["readiness", "manual"]],
        Field(
            None,
            title="When to save the snapshot",
            description=(
                "'readiness' saves once the guest reaches steady state; "
                "'manual' arms the Snapshot plugin to save on request "
                "(via guest_cmd / hypercall). None disables saving."
            ),
            examples=["readiness", "manual"],
        ),
    ]
    boot_from: Annotated[
        Optional[str],
        Field(
            None,
            title="Snapshot tag to boot from",
            description="If set, restore this internal snapshot at startup (-loadvm).",
            examples=["boot"],
        ),
    ]
    stop_after_save: Annotated[
        bool,
        Field(
            False,
            title="End the run after saving",
            description="Shut the guest down immediately after the snapshot is saved.",
            examples=[False, True],
        ),
    ]


class SharedDir(PartialModelMixin, BaseModel):
    """Host<->guest shared directory (9p) configuration.

    Accepted in ``core.shared_dir`` as ``true`` (enable with defaults), a string
    (shorthand for ``path``), or this object. Core dumps ride the same single
    mount (see ``core.core_dumps``); they do not need this feature enabled.
    """

    model_config = ConfigDict(title="Shared directory configuration", extra="forbid")

    path: Annotated[
        str,
        Field(
            "shared",
            title="Results-relative share directory",
            description=(
                "Directory shared into the guest at /igloo/shared. Resolved under "
                "the run's results dir unless core.shared_dir.host_path is set."
            ),
            examples=["shared", "my_shared_directory"],
        ),
    ]
    host_path: Annotated[
        Optional[str],
        Field(
            None,
            title="Absolute host directory to share",
            description=(
                "If set, share this absolute host directory instead of a "
                "results-relative one (path is ignored)."
            ),
            examples=["/data/fixtures"],
        ),
    ]
    msize: Annotated[
        Optional[int],
        Field(
            None,
            title="9p msize override",
            description=(
                "Override the 9p transport buffer size. Unset uses the default "
                "8MB with an automatic fallback to 128KB on memory-tight guests."
            ),
            examples=[8192000, 131072],
        ),
    ]


class CoreDumps(PartialModelMixin, BaseModel):
    """Guest core-dump capture configuration.

    Accepted in ``core.core_dumps`` as ``true`` (enable with defaults), a string
    (shorthand for ``pattern``), or this object. When enabled, penguin points
    core_pattern at /igloo/core_dumps (a symlink into the shared mount) and
    brings that mount up even when core.shared_dir is unset.
    """

    model_config = ConfigDict(title="Core dump configuration", extra="forbid")

    lock: Annotated[
        bool,
        Field(
            True,
            title="Lock core_pattern",
            description=(
                "Install a sysctl pseudofile that eats guest writes to "
                "core_pattern so dumps can't be redirected. Set false to let "
                "the guest firmware keep its own core_pattern."
            ),
            examples=[True, False],
        ),
    ]
    pattern: Annotated[
        Optional[str],
        Field(
            None,
            title="core_pattern override",
            description=(
                "Override the core_pattern string. Unset uses "
                "/igloo/core_dumps/core_%e.%p."
            ),
            examples=["/igloo/core_dumps/core_%e.%p.%t"],
        ),
    ]


class Core(PartialModelMixin, BaseModel):
    """Core configuration options for this rehosting"""

    model_config = ConfigDict(title="Core configuration options", extra="forbid")

    arch: Annotated[
        # Canonical config arch names plus accepted aliases. Aliases are
        # normalized to their canonical name at config-load time. This list MUST
        # equal penguin.arch_registry.all_names() — enforced by a unit test
        # (structure.py can't import penguin at schema-definition time).
        Optional[Literal[
            "armel", "arm", "armle",
            "aarch64", "arm64",
            "mipsel",
            "mipseb", "mipsbe",
            "mips64el",
            "mips64eb", "mips64be",
            "powerpc", "ppc",
            "powerpc64", "ppc64",
            "powerpc64le", "ppc64le", "powerpc64el", "ppc64el",
            "riscv64", "riscv", "rv64",
            "loongarch64", "loongarch", "la64",
            "x86_64", "intel64", "amd64", "x86-64", "x64",
        ]],
        Field(
            None,
            title="Architecture of guest",
            description="Canonical name or an accepted alias (normalized at load, e.g. intel64 -> x86_64).",
            examples=["x86_64", "armel", "aarch64", "mipsel", "mipseb", "mips64el", "powerpc64le"],
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
    analysis_scope: Annotated[
        Union[bool, str],
        Field(
            "firmware",
            title="Scope of per-process analysis",
            description=" ".join((
                "Which processes the per-process analysis loggers capture. Affects the",
                "syscall/exec-derived loggers (syscalls, exec, read/write, ficd,",
                "interfaces) and busybox shell coverage; netbinds always reports for",
                "every process regardless of this setting. Recognized values:",
                "'firmware' (default) captures only the firmware-under-analysis",
                "process subtree, excluding Penguin's own infrastructure (boot",
                "machinery and the vpnguin/console/guesthopper helpers); 'none'",
                "captures every process, including Penguin infrastructure; 'infra'",
                "inverts the firmware filter to capture only Penguin's own tools.",
                "Booleans are accepted for backward compatibility: true == 'firmware',",
                "false == 'none'. The field is a string so further interpretations can",
                "be added without a schema change.",
            )),
            examples=["firmware", "none", "infra"],
        ),
    ]
    strace: Annotated[
        Union[bool, list[str]],
        Field(
            False,
            title="Enable strace",
            description=" ".join((
                "If true, run strace for entire system starting from init.",
                "If names of programs, enable strace only for those programs.",
            )),
            examples=[False, True, ["lighttpd"]],
        ),
    ]
    ltrace: Annotated[
        Union[bool, list[str]],
        Field(
            False,
            title="Enable ltrace",
            description=" ".join((
                "If true, run ltrace for entire system starting from init.",
                "If names of programs, enable ltrace only for those programs.",
            )),
            examples=[False, True, ["lighttpd"]],
        ),
    ]
    gdbserver: Optional[GDBServerPrograms] = None
    snapshot: Optional[Snapshot] = None
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
    log_file: Annotated[
      Optional[str],
      Field(
            None,
            title="Penguin log file",
            description="If set, write penguin/plugin logger output to this file (relative paths resolve under the results dir).",
            examples=["penguin.log"],
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
        Optional[Union[bool, str, SharedDir]],
        Field(
            None,
            title="Shared directory",
            description=(
                "Share a directory as /igloo/shared in the guest. Accepts true "
                "(enable with defaults), a project-relative path string, or a "
                "SharedDir object."
            ),
            examples=[True, "my_shared_directory", {"path": "shared", "msize": 131072}],
        ),
    ]
    core_dumps: Annotated[
        Optional[Union[bool, str, CoreDumps]],
        Field(
            None,
            title="Core dump capture",
            description=(
                "Capture guest core dumps to /igloo/core_dumps (a symlink into "
                "the shared mount). Accepts true (enable with defaults), a "
                "core_pattern string, or a CoreDumps object. Independent of "
                "core.shared_dir. When core.core_dumps is unset but "
                "core.shared_dir is set, core dumps are enabled for backward "
                "compatibility (deprecated)."
            ),
            examples=[True, "/igloo/core_dumps/core_%e.%p", {"lock": False}],
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
    execution_mode: Annotated[
        Literal["qemu", "kvm"],
        Field(
            "qemu",
            title="Execution Mode",
            description="The execution backend to use for the guest (qemu for TCG, kvm for hardware acceleration)",
            examples=["qemu", "kvm"],
        ),
    ]
    extra_qemu_args: Annotated[
        Optional[StrSepSpace],
        Field(
            None,
            title="Extra QEMU arguments",
            description="A list of additional QEMU command-line arguments to use when booting the guest",
            examples=["-vnc :0 -vga std -device usb-kbd -device usb-tablet"],
        ),
    ]
    kernel_cmdline_append: Annotated[
        Optional[StrSepSpace],
        Field(
            None,
            title="Extra kernel command-line tokens",
            description=(
                "Tokens appended verbatim to the kernel command line (-append). "
                "Use this to set real kernel parameters or anything you need on "
                "/proc/cmdline. Unlike `env`, these are never diverted to the "
                "early-boot env blob, so they always reach the kernel cmdline. "
                "They count against the per-arch COMMAND_LINE_SIZE budget (256 "
                "bytes on MIPS), so penguin warns/errors if they overflow it."
            ),
            examples=["nokaslr mem=256M", "igloo_debug=1"],
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
    kernel_quiet: Annotated[
        bool,
        Field(
            True,
            title="Whether to include quiet flag in kernel command line",
            description="If true, the kernel command line will include the quiet flag, otherwise all kernel boot messages will be printed to the console",
            examples=[False, True],
        ),
    ]
    smp: Annotated[
        Optional[int],
        Field(
            1,
            title="Number of CPUs",
            description="Number of CPUs to emulate in the guest (Warning: This can break things)",
            examples=[1, 2, 4],
        ),
    ]
    timeout: Annotated[
        Optional[int],
        Field(
            None,
            title="Run timeout (seconds)",
            description="If set, automatically shut the guest down after this many seconds. Overridden by the --timeout CLI flag. No timeout when unset.",
            examples=[60, 300],
        ),
    ]
    graphics: Annotated[
        bool,
        Field(
            False,
            title="Enable graphics",
            description="Whether to enable graphics in the guest",
            examples=[False, True],
        ),
    ]
    allow_reboot: Annotated[
        bool,
        Field(
            False,
            title="Allow the guest to reboot",
            description=" ".join((
                "If False (default), QEMU is launched with '-no-reboot' so a",
                "guest-initiated reboot terminates the emulation (one boot per run).",
                "If True, '-no-reboot' is omitted so QEMU resets the machine in place",
                "and the guest reboots within the same run. Persistent drives and",
                "host-file-backed MTD devices survive the reset; stateful plugins must",
                "tolerate a second guest init.",
            )),
            examples=[False, True],
        ),
    ]
    startup_script: Annotated[
        Optional[str],
        Field(
            None,
            title="Inline guest startup script",
            description=" ".join((
                "Shell script body dropped into /igloo/init.d to run during guest boot.",
                "Installed under a name that sorts after other init.d entries so it runs last.",
                "A '#!/igloo/utils/sh' shebang is prepended automatically.",
            )),
            examples=["ip link set eth0 up\nudhcpc -i eth0\n"],
        ),
    ]

    @field_validator("shared_dir", mode="before")
    @classmethod
    def _norm_shared_dir(cls, v):
        # Normalize bool/str shorthands to a SharedDir dict; false/None disable.
        if v is None or v is False:
            return None
        if v is True:
            return {}
        if isinstance(v, str):
            return {"path": v}
        return v

    @field_validator("core_dumps", mode="before")
    @classmethod
    def _norm_core_dumps(cls, v):
        # Normalize bool/str shorthands to a CoreDumps dict; false/None disable.
        if v is None or v is False:
            return None
        if v is True:
            return {}
        if isinstance(v, str):
            return {"pattern": v}
        return v


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
    default=[],
    title="Network devices",
    description="Names for guest network interfaces",
    examples=[["eth0", "eth1"], ["ens33", "wlp3s0"]],
)

BlockedSignalsField = Field(
    default=[],
    title="List of blocked signals",
    description="Signals numbers to block within the guest. Supported values are 6 (SIGABRT), 9 (SIGKILL), 15 (SIGTERM), and 17 (SIGCHLD).",
    example=[[9], [9, 15]],
)

ConstMapVal = _newtype(
    class_name="ConstMapVal",
    type_=Union[str, list[int], list[str]],
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
    allow_custom=True,
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
            discrim_val="one",
            title="Read a one",
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
                    Field(title="Pseudofile contents"),
                ),
                (
                    "null_terminate",
                    bool,
                    Field(False, title="Append a NUL byte to the configured contents"),
                ),
                (
                    "nul_terminate",
                    bool,
                    Field(False, title="Alias for null_terminate"),
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
            discrim_val="cycle",
            title="Read a repeating buffer",
            description="Repeat the configured buffer forever (never reports EOF).",
            fields=(
                ("val", str, Field(title="Buffer to repeat")),
            ),
        ),
        dict(
            discrim_val="from_file",
            title="Read from a host file",
            description=None,
            fields=(("filename", str, Field(title="Path to host file")),),
        ),
        dict(
            discrim_val="stateful",
            title="Read back what was written",
            description=(
                "Serve bytes from this node's write buffer, giving a "
                "read-after-write register. Pair with write model 'default' "
                "(or 'discard'/'record', which all record) so writes are stored."
            ),
            fields=(
                ("initial", Optional[str], Field(None, title="Initial buffer contents")),
            ),
        ),
        dict(
            discrim_val="sequence",
            title="Read successive values",
            description=(
                "Return each entry of 'vals' on successive reads; the common "
                "'busy... busy... ready' status pattern. Holds the last entry "
                "when exhausted unless 'cycle' wraps around."
            ),
            fields=(
                ("vals", list, Field(title="Ordered values to return")),
                ("cycle", bool, Field(False, title="Wrap around when exhausted")),
            ),
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
    allow_custom=True,
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
                ("function", Optional[str], Field(title="Function to call", default="write")),
            ),
        ),
        dict(
            discrim_val="discard",
            title="Discard write",
            description=None,
            fields=(),
        ),
        dict(
            discrim_val="return_const",
            title="Return a constant on write",
            description="Return a fixed value (e.g. a byte count or a negative errno) without storing data.",
            fields=(("const", int, Field(title="Value to return from write()")),),
        ),
        dict(
            discrim_val="unhandled",
            title="Reject writes",
            description="Return -EINVAL for every write.",
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
            fields=(("val", int, Field(0, title="Constant to return")),),
        ),
        dict(
            discrim_val="zero",
            title="Return zero",
            description=None,
            fields=(),
        ),
        dict(
            discrim_val="unhandled",
            title="Reject ioctl",
            description="Return -ENOTTY (inappropriate ioctl for device).",
            fields=(),
        ),
        dict(
            discrim_val="write_data",
            title="Write a buffer to the arg pointer",
            description=(
                "Write a constant buffer to the user pointer in 'arg' (the common "
                "shape of an ioctl that fills a struct), then return 'val'."
            ),
            fields=(
                ("data", str, Field(title="Bytes to write to *arg")),
                ("val", int, Field(0, title="Value to return from ioctl()")),
            ),
        ),
        dict(
            discrim_val="from_plugin",
            title="ioctl from a custom PyPlugin",
            description=None,
            fields=(
                ("plugin", str, Field(title="Name of the loaded PyPlugin")),
                ("function", Optional[str], Field(title="Function to call", default="ioctl")),
            ),
        )
    ),
)


Poll = _union(
    class_name="Poll",
    allow_custom=True,
    title="Poll",
    description="How to answer poll()/select() on the file",
    discrim_key="model",
    discrim_title="Poll modelling method",
    variants=(
        dict(
            discrim_val="always_ready",
            title="Always report ready",
            description="Constant POLLIN|POLLRDNORM|POLLOUT|POLLWRNORM mask (legacy behavior).",
            fields=(),
        ),
        dict(
            discrim_val="from_plugin",
            title="Poll from a custom PyPlugin",
            description="Data-aware poll: the plugin returns a poll mask reflecting actual readiness.",
            fields=(
                ("plugin", str, Field(title="Name of the loaded PyPlugin")),
                ("function", Optional[str], Field(title="Function to call", default="poll")),
            ),
        ),
    ),
)


Seek = _union(
    class_name="Seek",
    allow_custom=True,
    title="Seek",
    description="How to handle lseek() on the file",
    discrim_key="model",
    discrim_title="Seek modelling method",
    variants=(
        dict(
            discrim_val="default",
            title="Standard offset arithmetic",
            description="SEEK_SET/CUR/END against the node's reported size.",
            fields=(),
        ),
        dict(
            discrim_val="unsupported",
            title="Reject seeks",
            description="Return -ESPIPE (for pipe/stream-like nodes).",
            fields=(),
        ),
        dict(
            discrim_val="from_plugin",
            title="lseek from a custom PyPlugin",
            description=None,
            fields=(
                ("plugin", str, Field(title="Name of the loaded PyPlugin")),
                ("function", Optional[str], Field(title="Function to call", default="lseek")),
            ),
        ),
    ),
)


Mmap = _union(
    class_name="Mmap",
    allow_custom=True,
    title="Mmap",
    description="How to handle mmap() on the file",
    discrim_key="model",
    discrim_title="Mmap modelling method",
    variants=(
        dict(
            discrim_val="from_plugin",
            title="mmap from a custom PyPlugin",
            description=None,
            fields=(
                ("plugin", str, Field(title="Name of the loaded PyPlugin")),
                ("function", Optional[str], Field(title="Function to call", default="mmap")),
            ),
        ),
    ),
)


Open = _union(
    class_name="Open",
    allow_custom=True,
    title="Open",
    description="How to handle open() on the file",
    discrim_key="model",
    discrim_title="Open modelling method",
    variants=(
        dict(
            discrim_val="from_plugin",
            title="open from a custom PyPlugin",
            description="Fire a plugin function when the guest opens this node.",
            fields=(
                ("plugin", str, Field(title="Name of the loaded PyPlugin")),
                ("function", Optional[str], Field(title="Function to call", default="open")),
            ),
        ),
    ),
)


Release = _union(
    class_name="Release",
    allow_custom=True,
    title="Release",
    description="How to handle release()/close() on the file",
    discrim_key="model",
    discrim_title="Release modelling method",
    variants=(
        dict(
            discrim_val="from_plugin",
            title="release from a custom PyPlugin",
            description="Fire a plugin function when the guest closes this node.",
            fields=(
                ("plugin", str, Field(title="Name of the loaded PyPlugin")),
                ("function", Optional[str], Field(title="Function to call", default="release")),
            ),
        ),
    ),
)


def _plugin_op_union(class_name, title, op):
    """A 'from_plugin'-only op union (with the shared custom escape variant)."""
    return _union(
        class_name=class_name,
        title=title,
        description=f"How to handle {op}() on the file",
        discrim_key="model",
        discrim_title=f"{title} modelling method",
        allow_custom=True,
        variants=(
            dict(
                discrim_val="from_plugin",
                title=f"{op} from a custom PyPlugin",
                description=None,
                fields=(
                    ("plugin", str, Field(title="Name of the loaded PyPlugin")),
                    ("function", Optional[str], Field(title="Function to call", default=op)),
                ),
            ),
        ),
    )


# Device-specific / advanced fops. flush/fsync/fasync/lock are /dev-only
# (procfs does not wire them); read_iter/write_iter/get_unmapped_area are
# advanced. All are plugin-driven.
Flush = _plugin_op_union("Flush", "Flush", "flush")
Fsync = _plugin_op_union("Fsync", "Fsync", "fsync")
Fasync = _plugin_op_union("Fasync", "Fasync", "fasync")
Lock = _plugin_op_union("Lock", "Lock", "lock")
ReadIter = _plugin_op_union("ReadIter", "Read iterator", "read_iter")
WriteIter = _plugin_op_union("WriteIter", "Write iterator", "write_iter")
GetUnmappedArea = _plugin_op_union("GetUnmappedArea", "Get unmapped area", "get_unmapped_area")


CompatIoctl = _union(
    class_name="CompatIoctl",
    title="Compat ioctl",
    description="How to handle 32-bit compat_ioctl() on the file",
    discrim_key="model",
    discrim_title="compat_ioctl modelling method",
    variants=(
        dict(
            discrim_val="same_as_ioctl",
            title="Reuse the ioctl model",
            description="Route compat_ioctl through the same handlers as ioctl (the common driver pattern).",
            fields=(),
        ),
        dict(
            discrim_val="from_plugin",
            title="compat_ioctl from a custom PyPlugin",
            description=None,
            fields=(
                ("plugin", str, Field(title="Name of the loaded PyPlugin")),
                ("function", Optional[str], Field(title="Function to call", default="compat_ioctl")),
            ),
        ),
    ),
)


Star = Literal["*"]

Ioctls = _newtype(
    class_name="Ioctls",
    type_=Union[IoctlCommand, Dict[Union[int, Star], IoctlCommand]],
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


class Pseudofile(PartialModelMixin, BaseModel):
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
    plugin: Annotated[
        Optional[str],
        Field(
            None,
            title="Single backing class",
            description=(
                "Name of a single backing class that owns the whole file_operations "
                "surface (read/write/ioctl/poll) for this node. Reference a built-in "
                "backing by name, or a user class as 'file:ClassName' (the file is found "
                "via the normal pyplugin search path). When set, the per-domain "
                "read/write/ioctl/poll keys are ignored — the class owns them all."
            ),
            examples=["my_backing:SerialBacking"],
        ),
    ]
    read: Optional[Read] = None
    write: Optional[Write] = None
    ioctl: Optional[Ioctls] = None
    poll: Optional[Poll] = None
    lseek: Optional[Seek] = None
    mmap: Optional[Mmap] = None
    open: Optional[Open] = None
    release: Optional[Release] = None
    compat_ioctl: Optional[CompatIoctl] = None
    flush: Optional[Flush] = None
    fsync: Optional[Fsync] = None
    fasync: Optional[Fasync] = None
    lock: Optional[Lock] = None
    read_iter: Optional[ReadIter] = None
    write_iter: Optional[WriteIter] = None
    get_unmapped_area: Optional[GetUnmappedArea] = None


# Which path classes wire each operation, so we can reject a model attached to
# a node whose filesystem can't service it. Keyed by Pseudofile field name.
#   - char-device fops (flush/fsync/fasync/lock/write_iter) only wire for /dev
#   - the broader VFS fops also wire for /proc (procfs), but NOT /proc/sys
#     (sysctl) or /sys (sysfs), which only service reads/writes.
_OP_SUPPORTED_PATHS = {
    "flush": ("dev",),
    "fsync": ("dev",),
    "fasync": ("dev",),
    "lock": ("dev",),
    "write_iter": ("dev",),
    "lseek": ("dev", "proc"),
    "mmap": ("dev", "proc"),
    "open": ("dev", "proc"),
    "release": ("dev", "proc"),
    "compat_ioctl": ("dev", "proc"),
    "read_iter": ("dev", "proc"),
    "get_unmapped_area": ("dev", "proc"),
}

_PATH_CLASS_LABEL = {
    "dev": "/dev",
    "proc": "/proc",
    "procsys": "/proc/sys",
    "sys": "/sys",
}


def _classify_pseudofile_path(path: str) -> str:
    if path.startswith("/dev/"):
        return "dev"
    if path.startswith("/proc/sys/"):
        return "procsys"
    if path.startswith("/proc/"):
        return "proc"
    if path.startswith("/sys/"):
        return "sys"
    return "other"


class Pseudofiles(RootModel):
    """Device files to emulate in the guest"""

    model_config = ConfigDict(title="Pseudo-files")

    root: dict[str, Pseudofile] = {}

    @model_validator(mode="after")
    def _validate_op_paths(self):
        for path, node in (self.root or {}).items():
            cls = _classify_pseudofile_path(path)
            for op, allowed in _OP_SUPPORTED_PATHS.items():
                if getattr(node, op, None) is None:
                    continue
                if cls not in allowed:
                    allowed_labels = " or ".join(_PATH_CLASS_LABEL[a] for a in allowed)
                    raise ValueError(
                        f"pseudofile '{path}': the '{op}' model is only supported "
                        f"on {allowed_labels} nodes (this filesystem does not wire "
                        f"{op}()). Remove it or move the node."
                    )
        return self


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


class LibInject(PartialModelMixin, BaseModel):
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
        Optional[StrLines],
        Field(
            None,
            title="Extra injected library code",
            description="Custom source code for library functions to intercept and model",
        ),
    ]


class BinaryPatchEntry(PartialModelMixin, BaseModel):
    """A single edit within a ``binary_patch`` action: bytes to write at one
    file offset, optionally guarded by an ``expect`` check. Multiple entries can
    target one file via the action's ``patches`` list; they are applied
    host-side to one buffer in a single pass, and overlapping write ranges are
    rejected."""

    model_config = ConfigDict(title="Binary patch entry", extra="forbid")

    file_offset: Annotated[int, Field(title="File offset (integer)", ge=0)]
    hex_bytes: Annotated[
        Optional[HexStr],
        Field(default=None, title="Bytes to write at offset (hex string)",
              examples=["DEADBEEF", "90 90"]),
    ] = None
    asm: Annotated[
        Optional[str],
        Field(default=None,
              title="Assembly code to write at offset (runs through keystone)",
              examples=["nop", "mov r0, #0xdeadbeef"]),
    ] = None
    mode: Annotated[
        Optional[str],
        Field(default=None, title="Assembly mode", examples=["arm", "thumb"]),
    ] = None
    expect: Annotated[
        Optional[HexStr],
        Field(default=None,
              title="Expected bytes at offset before patching (hex string)",
              description="If set, the current bytes at file_offset are compared against this hex string (over its own length, which may differ from the patch length) before the patch is written. If the bytes at the offset already equal the patch bytes, the patch is skipped (idempotent re-run); otherwise the on_mismatch policy applies.",
              examples=["0102 0304", "DEADBEEF"]),
    ] = None
    on_mismatch: Annotated[
        Literal["fail", "skip", "warn"],
        Field(default="fail", title="Policy when 'expect' does not match",
              description="fail: abort the run (default, safest). skip: leave the file unpatched and continue. warn: log a warning and write the patch anyway. Only meaningful when 'expect' is set."),
    ] = "fail"
    why: Annotated[
        Optional[str],
        Field(default=None,
              title="Rationale for this patch, recorded in the run's binary_patches.yaml",
              examples=["NOP out the secure-boot check"]),
    ] = None
    tag: Annotated[
        Optional[str],
        Field(default=None,
              title="Label grouping related patches, recorded in the run's binary_patches.yaml",
              examples=["secureboot"]),
    ] = None


# Shared 'patches' field for the file-producing actions (inline_file /
# host_file). Placing a file and patching it are orthogonal — the file's
# 'type' says what it is, 'patches' modifies what was placed — so patching is
# expressed as an operation on those actions rather than a mutually-exclusive
# type. The edits funnel into the same host-side pipeline as the standalone
# 'binary_patch' action, applied after the file is staged into the guest.
_PLACED_FILE_PATCHES = (
    "patches",
    Optional[List[BinaryPatchEntry]],
    Field(
        default=None,
        title="Binary patches to apply after this file is placed",
        description="A list of binary edits applied to this file after it is "
        "staged into the guest, in a single host-side pass (same semantics as "
        "the standalone 'binary_patch' action). Each edit may verify the bytes "
        "currently at its offset (expect/on_mismatch) and record rationale "
        "(why/tag); every outcome is written to binary_patches.yaml in the run "
        "output. Overlapping write ranges are rejected. Cannot be combined with "
        "a glob source or destination (the patch target would be ambiguous).",
    ),
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
                ("mode", int, Field(0o644, title="Permissions of file")),
                ("contents", str, Field(title="Contents of file")),
                _PLACED_FILE_PATCHES,
            ),
        ),
        dict(
            discrim_val="host_file",
            title="Copy host file",
            description="Copy a file from the host into the guest",
            fields=(
                ("mode", int, Field(0o755, title="Permissions of file")),
                ("host_path", str, Field(title="Host path")),
                _PLACED_FILE_PATCHES,
            ),
        ),
        dict(
            discrim_val="dir",
            title="Add directory",
            description=None,
            fields=(("mode", int, Field(0o755, title="Permissions of directory")),),
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
                    Field(0o666, title="Permissions of device file"),
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
                ("mode", Optional[int], Field(title="Permissions of target file", default=None)),
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
        dict(
            discrim_val="binary_patch",
            title="Patch binary file",
            description="Patch a binary file at one or more offsets. A single edit is given inline (file_offset + one of hex_bytes/asm); multiple edits to the same file go in the 'patches' list (applied together in one host-side pass, with overlapping write ranges rejected). Each edit may verify the bytes currently at its offset first (expect/on_mismatch) so the patch is idempotent and safe across firmware variants, and record rationale (why/tag); every edit's outcome is written to binary_patches.yaml in the run output.",
            fields=(
                (
                    "file_offset",
                    Optional[int],
                    Field(
                        default=None,
                        ge=0,
                        title="File offset (integer) — for a single inline edit; omit when using 'patches'",
                    ),
                ),
                (
                    "hex_bytes",
                    Optional[HexStr],
                    Field(
                        default=None,
                        title="Bytes to write at offset (hex string)",
                        examples=["DEADBEEF", "90 90"],
                    ),
                ),
                (
                    "asm",
                    Optional[str],
                    Field(
                        default=None,
                        title="Assembly code to write at offset (runs through keystone)",
                        examples=["nop", "mov r0, #0xdeadbeef"],
                    ),
                ),
                (
                    "mode",
                    Optional[str],
                    Field(
                        default=None,
                        title="Assembly mode",
                        examples=["arm", "thumb"],
                    ),
                ),
                (
                    "expect",
                    Optional[HexStr],
                    Field(
                        default=None,
                        title="Expected bytes at offset before patching (hex string)",
                        description="If set, the current bytes at file_offset are compared against this hex string (over its own length, which may differ from the patch length) before the patch is written. If the bytes at the offset already equal the patch bytes, the patch is skipped (idempotent re-run); otherwise the on_mismatch policy applies.",
                        examples=["0102 0304", "DEADBEEF"],
                    ),
                ),
                (
                    "on_mismatch",
                    Literal["fail", "skip", "warn"],
                    Field(
                        default="fail",
                        title="Policy when 'expect' does not match",
                        description="fail: abort the run (default, safest). skip: leave the file unpatched and continue. warn: log a warning and write the patch anyway. Only meaningful when 'expect' is set.",
                    ),
                ),
                (
                    "why",
                    Optional[str],
                    Field(
                        default=None,
                        title="Rationale for this patch, recorded in the run's binary_patches.yaml",
                        examples=["NOP out the secure-boot check"],
                    ),
                ),
                (
                    "tag",
                    Optional[str],
                    Field(
                        default=None,
                        title="Label grouping related patches, recorded in the run's binary_patches.yaml",
                        examples=["secureboot"],
                    ),
                ),
                (
                    "patches",
                    Optional[List[BinaryPatchEntry]],
                    Field(
                        default=None,
                        title="Multiple edits to this file",
                        description="A list of edits applied to this one file in a single host-side pass. Use this instead of the inline file_offset/hex_bytes/asm fields when patching a binary at more than one offset. Overlapping write ranges are rejected.",
                    ),
                ),
            )
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


class Plugin(PartialModelMixin, BaseModel):
    model_config = ConfigDict(title="Plugin", extra="allow")

    description: Annotated[Optional[str], Field(None, title="Plugin description")]
    depends_on: Annotated[Optional[str], Field(None, title="Plugin dependency")]
    enabled: Annotated[
        bool,
        Field(True, title="Enable this plugin (default depends on plugin)"),
    ]
    version: Annotated[Optional[str], Field(None, title="Plugin version")]


class InitPluginEntry(PartialModelMixin, BaseModel):
    """One init plugin's record/settings in the init_plugins section."""

    model_config = ConfigDict(title="Init plugin", extra="allow")

    enabled: Annotated[
        bool,
        Field(
            True,
            title="Run this init plugin during penguin refresh",
            description=(
                "Set to false to skip this plugin entirely when re-running "
                "init analyses with `penguin refresh`."
            ),
        ),
    ]


class ExternalNetwork(PartialModelMixin, BaseModel):
    """Configuration for NAT for external connections"""

    model_config = ConfigDict(title="Set up NAT for outgoing connections", extra="forbid")

    mac: Optional[str] = Field(
        title="MAC Address for external interface",
        default="52:54:00:12:34:56",
        description="MAC Address for external network interface"
    )

    # Not supported until QEMU 4.0+
    # net: Optional[str] = Field(
    #     default="10.0.2.0/24",
    #     description="Net for external interface (e.g., 10.0.2.0/24). Host will accessible via .2"
    # )

    pcap: Optional[bool] = Field(
        title="pcap file name",
        default=None,
        description="Whether to capture traffic over the external net in a pcap file. The file will be called 'ext.pcap' in the output directory. Capture disabled if unset."
    )


class Network(PartialModelMixin, BaseModel):
    """Configuration for networks to attach to guest"""

    model_config = ConfigDict(title="Network Configuration", extra="forbid")

    external: ExternalNetwork = Field(default_factory=ExternalNetwork)


class Main(PartialModelMixin, BaseModel):
    """Configuration file for config-file-based rehosting with IGLOO"""

    model_config = ConfigDict(title="Penguin Configuration", extra="forbid")

    core: Core
    patches: Optional[Patches] = None
    vars: Annotated[
        Optional[dict[str, Any]],
        Field(
            None,
            title="Template variables",
            description=" ".join((
                "User-defined variables usable elsewhere via Jinja2 templating,",
                "e.g. `{{ myvar }}`. Alongside these, `{{ arch }}`, `{{ core.<field> }}`,",
                "and `{{ kernel_version }}` are available. This section is consumed at",
                "load time and does not appear in the realized config.",
            )),
            examples=[dict(webroot="/www", libdir="/lib/{{ arch }}")],
        ),
    ] = None
    env: Env
    pseudofiles: Pseudofiles
    nvram: NVRAM
    netdevs: List[str] = NetDevs
    uboot_env: Optional[UBootEnv] = None
    blocked_signals: List[int] = BlockedSignalsField
    lib_inject: LibInject
    static_files: StaticFiles
    plugins: Annotated[dict[str, Plugin], Field(title="Plugins")]
    init_plugins: Annotated[
        dict[str, InitPluginEntry],
        Field(
            None,
            title="Init plugins",
            description=(
                "The init plugins that generated this project (recorded by "
                "`penguin init`). Drives which plugins re-run on `penguin "
                "refresh`; newly available plugins are appended when they run."
            ),
        ),
    ] = None
    network: Optional[Network] = None

    @field_validator("init_plugins", mode="before")
    @classmethod
    def _init_plugins_none_ok(cls, v):
        # Partial-model merging can hand us an explicit None; treat as empty
        return {} if v is None else v


Patch = create_partial_model(Main, recursive=True)
