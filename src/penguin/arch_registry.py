"""
penguin.arch_registry
=====================

Single source of truth for architecture naming in Penguin.

Historically arch names were spelled differently in a half-dozen tables
(``q_config.qemu_configs``, ``utils.get_arch_subdir``, ``arch.get_dylib_subdir``,
``dropin_compile.DYLIB_DIRS``, ``abi_info.ARCH_ABI_INFO``,
``qemu_compat._normalize_arch_name``), with drift and bugs between them. This
module defines one :class:`ArchSpec` per architecture holding every per-namespace
name, plus alias handling so a user may write any common spelling.

The canonical x86-64 name is ``x86_64`` (``intel64`` is an accepted alias),
matching the on-disk asset layout (dylibs/x86_64, kernels vmlinux.x86_64, …).

This module is intentionally **dependency-free** (stdlib only) so that
``utils``, ``arch``, ``q_config``, ``dropin_compile``, ``abi_info`` and the config
``templating`` module can all import it without import cycles or heavy
dependencies. It must NOT touch the filesystem — the canonical/alias on-disk
fallback resolver lives in ``utils.resolve_arch_asset``.
"""

import dataclasses
from typing import Optional, Tuple


@dataclasses.dataclass(frozen=True)
class ArchSpec:
    """All naming/config facts about one architecture."""

    canonical: str                         # canonical config arch name, e.g. "x86_64"
    aliases: Tuple[str, ...] = ()           # other accepted spellings -> canonical
    # Static asset layout
    arch_subdir: str = ""                   # /igloo_static/<arch_subdir>/ (guest utils)
    dylib_subdir: str = ""                  # /igloo_static/dylibs/<dylib_subdir>/
    _kmod_subdir: Optional[str] = None      # igloo.ko.<kmod_subdir> (defaults to arch_subdir)
    # QEMU / PANDA
    qemu_arch: Optional[str] = None         # q_config "arch" / panda arch (defaults to canonical)
    qemu_machine: Optional[str] = None      # None => not runnable (load_q_config raises)
    cpu: Optional[str] = None
    _kconf_group: Optional[str] = None      # defaults to canonical
    kernel_fmt: str = "vmlinux"
    _kernel_whole: Optional[str] = None     # defaults to f"vmlinux.{qemu_arch}"
    # Guest device / boot
    serial: Tuple[int, int] = (204, 65)     # (major, minor) of /igloo/serial
    console_replacement: Optional[Tuple[str, str]] = None  # (find, replace) on kernel append
    # Effective kernel command-line cap (incl. the NUL terminator): the smaller
    # of what the emulated machine can deliver and the kernel's COMMAND_LINE_SIZE
    # boot_command_line buffer. Anything longer is silently truncated, so it caps
    # how much we can smuggle on the cmdline. All shipped arches are 4096: the
    # MIPS kernels use COMMAND_LINE_SIZE=4096 (upstream since v3.7), and our QEMU
    # malta board passes a cmdline that large (hw/mips/malta.c ENVP_ENTRY_SIZE is
    # bumped from the stock 256 to 0xfdc0). NOTE: that malta bump must be present
    # in the running qemu (rehosting/qemu release pinned by the Dockerfile's
    # QEMU_VERSION) for MIPS to actually receive >256B; the old prom slot
    # truncated at 256 before the kernel ever saw the tail.
    # TODO(env-off-cmdline slice 1): derive this from each shipped kernel's
    # config/ISF instead of hardcoding, so it tracks the kernels we actually ship.
    command_line_size: int = 4096
    endianness: str = "little"              # "little" | "big"
    _abi_key: Optional[str] = None          # key into ARCH_ABI_INFO (defaults to canonical)

    # ---- resolved accessors (apply the "defaults to canonical" rules) ----
    @property
    def kmod_subdir(self) -> str:
        return self._kmod_subdir or self.arch_subdir

    @property
    def panda_arch(self) -> str:
        return self.qemu_arch or self.canonical

    @property
    def kconf_group(self) -> str:
        return self._kconf_group or self.canonical

    @property
    def kernel_whole(self) -> str:
        return self._kernel_whole or f"vmlinux.{self.panda_arch}"

    @property
    def abi_key(self) -> str:
        return self._abi_key or self.canonical


# One entry per architecture. Values transcribed from the previous scattered
# tables; parity tests (tests/unit_tests/test_config.py) assert no regression.
_SPECS = (
    ArchSpec(
        canonical="armel",
        aliases=("arm", "armle"),
        arch_subdir="armel",
        dylib_subdir="armel",
        qemu_arch="arm",
        qemu_machine="virt",
        _kernel_whole="zImage.armel",
        serial=(204, 65),
        console_replacement=("console=ttyS0", "console=ttyAMA0"),
        endianness="little",
    ),
    ArchSpec(
        canonical="aarch64",
        aliases=("arm64",),
        arch_subdir="aarch64",
        # penguin-tools ships dylibs/sysroots under the canonical arch name
        # (aarch64), not the hyperfs-era "arm64". The alias above keeps any
        # arm64-named asset resolving via resolve_arch_asset.
        dylib_subdir="aarch64",
        _kmod_subdir="arm64",
        qemu_arch="aarch64",
        qemu_machine="virt",
        cpu="cortex-a57",
        _kconf_group="arm64",
        _kernel_whole="zImage.arm64",
        serial=(204, 65),
        console_replacement=("console=ttyS0", "console=ttyAMA0"),
        endianness="little",
    ),
    ArchSpec(
        canonical="mipsel",
        arch_subdir="mipsel",
        dylib_subdir="mipsel",
        qemu_arch="mipsel",
        qemu_machine="malta",
        serial=(4, 65),
        endianness="little",
    ),
    ArchSpec(
        canonical="mipseb",
        aliases=("mipsbe",),
        arch_subdir="mipseb",
        dylib_subdir="mipseb",
        qemu_arch="mips",
        qemu_machine="malta",
        _kernel_whole="vmlinux.mipseb",
        serial=(4, 65),
        endianness="big",
    ),
    ArchSpec(
        canonical="mips64el",
        arch_subdir="mips64el",
        dylib_subdir="mips64el",
        qemu_arch="mips64el",
        qemu_machine="malta",
        cpu="MIPS64R2-generic",
        _kernel_whole="vmlinux.mips64el",
        serial=(4, 65),
        endianness="little",
    ),
    ArchSpec(
        canonical="mips64eb",
        aliases=("mips64be",),
        arch_subdir="mips64eb",
        dylib_subdir="mips64eb",
        qemu_arch="mips64",
        qemu_machine="malta",
        cpu="MIPS64R2-generic",
        _kernel_whole="vmlinux.mips64eb",
        serial=(4, 65),
        endianness="big",
    ),
    ArchSpec(
        canonical="powerpc",
        aliases=("ppc",),
        arch_subdir="powerpc",
        dylib_subdir="powerpc",
        qemu_arch="ppc",
        qemu_machine=None,  # no QEMU machine was ever configured for 32-bit ppc
        serial=(229, 1),
        console_replacement=("console=ttyS0", "console=hvc0 console=ttyS0"),
        endianness="big",
    ),
    ArchSpec(
        canonical="powerpc64",
        aliases=("ppc64",),
        arch_subdir="powerpc64",
        dylib_subdir="powerpc64",
        qemu_arch="ppc64",
        qemu_machine="pseries",
        cpu="power9",
        _kconf_group="powerpc64",
        _kernel_whole="vmlinux.powerpc64",
        serial=(229, 1),
        console_replacement=("console=ttyS0", "console=hvc0 console=ttyS0"),
        endianness="big",
    ),
    ArchSpec(
        canonical="powerpc64le",
        aliases=("ppc64le", "powerpc64el", "ppc64el"),
        arch_subdir="powerpc64",
        dylib_subdir="powerpc64le",
        qemu_arch="ppc64",
        qemu_machine="pseries",
        cpu="power9",
        serial=(229, 1),
        console_replacement=("console=ttyS0", "console=hvc0 console=ttyS0"),
        endianness="little",
    ),
    ArchSpec(
        canonical="riscv64",
        aliases=("riscv", "rv64"),
        arch_subdir="riscv64",
        dylib_subdir="riscv64",
        qemu_arch="riscv64",
        qemu_machine="virt",
        kernel_fmt="Image",
        serial=(204, 65),
        endianness="little",
    ),
    ArchSpec(
        canonical="loongarch64",
        aliases=("loongarch", "la64"),
        arch_subdir="loongarch64",
        dylib_subdir="loongarch64",
        qemu_arch="loongarch64",
        qemu_machine="virt",
        cpu="la464",
        kernel_fmt="vmlinuz.efi",
        serial=(4, 65),
        endianness="little",
    ),
    ArchSpec(
        canonical="x86_64",
        aliases=("intel64", "amd64", "x86-64", "x64"),
        arch_subdir="x86_64",
        dylib_subdir="x86_64",
        qemu_arch="x86_64",
        qemu_machine="pc",
        _kconf_group="x86_64",
        kernel_fmt="bzImage",
        serial=(4, 65),
        endianness="little",
    ),
)


_BY_CANONICAL = {s.canonical: s for s in _SPECS}
_BY_NAME = {}
for _s in _SPECS:
    for _n in (_s.canonical, *_s.aliases):
        _key = _n.lower()
        assert _key not in _BY_NAME, f"duplicate arch name/alias: {_n!r}"
        _BY_NAME[_key] = _s
del _s, _n, _key


def spec(name: str) -> ArchSpec:
    """Return the :class:`ArchSpec` for a canonical name or any accepted alias."""
    try:
        return _BY_NAME[name.lower()]
    except (KeyError, AttributeError):
        raise KeyError(f"Unknown architecture: {name!r}")


def normalize_arch(name: str) -> str:
    """Map any accepted spelling to its canonical config arch name."""
    return spec(name).canonical


def is_known(name: str) -> bool:
    try:
        spec(name)
        return True
    except KeyError:
        return False


def all_names() -> list:
    """Canonical names + every alias — exactly the set the schema Literal accepts."""
    return [n for s in _SPECS for n in (s.canonical, *s.aliases)]


def canonical_names() -> list:
    """Just the canonical names, in registry order."""
    return [s.canonical for s in _SPECS]


# Thin accessors so consumers don't reach into the dataclass directly.
def arch_subdir(name: str) -> str:
    return spec(name).arch_subdir


def dylib_subdir(name: str) -> str:
    return spec(name).dylib_subdir


def kmod_subdir(name: str) -> str:
    return spec(name).kmod_subdir


def qemu_arch(name: str) -> str:
    return spec(name).panda_arch
