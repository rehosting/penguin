import dataclasses
from typing import Optional
from elftools.elf.constants import E_FLAGS, E_FLAGS_MASKS
from penguin import getColoredLogger

logger = getColoredLogger("penguin.arch")

# MIPS "machine" (SoC family) selector in e_flags. pyelftools' E_FLAGS/
# E_FLAGS_MASKS don't expose these, so transcribe the binutils values
# (include/elf/mips.h EF_MIPS_MACH_*). Cavium Octeon parts implement custom
# MIPS64 ASE opcodes that fault on QEMU's generic MIPS64R2 CPU, so we have to
# identify them here and route them to the Octeon CPU model.
EF_MIPS_MACH = 0x00FF0000
EF_MIPS_MACH_OCTEON = 0x008B0000   # Octeon (CN3xxx/CN5xxx)
EF_MIPS_MACH_OCTEON2 = 0x008D0000  # Octeon II (CN6xxx/CN7xxx)
EF_MIPS_MACH_OCTEON3 = 0x008E0000  # Octeon III
_OCTEON_MACHS = (EF_MIPS_MACH_OCTEON, EF_MIPS_MACH_OCTEON2, EF_MIPS_MACH_OCTEON3)


def get_dylib_subdir(arch_name: str) -> str:
    """
    Map a config arch name (or alias) to the subdirectory under
    ``<static>/dylibs`` holding that arch's prebuilt dynamic libraries.

    Thin wrapper over the arch registry (the single source of truth), kept for
    backward compatibility with existing callers / the ``{{ dylib_dir }}``
    template variable.
    """
    from .arch_registry import dylib_subdir
    return dylib_subdir(arch_name)


@dataclasses.dataclass
class ArchInfo:
    arch: Optional[str] = None
    abi: str = "default"
    bits: Optional[int] = None
    # All other fields are only used on MIPS
    endianness: Optional[str] = None
    description: Optional[str] = None

    def __str__(self):
        def print_field(field):
            name = field.name
            value = getattr(self, name)
            value = "unknown" if value is None else str(value)
            return f"{name}={value}"

        return ", ".join(map(print_field, dataclasses.fields(self)))


def arch_end(value):
    arch = None
    end = None

    tmp = value.lower()
    if tmp.startswith("mips64"):
        arch = "mips64"
    elif tmp.startswith("mips"):
        arch = "mips"
    elif tmp.startswith("aarch64"):
        arch = "aarch64"
        end = "el"
    elif tmp.startswith("arm"):
        arch = "arm"
    elif tmp.startswith("intel"):
        arch = "intel64"
        end = "el"
    elif tmp.startswith("riscv32"):
        arch = "riscv64"  # just use riscv64
        end = "el"
    elif tmp.startswith("riscv64"):
        arch = "riscv64"
        end = "el"
    elif tmp.startswith("ppc"):
        arch = "powerpc64"
        end = "eb"
    # elif tmp.startswith("ppc"):
        # arch = "powerpc"
        # end = "eb"  # it can be either so we give it eb
    elif tmp.startswith("loongarch64"):
        arch = "loongarch64"
        end = "el"

    if tmp.endswith("el"):
        end = "el"
    elif tmp.endswith("eb"):
        end = "eb"

    if arch is None or end is None:
        logger.error(f"Unhandled arch_end for {value}. Have arch={arch}, end={end}")

    return (arch, end)


def _elf_bits(header):
    return 64 if header.e_ident["EI_CLASS"] == "ELFCLASS64" else 32


def _identify_arm_arch(elf):
    """
    Check for hard/soft float
    """
    attrs = elf.get_section_by_name(".ARM.attributes")
    hf = (
        False
        if attrs is None
        else any(
            (attr.tag, attr.value) == ("TAG_ABI_VFP_ARGS", 1)
            for attrs in attrs.iter_subsections()
            for attrs in attrs.iter_subsubsections()
            for attr in attrs.iter_attributes()
        )
    )
    return ArchInfo(
        arch="armel",
        abi="hard_float" if hf else "soft_float",
        bits=_elf_bits(elf.header),
    )


def _identify_mips_arch(header):
    """
    Mips is more complicated. We could have 32 bit binaries that only run on a 64-bit
    system (i.e., mips64 with the n32 ABI). Other permutations will likely cause issues
    later so trying to future-proof this a bit. Masks/comparisons based off readelf.py
    from PyElfTools.
    """
    endianness = header.e_ident["EI_DATA"]
    flags = header["e_flags"]

    if flags & E_FLAGS.EF_MIPS_ARCH == E_FLAGS.EF_MIPS_ARCH_1:
        mips_arch = "mips1"
    if flags & E_FLAGS.EF_MIPS_ARCH == E_FLAGS.EF_MIPS_ARCH_2:
        mips_arch = "mips2"
    if flags & E_FLAGS.EF_MIPS_ARCH == E_FLAGS.EF_MIPS_ARCH_3:
        mips_arch = "mips3"
    if flags & E_FLAGS.EF_MIPS_ARCH == E_FLAGS.EF_MIPS_ARCH_4:
        mips_arch = "mips4"
    if flags & E_FLAGS.EF_MIPS_ARCH == E_FLAGS.EF_MIPS_ARCH_5:
        mips_arch = "mips5"
    if flags & E_FLAGS.EF_MIPS_ARCH == E_FLAGS.EF_MIPS_ARCH_32R2:
        mips_arch = "mips32r2"
    if flags & E_FLAGS.EF_MIPS_ARCH == E_FLAGS.EF_MIPS_ARCH_64R2:
        mips_arch = "mips64r2"
    if flags & E_FLAGS.EF_MIPS_ARCH == E_FLAGS.EF_MIPS_ARCH_32:
        mips_arch = "mips32"
    if flags & E_FLAGS.EF_MIPS_ARCH == E_FLAGS.EF_MIPS_ARCH_64:
        mips_arch = "mips64"

    is_octeon = (flags & EF_MIPS_MACH) in _OCTEON_MACHS

    # Some extra flags that only affect what gets printed
    description = "mips"
    if is_octeon:
        description += ", octeon"
    if flags & E_FLAGS.EF_MIPS_NOREORDER:
        description += ", noreorder"
    if flags & E_FLAGS.EF_MIPS_PIC:
        description += ", pic"
    if flags & E_FLAGS.EF_MIPS_CPIC:
        description += ", cpic"
    if flags & E_FLAGS.EF_MIPS_ABI2:
        description += ", abi2"
    if flags & E_FLAGS.EF_MIPS_32BITMODE:
        description += ", 32bitmode"

    bits = _elf_bits(header)

    # GDB's source code is a good resource for MIPS ABI identification:
    # https://github.com/bminor/binutils-gdb/blob/master/gdb/mips-tdep.c
    if flags & E_FLAGS_MASKS.EFM_MIPS_ABI_O32:
        abi = "o32"
    elif flags & E_FLAGS_MASKS.EFM_MIPS_ABI_O64:
        abi = "o64"  # never seen this before - unsupported for now?
    elif flags & 0x20:
        abi = "n32"
        bits = 64  # Even though n32 is 32-bit, it only runs on 64-bit CPUs
    elif bits == 32:
        abi = "o32"  # Default 32-bit ABI
    else:
        assert bits == 64
        abi = "n64"  # Default 64-bit ABI

    logger.debug(
        f"Identified MIPS firmware: arch={mips_arch}, bits={bits}, abi={abi}, endian={endianness}, extras={description}"
    )

    arch = {
        (32, "ELFDATA2LSB"): "mipsel",
        (32, "ELFDATA2MSB"): "mipseb",
        (64, "ELFDATA2LSB"): "mips64el",
        (64, "ELFDATA2MSB"): "mips64eb",
    }.get((bits, endianness))

    if arch is None:
        logger.error(
            "Unexpected MIPS architecture: bits %d, endianness %s", bits, endianness
        )
    elif is_octeon and bits == 64:
        # Octeon is a MIPS64 superset: same kernels/dylibs/ABI, but it needs
        # QEMU's Octeon CPU model (the generic MIPS64R2 CPU faults on the
        # Cavium-specific opcodes). Route to the dedicated arch spec, which
        # reuses the mips64{el,eb} assets and only overrides the CPU model.
        arch += "_octeon"
    elif is_octeon:
        # 32-bit ELFs (e.g. n32) can carry the Octeon MACH tag too; the 64-bit
        # kernel is what actually needs the CPU model, so a 32-bit-only view
        # stays generic but we note it for debugging.
        logger.debug("Octeon MACH flag on a %d-bit MIPS ELF; keeping arch=%s", bits, arch)

    return ArchInfo(
        arch=arch, abi=abi, bits=bits, endianness=endianness, description=description
    )


def arch_filter(elf):
    header = elf.header

    if not isinstance(header.e_machine, str):
        # It's an int sometimes? That's no good
        logger.warning(
            f"Unexpected e_machine type: {type(header.e_machine)}: {header.e_machine}. Cannot identify architecture."
        )
        return ArchInfo()

    friendly_arch = header.e_machine.replace("EM_", "")

    arch = {
        # Normal architectures:
        "X86_64": "intel64",
        "386": "intel",
        "AARCH64": "aarch64",
        "PPC": "ppc",
        "PPC64": "ppc64",
        "RISCV": "riscv",
        "LOONGARCH": "loongarch64",
        # Additional processing required for these:
        "ARM": "arm",
        "MIPS": "mips",
    }.get(friendly_arch)

    if arch is None:
        logger.debug(f"Unsupported architecture: {friendly_arch}")
        logger.debug(f"ELF Header: {header}")
        return ArchInfo()

    # Special processing for ARM and MIPS
    if arch == "arm":
        try:
            return _identify_arm_arch(elf)
        except Exception as e:
            logger.error(f"Error identifying ARM architecture: {e}")
            return ArchInfo()  # Return unknown if we fail to parse for some reason
    elif arch == "mips":
        try:
            return _identify_mips_arch(header)
        except Exception as e:
            logger.error(f"Error identifying MIPS architecture: {e}")
            return ArchInfo()  # Return unknown if we fail to parse for some reason
    elif arch == "riscv":
        return ArchInfo(arch=f"{arch}{_elf_bits(elf.header)}", bits=_elf_bits(elf.header))
    elif arch == "ppc":
        # same for big and little
        return ArchInfo(arch="ppc", bits=_elf_bits(elf.header))
    elif arch == "intel":
        return ArchInfo(arch=arch, bits=_elf_bits(elf.header), abi="i386")

    # Other architectures get eb suffix if big-endian. mips/arm are handled in their helpers
    if header.e_ident.get("EI_DATA", None) == "ELFDATA2MSB":
        arch += "eb"
    return ArchInfo(arch=arch, bits=_elf_bits(elf.header))
