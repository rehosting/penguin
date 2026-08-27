"""
Octeon CPU identification.

Cavium Octeon parts are MIPS64 supersets that implement custom ASE opcodes;
the generic MIPS64R2 QEMU CPU faults on them. ``_identify_mips_arch`` must spot
the ``EF_MIPS_MACH`` Octeon tag in a 64-bit ELF and emit the dedicated
``mips64{eb,el}_octeon`` arch, which reuses the base mips64 assets and only
overrides the QEMU CPU model to ``Octeon68XX``.
"""

import pytest
from elftools.elf.constants import E_FLAGS

from penguin import arch_registry
from penguin.arch import (
    _identify_mips_arch,
    EF_MIPS_MACH_OCTEON,
    EF_MIPS_MACH_OCTEON2,
    EF_MIPS_MACH_OCTEON3,
)


class _FakeHeader:
    """Minimal stand-in for a pyelftools ELF header: attribute e_ident + [] flags."""

    def __init__(self, *, bits, data, e_flags):
        self.e_ident = {
            "EI_CLASS": "ELFCLASS64" if bits == 64 else "ELFCLASS32",
            "EI_DATA": data,
        }
        self._flags = e_flags

    def __getitem__(self, key):
        assert key == "e_flags"
        return self._flags


# n64 ABI (no O32/O64/n32 bits) at MIPS64R2 — the assignment mips_arch needs.
_MIPS64_BASE = E_FLAGS.EF_MIPS_ARCH_64R2


def _hdr(bits, data, mach=0):
    return _FakeHeader(bits=bits, data=data, e_flags=_MIPS64_BASE | mach)


@pytest.mark.parametrize("mach", [EF_MIPS_MACH_OCTEON, EF_MIPS_MACH_OCTEON2, EF_MIPS_MACH_OCTEON3])
def test_octeon_big_endian_64bit(mach):
    info = _identify_mips_arch(_hdr(64, "ELFDATA2MSB", mach))
    assert info.arch == "mips64eb_octeon"
    assert info.bits == 64
    assert "octeon" in info.description


@pytest.mark.parametrize("mach", [EF_MIPS_MACH_OCTEON, EF_MIPS_MACH_OCTEON2, EF_MIPS_MACH_OCTEON3])
def test_octeon_little_endian_64bit(mach):
    info = _identify_mips_arch(_hdr(64, "ELFDATA2LSB", mach))
    assert info.arch == "mips64el_octeon"


def test_generic_mips64_unaffected():
    # No MACH tag -> plain mips64eb, exactly as before.
    info = _identify_mips_arch(_hdr(64, "ELFDATA2MSB", mach=0))
    assert info.arch == "mips64eb"
    assert "octeon" not in info.description


def test_octeon_tag_on_32bit_stays_generic():
    # A 32-bit ELF carrying the Octeon MACH tag: the 64-bit kernel is what needs
    # the CPU model, so a 32-bit-only view must not claim the octeon arch.
    info = _identify_mips_arch(_FakeHeader(bits=32, data="ELFDATA2MSB", e_flags=EF_MIPS_MACH_OCTEON2))
    assert info.arch == "mipseb"


def test_octeon_arch_reuses_base_assets_and_overrides_cpu():
    base = arch_registry.spec("mips64eb")
    oct_be = arch_registry.spec("mips64eb_octeon")
    # CPU model is the ONLY thing that changes.
    assert oct_be.cpu == "Octeon68XX"
    assert base.cpu != oct_be.cpu
    # Every asset/subdir points back at the base arch.
    for attr in ("arch_subdir", "dylib_subdir", "kmod_subdir", "kernel_whole",
                 "abi_key", "kconf_group", "panda_arch", "qemu_machine"):
        assert getattr(oct_be, attr) == getattr(base, attr), attr


def test_octeon_aliases_resolve():
    assert arch_registry.normalize_arch("octeon") == "mips64eb_octeon"
    assert arch_registry.normalize_arch("octeonel") == "mips64el_octeon"


def test_octeon_runnable_via_q_config():
    from penguin.q_config import load_q_config
    q = load_q_config({"core": {"arch": "mips64eb_octeon"}})
    assert q["cpu"] == "Octeon68XX"
    assert q["qemu_machine"] == "malta"
    assert q["arch"] == "mips64"
