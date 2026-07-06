"""Tests for the real-ISF enum path (``RealKffi`` / ``install_real_consts`` /
``real_isf=``).

Instead of a checked-in fixture, the harness loads the *real* published driver
ISF (``igloo.ko.<arch>.json.xz`` for the Dockerfile-pinned ``IGLOO_DRIVER_VERSION``)
through ``dwarffi`` — the same artifact ``apis.kffi`` reads at runtime. This
exercises ``dwarffi`` for real, exposes the whole driver type universe (not just
seven enums), and can't drift: the ISF is pinned to the release, not a copy in the
repo. The one enum with no host-reachable ISF home, ``igloo_base_hypercalls``, is
supplied by :class:`RealKffi` (a single ABI-fixed constant).
"""
from penguin.testing import RealKffi, install_real_consts, load_pyplugin
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = str(REPO_ROOT / "pyplugins" / "core" / "scope.py")


def test_real_kffi_returns_real_enum_values(igloo_ko_isf):
    kffi = RealKffi([igloo_ko_isf])
    # stable ABI values straight from the driver's DWARF
    assert kffi.get_enum_dict("HYPER_OP")["HYPER_OP_EXEC"] == 6
    assert kffi.get_enum_dict("value_filter_type")["SYSCALLS_HC_FILTER_EXACT"] == 0
    # the one supplemented enum (no host-reachable ISF home)
    assert (kffi.get_enum_dict("igloo_base_hypercalls")["IGLOO_HYP_SETUP_SYSCALL"]
            == 0x1337)


def test_dwarffi_exposes_driver_types_not_just_enums(igloo_ko_isf):
    # "fuller": real driver structs resolve too, so type-reading plugins work
    kffi = RealKffi([igloo_ko_isf])
    assert kffi.get_type("portal_devfs_dir_req") is not None
    assert kffi.get_type("hyperfs") is not None


def test_install_real_consts_builds_genuine_hyper_consts(igloo_ko_isf):
    # loading a boundary plugin with real_isf builds the *real* hyper.consts
    load_pyplugin(SCOPE, real_isf=igloo_ko_isf,
                  args={"conf": {"core": {"analysis_scope": "firmware"}}})
    import hyper.consts as consts
    # the genuine file-backed module (pyplugins/hyper/consts.py), not a stand-in
    assert consts.__file__ and consts.__file__.endswith("hyper/consts.py")
    assert consts.HYPER_OP.HYPER_OP_EXEC == 6
    assert consts.igloo_base_hypercalls.IGLOO_HYP_SETUP_SYSCALL == 0x1337


def test_install_real_consts_returns_real_kffi(igloo_ko_isf):
    kffi = install_real_consts(igloo_ko_isf)
    assert isinstance(kffi, RealKffi)
    assert kffi.get_enum_dict("HYPER_OP")["HYPER_OP_EXEC"] == 6
