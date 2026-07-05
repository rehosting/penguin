"""Tests for the captured-enum mechanism behind ``install_fake_enums``.

``hyper_enums.json`` holds the real ``hyper.consts`` enum values, extracted from
the published kernel/driver ISF (regenerable via
``python -m penguin.testing.gen_hyper_enums``). ``install_fake_enums`` seeds the
stand-in ``hyper.consts`` with them, so plugins behind the FFI-enum boundary see
*real* enum values host-side; only members absent from the capture fall back to a
bogus auto-int.
"""
import json
from pathlib import Path

from penguin.testing import install_fake_enums

FIXTURE = (Path(__file__).resolve().parents[2]
           / "src" / "penguin" / "testing" / "hyper_enums.json")


def test_fixture_has_the_hyper_consts_enums():
    data = json.loads(FIXTURE.read_text())
    for name in ("HYPER_OP", "value_filter_type", "portal_type",
                 "igloo_hypercall_constants", "hyperfs_ops", "hyperfs_file_ops"):
        assert isinstance(data[name], dict) and data[name], f"{name} missing/empty"


def test_stub_returns_real_captured_values():
    consts = install_fake_enums()
    # Stable ABI values straight from the ISF (not assignment order).
    assert consts.value_filter_type.SYSCALLS_HC_FILTER_EXACT == 0
    assert consts.HYPER_OP.HYPER_OP_DEVFS_CREATE_OR_LOOKUP_DIR == 43
    # matches what the fixture on disk records
    data = json.loads(FIXTURE.read_text())
    assert consts.HYPER_OP.HYPER_OP_EXEC == data["HYPER_OP"]["HYPER_OP_EXEC"]


def test_unknown_member_falls_back_above_the_real_range():
    consts = install_fake_enums()
    data = json.loads(FIXTURE.read_text())
    real_max = max(data["HYPER_OP"].values())
    # a member not in the capture still resolves (so the plugin imports), but with
    # a bogus value that can't collide with a real one
    assert consts.HYPER_OP.HYPER_OP_NOT_A_REAL_MEMBER > real_max


def test_install_is_idempotent():
    assert install_fake_enums() is install_fake_enums()
