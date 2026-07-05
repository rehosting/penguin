"""In-place harness coverage for the Scope core plugin
(pyplugins/core/scope.py), driven host-side with no PANDA/guest.

Scope sits behind the FFI-enum boundary (``from hyper.portal import PortalCmd`` /
``from hyper.consts import HYPER_OP``), so we load it with ``fake_enums=True``.

The point of this test is the concern the fake-enum mode raises: the enum *value*
is meaningless, but the **portal command logic must be correct on the Python
side**. So we drive the enable handler and assert it emits the *right* command —
``HYPER_OP_SET_SCOPE_ENABLED`` with ``addr=1`` — by comparing the yielded
``PortalCmd.op`` against the *same* enum member (self-consistent within the run),
plus the mode-normalization and the register/queue wiring done at init.
"""
from pathlib import Path

from penguin.testing import drive, install_fake_enums, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = str(REPO_ROOT / "pyplugins" / "core" / "scope.py")


def _load(scope_value):
    return load_pyplugin(
        SCOPE, fake_enums=True,
        args={"conf": {"core": {"analysis_scope": scope_value}}},
    )


def test_enable_handler_emits_set_scope_enabled_command():
    consts = install_fake_enums()  # the same fake module scope.py imported hop from

    lp = _load("firmware")
    ret, yielded = drive(lp.plugin._enable_handler(), collect=True)

    assert len(yielded) == 1
    cmd = yielded[0]
    # the RIGHT portal op is chosen (compared against the same enum member) ...
    assert cmd.op == consts.HYPER_OP.HYPER_OP_SET_SCOPE_ENABLED
    # ... with the right argument (1 == enable) and a clean end.
    assert cmd.addr == 1
    assert ret is False


def test_enable_handler_is_idempotent():
    lp = _load("firmware")
    drive(lp.plugin._enable_handler(), collect=True)          # first: emits
    _ret, yielded = drive(lp.plugin._enable_handler(), collect=True)
    assert yielded == []  # already sent -> no second command


def test_firmware_mode_wires_the_portal_interrupt():
    lp = _load("firmware")
    assert lp.plugin.mode == "firmware" and lp.plugin.enabled is True
    # the enable path is queued through the portal at init
    paths = [c[0] for c in lp.calls]
    assert any("portal.register_interrupt_handler" in p for p in paths)
    assert any("portal.queue_interrupt" in p for p in paths)


def test_scope_none_disables_and_skips_portal():
    lp = _load("none")
    assert lp.plugin.enabled is False
    paths = [c[0] for c in lp.calls]
    assert not any("portal.queue_interrupt" in p for p in paths)


def test_mode_normalization():
    # booleans map for backwards compat; strings are lowercased/passed through
    assert _load(True).plugin.mode == "firmware"
    assert _load(False).plugin.mode == "none"
    assert _load("FIRMWARE").plugin.mode == "firmware"
