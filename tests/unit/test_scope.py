"""In-place harness coverage for the Scope core plugin
(pyplugins/core/scope.py), driven host-side with no PANDA/guest.

Scope sits behind the FFI-enum boundary (``from hyper.portal import PortalCmd`` /
``from hyper.consts import HYPER_OP``), so we load it with ``real_isf=`` — the real
published driver ISF, read through ``dwarffi``, so ``hyper.consts`` builds with
**real** enum values. We then drive the enable handler and assert it emits the
*right* command — ``HYPER_OP_SET_SCOPE_ENABLED`` (its real op number) with
``addr=1`` — plus mode-normalization and the register/queue wiring done at init.
"""
from pathlib import Path

from penguin.testing import drive, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
SCOPE = str(REPO_ROOT / "pyplugins" / "core" / "scope.py")


def _load(scope_value, isf):
    return load_pyplugin(
        SCOPE, real_isf=isf,
        args={"conf": {"core": {"analysis_scope": scope_value}}},
    )


def test_enable_handler_emits_set_scope_enabled_command(igloo_ko_isf):
    lp = _load("firmware", igloo_ko_isf)
    # the genuine hyper.consts scope.py imported hop from, built from the real ISF
    import hyper.consts as consts

    ret, yielded = drive(lp.plugin._enable_handler(), collect=True)

    assert len(yielded) == 1
    cmd = yielded[0]
    # the RIGHT portal op is chosen, carrying its real op number ...
    assert cmd.op == consts.HYPER_OP.HYPER_OP_SET_SCOPE_ENABLED
    # ... with the right argument (1 == enable) and a clean end.
    assert cmd.addr == 1
    assert ret is False


def test_enable_handler_is_idempotent(igloo_ko_isf):
    lp = _load("firmware", igloo_ko_isf)
    drive(lp.plugin._enable_handler(), collect=True)          # first: emits
    _ret, yielded = drive(lp.plugin._enable_handler(), collect=True)
    assert yielded == []  # already sent -> no second command


def test_firmware_mode_wires_the_portal_interrupt(igloo_ko_isf):
    lp = _load("firmware", igloo_ko_isf)
    assert lp.plugin.mode == "firmware" and lp.plugin.enabled is True
    # the enable path is queued through the portal at init
    paths = [c[0] for c in lp.calls]
    assert any("portal.register_interrupt_handler" in p for p in paths)
    assert any("portal.queue_interrupt" in p for p in paths)


def test_scope_none_disables_and_skips_portal(igloo_ko_isf):
    lp = _load("none", igloo_ko_isf)
    assert lp.plugin.enabled is False
    paths = [c[0] for c in lp.calls]
    assert not any("portal.queue_interrupt" in p for p in paths)


def test_mode_normalization(igloo_ko_isf):
    # booleans map for backwards compat; strings are lowercased/passed through
    assert _load(True, igloo_ko_isf).plugin.mode == "firmware"
    assert _load(False, igloo_ko_isf).plugin.mode == "none"
    assert _load("FIRMWARE", igloo_ko_isf).plugin.mode == "firmware"
