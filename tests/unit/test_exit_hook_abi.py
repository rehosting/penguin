"""ABI compatibility gate for the do_exit process-exit hook.

``exit_monitor.py`` and ``processes.py`` (``use_do_exit``) arm the igloo_driver
do_exit kprobe via ``HYPER_OP_REGISTER_EXIT_HOOK``, receive the
``IGLOO_HYP_PROC_EXIT`` hypercall, and decode ``struct exit_event``. This asserts
the *pinned* driver ISF carries all three. If it does not, penguin's host code is
incompatible with the driver it ships against, so we FAIL loudly rather than
``skip`` (a skip reads green and lets incompatible code merge). The failure is
the forcing function: bump the ``igloo-driver`` pin (flake.nix) to a release
carrying the do_exit hook and the test goes green with no edit here.

Mirrors ``test_osi_bulk._assert_pinned_driver_has_bulk_op``. The ``igloo_ko_isf``
fixture still skips cleanly when no ISF resolves at all (offline).
"""
from pathlib import Path

from penguin.testing import RealKffi, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
OSI = str(REPO_ROOT / "pyplugins" / "apis" / "osi.py")


class _KFFI(RealKffi):
    """Real dwarffi-backed kffi exposing ``sizeof`` for the struct check."""

    def sizeof(self, type_name):
        return self.ffi.sizeof(type_name)


def test_pinned_driver_has_do_exit_hook(tmp_path, igloo_ko_isf):
    # Bootstrap real hyper.consts + kffi against the pinned driver ISF (loading
    # any plugin with real_isf wires plugins.kffi to it, as test_osi_bulk does).
    kffi = _KFFI([igloo_ko_isf])
    load_pyplugin(OSI, outdir=tmp_path, real_isf=igloo_ko_isf,
                  doubles={"kffi": kffi})
    import hyper.consts as consts

    assert hasattr(consts.HYPER_OP, "HYPER_OP_REGISTER_EXIT_HOOK"), (
        "pinned igloo_driver ISF lacks HYPER_OP_REGISTER_EXIT_HOOK: penguin's "
        "exit_monitor cannot arm the do_exit hook against the pinned driver. "
        "Bump the igloo-driver pin (flake.nix) to a release carrying the hook.")
    assert hasattr(consts.igloo_hypercall_constants, "IGLOO_HYP_PROC_EXIT"), (
        "pinned igloo_driver ISF lacks IGLOO_HYP_PROC_EXIT: bump the "
        "igloo-driver pin to a release carrying the do_exit hook.")

    try:
        size = kffi.sizeof("exit_event")
    except Exception:
        size = 0
    assert size > 0, (
        "pinned igloo_driver ISF lacks struct exit_event: bump the "
        "igloo-driver pin to a release carrying the do_exit hook.")
