"""In-place harness coverage for the Sysctl registrar (pyplugins/hyperfile/sysctl.py),
driven host-side with no PANDA/guest.

Sysctls live under ``/proc/sys`` but are ctl_tables, not real files. This registrar
carries a safety guard that must not regress: some ``/proc/sys`` subtrees
(``fs/binfmt_misc``) are mounted filesystems, and asking an old guest kernel to
register a ctl_table there panics in the cleanup path — so they are rejected
host-side. Behind the FFI-enum boundary, so loaded with ``real_isf=``.
"""
import pytest

from pathlib import Path

from penguin.testing import RealKffi, drive, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
SYSCTL = str(REPO_ROOT / "pyplugins" / "hyperfile" / "sysctl.py")


class _FakeSysctlFile:
    """Duck-typed SysctlFile: not a subclass, so nothing is 'customized' and the
    handler-callback path stays a no-op (that path is a guest concern)."""

    def __init__(self, path):
        self.PATH = path

    @property
    def full_path(self):
        return self.PATH

    @property
    def fs_relative_path(self):
        return (self.PATH or "").strip("/")


class _KFFI(RealKffi):
    REQ = b"\x00\x01\x02\x03"

    def new(self, type_name, init_data):
        return self.REQ


class _Portal:
    def __init__(self, budget=100):
        self._budget = budget
        self.interrupts = []
        self.handlers = {}

    def register_interrupt_handler(self, name, fn):
        self.handlers[name] = fn

    def queue_interrupt(self, name):
        self.interrupts.append(name)

    def take_install_budget(self):
        if self._budget > 0:
            self._budget -= 1
            return True
        return False


def _load(tmp_path, isf, portal=None):
    doubles = {"kffi": _KFFI([isf])}
    if portal is not None:
        doubles["portal"] = portal
    return load_pyplugin(SYSCTL, outdir=tmp_path, real_isf=isf, doubles=doubles)


# --- _reject_reason: the panic guard (must not regress) -------------------- #
def test_binfmt_misc_subtree_is_rejected(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    assert lp.plugin._reject_reason("fs/binfmt_misc") is not None
    assert lp.plugin._reject_reason("fs/binfmt_misc/status") is not None


def test_empty_and_malformed_paths_are_rejected(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    assert lp.plugin._reject_reason("") is not None
    assert lp.plugin._reject_reason("net//ipv4") is not None  # empty component


def test_ordinary_sysctl_path_is_accepted(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    assert lp.plugin._reject_reason("net/ipv4/ip_forward") is None


# --- register_sysctl: reject path is queued nowhere ------------------------ #
def test_register_rejected_path_does_not_queue(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    lp.plugin.register_sysctl(_FakeSysctlFile("fs/binfmt_misc/register"))
    assert lp.plugin._pending_sysctls == []
    assert lp.plugin._sysctls == {}


def test_register_ordinary_path_queues(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    f = _FakeSysctlFile("net/ipv4/ip_forward")
    lp.plugin.register_sysctl(f)
    assert lp.plugin._pending_sysctls == [("net/ipv4/ip_forward", f)]
    assert any("portal.queue_interrupt" in c[0] for c in lp.calls)


def test_register_requires_a_path(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    with pytest.raises(ValueError):
        lp.plugin.register_sysctl(_FakeSysctlFile(None))


def test_register_rejects_duplicate(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    lp.plugin.register_sysctl(_FakeSysctlFile("net/x"))
    with pytest.raises(ValueError):
        lp.plugin.register_sysctl(_FakeSysctlFile("net/x"))


# --- _split_sysctl_path: pure helper --------------------------------------- #
def test_split_sysctl_path(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    assert lp.plugin._split_sysctl_path("net/ipv4/ip_forward") == ("net/ipv4", "ip_forward")
    assert lp.plugin._split_sysctl_path("hostname") == ("", "hostname")


# --- _register_sysctls: the create-file portal command --------------------- #
def test_register_emits_create_file_command(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    import hyper.consts as consts

    _ret, yielded = drive(
        lp.plugin._register_sysctls([("net/ipv4/ip_forward",
                                      _FakeSysctlFile("net/ipv4/ip_forward"))]),
        responses=[1], collect=True)
    assert len(yielded) == 1
    cmd = yielded[0]
    assert cmd.op == consts.HYPER_OP.HYPER_OP_SYSCTL_CREATE_FILE
    assert cmd.data == _KFFI.REQ and cmd.size == len(_KFFI.REQ)


def test_register_reports_failure_and_continues(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    # kernel returns <= 0 -> logged as failure, generator still completes cleanly
    ret, yielded = drive(
        lp.plugin._register_sysctls([("net/x", _FakeSysctlFile("net/x"))]),
        responses=[0], collect=True)
    assert ret is None and len(yielded) == 1


# --- the interrupt handler drains the pending queue ------------------------ #
def test_interrupt_handler_drains_pending(tmp_path, igloo_ko_isf):
    portal = _Portal()
    lp = _load(tmp_path, igloo_ko_isf, portal=portal)
    lp.plugin.register_sysctl(_FakeSysctlFile("net/a"))
    lp.plugin.register_sysctl(_FakeSysctlFile("net/b"))
    assert len(lp.plugin._pending_sysctls) == 2
    drive(lp.plugin._sysctl_interrupt_handler(), responses=[1, 1])
    assert lp.plugin._pending_sysctls == []
