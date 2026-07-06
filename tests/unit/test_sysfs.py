"""In-place harness coverage for the Sysfs registrar (pyplugins/hyperfile/sysfs.py),
driven host-side with no PANDA/guest.

Sysfs is the kernel-facing half of the pseudofile stack for ``/sys``. Unlike proc,
every sysfs attribute must live in a directory (``foo/bar``); root-level names are
rejected. Behind the FFI-enum boundary, so loaded with ``real_isf=`` and asserted
against the **real** op numbers each ``PortalCmd`` carries.
"""
from pathlib import Path

from penguin.testing import RealKffi, drive, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
SYSFS = str(REPO_ROOT / "pyplugins" / "hyperfile" / "sysfs.py")


class _FakeSysFile:
    """Duck-typed SysFile: not a SysFile subclass, so no show/store is 'overridden'
    and the ops-struct build stays a no-op (that path is a guest concern)."""

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
    return load_pyplugin(SYSFS, outdir=tmp_path, real_isf=isf, doubles=doubles)


# --- register_sysfs: the queue/dedup handoff ------------------------------- #
def test_register_sysfs_queues_file_with_mode(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    f = _FakeSysFile("class/net/eth0/foo")
    lp.plugin.register_sysfs(f, mode=0o600)
    assert lp.plugin._pending_sysfs == [("class/net/eth0/foo", f, 0o600)]
    assert lp.plugin._sysfs["class/net/eth0/foo"] is f
    assert any("portal.queue_interrupt" in c[0] for c in lp.calls)


def test_register_sysfs_uses_explicit_path_arg(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    f = _FakeSysFile(None)
    lp.plugin.register_sysfs(f, path="devices/foo")
    assert f.PATH == "devices/foo"
    assert lp.plugin._sysfs["devices/foo"] is f


def test_register_sysfs_requires_a_path(tmp_path, igloo_ko_isf):
    import pytest
    lp = _load(tmp_path, igloo_ko_isf)
    with pytest.raises(ValueError):
        lp.plugin.register_sysfs(_FakeSysFile(None))


def test_register_sysfs_deduplicates(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    lp.plugin.register_sysfs(_FakeSysFile("dir/dup"))
    lp.plugin.register_sysfs(_FakeSysFile("dir/dup"))
    # second registration is not re-queued (dedup), only the map is refreshed
    assert len(lp.plugin._pending_sysfs) == 1


# --- _get_or_create_sysfs_dir: the dir portal command ---------------------- #
def test_root_dir_is_zero_without_portal(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    ret, yielded = drive(lp.plugin._get_or_create_sysfs_dir(""), collect=True)
    assert ret == 0 and yielded == []


def test_nested_dir_creation_emits_command_per_level(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    import hyper.consts as consts

    ret, yielded = drive(lp.plugin._get_or_create_sysfs_dir("class/net"),
                         responses=[3, 8], collect=True)
    assert len(yielded) == 2
    assert all(c.op == consts.HYPER_OP.HYPER_OP_SYSFS_CREATE_OR_LOOKUP_DIR
               for c in yielded)
    assert ret == 8
    assert lp.plugin._sysfs_dirs == {"class": 3, "class/net": 8}


def test_dir_creation_failure_raises(tmp_path, igloo_ko_isf):
    import pytest
    lp = _load(tmp_path, igloo_ko_isf)
    with pytest.raises(RuntimeError):
        drive(lp.plugin._get_or_create_sysfs_dir("bad"), responses=[0])


# --- _register_sysfs: the file-create portal command ----------------------- #
def test_directory_backed_file_emits_create_file_command(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    import hyper.consts as consts

    _ret, yielded = drive(
        lp.plugin._register_sysfs([("dir/foo", _FakeSysFile("dir/foo"), 0o644)]),
        responses=[4, 1], collect=True)
    ops = [c.op for c in yielded]
    assert ops == [consts.HYPER_OP.HYPER_OP_SYSFS_CREATE_OR_LOOKUP_DIR,
                   consts.HYPER_OP.HYPER_OP_SYSFS_CREATE_FILE]
    assert yielded[-1].data == _KFFI.REQ


def test_root_level_file_is_rejected(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    # a name with no directory level is skipped (sysfs requires foo/bar) -> no command
    _ret, yielded = drive(
        lp.plugin._register_sysfs([("toplevel", _FakeSysFile("toplevel"), 0o644)]),
        collect=True)
    assert yielded == []


# --- the interrupt handler drains the pending queue ------------------------ #
def test_interrupt_handler_drains_pending(tmp_path, igloo_ko_isf):
    portal = _Portal()
    lp = _load(tmp_path, igloo_ko_isf, portal=portal)
    lp.plugin.register_sysfs(_FakeSysFile("dir/a"))
    lp.plugin.register_sysfs(_FakeSysFile("dir/b"))
    assert len(lp.plugin._pending_sysfs) == 2
    drive(lp.plugin._hypersysfs_interrupt_handler(), responses=[1, 1, 1, 1])
    assert lp.plugin._pending_sysfs == []
