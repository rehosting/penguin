"""In-place harness coverage for the Procfs registrar (pyplugins/hyperfile/procfs.py),
driven host-side with no PANDA/guest.

Procfs is the kernel-facing half of the pseudofile stack for ``/proc``: it queues
composed ProcFile objects and, on the portal interrupt, emits the portal commands
that create the directory tree and the files. Like devfs it is behind the
FFI-enum boundary (imports ``hyper.portal``/``hyper.consts``), so we load it with
``real_isf=`` and assert on the **real** op numbers each ``PortalCmd`` carries.
"""
from pathlib import Path

import pytest

from penguin.testing import RealKffi, drive, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
PROCFS = str(REPO_ROOT / "pyplugins" / "hyperfile" / "procfs.py")


class _FakeProcFile:
    """Duck-typed ProcFile: the registrar only touches these. Not a ProcFile
    subclass, so ``_get_overridden_methods`` finds nothing overridden and the
    fops struct build stays a no-op (the struct-building path is a guest concern)."""

    def __init__(self, path):
        self.PATH = path

    @property
    def full_path(self):
        return self.PATH

    @property
    def fs_relative_path(self):
        return (self.PATH or "").strip("/")

    def _is_overridden(self, name):
        return False


class _KFFI(RealKffi):
    """Real dwarffi-backed kffi (so hyper.consts builds with real enums) whose
    ``new`` returns a fixed request blob so bytes()/len() work without real
    struct packing (that's the guest ABI's job, not the host logic under test)."""
    REQ = b"\x00\x01\x02\x03"

    def new(self, type_name, init_data):
        return self.REQ


class _Portal:
    """Portal double: records interrupts and hands out a finite install budget so
    the interrupt handler actually drains (a RecorderStub is falsy, so it wouldn't)."""

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
    return load_pyplugin(PROCFS, outdir=tmp_path, real_isf=isf, doubles=doubles)


# --- register_proc: the queue/dedup/validation handoff --------------------- #
def test_register_proc_queues_file(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    f = _FakeProcFile("foo")
    lp.plugin.register_proc(f)
    assert lp.plugin._pending_procs == [("foo", f)]
    assert lp.plugin._procs["foo"] is f
    assert any("portal.queue_interrupt" in c[0] for c in lp.calls)


def test_register_proc_uses_explicit_path_arg(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    f = _FakeProcFile(None)
    lp.plugin.register_proc(f, path="net/dev")
    assert f.PATH == "net/dev"
    assert lp.plugin._procs["net/dev"] is f


def test_register_proc_requires_a_path(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    with pytest.raises(ValueError):
        lp.plugin.register_proc(_FakeProcFile(None))


def test_register_proc_rejects_duplicate(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    lp.plugin.register_proc(_FakeProcFile("dup"))
    with pytest.raises(ValueError):
        lp.plugin.register_proc(_FakeProcFile("dup"))


# --- _get_or_create_proc_dir: the dir portal command ----------------------- #
def test_root_dir_is_zero_without_portal(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    ret, yielded = drive(lp.plugin._get_or_create_proc_dir(""), collect=True)
    assert ret == 0 and yielded == []


def test_pid_dir_is_parent_sentinel_without_portal(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    # "self" and numeric pid dirs resolve to the shared PID-parent id, no command
    for part in ("self", "1234"):
        ret, yielded = drive(lp.plugin._get_or_create_proc_dir(part), collect=True)
        assert ret == -1 and yielded == []


def test_nested_dir_creation_emits_command_per_level(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    import hyper.consts as consts

    ret, yielded = drive(lp.plugin._get_or_create_proc_dir("a/b"),
                         responses=[10, 20], collect=True)
    assert len(yielded) == 2
    assert all(c.op == consts.HYPER_OP.HYPER_OP_PROCFS_CREATE_OR_LOOKUP_DIR
               for c in yielded)
    # the deepest id is threaded back and each level cached
    assert ret == 20
    assert lp.plugin._proc_dirs == {"a": 10, "a/b": 20}


def test_dir_creation_is_cached_no_second_command(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    lp.plugin._proc_dirs["net"] = 7
    ret, yielded = drive(lp.plugin._get_or_create_proc_dir("net"),
                         responses=[99], collect=True)
    assert ret == 7 and yielded == []


def test_dir_creation_failure_raises(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    with pytest.raises(RuntimeError):
        drive(lp.plugin._get_or_create_proc_dir("bad"), responses=[-1])


# --- _register_procs: the file-create portal command ----------------------- #
def test_root_file_emits_create_file_command(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    import hyper.consts as consts

    _ret, yielded = drive(lp.plugin._register_procs([("foo", _FakeProcFile("foo"))]),
                          responses=[1], collect=True)
    assert len(yielded) == 1
    cmd = yielded[0]
    assert cmd.op == consts.HYPER_OP.HYPER_OP_PROCFS_CREATE_FILE
    assert cmd.data == _KFFI.REQ and cmd.size == len(_KFFI.REQ)


def test_nested_file_creates_dir_then_file(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    import hyper.consts as consts

    _ret, yielded = drive(
        lp.plugin._register_procs([("net/foo", _FakeProcFile("net/foo"))]),
        responses=[5, 1], collect=True)
    ops = [c.op for c in yielded]
    assert ops == [consts.HYPER_OP.HYPER_OP_PROCFS_CREATE_OR_LOOKUP_DIR,
                   consts.HYPER_OP.HYPER_OP_PROCFS_CREATE_FILE]


# --- the interrupt handler drains the pending queue ------------------------ #
def test_interrupt_handler_drains_pending(tmp_path, igloo_ko_isf):
    portal = _Portal()
    lp = _load(tmp_path, igloo_ko_isf, portal=portal)
    lp.plugin.register_proc(_FakeProcFile("foo"))
    lp.plugin.register_proc(_FakeProcFile("bar"))
    assert len(lp.plugin._pending_procs) == 2
    drive(lp.plugin._proc_interrupt_handler(), responses=[1, 1])
    assert lp.plugin._pending_procs == []
