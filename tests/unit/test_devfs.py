"""In-place harness coverage for the Devfs registrar (pyplugins/hyperfile/devfs.py),
driven host-side with no PANDA/guest.

Devfs is behind the FFI-enum boundary (imports ``hyper.portal``/``hyper.consts``),
so we load it with ``fake_enums=True``. This is the kernel-facing half of the
pseudofile stack: ``register_devfs`` queues a composed DevFile for portal
registration, and ``_get_or_create_dev_dir`` actually emits the portal command.

Per the fake-enum caveat, the enum value is meaningless — so we verify the
**portal command logic on the Python side**: the right op is chosen
(``HYPER_OP_DEVFS_CREATE_OR_LOOKUP_DIR``, compared against the same enum member),
the request bytes are carried as the command payload, and the portal's returned
id is threaded back and cached.
"""
from pathlib import Path

import pytest

from penguin.testing import drive, install_fake_enums, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
DEVFS = str(REPO_ROOT / "pyplugins" / "hyperfile" / "devfs.py")


class _FakeDevFile:
    """Duck-typed DevFile: register_devfs only touches these attributes."""
    def __init__(self, path, major=-1, minor=0):
        self.PATH = path
        self.MAJOR = major
        self.MINOR = minor

    @property
    def full_path(self):
        return self.PATH

    @property
    def fs_relative_path(self):
        return self.PATH.rsplit("/", 1)[-1]


class _KFFI:
    """kffi.new returns a fixed request blob so bytes()/len() work."""
    REQ = b"\x00\x01\x02\x03"

    def new(self, type_name, init_data):
        return self.REQ


def _load(tmp_path):
    return load_pyplugin(DEVFS, outdir=tmp_path, fake_enums=True,
                         doubles={"kffi": _KFFI()})


# --- register_devfs: the queue/dedup handoff -------------------------------- #
def test_register_devfs_queues_file_and_interrupt(tmp_path):
    lp = _load(tmp_path)
    lp.plugin.register_devfs(_FakeDevFile("/dev/foo", major=10, minor=5))
    assert lp.plugin._pending_devfs == [("foo", lp.plugin._devfs["foo"], 10, 5)]
    assert any("portal.queue_interrupt" in c[0] for c in lp.calls)


def test_register_devfs_defaults_major_minor_from_file(tmp_path):
    lp = _load(tmp_path)
    lp.plugin.register_devfs(_FakeDevFile("/dev/bar"))
    fname, _f, major, minor = lp.plugin._pending_devfs[0]
    assert (fname, major, minor) == ("bar", -1, 0)


def test_register_devfs_rejects_duplicate(tmp_path):
    lp = _load(tmp_path)
    lp.plugin.register_devfs(_FakeDevFile("/dev/dup"))
    with pytest.raises(ValueError):
        lp.plugin.register_devfs(_FakeDevFile("/dev/dup"))


def test_register_devfs_requires_a_path(tmp_path):
    lp = _load(tmp_path)
    with pytest.raises(ValueError):
        lp.plugin.register_devfs(_FakeDevFile(None))


# --- _get_or_create_dev_dir: the actual portal command --------------------- #
def test_dir_creation_emits_correct_portal_command(tmp_path):
    consts = install_fake_enums()
    lp = _load(tmp_path)

    # portal replies with dir id 42
    ret, yielded = drive(lp.plugin._get_or_create_dev_dir("net"),
                         responses=[42], collect=True)

    assert len(yielded) == 1
    cmd = yielded[0]
    assert cmd.op == consts.HYPER_OP.HYPER_OP_DEVFS_CREATE_OR_LOOKUP_DIR
    assert cmd.data == _KFFI.REQ and cmd.size == len(_KFFI.REQ)
    # the portal's returned id is threaded back out and cached
    assert ret == 42
    assert lp.plugin._dev_dirs["net"] == 42


def test_dir_creation_is_cached_no_second_command(tmp_path):
    lp = _load(tmp_path)
    lp.plugin._dev_dirs["net"] = 7  # pre-seed cache
    ret, yielded = drive(lp.plugin._get_or_create_dev_dir("net"),
                         responses=[99], collect=True)
    assert ret == 7 and yielded == []  # served from cache, no portal command


def test_root_dir_is_zero_without_portal(tmp_path):
    lp = _load(tmp_path)
    ret, yielded = drive(lp.plugin._get_or_create_dev_dir(""), collect=True)
    assert ret == 0 and yielded == []


def test_dir_creation_failure_raises(tmp_path):
    lp = _load(tmp_path)
    with pytest.raises(RuntimeError):
        # portal replies -1 -> failure
        drive(lp.plugin._get_or_create_dev_dir("bad"), responses=[-1])
