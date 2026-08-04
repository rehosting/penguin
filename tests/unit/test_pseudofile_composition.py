"""In-place harness coverage for the pseudofile *composition* + *registration*
layer (pyplugins/hyperfile/pseudofiles.py), driven host-side with no PANDA/guest.

Where ``test_{read,write,seek,ioctl}_models.py`` cover what each model *does*,
this covers how a pseudofile config is turned into a live node:

  * composition — ``_create_dynamic_class`` assembles the right model mixins into
    one class (correct MRO) with the right kwargs, and the per-domain resolvers
    (``_resolve_mixin``/``_create_ioctl_handler``/``_translate_kwargs``/
    ``_normalize_ioctl_conf``/``_resolve_known_size``) that feed it;
  * passing to the kernel — ``_populate_hf_config`` routes each path prefix to the
    correct subsystem registrar (devfs/procfs/sysctl/sysfs) with the composed
    instance, and defers MTD nodes to the native subsystem.

The Pseudofiles ``__init__`` initializes the tracker and reads config, so we load
with ``call_init=False`` and set ``config``/``_tracking`` directly.
"""
from pathlib import Path

import pytest

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
PSEUDOFILES = str(REPO_ROOT / "pyplugins" / "hyperfile" / "pseudofiles.py")


def _mro_names(inst):
    return [c.__name__ for c in type(inst).__mro__]


@pytest.fixture(scope="module")
def pf():
    lp = load_pyplugin(PSEUDOFILES, call_init=False, class_name="Pseudofiles")
    p = lp.plugin
    p._tracking = False
    return p


# --------------------------------------------------------------------------- #
# per-domain resolvers
# --------------------------------------------------------------------------- #
def test_resolve_mixin_maps_model_names(pf):
    assert pf._resolve_mixin("read", {"model": "zero"}).__name__ == "ReadZero"
    assert pf._resolve_mixin("write", {"model": "discard"}).__name__ == "WriteDefault"
    # unknown model falls back to the domain default, not a crash
    assert pf._resolve_mixin("read", {"model": "bogus"}).__name__ == "ReadDefault"


def test_normalize_ioctl_conf_forms(pf):
    # whole-operation form is wrapped under the "*" wildcard
    assert pf._normalize_ioctl_conf({"model": "return_const", "val": 1}) == \
        {"*": {"model": "return_const", "val": 1}}
    # command-map form is passed through; empty stays empty
    cmd_map = {"5": {"model": "zero"}}
    assert pf._normalize_ioctl_conf(cmd_map) == cmd_map
    assert pf._normalize_ioctl_conf({}) == {}


def test_create_ioctl_handler_variants(pf):
    rc = pf._create_ioctl_handler({"model": "return_const", "val": 9})
    assert type(rc).__name__ == "IoctlReturnConst" and rc.val == 9
    unh = pf._create_ioctl_handler({"model": "unhandled"})
    assert unh.val == -25  # -ENOTTY
    wd = pf._create_ioctl_handler({"model": "write_data", "data": b"AB", "val": 3})
    assert type(wd).__name__ == "IoctlWriteData" and wd.data == b"AB" and wd.val == 3


def test_translate_kwargs_renames_schema_keys(pf):
    kw = pf._translate_kwargs("read", {"filename": "f", "val": "v",
                                       "provenance": "default", "size": 16})
    assert kw["read_provenance"] == "default"
    assert kw["buffer"] == "v"        # read 'val' -> buffer
    assert kw["filename"] == "f"
    assert kw["size"] == 16           # non-conflicting keys pass through
    assert "val" not in kw and "model" not in kw


def test_resolve_known_size_by_model(pf):
    assert pf._resolve_known_size("/dev/x", {}, {"model": "zero"}) == 1
    assert pf._resolve_known_size("/dev/x", {}, {"model": "empty"}) == 0
    assert pf._resolve_known_size("/dev/x", {}, {"model": "const_buf", "val": "abc"}) == 3
    # explicit size wins
    assert pf._resolve_known_size("/dev/x", {"size": 42}, {"model": "zero"}) == 42


# --------------------------------------------------------------------------- #
# composition — _create_dynamic_class
# --------------------------------------------------------------------------- #
def _dev(pf, details):
    from importlib import import_module
    DevFile = import_module("hyperfile.models.base").DevFile
    return pf._create_dynamic_class("/dev/thing", details, DevFile)


def test_dev_node_composes_expected_mixins(pf):
    inst = _dev(pf, {"read": {"model": "zero"}, "write": {"model": "discard"}})
    names = _mro_names(inst)
    for expected in ("ReadZero", "WriteDefault", "IoctlDispatcher",
                     "PollAlwaysReady", "DevFile"):
        assert expected in names, f"{expected} missing from MRO {names}"
    assert inst.PATH == "/dev/thing" and inst.FS == "devfs"


def test_dev_known_size_gets_seek_compat(pf):
    # a known-size /dev node (zero -> SIZE 1) gains the legacy seek shim
    inst = _dev(pf, {"read": {"model": "zero"}})
    assert "_LegacyDevSeekCompat" in _mro_names(inst)
    assert inst.SIZE == 1


def test_const_buf_sets_buffer_and_size(pf):
    inst = _dev(pf, {"read": {"model": "const_buf", "val": "hi"}})
    assert "ReadConstBuf" in _mro_names(inst)
    # buffer is held as-configured (encoded to bytes at read time); size is known
    assert inst._data == "hi" and inst.SIZE == 2


def test_ioctl_command_map_is_wired_into_dispatcher(pf):
    inst = _dev(pf, {"ioctl": {"5": {"model": "return_const", "val": 7},
                               "*": {"model": "zero"}}})
    handlers = inst.ioctl_handlers
    assert handlers[5].val == 7                    # numeric key coerced from "5"
    assert type(handlers["*"]).__name__ == "IoctlReturnConst"


def test_explicit_seek_model_is_composed(pf):
    inst = _dev(pf, {"seek": {"model": "unsupported"}})
    assert "SeekUnsupported" in _mro_names(inst)


def test_poll_blocking_maps_to_never_ready(pf):
    # poll:blocking resolves to the not-ready mixin (parks the waiter on the
    # per-device wait queue instead of spinning; see poll issue #77).
    assert pf._resolve_mixin("poll", {"model": "blocking"}).__name__ == "PollNeverReady"


def test_dev_node_with_blocking_poll_composes_never_ready(pf):
    # An explicit poll:blocking overrides the /dev always-ready fallback.
    inst = _dev(pf, {"read": {"model": "zero"}, "poll": {"model": "blocking"}})
    names = _mro_names(inst)
    assert "PollNeverReady" in names
    assert "PollAlwaysReady" not in names


def test_poll_periodic_maps_to_periodic(pf):
    # poll:periodic resolves to the heartbeat mixin (driver timer wakes the wait
    # queue every interval_ms; see PollPeriodic).
    assert pf._resolve_mixin("poll", {"model": "periodic"}).__name__ == "PollPeriodic"


def test_dev_node_with_periodic_poll_carries_interval(pf):
    # An explicit poll:periodic composes PollPeriodic (not the /dev always-ready
    # fallback) and carries interval_ms down as POLL_INTERVAL_MS so devfs
    # registration can arm the driver timer.
    inst = _dev(pf, {"read": {"model": "zero"},
                     "poll": {"model": "periodic", "interval_ms": 250}})
    names = _mro_names(inst)
    assert "PollPeriodic" in names
    assert "PollAlwaysReady" not in names
    assert inst.POLL_INTERVAL_MS == 250


def test_dev_node_periodic_poll_defaults_interval(pf):
    # interval_ms is optional; PollPeriodic defaults it (matches the schema).
    inst = _dev(pf, {"read": {"model": "zero"}, "poll": {"model": "periodic"}})
    assert inst.POLL_INTERVAL_MS == 1000


def test_proc_node_has_no_dev_only_fallbacks(pf):
    from importlib import import_module
    ProcFile = import_module("hyperfile.models.base").ProcFile
    inst = pf._create_dynamic_class("/proc/thing", {"read": {"model": "empty"}}, ProcFile)
    names = _mro_names(inst)
    assert "PollAlwaysReady" not in names          # /dev-only
    assert "_LegacyDevSeekCompat" not in names
    assert inst.FS == "procfs"


# --------------------------------------------------------------------------- #
# passing to the kernel — _populate_hf_config routing
# --------------------------------------------------------------------------- #
class _Registrar:
    def __init__(self):
        self.calls = []

    def _record(self, instance, path=None):
        self.calls.append((path, instance))


class _Devfs(_Registrar):
    register_devfs = _Registrar._record


class _Procfs(_Registrar):
    register_proc = _Registrar._record


class _Sysctl(_Registrar):
    register_sysctl = _Registrar._record


class _Sysfs(_Registrar):
    register_sysfs = _Registrar._record


class _Mtd:
    def __init__(self):
        self.ensure_init_calls = 0

    def ensure_init(self):
        self.ensure_init_calls += 1


def test_populate_routes_each_prefix_to_its_registrar():
    devfs, procfs, sysctl, sysfs, mtd = _Devfs(), _Procfs(), _Sysctl(), _Sysfs(), _Mtd()
    lp = load_pyplugin(
        PSEUDOFILES, call_init=False, class_name="Pseudofiles",
        doubles={"devfs": devfs, "procfs": procfs, "sysctl": sysctl,
                 "sysfs": sysfs, "mtd": mtd},
    )
    p = lp.plugin
    p._tracking = False
    p.config = {"pseudofiles": {
        "/dev/foo": {"read": {"model": "zero"}},
        "/proc/bar": {"read": {"model": "empty"}},
        "/proc/sys/net/x": {"read": {"model": "const_buf", "val": "1"}},
        "/sys/class/y": {"read": {"model": "zero"}},
        "/dev/mtd0": {},   # deferred to native MTD subsystem
        "/proc/mtd": {},   # ditto
    }}

    p._populate_hf_config()

    assert [pth for pth, _ in devfs.calls] == ["/dev/foo"]
    assert [pth for pth, _ in procfs.calls] == ["/proc/bar"]
    assert [pth for pth, _ in sysctl.calls] == ["/proc/sys/net/x"]
    assert [pth for pth, _ in sysfs.calls] == ["/sys/class/y"]
    # the composed object handed to the registrar is the right file type
    assert devfs.calls[0][1].FS == "devfs"
    assert "DevFile" in _mro_names(devfs.calls[0][1])
    # MTD nodes are not registered as pseudofiles; they defer to mtd.ensure_init
    assert mtd.ensure_init_calls >= 1
    all_paths = [pth for reg in (devfs, procfs, sysctl, sysfs) for pth, _ in reg.calls]
    assert "/dev/mtd0" not in all_paths and "/proc/mtd" not in all_paths
