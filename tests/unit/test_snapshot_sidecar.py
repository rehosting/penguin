"""Host-side coverage for the Snapshot plugin's host-sidecar marshalling
(pyplugins/core/snapshot.py), driven with no PANDA/guest.

`_save_host_state` / `_restore_host_state` are the pure host-side half of the
snapshot contract: collect each plugin's `save_state()` into a versioned JSON
sidecar, and on restore hand each blob back to the right plugin's
`load_state()`. Everything guest/VM-facing (savevm/loadvm scheduling) is an
integration concern and lives in tests/integration/basic_target/snapshot_*.py.
"""
import json
from pathlib import Path

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
SNAPSHOT = str(REPO_ROOT / "pyplugins" / "core" / "snapshot.py")


class _FakePlugin:
    """Minimal sibling: the sidecar code touches only name/save_state/load_state."""

    def __init__(self, name, state=None, save_raises=False, load_raises=False):
        self.name = name
        self._state = state
        self._save_raises = save_raises
        self._load_raises = load_raises
        self.loaded = "UNSET"  # records what load_state received

    def save_state(self):
        if self._save_raises:
            raise RuntimeError("boom-save")
        return self._state

    def load_state(self, data):
        if self._load_raises:
            raise RuntimeError("boom-load")
        self.loaded = data


def _snap(tmp_path, plugins):
    """A constructed Snapshot whose plugin-iteration is the given fake set."""
    lp = load_pyplugin(SNAPSHOT, outdir=str(tmp_path),
                       args={"proj_dir": str(tmp_path), "conf": {"core": {}}})
    lp.plugin._iter_plugins = lambda: list(plugins)
    return lp.plugin


def _sidecar(tmp_path):
    return tmp_path / "qcows" / "snapshot_boot.host.json"


# --- save: versioned envelope, None skipped -------------------------------- #
def test_save_writes_versioned_envelope(tmp_path):
    snap = _snap(tmp_path, [_FakePlugin("A", {"x": 1}),
                            _FakePlugin("B", {"y": [2, 3]})])
    snap._save_host_state("boot")

    doc = json.loads(_sidecar(tmp_path).read_text())
    assert doc["schema_version"] == 1
    assert doc["plugins"] == {"A": {"x": 1}, "B": {"y": [2, 3]}}


def test_save_skips_none_state(tmp_path):
    snap = _snap(tmp_path, [_FakePlugin("A", None), _FakePlugin("B", {"y": 1})])
    snap._save_host_state("boot")
    assert json.loads(_sidecar(tmp_path).read_text())["plugins"] == {"B": {"y": 1}}


def test_save_writes_nothing_when_all_none(tmp_path):
    snap = _snap(tmp_path, [_FakePlugin("A", None), _FakePlugin("B", None)])
    snap._save_host_state("boot")
    assert not _sidecar(tmp_path).exists()  # empty -> no sidecar at all


def test_save_swallows_a_failing_plugin(tmp_path):
    # One plugin's broken save_state must not abort the whole snapshot.
    snap = _snap(tmp_path, [_FakePlugin("A", save_raises=True),
                            _FakePlugin("B", {"y": 1})])
    snap._save_host_state("boot")
    assert json.loads(_sidecar(tmp_path).read_text())["plugins"] == {"B": {"y": 1}}


# --- restore: route blobs back, skip absent, swallow failures -------------- #
def test_restore_routes_state_by_name(tmp_path):
    a, b = _FakePlugin("A"), _FakePlugin("B")
    saver = _snap(tmp_path, [_FakePlugin("A", {"x": 1}), _FakePlugin("B", {"y": 2})])
    saver._save_host_state("boot")

    _snap(tmp_path, [a, b])._restore_host_state("boot")
    assert a.loaded == {"x": 1}
    assert b.loaded == {"y": 2}


def test_restore_skips_plugin_not_loaded(tmp_path):
    _snap(tmp_path, [_FakePlugin("A", {"x": 1}), _FakePlugin("GONE", {"z": 9})]) \
        ._save_host_state("boot")

    a = _FakePlugin("A")  # "GONE" is not present on the restore side
    _snap(tmp_path, [a])._restore_host_state("boot")
    assert a.loaded == {"x": 1}  # no crash on the missing plugin


def test_restore_missing_sidecar_is_noop(tmp_path):
    a = _FakePlugin("A")
    _snap(tmp_path, [a])._restore_host_state("boot")  # nothing written earlier
    assert a.loaded == "UNSET"  # load_state never called


def test_restore_swallows_a_failing_load(tmp_path):
    _snap(tmp_path, [_FakePlugin("A", {"x": 1}), _FakePlugin("B", {"y": 2})]) \
        ._save_host_state("boot")

    a = _FakePlugin("A", load_raises=True)
    b = _FakePlugin("B")
    _snap(tmp_path, [a, b])._restore_host_state("boot")
    assert b.loaded == {"y": 2}  # B still restored despite A blowing up


# --- backward compatibility: a bare {name: data} map from an older penguin -- #
def test_restore_reads_legacy_unversioned_sidecar(tmp_path):
    sc = _sidecar(tmp_path)
    sc.parent.mkdir(parents=True, exist_ok=True)
    sc.write_text(json.dumps({"A": {"x": 1}}))  # pre-envelope format

    a = _FakePlugin("A")
    _snap(tmp_path, [a])._restore_host_state("boot")
    assert a.loaded == {"x": 1}
