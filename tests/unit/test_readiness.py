"""In-place harness coverage for the Readiness core plugin
(pyplugins/core/readiness.py), driven host-side with no PANDA/guest.

Readiness writes ``igloo_init.ready`` / ``netbind.ready`` marker files and
re-publishes a single ``ready`` event once init and the first netbind are seen.
Both are plain host logic: the ``on_readiness`` hypercall handler and the
``on_netbind`` subscriber (the latter is driven through the harness dispatch).
"""
from pathlib import Path

from penguin.testing import load_pyplugin, snapshot_roundtrip

REPO_ROOT = Path(__file__).resolve().parents[2]
READINESS = REPO_ROOT / "pyplugins" / "core" / "readiness.py"


def _load(outdir):
    return load_pyplugin(str(READINESS), outdir=outdir)


def test_on_readiness_writes_marker_and_publishes_once(tmp_path):
    lp = load_pyplugin(str(READINESS), outdir=tmp_path)
    rc = lp.plugin.on_readiness("igloo_init", "5")
    assert rc == (0, "")
    assert (tmp_path / "igloo_init.ready").read_text() == "5\n"
    assert lp.plugin.init_seen is True
    assert (lp.plugin, "ready", ("igloo_init",), {}) in lp.published

    # Second call is a no-op (marker already written, still returns cleanly).
    published_before = len(lp.published)
    assert lp.plugin.on_readiness("igloo_init", "9") == (0, "")
    assert (tmp_path / "igloo_init.ready").read_text() == "5\n"  # unchanged
    assert len(lp.published) == published_before


def test_on_readiness_ignores_other_kinds(tmp_path):
    lp = load_pyplugin(str(READINESS), outdir=tmp_path)
    assert lp.plugin.on_readiness("something_else", "x") == (0, "")
    assert not (tmp_path / "igloo_init.ready").exists()
    assert lp.plugin.init_seen is False


def test_on_netbind_writes_marker_and_dedupes(tmp_path):
    lp = load_pyplugin(str(READINESS), outdir=tmp_path)
    lp.dispatch("on_bind", "tcp", 4, "0.0.0.0", 80, "httpd")
    assert (tmp_path / "netbind.ready").read_text() == "httpd,4,tcp,0.0.0.0,80\n"
    assert (lp.plugin, "ready", ("netbind",), {}) in lp.published

    # A second bind does not overwrite or re-publish.
    lp.dispatch("on_bind", "tcp", 4, "0.0.0.0", 443, "httpd")
    assert (tmp_path / "netbind.ready").read_text() == "httpd,4,tcp,0.0.0.0,80\n"


# --------------------------------------------------------------------------- #
# Snapshot / restore
# --------------------------------------------------------------------------- #
def test_save_state_is_none_when_idle(tmp_path):
    lp = _load(tmp_path)
    assert lp.plugin.save_state() is None  # nothing ready yet -> nothing to carry


def test_snapshot_recreates_init_marker(tmp_path):
    # Producer: init readiness reached, marker written.
    src = _load(tmp_path / "a")
    src.plugin.on_readiness("igloo_init", "5")
    assert (tmp_path / "a" / "igloo_init.ready").read_text() == "5\n"

    # Consumer: a restored run starts with a wiped out_dir; the guest is past
    # igloo_init, so the marker must be re-created from the snapshot state.
    dst = _load(tmp_path / "b")
    assert not (tmp_path / "b" / "igloo_init.ready").exists()
    state = snapshot_roundtrip(src, dst)

    assert state == {"init_marker": "5\n"}
    assert dst.plugin.init_seen is True
    assert (tmp_path / "b" / "igloo_init.ready").read_text() == "5\n"
    # Ground-truth replay: the sole ready-owner re-broadcasts for consumers.
    assert (dst.plugin, "ready", ("igloo_init",), {}) in dst.published


def test_snapshot_recreates_netbind_marker(tmp_path):
    src = _load(tmp_path / "a")
    src.dispatch("on_bind", "tcp", 4, "0.0.0.0", 80, "httpd")

    dst = _load(tmp_path / "b")
    state = snapshot_roundtrip(src, dst)

    assert state == {"netbind_marker": "httpd,4,tcp,0.0.0.0,80\n"}
    assert dst.plugin.netbind_seen is True
    assert (tmp_path / "b" / "netbind.ready").read_text() == "httpd,4,tcp,0.0.0.0,80\n"
    assert (dst.plugin, "ready", ("netbind",), {}) in dst.published


def test_snapshot_recreates_both_markers(tmp_path):
    src = _load(tmp_path / "a")
    src.plugin.on_readiness("igloo_init", "7")
    src.dispatch("on_bind", "udp", 4, "0.0.0.0", 53, "dnsmasq")

    dst = _load(tmp_path / "b")
    state = snapshot_roundtrip(src, dst)

    assert state == {"init_marker": "7\n",
                     "netbind_marker": "dnsmasq,4,udp,0.0.0.0,53\n"}
    assert (tmp_path / "b" / "igloo_init.ready").read_text() == "7\n"
    assert (tmp_path / "b" / "netbind.ready").read_text() == "dnsmasq,4,udp,0.0.0.0,53\n"


def test_on_restore_without_state_is_noop(tmp_path):
    # A plugin that saved nothing (idle at snapshot) restores cleanly to nothing.
    dst = _load(tmp_path)
    dst.plugin.on_restore("boot")
    assert dst.plugin.init_seen is False and dst.plugin.netbind_seen is False
    assert not (tmp_path / "igloo_init.ready").exists()
