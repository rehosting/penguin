"""In-place harness coverage for the Readiness core plugin
(pyplugins/core/readiness.py), driven host-side with no PANDA/guest.

Readiness writes ``igloo_init.ready`` / ``netbind.ready`` marker files and
re-publishes a single ``ready`` event once init and the first netbind are seen.
Both are plain host logic: the ``on_readiness`` hypercall handler and the
``on_netbind`` subscriber (the latter is driven through the harness dispatch).
"""
from pathlib import Path

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
READINESS = REPO_ROOT / "pyplugins" / "core" / "readiness.py"


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
