"""In-place harness coverage for the FetchWeb actuation plugin
(pyplugins/actuation/fetch_web.py), driven host-side with no PANDA/guest.

FetchWeb subscribes to the VPN's ``on_bind`` and, for web ports (80/443),
enqueues a wget fetch. We don't run wget: the testable host logic is the
port/dedup decision in ``fetchweb_on_bind`` and the snapshot save/restore of the
already-fetched set, so ``fetch`` is patched out and we assert on ``_handled``
(updated synchronously in the handler, before the worker thread touches it).
"""
from pathlib import Path

from penguin.testing import load_pyplugin, snapshot_roundtrip

REPO_ROOT = Path(__file__).resolve().parents[2]
FETCH_WEB = REPO_ROOT / "pyplugins" / "actuation" / "fetch_web.py"


def _load(outdir, monkeypatch):
    lp = load_pyplugin(str(FETCH_WEB), outdir=outdir)
    # Neutralise the worker's fetch so a drained task never shells out to wget.
    monkeypatch.setattr(lp.plugin, "fetch", lambda *a, **k: False)
    return lp


def _bind(lp, guest_ip, guest_port, host_port=8080):
    lp.dispatch("on_bind", "tcp", guest_ip, guest_port, host_port, "127.0.0.1", "httpd")


def test_on_bind_records_web_port_once(tmp_path, monkeypatch):
    lp = _load(tmp_path, monkeypatch)
    _bind(lp, "10.0.0.1", 80, 8080)
    # Same guest service, different host_port (a plausible re-map) -> still deduped.
    _bind(lp, "10.0.0.1", 80, 9090)
    assert lp.plugin._handled == {("10.0.0.1", 80)}


def test_on_bind_ignores_non_web_port(tmp_path, monkeypatch):
    lp = _load(tmp_path, monkeypatch)
    _bind(lp, "10.0.0.1", 22, 2222)
    assert lp.plugin._handled == set()


def test_save_state_none_when_idle(tmp_path, monkeypatch):
    lp = _load(tmp_path, monkeypatch)
    assert lp.plugin.save_state() is None


def test_snapshot_suppresses_replayed_fetch(tmp_path, monkeypatch):
    # Producer: an https service fetched pre-snapshot.
    src = _load(tmp_path / "a", monkeypatch)
    _bind(src, "10.0.0.1", 443, 8443)
    assert src.plugin._handled == {("10.0.0.1", 443)}

    # Consumer: fresh restored run; the fetched-set is rehydrated in load_state
    # so the VPN's on_bind replay does not re-fetch (and cannot re-end_analysis).
    dst = _load(tmp_path / "b", monkeypatch)
    enq = []
    monkeypatch.setattr(dst.plugin.task_queue, "put", lambda item: enq.append(item))
    state = snapshot_roundtrip(src, dst)

    assert state == {"handled": [["10.0.0.1", 443]]}
    assert dst.plugin._handled == {("10.0.0.1", 443)}
    _bind(dst, "10.0.0.1", 443, 9443)  # VPN replay after restore
    assert enq == []  # nothing enqueued -> no re-fetch, no shutdown
