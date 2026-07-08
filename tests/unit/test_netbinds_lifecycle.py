"""Host-side tests for the NetBinds announce debounce / lifecycle state machine
and its snapshot-restore support.

These drive the real analysis/netbinds.py plugin through the penguin.testing
harness (load_pyplugin -> null backend, no PANDA/guest). Time is controlled with
a fake clock and the announce backup timer is replaced with a no-op, so the
debounce/flap machinery is exercised deterministically with no sleeps and no
background threads (which can be GIL-starved under real emulation anyway -- the
production code promotes via a hypercall-path sweep for exactly that reason).

The zero-window immediate-announce behaviour and the netbinds.csv shape are
covered in test_pyplugin_harness.py; the in-guest path is covered by the
tests/integration/test_target netbinds*.yaml fixtures.
"""
import sys
from pathlib import Path

import pytest

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
NETBINDS = REPO_ROOT / "pyplugins" / "analysis" / "netbinds.py"


class FakeClock:
    """A controllable stand-in for the module's ``time``: only ``time()`` is used."""

    def __init__(self, t=1000.0):
        self.t = float(t)

    def time(self):
        return self.t

    def advance(self, dt):
        self.t += dt


class DeadTimer:
    """A threading.Timer that never fires. Promotion then happens solely via the
    hypercall-path sweep (deterministic), never a background thread."""

    def __init__(self, *a, **k):
        self.daemon = False

    def start(self):
        pass

    def cancel(self):
        pass


def _load(tmp_path, monkeypatch, clock=None, **args):
    """Load a fresh netbinds plugin with a fake clock and dead announce timer.

    Returns ``(lp, g, clock)`` where ``g`` is the plugin module's global
    namespace (the harness execs the module under an internal name that isn't in
    sys.modules, so we reach ``time`` / ``threading`` / ``plugins`` through a
    method's __globals__)."""
    clock = clock or FakeClock()
    args.setdefault("shutdown_on_www", False)
    args.setdefault("announce_debounce_s", 0.2)
    args.setdefault("debounce_period", 0.2)
    args.setdefault("transient_threshold", 3)
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    # endianness="big" keeps "port:pid" ports un-swapped so f"{port}:{pid}" reads back as `port`.
    lp = load_pyplugin(str(NETBINDS), outdir=tmp_path, args=args, endianness="big")
    g = type(lp.plugin).save_state.__globals__
    monkeypatch.setitem(g, "time", clock)
    monkeypatch.setattr(g["threading"], "Timer", DeadTimer)
    lp.plugin.start_time = clock.t  # rebase deltas onto the fake clock
    return lp, g, clock


def _bind(lp, port, proc="daemon", stream=True, pid=42):
    lp.dispatch("igloo_ipv4_setup", None, proc, 0)  # sin_addr 0 -> 0.0.0.0
    lp.dispatch("igloo_ipv4_bind", None, f"{port}:{pid}", stream)


def _close(lp, port, stream=True):
    lp.dispatch("igloo_ipv4_release", None, f"0.0.0.0:{port}", stream)


def _rec(lp, port, ip="0.0.0.0", sock_type="tcp", ipvn=4):
    return lp.plugin.sockets[(ipvn, sock_type, ip, port)]


def _read(tmp_path, name):
    p = Path(tmp_path) / name
    return p.read_text() if p.exists() else ""


def _on_binds(lp):
    return [p[2] for p in lp.published if p[1] == "on_bind"]


# --------------------------------------------------------------------------- #
# Announce debounce
# --------------------------------------------------------------------------- #
def test_transient_bind_never_announced(tmp_path, monkeypatch):
    lp, _mod, _clk = _load(tmp_path, monkeypatch)
    _bind(lp, 8401)
    _close(lp, 8401)  # released within the announce window -> transient

    assert _on_binds(lp) == []
    assert _rec(lp, 8401)["state"] == "transient"

    lp.finalize()
    row = [r for r in _read(tmp_path, "netbinds.csv").splitlines() if ",8401," in r]
    assert len(row) == 1
    fields = row[0].split(",")
    assert fields[7] == "transient"
    assert fields[8] != ""  # closed_time recorded
    assert _on_binds(lp) == []


def test_bind_announced_after_debounce(tmp_path, monkeypatch):
    lp, _mod, clk = _load(tmp_path, monkeypatch)
    _bind(lp, 8402)
    assert _on_binds(lp) == []  # held pending, not announced synchronously

    clk.advance(0.3)      # past the 0.2s announce window
    _bind(lp, 9999)       # any later event drives the hypercall-path sweep

    assert ("tcp", 4, "0.0.0.0", 8402, "daemon") in _on_binds(lp)
    assert _rec(lp, 8402)["state"] == "listening"
    assert ",8402,42," in _read(tmp_path, "netbinds.csv")


def test_timer_callback_announces(tmp_path, monkeypatch):
    """The backup timer path (used for a quiet guest with no later events)
    promotes and publishes when it fires."""
    lp, _mod, clk = _load(tmp_path, monkeypatch)
    _bind(lp, 8411)
    key = (4, "tcp", "0.0.0.0", 8411)
    clk.advance(0.3)
    lp.plugin._announce_cb(key)  # what the (dead) Timer would have called

    assert ("tcp", 4, "0.0.0.0", 8411, "daemon") in _on_binds(lp)
    assert _rec(lp, 8411)["state"] == "listening"


def test_announced_bind_closes_for_good(tmp_path, monkeypatch):
    lp, _mod, clk = _load(tmp_path, monkeypatch)
    _bind(lp, 8403)
    clk.advance(0.3)
    _bind(lp, 9999)                 # sweep -> 8403 listening
    assert _rec(lp, 8403)["state"] == "listening"

    _close(lp, 8403)               # held pending-close
    clk.advance(0.3)               # past debounce_period (0.2)
    lp.finalize()

    assert _rec(lp, 8403)["state"] == "closed"
    fields = [r for r in _read(tmp_path, "netbinds.csv").splitlines()
              if ",8403," in r][0].split(",")
    assert fields[7] == "closed"
    assert fields[8] != ""
    life = [r for r in _read(tmp_path, "netbinds_lifecycle.csv").splitlines() if ",8403," in r]
    assert life and "closed" in life[0]


def test_flap_after_announce_is_not_a_close(tmp_path, monkeypatch):
    lp, _mod, clk = _load(tmp_path, monkeypatch)
    _bind(lp, 8404)
    clk.advance(0.3)
    _bind(lp, 9999)                 # 8404 -> listening
    _close(lp, 8404)               # pending-close (within debounce)
    _bind(lp, 8404)                 # re-bind inside the window -> flap

    rec = _rec(lp, 8404)
    assert rec["state"] == "listening"
    assert rec["flap_count"] == 1
    assert len(_on_binds(lp)) == 1
    assert "flap," in _read(tmp_path, "netbind_events.csv")


def test_pending_at_shutdown_stays_pending(tmp_path, monkeypatch):
    lp, _mod, _clk = _load(tmp_path, monkeypatch)
    _bind(lp, 8405)
    lp.finalize()  # younger than the announce window when the run ends

    assert _on_binds(lp) == []
    assert _rec(lp, 8405)["state"] == "pending"
    row = [r for r in _read(tmp_path, "netbinds.csv").splitlines() if ",8405," in r]
    assert len(row) == 1
    assert row[0].split(",")[7] == "pending"


def test_zero_debounce_announces_synchronously(tmp_path, monkeypatch):
    lp, _mod, _clk = _load(tmp_path, monkeypatch, announce_debounce_s=0)
    _bind(lp, 8406)
    assert ("tcp", 4, "0.0.0.0", 8406, "daemon") in _on_binds(lp)
    assert _rec(lp, 8406)["state"] == "listening"


def test_shutdown_on_www_fires_only_after_debounce(tmp_path, monkeypatch):
    lp, _mod, clk = _load(tmp_path, monkeypatch, shutdown_on_www=True)
    ended = []
    lp.plugin.panda.end_analysis = lambda: ended.append(True)

    # Transient www bind must NOT end the run.
    _bind(lp, 80, proc="flaky_httpd")
    _close(lp, 80)
    assert ended == []

    # A www bind that survives the window must end the run.
    _bind(lp, 80, proc="httpd")
    clk.advance(0.3)
    _bind(lp, 9999)  # sweep promotes/announces 80
    assert ended == [True]


def test_transient_rebind_can_still_become_listening(tmp_path, monkeypatch):
    lp, _mod, clk = _load(tmp_path, monkeypatch)
    _bind(lp, 8407)
    _close(lp, 8407)
    assert _rec(lp, 8407)["state"] == "transient"

    _bind(lp, 8407)      # genuine re-open -> pending again
    clk.advance(0.3)
    _bind(lp, 9999)      # sweep -> listening
    assert _rec(lp, 8407)["state"] == "listening"
    assert len(_on_binds(lp)) == 1


def test_subscriber_may_reenter_plugin_during_publish(tmp_path, monkeypatch):
    """on_bind is published without _lock held, so a subscriber can call back
    into the plugin (e.g. give_list) without deadlocking."""
    lp, g, _clk = _load(tmp_path, monkeypatch, announce_debounce_s=0)
    reentered = []
    monkeypatch.setattr(
        g["plugins"], "publish",
        lambda src, event, *a: reentered.append(lp.plugin.give_list()),
    )
    _bind(lp, 8410)
    assert len(reentered) == 1
    assert reentered[0][0]["Port"] == 8410


# --------------------------------------------------------------------------- #
# Snapshot / restore
# --------------------------------------------------------------------------- #
def test_save_state_is_none_when_idle(tmp_path, monkeypatch):
    lp, _mod, _clk = _load(tmp_path, monkeypatch)
    assert lp.plugin.save_state() is None  # nothing bound -> nothing to carry


def test_snapshot_restores_listening_silently(tmp_path, monkeypatch):
    # Producer: a listening service is captured in save_state.
    src = _load(tmp_path / "a", monkeypatch, announce_debounce_s=0)[0]
    _bind(src, 8500, proc="httpd")  # announced immediately, stays listening
    assert _rec(src, 8500)["state"] == "listening"
    state = src.plugin.save_state()
    assert state is not None

    # Consumer: a fresh restored run rebuilds the record from the snapshot.
    dst, _mod, _clk = _load(tmp_path / "b", monkeypatch, announce_debounce_s=0)
    dst.plugin.load_state(state)
    dst.plugin.on_restore("boot")

    assert _rec(dst, 8500)["state"] == "listening"
    row = [r for r in _read(tmp_path / "b", "netbinds.csv").splitlines() if ",8500," in r]
    assert len(row) == 1 and row[0].split(",")[7] == "listening"
    assert {b["Port"] for b in dst.plugin.give_list()} == {8500}
    # Already-announced: consumers (VPN) replay their own bridges, so NetBinds
    # must NOT re-publish on_bind for it (that would double-actuate).
    assert _on_binds(dst) == []


def test_snapshot_promotes_pending_on_restore(tmp_path, monkeypatch):
    # Producer: a bind still inside its announce window at snapshot time.
    src = _load(tmp_path / "a", monkeypatch)[0]  # nonzero announce window
    _bind(src, 8501, proc="slowsvc")
    assert _rec(src, 8501)["state"] == "pending"
    state = src.plugin.save_state()

    # Consumer: the restored guest genuinely holds that socket -> promote and
    # announce it (nobody downstream saved it, so it must be published now).
    dst, _mod, _clk = _load(tmp_path / "b", monkeypatch)
    dst.plugin.load_state(state)
    dst.plugin.on_restore("boot")

    assert _rec(dst, 8501)["state"] == "listening"
    assert ("tcp", 4, "0.0.0.0", 8501, "slowsvc") in _on_binds(dst)
    row = [r for r in _read(tmp_path / "b", "netbinds.csv").splitlines() if ",8501," in r]
    assert len(row) == 1 and row[0].split(",")[7] == "listening"
