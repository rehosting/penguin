"""Shutdown requests wait for pending work (#947).

``request_shutdown()`` ends the run only once no work registered with ``begin_work()``
is left, so a plugin finishing does not cut off another plugin's work in progress.
"""
import threading
import time
from pathlib import Path

import pytest

from penguin import plugin_manager
from penguin.plugin_manager import IGLOOPluginManager
from penguin.testing import load_pyplugin

PYPLUGINS = Path(__file__).resolve().parents[2] / "pyplugins" / "actuation"
BIND = ("tcp", "192.168.0.1", 80, 8080, "127.0.0.1", "httpd")


class FakePanda:
    ended = 0

    def end_analysis(self):
        self.ended += 1


@pytest.fixture
def manager():
    mgr = IGLOOPluginManager()
    mgr.initialize(FakePanda(), {})
    yield mgr
    if mgr._shutdown_thread is not None:
        mgr._shutdown_thread.join(timeout=5)


def ended_after(manager, seconds):
    """How many times the run was ended, after waiting up to ``seconds`` for the request."""
    deadline = time.monotonic() + seconds
    while manager._shutdown_thread is None and time.monotonic() < deadline:
        time.sleep(0.01)
    if manager._shutdown_thread is not None:
        manager._shutdown_thread.join(timeout=max(0, deadline - time.monotonic()))
    return manager.panda.ended


def test_with_no_pending_work_the_run_ends_at_once(manager):
    manager.request_shutdown("test", "done")
    assert ended_after(manager, 5) == 1


def test_the_run_waits_for_pending_work(manager):
    work = manager.begin_work("busy")
    manager.request_shutdown("test", "done")
    assert ended_after(manager, 0.5) == 0

    work.done()
    assert ended_after(manager, 5) == 1


def test_stuck_work_is_given_up_on(manager, monkeypatch):
    monkeypatch.setattr(plugin_manager, "SHUTDOWN_WAIT", 0.3)
    manager.begin_work("stuck")
    manager.request_shutdown("test", "done")
    assert ended_after(manager, 5) == 1


def test_the_first_request_wins(manager):
    manager.request_shutdown("test", "first")
    manager.request_shutdown("test", "second")
    assert ended_after(manager, 5) == 1


def load_fetch_web(tmp_path, manager, fetch, **args):
    lp = load_pyplugin(str(PYPLUGINS / "fetch_web.py"), outdir=tmp_path,
                       args={"fetch_delay": 0, **args},
                       doubles={"begin_work": manager.begin_work,
                                "request_shutdown": manager.request_shutdown})
    lp.plugin.fetch = fetch
    return lp


def test_fetch_web_releases_queued_binds_when_it_stops(tmp_path, manager):
    """With shutdown_after_www, binds still queued after the first fetch are released
    rather than holding the run until the wait gives up."""
    release = threading.Event()
    lp = load_fetch_web(tmp_path, manager, lambda *a: release.wait(5), shutdown_after_www=True)
    try:
        lp.dispatch("on_bind", *BIND)
        lp.dispatch("on_bind", "tcp", "192.168.0.2", 443, 8443, "127.0.0.1", "httpd")
    finally:
        release.set()

    assert ended_after(manager, 5) == 1
    assert manager._pending_work == []


def test_run_on_bind_finishing_does_not_cut_off_a_fetch(tmp_path, manager):
    """#947: run_on_bind's commands succeed while fetch_web is still fetching."""
    release = threading.Event()
    lp = load_fetch_web(tmp_path, manager, lambda *a: release.wait(5))
    run = load_pyplugin(str(PYPLUGINS / "run_on_bind.py"), outdir=tmp_path,
                        args={"commands": [{"mode": "host", "run": "true"}], "delay": 0,
                              "shutdown_after_cmd": True},
                        doubles={"request_shutdown": manager.request_shutdown})
    run.plugin.run_commands = lambda *a: True

    try:
        lp.dispatch("on_bind", *BIND)
        run.plugin._run_attempt("192.168.0.1:80", "127.0.0.1", 8080, time.time())
        assert ended_after(manager, 0.5) == 0, "the run ended while fetch_web was fetching"
    finally:
        release.set()

    assert ended_after(manager, 5) == 1
