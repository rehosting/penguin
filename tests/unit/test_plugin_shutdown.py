"""Host-side tests for shutdown requests and pending work (#947).

A plugin that calls ``panda.end_analysis()`` ends the run on the spot, cutting off other
plugins' work in progress: run_on_bind finishing while fetch_web was mid-fetch was the
reported case. Plugins now call ``request_shutdown()``, which waits (bounded) for work
registered with ``begin_work()`` before ending the run.

The manager tests drive the real ``IGLOOPluginManager`` with a fake panda. The plugin
tests load fetch_web and run_on_bind through the test harness, with the network fetch and
the commands replaced.
"""
import threading
import time
from pathlib import Path

import pytest

from penguin import plugin_manager
from penguin.plugin_manager import IGLOOPluginManager
from penguin.testing import load_pyplugin
from penguin.testing.harness import NullManager

REPO_ROOT = Path(__file__).resolve().parents[2]
FETCH_WEB = REPO_ROOT / "pyplugins" / "actuation" / "fetch_web.py"
RUN_ON_BIND = REPO_ROOT / "pyplugins" / "actuation" / "run_on_bind.py"
BIND = ("tcp", "192.168.0.1", 80, 8080, "127.0.0.1", "httpd")
HOST_CMD = [{"mode": "host", "run": "true"}]  # never run: run_commands is replaced


class FakePanda:
    def __init__(self):
        self.ended = 0

    def end_analysis(self):
        self.ended += 1


class LogRecorder:
    def __init__(self):
        self.records = []

    def __getattr__(self, level):
        return lambda msg, *a, **k: self.records.append((level, msg))

    def at(self, level):
        return [msg for lvl, msg in self.records if lvl == level]


class Owner:
    name = "Owner"


@pytest.fixture
def manager():
    """A freshly initialized manager (it is a process-wide singleton)."""
    mgr = IGLOOPluginManager()
    mgr.initialize(FakePanda(), {"conf": None})
    mgr.logger = LogRecorder()
    yield mgr
    if mgr._shutdown_thread is not None:
        mgr._tearing_down.set()
        mgr._shutdown_thread.join(timeout=5)


def wait_for(predicate, timeout=5.0):
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail(f"timed out after {timeout}s waiting for {predicate}")
        time.sleep(0.01)


def join_shutdown(manager, timeout=5):
    manager._shutdown_thread.join(timeout=timeout)
    assert not manager._shutdown_thread.is_alive(), "shutdown thread did not finish"


# --- the manager ------------------------------------------------------------ #

def test_with_no_pending_work_the_run_ends_at_once(manager):
    assert manager.request_shutdown(Owner(), "done") is True
    join_shutdown(manager)

    assert manager.panda.ended == 1


def test_the_run_waits_for_pending_work(manager):
    work = manager.begin_work(Owner(), "fetch 10.0.0.1:80")

    manager.request_shutdown(Owner(), "done")
    time.sleep(0.4)
    assert manager.panda.ended == 0, "the run ended with work still pending"
    assert any("fetch 10.0.0.1:80" in m for m in manager.logger.at("info"))

    work.done()
    join_shutdown(manager)
    assert manager.panda.ended == 1


def test_work_registered_after_the_request_is_waited_for(manager):
    first = manager.begin_work(Owner(), "first")
    manager.request_shutdown(Owner(), "done")

    second = manager.begin_work(Owner(), "second")
    first.done()
    time.sleep(0.4)
    assert manager.panda.ended == 0

    second.done()
    join_shutdown(manager)
    assert manager.panda.ended == 1


def test_stuck_work_is_given_up_on_after_the_bound(manager, monkeypatch):
    monkeypatch.setattr(plugin_manager, "SHUTDOWN_WAIT", 0.3)
    manager.begin_work(Owner(), "wedged")

    started = time.monotonic()
    manager.request_shutdown(Owner(), "done")
    join_shutdown(manager)

    assert time.monotonic() - started >= 0.3
    assert manager.panda.ended == 1
    assert any("wedged" in m for m in manager.logger.at("warning"))


def test_the_first_request_wins(manager):
    work = manager.begin_work(Owner(), "busy")

    assert manager.request_shutdown(Owner(), "first") is True
    assert manager.request_shutdown(Owner(), "second") is False

    work.done()
    join_shutdown(manager)
    assert manager.panda.ended == 1


def test_done_is_idempotent(manager):
    work = manager.begin_work(Owner(), "once")
    other = manager.begin_work(Owner(), "other")

    work.done()
    work.done()

    assert manager.pending_work() == [other]


def test_teardown_begun_elsewhere_stops_the_wait(manager):
    """core.timeout or a guest poweroff ended the run while a request was waiting:
    the emulator may already be gone, so the request must not call into it."""
    manager.begin_work(Owner(), "wedged")
    manager.request_shutdown(Owner(), "done")

    manager.unload_all()  # what core.timeout and pre_shutdown do
    join_shutdown(manager)

    assert manager.panda.ended == 0


def test_a_failed_wait_still_ends_the_run(manager, monkeypatch):
    def broken():
        raise RuntimeError("boom")

    monkeypatch.setattr(manager, "pending_work", broken)
    manager.request_shutdown(Owner(), "done")
    join_shutdown(manager)

    assert manager.panda.ended == 1


# --- fetch_web --------------------------------------------------------------- #

def load_fetch_web(tmp_path, fetch, **args):
    lp = load_pyplugin(str(FETCH_WEB), outdir=tmp_path, args={"fetch_delay": 0, **args})
    lp.plugin.fetch = fetch
    return lp


def test_fetch_web_holds_each_bind_as_pending_until_its_fetch_ends(tmp_path):
    release = threading.Event()
    fetching = threading.Event()

    def fetch(*_args):
        fetching.set()
        release.wait(5)
        return True

    lp = load_fetch_web(tmp_path, fetch)
    try:
        lp.dispatch("on_bind", *BIND)
        wait_for(fetching.is_set)
        assert lp.pending_work == ["fetch 192.168.0.1:80"]
    finally:
        release.set()
    wait_for(lambda: lp.pending_work == [])


# The raising fetch still kills the worker thread, as before; only the release is new.
@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_fetch_web_releases_a_bind_whose_fetch_raises(tmp_path):
    def fetch(*_args):
        raise OSError("wget output vanished")

    lp = load_fetch_web(tmp_path, fetch)
    lp.dispatch("on_bind", *BIND)

    wait_for(lambda: lp.pending_work == [])
    wait_for(lambda: lp.plugin.shutting_down)


def test_fetch_web_requests_shutdown_and_releases_what_it_will_not_fetch(tmp_path):
    """shutdown_after_www stops after the first success; a bind still queued is
    released rather than holding the run open."""
    release = threading.Event()

    def fetch(*_args):
        release.wait(5)
        return True

    lp = load_fetch_web(tmp_path, fetch, shutdown_after_www=True)
    try:
        lp.dispatch("on_bind", *BIND)
        lp.dispatch("on_bind", "tcp", "192.168.0.2", 443, 8443, "127.0.0.1", "httpd")
        wait_for(lambda: len(lp.pending_work) == 2)
    finally:
        release.set()

    wait_for(lambda: lp.shutdown_requests)
    wait_for(lambda: lp.pending_work == [])
    assert [c for c in lp.calls if c[0] == "panda.end_analysis"] == []

    lp.dispatch("on_bind", *BIND)  # stopped: no longer queued or registered
    assert lp.pending_work == []


# --- run_on_bind ------------------------------------------------------------- #

def load_run_on_bind(tmp_path):
    lp = load_pyplugin(str(RUN_ON_BIND), outdir=tmp_path,
                       args={"commands": HOST_CMD, "delay": 0, "shutdown_after_cmd": True})
    lp.plugin.run_commands = lambda *a: True
    return lp


def test_run_on_bind_requests_shutdown_instead_of_ending_the_run(tmp_path):
    lp = load_run_on_bind(tmp_path)

    lp.plugin._run_attempt("10.0.0.1:80", "127.0.0.1", 8080, time.time())

    assert [reason for _, reason in lp.shutdown_requests] == [
        "commands succeeded for 10.0.0.1:80"]
    assert [c for c in lp.calls if c[0] == "panda.end_analysis"] == []


# --- the reported case -------------------------------------------------------- #

def test_run_on_bind_finishing_does_not_cut_off_a_fetch(tmp_path, manager, monkeypatch):
    """#947: run_on_bind's commands succeed while fetch_web is still fetching. The run
    ends only after the fetch does."""
    monkeypatch.setattr(NullManager, "begin_work",
                        lambda self, plugin, description: manager.begin_work(plugin, description))
    monkeypatch.setattr(NullManager, "request_shutdown",
                        lambda self, requester, reason: manager.request_shutdown(requester, reason))
    release = threading.Event()
    fetched = []

    def fetch(*args):
        release.wait(5)
        fetched.append(args[0])
        return True

    web = load_fetch_web(tmp_path, fetch)
    run = load_run_on_bind(tmp_path)

    try:
        web.dispatch("on_bind", *BIND)
        run.plugin._run_attempt("192.168.0.1:80", "127.0.0.1", 8080, time.time())
        time.sleep(0.4)
        assert manager.panda.ended == 0, "the run ended while fetch_web was fetching"
    finally:
        release.set()

    join_shutdown(manager)
    assert fetched == ["192.168.0.1"]
    assert manager.panda.ended == 1
