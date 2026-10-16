"""Plugin-side halves of the graceful shutdown: run_on_bind ending the run while
fetch_web was still fetching was the reported bug, and nmap / fetch_web_testing
opt in the same way.

Each has two responsibilities under the contract in
docs/pyplugin_architecture.md: ask for the run to end rather than ending it
(`request_shutdown`, not `panda.end_analysis`), and keep its pending work
(`begin_work` / `done`) accurate: what it expects to do, and what is queued or
running.

What neither may do is change its own behaviour because some other plugin
asked to end the run -- that is the whole point, so several of these drive a
plugin with a shutdown already pending and check it carries on exactly as it
would have otherwise. Everything runs through the penguin.testing harness: no
PANDA, no guest, no wget, no subprocesses.

The manager side (who waits for whom, the watchdog) is covered in
test_graceful_shutdown.py.
"""
import threading
import time
from pathlib import Path

import pytest

from penguin.plugin_manager import IGLOOPluginManager, Plugin
from penguin.testing import load_pyplugin
from penguin.testing.harness import NullManager

REPO_ROOT = Path(__file__).resolve().parents[2]
FETCH_WEB = REPO_ROOT / "pyplugins" / "actuation" / "fetch_web.py"
RUN_ON_BIND = REPO_ROOT / "pyplugins" / "actuation" / "run_on_bind.py"
NMAP = REPO_ROOT / "pyplugins" / "actuation" / "nmap.py"
FETCH_WEB_TEST = REPO_ROOT / "pyplugins" / "testing" / "fetch_web_testing.py"

FETCH_GOAL = "fetch a web page"
FETCH_BIND = "fetch 192.168.0.1:80"
RUN_GOAL = "commands succeed on a matching bind"
RUN_BIND = "commands attempt for 192.168.0.1:80"

BIND = ("tcp", "192.168.0.1", 80, 8080, "127.0.0.1", "httpd")


def wait_for(predicate, timeout=5.0):
    """Block until ``predicate()`` is true, or fail the test."""
    deadline = threading.Event()
    timer = threading.Timer(timeout, deadline.set)
    timer.daemon = True
    timer.start()
    try:
        while not predicate():
            if deadline.is_set():
                pytest.fail(f"timed out after {timeout}s waiting for {predicate}")
            deadline.wait(0.01)
    finally:
        timer.cancel()
    return True


def ended_analysis(lp):
    """Direct ``panda.end_analysis()`` calls -- what a plugin must NOT do."""
    return [c for c in lp.calls if c[0] == "panda.end_analysis"]


def pending_shutdown(lp, reason="another plugin finished"):
    """Record a shutdown request from some other plugin.

    The null manager only notes it -- which is also all the real manager does
    to the plugins -- so whatever the plugin does next is what it would have
    done with no shutdown pending at all.
    """
    lp.plugin.plugins.request_shutdown(object(), reason)


# --- fetch_web ------------------------------------------------------------ #

def load_fetch_web(tmp_path, fetch, **args):
    """Load fetch_web with its network fetch replaced by ``fetch``."""
    lp = load_pyplugin(str(FETCH_WEB), outdir=tmp_path,
                       args={"fetch_delay": 0, **args})
    lp.plugin.fetch = fetch
    return lp


def test_fetch_web_requests_shutdown_rather_than_ending_the_analysis(tmp_path):
    lp = load_fetch_web(tmp_path, lambda *a: True, shutdown_after_www=True)

    lp.dispatch("on_bind", *BIND)
    wait_for(lambda: lp.shutdown_requests)

    requester, reason = lp.shutdown_requests[0]
    assert requester is lp.plugin
    assert "192.168.0.1:80" in reason
    assert ended_analysis(lp) == []


def test_fetch_web_expects_a_fetch_from_load(tmp_path):
    """Before any bind there is nothing queued, but fetch_web still intends to
    fetch, so a sibling's shutdown must not end the run yet."""
    lp = load_fetch_web(tmp_path, lambda *a: True)

    assert lp.pending_work == [FETCH_GOAL]
    assert lp.manager.pending_work()[0].expected is True


def test_fetch_web_holds_the_run_open_while_fetching(tmp_path):
    release = threading.Event()
    fetching = threading.Event()

    def slow_fetch(*_args):
        fetching.set()
        release.wait(5)
        return True

    lp = load_fetch_web(tmp_path, slow_fetch, shutdown_after_www=True)

    lp.dispatch("on_bind", *BIND)
    wait_for(fetching.is_set)
    assert lp.pending_work == [FETCH_GOAL, FETCH_BIND]

    release.set()
    wait_for(lambda: lp.pending_work == [])


def test_fetch_web_success_releases_its_goal_and_keeps_fetching(tmp_path):
    """Without shutdown_after_www the plugin carries on after a success; its
    goal is met, and later binds are tracked on their own."""
    release = threading.Event()
    fetched = []

    def fetch(*args):
        fetched.append(args[2])
        if args[2] == 443:
            release.wait(5)
        return True

    lp = load_fetch_web(tmp_path, fetch)
    lp.dispatch("on_bind", *BIND)
    wait_for(lambda: lp.pending_work == [])

    lp.dispatch("on_bind", "tcp", "192.168.0.2", 443, 8443, "127.0.0.1", "httpd")
    wait_for(lambda: fetched == [80, 443])
    assert lp.pending_work == ["fetch 192.168.0.2:443"]
    release.set()
    wait_for(lambda: lp.pending_work == [])


def test_a_failed_fetch_keeps_the_goal_open(tmp_path):
    """A failure is not the page fetch_web is here for; it waits for the next bind."""
    lp = load_fetch_web(tmp_path, lambda *a: False)

    lp.dispatch("on_bind", *BIND)
    wait_for(lambda: FETCH_BIND not in lp.pending_work)
    assert lp.pending_work == [FETCH_GOAL]


def test_a_raising_fetch_does_not_kill_the_worker(tmp_path):
    """The next bind must still be fetched, and the raising one released."""
    fetched = []

    def fetch(*args):
        if args[2] == 80:
            raise OSError("wget output vanished")
        fetched.append(args[2])
        return True

    lp = load_fetch_web(tmp_path, fetch)
    lp.dispatch("on_bind", *BIND)
    lp.dispatch("on_bind", "tcp", "192.168.0.2", 443, 8443, "127.0.0.1", "httpd")

    wait_for(lambda: fetched == [443])
    wait_for(lambda: lp.pending_work == [])
    assert lp.plugin.worker_thread.is_alive()


def test_fetch_web_still_fetches_a_bind_that_arrives_after_the_request(tmp_path):
    """A pending shutdown must not cost this plugin a target. The bind is
    queued and fetched exactly as it would have been, and holds the run open
    while it happens."""
    fetched = []
    lp = load_fetch_web(tmp_path, lambda *a: fetched.append(a[:1]) or True)

    pending_shutdown(lp)
    lp.dispatch("on_bind", *BIND)

    assert FETCH_BIND in lp.pending_work, "a queued target was not tracked"
    wait_for(lambda: fetched == [("192.168.0.1",)])
    wait_for(lambda: lp.pending_work == [])


def test_fetch_web_keeps_fetching_later_binds_while_a_shutdown_is_pending(tmp_path):
    """Not just the first one: the plugin's lifecycle is untouched, so every
    target it would normally take, it still takes."""
    fetched = []
    lp = load_fetch_web(tmp_path, lambda *a: fetched.append(a[2]) or True)

    pending_shutdown(lp)
    lp.dispatch("on_bind", *BIND)
    lp.dispatch("on_bind", "tcp", "192.168.0.2", 443, 8443, "127.0.0.1", "httpd")

    wait_for(lambda: sorted(fetched) == [80, 443])


def test_fetch_web_fetches_what_was_already_queued_when_the_request_landed(tmp_path):
    """The reported bug, from fetch_web's side: a target queued when another
    plugin ends the run is still fetched, not dropped."""
    fetched = []
    lp = load_fetch_web(tmp_path, lambda *a: fetched.append(a[:1]) or True)

    lp.dispatch("on_bind", *BIND)
    pending_shutdown(lp, "run_on_bind finished")

    wait_for(lambda: fetched == [("192.168.0.1",)])
    wait_for(lambda: lp.pending_work == [])


def test_fetch_web_releases_everything_on_its_own_terminal_condition(tmp_path):
    """`shutdown_after_www` stops the worker with a target still queued.
    Nothing will drain it, so it must not hold the run open, and a bind after
    that must not be accepted at all."""
    release = threading.Event()

    def fetch(*_args):
        release.wait(5)
        return True

    lp = load_fetch_web(tmp_path, fetch, shutdown_after_www=True)
    lp.dispatch("on_bind", *BIND)
    lp.dispatch("on_bind", "tcp", "192.168.0.2", 443, 8443, "127.0.0.1", "httpd")
    release.set()

    wait_for(lambda: not lp.plugin.worker_thread.is_alive())
    assert lp.pending_work == []

    lp.dispatch("on_bind", "tcp", "192.168.0.3", 80, 9080, "127.0.0.1", "httpd")
    assert lp.pending_work == []


# --- run_on_bind ---------------------------------------------------------- #

def load_run_on_bind(tmp_path, run_commands, **args):
    """Load run_on_bind (host mode, no guest_cmd needed) with its command
    execution replaced by ``run_commands``."""
    lp = load_pyplugin(str(RUN_ON_BIND), outdir=tmp_path,
                       args={"commands": [{"mode": "host", "run": ["true"]}],
                             "delay": 0, **args})
    lp.plugin.run_commands = run_commands
    return lp


def test_run_on_bind_requests_shutdown_rather_than_ending_the_analysis(tmp_path):
    lp = load_run_on_bind(tmp_path, lambda *a: True, shutdown_after_cmd=True)

    lp.dispatch("on_bind", *BIND)
    wait_for(lambda: lp.shutdown_requests)

    requester, reason = lp.shutdown_requests[0]
    assert requester is lp.plugin
    assert "192.168.0.1:80" in reason
    assert ended_analysis(lp) == []


def test_run_on_bind_expects_a_successful_attempt_from_load(tmp_path):
    lp = load_run_on_bind(tmp_path, lambda *a: True)

    assert lp.pending_work == [RUN_GOAL]
    assert lp.manager.pending_work()[0].expected is True


def test_run_on_bind_holds_the_run_open_while_commands_execute(tmp_path):
    release = threading.Event()
    running = threading.Event()

    def slow_commands(*_args):
        running.set()
        release.wait(5)
        return True

    lp = load_run_on_bind(tmp_path, slow_commands, shutdown_after_cmd=True)

    lp.dispatch("on_bind", *BIND)
    wait_for(running.is_set)
    assert lp.pending_work == [RUN_GOAL, RUN_BIND]

    release.set()
    wait_for(lambda: lp.pending_work == [])


def test_a_failed_attempt_keeps_the_goal_open(tmp_path):
    """run_on_bind goes on to try the next endpoint, so it is not done."""
    lp = load_run_on_bind(tmp_path, lambda *a: False)

    lp.dispatch("on_bind", *BIND)
    wait_for(lambda: lp.plugin.attempts == 1)
    wait_for(lambda: RUN_BIND not in lp.pending_work)
    assert lp.pending_work == [RUN_GOAL]


def test_run_on_bind_still_attempts_an_endpoint_that_binds_after_the_request(tmp_path):
    """A pending shutdown must not cost this plugin an attempt."""
    ran = []
    lp = load_run_on_bind(tmp_path, lambda endpoint, *a: ran.append(endpoint) or True)

    pending_shutdown(lp)
    lp.dispatch("on_bind", *BIND)

    wait_for(lambda: ran == ["192.168.0.1:80"])
    wait_for(lambda: lp.pending_work == [])


def test_run_on_bind_holds_the_run_open_through_an_attempts_delay(tmp_path):
    """The delay is part of the attempt. An endpoint queued but not yet running
    is work this plugin still intends to do, so it is not finished -- the first
    implementation abandoned exactly this case."""
    ran = []
    lp = load_run_on_bind(tmp_path, lambda *a: ran.append(True) or True, delay=30)

    lp.dispatch("on_bind", *BIND)

    assert lp.pending_work == [RUN_GOAL, RUN_BIND]
    assert ran == []


def test_run_on_bind_releases_everything_once_it_succeeds(tmp_path):
    """Its own success is terminal: the worker exits with an endpoint still
    queued, which nothing will attempt, so it must not hold the run open."""
    release = threading.Event()

    def commands(*_args):
        release.wait(5)
        return True

    lp = load_run_on_bind(tmp_path, commands, shutdown_after_cmd=True)
    lp.dispatch("on_bind", *BIND)
    lp.dispatch("on_bind", "tcp", "192.168.0.9", 80, 9080, "127.0.0.1", "httpd")
    release.set()

    wait_for(lambda: not lp.plugin.worker_thread.is_alive())
    assert lp.pending_work == []


# --- nmap and fetch_web_testing ------------------------------------------- #

def test_nmap_expects_nothing_but_tracks_each_scan(tmp_path):
    """nmap cannot know whether more services will bind, so it only holds
    the run open for scans it has actually started."""
    release = threading.Event()
    lp = load_pyplugin(str(NMAP), outdir=tmp_path)
    lp.plugin.scan_thread = lambda *a: release.wait(5)
    assert lp.pending_work == []

    lp.dispatch("on_bind", *BIND)
    assert lp.pending_work == ["nmap scan of guest port 80 (host 127.0.0.1:8080)"]

    release.set()
    wait_for(lambda: lp.pending_work == [])


def test_a_raising_nmap_scan_is_still_released(tmp_path):
    def scan(*_args):
        raise OSError("nmap not installed")

    lp = load_pyplugin(str(NMAP), outdir=tmp_path)
    lp.plugin.scan_thread = scan

    lp.dispatch("on_bind", *BIND)
    wait_for(lambda: lp.pending_work == [])


def test_fetch_web_testing_registers_no_work(tmp_path):
    """Its checks watch fetch_web's output; fetch_web's own work is what
    holds the run open."""
    lp = load_pyplugin(str(FETCH_WEB_TEST), outdir=tmp_path)
    lp.dispatch("on_bind", *BIND)
    assert lp.pending_work == []


def test_a_check_on_output_never_produced_does_not_hold_the_run(tmp_path, real_manager):
    """fetch_web dropped this target (e.g. it stopped after another fetch),
    so the file never appears. The run must not wait out the check, and the
    check still reports a failure rather than being lost."""
    checker = load_pyplugin(str(FETCH_WEB_TEST), outdir=tmp_path)
    check = checker.plugin._check_output
    checker.plugin._check_output = lambda *a: check(*a, timeout=1)
    panda, manager = _coordinator(real_manager, checker.plugin)

    checker.dispatch("on_bind", *BIND)
    started = time.monotonic()
    manager.request_shutdown(object(), "fetch_web finished", watchdog=30)
    manager._shutdown_thread.join(timeout=15)

    # Bounded by the check's own timeout via uninit's join, not by the watchdog.
    assert time.monotonic() - started < 10
    assert panda.ended == 1
    report = (tmp_path / "fetch_web_test.txt").read_text()
    assert "web_192.168.0.1_80: failed" in report


# --- the two together ----------------------------------------------------- #

class _FakePanda:
    def __init__(self):
        self.ended = 0

    def end_analysis(self):
        self.ended += 1


@pytest.fixture
def real_manager(monkeypatch):
    """The real manager, with harness-loaded plugins registering their work and
    requesting shutdown in it rather than in their null managers. Request it before loading plugins:
    fetch_web and run_on_bind register their expected work at load.

    Driving the real coordinator rather than calling the hooks by hand is what
    catches drift between what a plugin registers and what the manager waits on.
    """
    panda = _FakePanda()
    manager = IGLOOPluginManager()
    manager.initialize(panda, {"conf": None})
    monkeypatch.setattr(NullManager, "begin_work",
                        lambda self, plugin, description, expected=False:
                        manager.begin_work(plugin, description, expected))
    monkeypatch.setattr(NullManager, "request_shutdown",
                        lambda self, requester=None, reason=None, **kw:
                        manager.request_shutdown(requester, reason, **kw))
    yield panda, manager
    thread = manager._shutdown_thread
    if thread is not None:
        thread.join(timeout=5)


def _coordinator(real_manager, *plugins):
    """Hand loaded plugins to the real manager; return ``(panda, manager)``."""
    panda, manager = real_manager
    manager.plugins = {p.name: p for p in plugins}
    # The harness builds plugins without the manager's load(), which stamps the
    # load_time that unload_all orders teardown by.
    for order, plugin in enumerate(manager.plugins.values()):
        plugin.load_time = order
    return panda, manager


class StillWorking(Plugin):
    """A sibling that has not finished yet, holding the run open until released.

    Several plugins mid-task is the ordinary shape of a run, and it is what
    gives a late event somewhere deterministic to land.
    """

    def __init__(self, manager):
        self.plugins = manager
        self.work = self.begin_work("still working")


def test_run_on_bind_finishing_does_not_truncate_a_fetch_in_flight(tmp_path, real_manager):
    """The reported bug: `run_on_bind` and `fetch_web` with shutdown flags,
    where run_on_bind finishes first."""
    release = threading.Event()
    fetching = threading.Event()
    fetched = []

    def slow_fetch(*args):
        fetching.set()
        release.wait(5)
        fetched.append(args[:1])
        return True

    web = load_fetch_web(tmp_path, slow_fetch, shutdown_after_www=True)
    binder = load_run_on_bind(tmp_path, lambda *a: True, shutdown_after_cmd=True)
    panda, manager = _coordinator(real_manager, web.plugin, binder.plugin)

    web.dispatch("on_bind", *BIND)
    wait_for(fetching.is_set)

    # run_on_bind finishes its commands and asks for the run to end.
    binder.dispatch("on_bind", "tcp", "192.168.0.1", 443, 8443, "127.0.0.1", "httpd")
    wait_for(lambda: manager.shutdown_pending)

    # Several polls' worth of chances to get it wrong.
    time.sleep(0.5)
    assert "fetch 192.168.0.1:80" in [w.description for w in manager.pending_work()]
    assert panda.ended == 0, "the emulator stopped while fetch_web was still fetching"

    release.set()
    manager._shutdown_thread.join(timeout=5)

    assert fetched == [("192.168.0.1",)]
    assert panda.ended == 1


def test_run_on_bind_finishing_does_not_cost_fetch_web_a_later_service(tmp_path, real_manager):
    """The other half of the same requirement: a service that only binds *after*
    run_on_bind finished is still fetched. fetch_web had nothing queued when
    the request landed; its expected work is what holds the run open."""
    fetched = []
    web = load_fetch_web(tmp_path, lambda *a: fetched.append(a[2]) or True)
    binder = load_run_on_bind(tmp_path, lambda *a: True, shutdown_after_cmd=True)
    panda, manager = _coordinator(real_manager, web.plugin, binder.plugin)

    binder.dispatch("on_bind", "tcp", "192.168.0.1", 443, 8443, "127.0.0.1", "httpd")
    wait_for(lambda: manager.shutdown_pending)

    # Several polls with nothing queued anywhere: only the expectation holds it.
    time.sleep(0.5)
    assert panda.ended == 0, "the run ended before fetch_web saw a web service"

    # Only now does the web service come up.
    web.dispatch("on_bind", *BIND)
    wait_for(lambda: fetched == [80])
    manager._shutdown_thread.join(timeout=5)
    assert panda.ended == 1


def test_a_sibling_still_working_holds_the_run_after_fetch_web_is_done(tmp_path, real_manager):
    """fetch_web's goal being met is not the end of the run while another
    plugin still has work open."""
    web = load_fetch_web(tmp_path, lambda *a: True, shutdown_after_www=True)
    panda, manager = real_manager
    sibling = StillWorking(manager)
    _coordinator(real_manager, web.plugin, sibling)

    web.dispatch("on_bind", *BIND)
    wait_for(lambda: manager.shutdown_pending)
    time.sleep(0.5)
    assert panda.ended == 0

    sibling.work.done()
    manager._shutdown_thread.join(timeout=5)
    assert panda.ended == 1
