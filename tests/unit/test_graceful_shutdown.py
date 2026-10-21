"""Host-side tests for the plugin manager's graceful-shutdown coordination.

A plugin that has finished its own job ends the whole run, so ending it the
blunt way (``panda.end_analysis()``) truncates whatever the other plugins were
still doing -- run_on_bind finishing while fetch_web was mid-download was the
reported symptom. ``plugins.request_shutdown()`` instead waits until no work
registered through ``begin_work`` is open, and only then unloads and stops the
emulator.

The contract these pin down (docs/pyplugin_architecture.md):

* a request decides *when* the run may end and nothing else -- no plugin is
  notified, and none has its behaviour altered by one;
* work registered after the request is waited for too, and expected work a
  plugin registered at load holds the run before its trigger arrives;
* plugins that register nothing never hold the run open;
* the wait is bounded only by ``core.shutdown_watchdog`` (default 60s),
  which exists for broken plugins and not as a deadline for real work;
* teardown completes -- every ``uninit`` *returns* -- before the emulator
  stops, even when several threads tear down at once.

These drive the real ``IGLOOPluginManager`` with stub plugins and a fake panda:
no PANDA, no guest, no pyplugins. The plugin-side halves (fetch_web's queue
drain, run_on_bind's attempts) are covered in test_plugin_pending_work.py.
"""
import threading
import time

import pytest

from penguin import plugin_manager
from penguin.plugin_manager import (
    DEFAULT_SHUTDOWN_WATCHDOG,
    IGLOOPluginManager,
    Plugin,
)


class FakePanda:
    """Records end_analysis calls, and when they happened relative to uninit."""

    def __init__(self, timeline):
        self.timeline = timeline
        self.ended = 0

    def end_analysis(self):
        self.ended += 1
        self.timeline.append("end_analysis")


class Recorder(Plugin):
    """Base stub: notes its own teardown on a shared timeline."""

    def __init__(self):
        self.uninit_calls = 0

    def uninit(self):
        self.uninit_calls += 1
        self.args["timeline"].append(f"uninit:{self.name}")


class Finished(Recorder):
    """Always finished -- the common plugin with no background work."""


class Working(Recorder):
    """Has work open from load until ``finish()``, standing in for real work."""

    def __init__(self):
        super().__init__()
        self.work = self.begin_work("working")

    def finish(self):
        self.args["timeline"].append(f"finished:{self.name}")
        self.work.done()


class TakesWork(Recorder):
    """Registers work on demand, like an event-driven plugin handed a bind.

    A pending shutdown must not suppress this, and the work is waited for.
    """

    def take(self, description):
        self.args["timeline"].append(f"started:{description}")
        return self.begin_work(description)


class Expects(Recorder):
    """Intends to do something it has no trigger for yet, like fetch_web
    before any web service has bound."""

    def __init__(self):
        super().__init__()
        self.goal = self.begin_work("its intended work", expected=True)

    def deliver(self):
        self.args["timeline"].append(f"delivered:{self.name}")
        self.goal.done()


class Slow(Recorder):
    """Finishes on its own after a while -- legitimate work, not a hang."""

    duration = 0.8

    def __init__(self):
        super().__init__()
        self.work = self.begin_work("slow work")
        timer = threading.Timer(self.duration, self.work.done)
        timer.daemon = True
        timer.start()


class Stuck(Recorder):
    """Started work and never finishes: only a watchdog may override this one."""

    def __init__(self):
        super().__init__()
        self.work = self.begin_work("wedged work")


class Background(Recorder):
    """Busy for the whole session but registers nothing, like VPN."""

    def __init__(self):
        super().__init__()
        self.stop = threading.Event()
        threading.Thread(target=self.stop.wait, daemon=True).start()


class Notifiable(Recorder):
    """Carries the hook the first implementation called. Nothing may call it."""

    def __init__(self):
        super().__init__()
        self.notifications = []

    def on_shutdown_requested(self, reason):
        self.notifications.append(reason)


class Publisher(Recorder):
    """Owns an event its peers subscribe to, standing in for VPN's on_bind."""

    def __init__(self):
        super().__init__()
        self.plugins.register(self, "on_bind")


class Subscriber(Recorder):
    """Notes the events it is handed, to show when delivery stops."""

    def __init__(self):
        super().__init__()
        self.received = []
        # By name, not plugins.Publisher: __getattr__ caches the instance on
        # the manager, which is a singleton outliving the test.
        publisher = self.plugins.get_plugin_by_name("Publisher")
        self.plugins.subscribe(publisher, "on_bind", self.on_bind)

    def on_bind(self, port):
        self.received.append(port)


class BlockingSubscriber(Recorder):
    """A callback held mid-delivery, which accepts work once released --
    a bind handler that is already running when teardown begins."""

    def __init__(self):
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()
        self.work = None
        publisher = self.plugins.get_plugin_by_name("Publisher")
        self.plugins.subscribe(publisher, "on_bind", self.on_bind)

    def on_bind(self, port):
        self.entered.set()
        assert self.release.wait(5), "callback was never released"
        self.work = self.begin_work(f"accepted bind {port}")


class LogRecorder:
    """Stands in for the manager's logger to check what level a message got."""

    def __init__(self):
        self.records = []

    def __getattr__(self, level):
        return lambda msg, *a, **k: self.records.append((level, msg))

    def at(self, level):
        return [msg for lvl, msg in self.records if lvl == level]


class LingeringUninit(Recorder):
    """Teardown that takes a moment, to catch end_analysis racing uninit."""

    def uninit(self):
        self.uninit_calls += 1
        self.args["timeline"].append(f"uninit-start:{self.name}")
        time.sleep(0.2)
        self.args["timeline"].append(f"uninit:{self.name}")


class BlockingUninit(Recorder):
    """Teardown held open on demand, for the concurrent-teardown test."""

    def __init__(self):
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def uninit(self):
        self.uninit_calls += 1
        self.entered.set()
        assert self.release.wait(5), "uninit was never released"
        self.args["timeline"].append(f"uninit:{self.name}")


class RaisingUninit(Recorder):
    """Teardown that fails. It must not cost the run its only stop path."""

    def uninit(self):
        self.uninit_calls += 1
        self.args["timeline"].append(f"uninit:{self.name}")
        raise RuntimeError("boom in uninit")


class ReentrantUninit(Recorder):
    """Teardown that unloads everything again -- must not wait on itself."""

    def uninit(self):
        self.uninit_calls += 1
        self.plugins.unload_all()
        self.args["timeline"].append(f"uninit:{self.name}")


@pytest.fixture
def manager():
    """A freshly initialized manager (it is a process-wide singleton) with a
    timeline every stub plugin appends to, plus a helper to load stubs."""
    timeline = []
    mgr = IGLOOPluginManager()
    panda = FakePanda(timeline)
    mgr.initialize(panda, {"timeline": timeline, "conf": None})

    def load(*classes):
        mgr.load(list(classes), mgr.args)
        return [mgr.plugins[c.__name__] for c in classes]

    mgr.load_stubs = load
    yield mgr
    # The singleton outlives the test; leave no shutdown thread running.
    thread = getattr(mgr, "_shutdown_thread", None)
    if thread is not None:
        thread.join(timeout=5)


def _join_shutdown(manager, timeout=5):
    manager._shutdown_thread.join(timeout=timeout)
    assert not manager._shutdown_thread.is_alive(), "shutdown thread did not finish"


def _wait_for(predicate, timeout=5.0):
    """Block until ``predicate()`` is true, or fail the test."""
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            pytest.fail(f"timed out after {timeout}s waiting for {predicate}")
        time.sleep(0.01)


# --- a request must not disturb anyone else -------------------------------- #

def test_the_request_notifies_nobody(manager):
    """The request is a decision about when the run ends, not a signal to wind
    down. Nothing may call a plugin to tell it a shutdown is pending."""
    finished, notifiable = manager.load_stubs(Finished, Notifiable)

    manager.request_shutdown(finished, "done")
    _join_shutdown(manager)

    assert notifiable.notifications == []
    # And the hook that did this in the first implementation is gone for good,
    # so no plugin can grow a dependency on being told.
    assert not hasattr(Plugin, "on_shutdown_requested")


def test_work_registered_after_the_request_is_waited_for(manager):
    """A late bind is normal behaviour, not something a pending shutdown
    suppresses. Work started after the request is waited for like any other."""
    finished, working, late = manager.load_stubs(Finished, Working, TakesWork)
    timeline = manager.get_arg("timeline")

    manager.request_shutdown(finished, "done")
    late_work = late.take("late bind")
    working.finish()

    # The late work is still open, so the run must still be up.
    time.sleep(0.3)
    assert manager.panda.ended == 0
    assert late.uninit_calls == 0

    timeline.append("finished:late bind")
    late_work.done()
    _join_shutdown(manager)

    assert manager.panda.ended == 1
    assert timeline.index("finished:late bind") < timeline.index("end_analysis")


def test_shutdown_waits_for_a_working_plugin(manager):
    finished, working = manager.load_stubs(Finished, Working)
    timeline = manager.get_arg("timeline")

    assert manager.request_shutdown(finished, "the other plugin finished") is True

    # The emulator must still be running while the other plugin works.
    time.sleep(0.3)
    assert manager.panda.ended == 0
    assert working.uninit_calls == 0

    working.finish()
    _join_shutdown(manager)

    assert manager.panda.ended == 1
    assert timeline.index("finished:Working") < timeline.index("end_analysis")


def test_shutdown_waits_for_every_entry_not_just_the_first(manager):
    """One plugin finishing does not let the run end while another entry,
    from the same plugin or a different one, is still open."""
    first, second, third = manager.load_stubs(Finished, Working, TakesWork)
    timeline = manager.get_arg("timeline")
    a, b = third.take("a"), third.take("b")

    manager.request_shutdown(first, "done")
    second.finish()
    a.done()
    time.sleep(0.3)
    assert manager.panda.ended == 0, "ended while TakesWork still had work open"

    timeline.append("finished:b")
    b.done()
    _join_shutdown(manager)

    assert manager.panda.ended == 1
    for name in ("finished:Working", "finished:b"):
        assert timeline.index(name) < timeline.index("end_analysis")


def test_expected_work_holds_the_run_before_its_trigger_arrives(manager):
    """The reported bug's harder half: run_on_bind finishes before fetch_web
    has even seen a bind. fetch_web has nothing queued, but registered at
    load that it intends to fetch, so the run waits for it."""
    finished, expects = manager.load_stubs(Finished, Expects)
    timeline = manager.get_arg("timeline")

    manager.request_shutdown(finished, "done")
    time.sleep(0.3)
    assert manager.panda.ended == 0, "ended before the expected work happened"

    expects.deliver()
    _join_shutdown(manager)

    assert manager.panda.ended == 1
    assert timeline.index("delivered:Expects") < timeline.index("end_analysis")


def test_a_plugin_that_registers_nothing_never_blocks(manager):
    """Long-running plugins (VPN) stay out of it simply by not opting in."""
    finished, background = manager.load_stubs(Finished, Background)

    started = time.monotonic()
    manager.request_shutdown(finished, "done", watchdog=30)
    _join_shutdown(manager)

    assert time.monotonic() - started < 2
    assert manager.panda.ended == 1
    background.stop.set()


# --- real work is waited for; the watchdog only catches wedged plugins ------ #

def test_a_slow_plugin_is_allowed_to_finish(manager):
    """No deadline applies to real work: the slow plugin finishes on its own
    terms and is torn down normally rather than overridden."""
    finished, slow = manager.load_stubs(Finished, Slow)

    started = time.monotonic()
    manager.request_shutdown(finished, "done")
    _join_shutdown(manager, timeout=10)
    elapsed = time.monotonic() - started

    assert elapsed >= Slow.duration
    assert slow.work.is_done, "torn down before it had finished"
    assert manager.panda.ended == 1


def test_the_watchdog_defaults_to_a_backstop_rather_than_off(manager):
    """One wedged plugin must not be able to hang a run that opted into
    nothing, so the default is generous rather than absent."""
    assert manager._shutdown_watchdog() == DEFAULT_SHUTDOWN_WATCHDOG

    manager.args["conf"] = {"core": {}}
    assert manager._shutdown_watchdog() == DEFAULT_SHUTDOWN_WATCHDOG

    manager.args["conf"] = {"core": {"shutdown_watchdog": 7}}
    assert manager._shutdown_watchdog() == 7.0

    manager.args["conf"] = {"core": {"shutdown_watchdog": 0}}
    assert manager._shutdown_watchdog() == 0.0, "0 must mean now, not unset"

    manager.args["conf"] = None
    assert manager._shutdown_watchdog() == DEFAULT_SHUTDOWN_WATCHDOG


def test_the_watchdog_overrides_a_stuck_plugin(manager):
    """A plugin that never finishes is broken, not busy. With a watchdog
    configured it costs the run that long rather than hanging it forever."""
    finished, stuck = manager.load_stubs(Finished, Stuck)

    started = time.monotonic()
    manager.request_shutdown(finished, "done", watchdog=0.3)
    _join_shutdown(manager)
    elapsed = time.monotonic() - started

    assert elapsed >= 0.3
    assert manager.panda.ended == 1
    assert stuck.uninit_calls == 1  # overridden, not skipped


def test_the_watchdog_does_not_fire_when_everyone_finishes(manager):
    finished, working = manager.load_stubs(Finished, Working)
    working.finish()

    manager.request_shutdown(finished, "done", watchdog=5)
    _join_shutdown(manager)

    assert manager.panda.ended == 1


def test_a_second_request_does_not_restart_the_shutdown(manager):
    finished, working = manager.load_stubs(Finished, Working)

    assert manager.request_shutdown(finished, "first") is True
    first_thread = manager._shutdown_thread

    assert manager.request_shutdown(working, "second") is False
    assert manager._shutdown_thread is first_thread
    assert manager._shutdown_reason == "first"

    working.finish()
    _join_shutdown(manager)
    assert manager.panda.ended == 1


def test_the_watchdog_reports_unstarted_expected_work_as_skipped_not_stuck(manager):
    """No web service ever binding is a normal outcome; a fetch that started
    and never ended is a wedged plugin. Only the second is an error."""
    finished, expects, stuck = manager.load_stubs(Finished, Expects, Stuck)
    manager.logger = LogRecorder()

    manager.request_shutdown(finished, "done", watchdog=0.3)
    _join_shutdown(manager)

    errors = manager.logger.at("error")
    warnings = manager.logger.at("warning")
    assert len(errors) == 1 and "Stuck: wedged work" in errors[0]
    assert "Expects" not in errors[0]
    assert any("Expects: its intended work" in w for w in warnings)
    assert manager.panda.ended == 1


def test_done_is_idempotent(manager):
    """done() belongs in a finally, which may run after a path that already
    called it. A second call must not release someone else's entry."""
    finished, taker = manager.load_stubs(Finished, TakesWork)
    first, second = taker.take("first"), taker.take("second")

    first.done()
    first.done()

    assert [w.description for w in manager.pending_work()] == ["second"]
    second.done()
    assert manager.pending_work() == []


def test_concurrent_begin_and_done_leave_nothing_open(manager):
    """Workers on many threads register and release at once."""
    taker, = manager.load_stubs(TakesWork)

    def churn():
        for i in range(200):
            taker.begin_work(f"item {i}").done()

    threads = [threading.Thread(target=churn) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert manager.pending_work() == []


def test_shutdown_pending_is_visible(manager):
    finished, working = manager.load_stubs(Finished, Working)

    assert manager.shutdown_pending is False
    manager.request_shutdown(finished, "done")
    assert manager.shutdown_pending is True

    working.finish()
    _join_shutdown(manager)


# --- from the last check to teardown -------------------------------------- #

def _publish_in_background(manager, publisher, port=80):
    thread = threading.Thread(target=manager.publish,
                              args=(publisher, "on_bind", port), daemon=True)
    thread.start()
    return thread


def test_events_keep_reaching_plugins_while_the_shutdown_waits(manager):
    """A pending shutdown changes nothing for plugins: interventions and
    analysis subscribers keep getting events until the very end."""
    publisher, subscriber, working = manager.load_stubs(Publisher, Subscriber, Working)

    manager.request_shutdown(publisher, "done")
    time.sleep(0.3)  # well into the wait
    for port in (80, 443, 8080):
        manager.publish(publisher, "on_bind", port)
    assert subscriber.received == [80, 443, 8080]
    assert manager.panda.ended == 0

    working.finish()
    _join_shutdown(manager)
    manager.publish(publisher, "on_bind", 9999)  # after teardown: nobody
    assert subscriber.received == [80, 443, 8080]


def test_a_callback_running_when_the_registry_empties_is_waited_for(manager):
    """The teardown boundary: the registry is empty, but a subscriber is
    mid-callback and about to accept work. Sealing then would lose that work,
    so the shutdown waits for the callback, then for the work it accepted.
    Delivery stays open throughout, so later subscribers still get the event."""
    publisher, blocking, after = manager.load_stubs(
        Publisher, BlockingSubscriber, Subscriber)
    timeline = manager.get_arg("timeline")

    publishing = _publish_in_background(manager, publisher)
    assert blocking.entered.wait(5)

    manager.request_shutdown(publisher, "done")
    time.sleep(0.3)
    assert manager.pending_work() == []
    assert manager.panda.ended == 0, "sealed while a callback was running"
    assert not manager._sealed

    blocking.release.set()
    _wait_for(lambda: blocking.work is not None)
    publishing.join(timeout=5)
    assert after.received == [80], "delivery was cut off during the wait"
    time.sleep(0.3)
    assert manager.panda.ended == 0, "torn down before the accepted work finished"

    timeline.append("finished:accepted bind")
    blocking.work.done()
    _join_shutdown(manager)

    assert manager.panda.ended == 1
    assert timeline.index("finished:accepted bind") < timeline.index("end_analysis")


class EveryBindIsWork(Recorder):
    """Accepts work for each event it is handed, finished shortly after on
    another thread, and notes whether teardown had already sealed."""

    def __init__(self):
        super().__init__()
        self.after_seal = []
        self.accepted = []
        publisher = self.plugins.get_plugin_by_name("Publisher")
        self.plugins.subscribe(publisher, "on_bind", self.on_bind)

    def on_bind(self, port):
        if self.plugins._sealed:
            self.after_seal.append(port)
        work = self.begin_work(f"bind {port}")
        self.accepted.append(port)

        def finish():
            time.sleep(0.002)
            self.args["timeline"].append(f"done:{port}")
            work.done()

        threading.Thread(target=finish, daemon=True).start()


def test_sealing_under_concurrent_delivery_loses_nothing(manager):
    """Events arrive continuously while the shutdown waits, each accepting
    work. The seal can only land between callbacks with the registry empty,
    so every accepted bind is finished before end_analysis, no callback
    starts after the seal, and none of the work is registered late."""
    publisher, busy = manager.load_stubs(Publisher, EveryBindIsWork)
    timeline = manager.get_arg("timeline")
    manager.logger = LogRecorder()

    stop = threading.Event()
    ports = iter(range(10**6))

    def deliver():
        while not stop.is_set():
            manager.publish(publisher, "on_bind", next(ports))
            # Gaps longer than the work, so the registry does empty. Under
            # traffic that keeps it permanently busy the wait can only end at
            # the watchdog: late work is waited for, by design.
            time.sleep(0.01)

    threads = [threading.Thread(target=deliver, daemon=True) for _ in range(3)]
    for thread in threads:
        thread.start()
    time.sleep(0.05)
    manager.request_shutdown(publisher, "done", watchdog=30)
    _join_shutdown(manager, timeout=15)
    still_delivering = all(thread.is_alive() for thread in threads)
    stop.set()
    for thread in threads:
        thread.join(timeout=10)

    assert still_delivering, "the seal did not land under concurrent delivery"
    assert busy.accepted, "nothing was delivered during the wait"
    assert manager.panda.ended == 1
    assert busy.after_seal == [], "a callback started after the seal"
    assert not any("after teardown began" in w for w in manager.logger.at("warning"))
    end = timeline.index("end_analysis")
    for port in busy.accepted:
        assert timeline.index(f"done:{port}") < end, f"bind {port} finished after teardown"


def test_a_guest_poweroff_during_the_wait_is_not_reported_as_stuck(manager):
    """pre_shutdown tears down while the graceful wait is still waiting on
    work the stopping emulator will never let finish. The wait must notice
    teardown began elsewhere rather than run out the watchdog and call the
    work stuck."""
    finished, stuck = manager.load_stubs(Finished, Stuck)
    manager.logger = LogRecorder()

    manager.request_shutdown(finished, "done", watchdog=30)
    time.sleep(0.2)
    started = time.monotonic()
    manager.unload_all()  # the pre_shutdown path
    _join_shutdown(manager)

    assert time.monotonic() - started < 2
    assert manager.logger.at("error") == []
    assert stuck.uninit_calls == 1


def test_a_failed_wait_still_tears_down_and_ends_the_run(manager, monkeypatch):
    """Nothing in the shutdown may skip end_analysis: with a shutdown already
    requested, no later request (not even core.timeout) would start another."""
    finished, working = manager.load_stubs(Finished, Working)
    manager.logger = LogRecorder()

    def broken(_deadline):
        raise RuntimeError("boom in the wait")

    monkeypatch.setattr(manager, "_wait_and_seal", broken)
    manager.request_shutdown(finished, "done")
    _join_shutdown(manager)

    assert manager.panda.ended == 1
    assert working.uninit_calls == 1, "teardown was skipped"
    assert any("Waiting for pending work failed" in m for m in manager.logger.at("exception"))


def test_a_failed_detach_still_unloads_everyone(manager, monkeypatch):
    finished, working = manager.load_stubs(Finished, Working)
    working.finish()
    manager.logger = LogRecorder()

    def broken():
        raise RuntimeError("boom in detach")

    monkeypatch.setattr(manager, "_detach_subscriptions", broken)
    manager.request_shutdown(finished, "done")
    _join_shutdown(manager)

    assert manager.panda.ended == 1
    assert finished.uninit_calls == 1 and working.uninit_calls == 1
    assert any("Detaching subscriptions failed" in m for m in manager.logger.at("exception"))


class _RegistersWhileDetached(dict):
    """An event table whose detach registers a new plugin and event, as a
    lazy plugin load on another thread would, mid-iteration."""

    def __init__(self, manager, *a):
        super().__init__(*a)
        self.manager = manager

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if not getattr(self, "fired", False):
            self.fired = True
            self.manager.register(object(), "lazily_loaded")
            dict.__setitem__(self, "added_mid_detach", [])


def test_registration_during_detach_does_not_break_teardown(manager):
    publisher, subscriber = manager.load_stubs(Publisher, Subscriber)
    manager.plugin_cbs[publisher] = _RegistersWhileDetached(
        manager, manager.plugin_cbs[publisher])
    manager.logger = LogRecorder()

    manager.unload_all()

    assert manager.logger.at("exception") == []
    assert subscriber.uninit_calls == 1


def test_a_subscriber_called_through_call_subscriber_holds_the_seal(manager):
    """Dispatchers other than publish (the Events portalcall loop) go through
    call_subscriber, so a callback they are running counts like any other."""
    finished, = manager.load_stubs(Finished)
    entered, release = threading.Event(), threading.Event()
    accepted = []

    def portalcall_subscriber():
        entered.set()
        assert release.wait(5)
        accepted.append(finished.begin_work("accepted in a portalcall"))

    caller = threading.Thread(
        target=manager.call_subscriber, args=(portalcall_subscriber,), daemon=True)
    caller.start()
    assert entered.wait(5)

    manager.request_shutdown(finished, "done")
    time.sleep(0.3)
    assert manager.panda.ended == 0, "sealed while the portalcall subscriber ran"

    release.set()
    caller.join(timeout=5)
    _wait_for(lambda: accepted)
    accepted[0].done()
    _join_shutdown(manager)

    assert manager.panda.ended == 1
    assert manager.call_subscriber(lambda: None) == (False, None), \
        "a subscriber was called after the seal"


def test_an_immediate_request_does_not_wait_for_a_running_callback(manager):
    """Unchanged deadline behaviour: core.timeout does not wait for anything."""
    publisher, blocking = manager.load_stubs(Publisher, BlockingSubscriber)
    manager.logger = LogRecorder()

    publishing = _publish_in_background(manager, publisher)
    assert blocking.entered.wait(5)

    started = time.monotonic()
    manager.request_shutdown(publisher, "timeout", watchdog=30, immediate=True)
    _join_shutdown(manager)
    assert time.monotonic() - started < 2
    assert manager.panda.ended == 1
    assert any("1 event callback(s) still running" in w
               for w in manager.logger.at("warning"))

    # Released after the seal: its work is reported, not registered.
    blocking.release.set()
    publishing.join(timeout=5)
    assert manager.pending_work() == []


def test_work_registered_after_the_seal_is_reported_not_registered(manager):
    finished, taker = manager.load_stubs(Finished, TakesWork)
    manager.request_shutdown(finished, "done")
    _join_shutdown(manager)
    manager.logger = LogRecorder()

    work = taker.take("too late")

    assert manager.pending_work() == []
    assert any("TakesWork: too late" in w and "after teardown began" in w
               for w in manager.logger.at("warning"))
    work.done()  # still a usable handle
    assert manager.pending_work() == []


def test_handed_off_work_churning_through_the_shutdown_is_all_waited_for(manager):
    """Workers on several threads each register their next item before
    releasing the current one, while a shutdown is pending. The registry is
    never empty in between, so the run ends only after every worker is done,
    and nothing is registered after the seal."""
    finished, taker = manager.load_stubs(Finished, TakesWork)
    timeline = manager.get_arg("timeline")
    manager.logger = LogRecorder()

    def worker(n):
        current = taker.begin_work(f"worker {n} item 0")
        for i in range(1, 150):
            following = taker.begin_work(f"worker {n} item {i}")
            current.done()
            current = following
            time.sleep(0.001)
        timeline.append(f"finished:worker {n}")
        current.done()

    threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
    for thread in threads:
        thread.start()
    manager.request_shutdown(finished, "done", watchdog=30)
    for thread in threads:
        thread.join(timeout=10)
    _join_shutdown(manager)

    assert manager.panda.ended == 1
    for n in range(6):
        assert timeline.index(f"finished:worker {n}") < timeline.index("end_analysis")
    assert not any("after teardown began" in w for w in manager.logger.at("warning"))


# --- deadlines (core.timeout, SIGUSR1) stop the run ------------------------- #

def test_an_immediate_request_does_not_wait_for_plugins(manager):
    """core.timeout is a deadline: plugins mid-task are torn down, not waited for."""
    finished, stuck = manager.load_stubs(Finished, Stuck)

    started = time.monotonic()
    assert manager.request_shutdown(finished, "timeout", watchdog=30,
                                    immediate=True) is True
    _join_shutdown(manager)

    assert time.monotonic() - started < 2
    assert manager.panda.ended == 1
    assert stuck.uninit_calls == 1, "torn down so its output is still written"


def test_an_immediate_request_ends_a_wait_already_in_progress(manager):
    """A plugin asked first and the run is waiting on a busy sibling: the
    timeout must still end the run rather than be ignored."""
    finished, stuck = manager.load_stubs(Finished, Stuck)

    assert manager.request_shutdown(finished, "done", watchdog=30) is True
    _wait_for(lambda: manager._shutdown_thread.is_alive())
    assert manager.request_shutdown(finished, "timeout", immediate=True) is False

    _join_shutdown(manager)
    assert manager.panda.ended == 1
    assert manager._shutdown_reason == "done"


def test_an_immediate_request_lands_while_another_holds_the_lock(manager):
    """SIGUSR1 can interrupt a request inside the lock on the main thread;
    it declines rather than blocking, but the run still ends now."""
    finished, stuck = manager.load_stubs(Finished, Stuck)

    assert manager._shutdown_lock.acquire(blocking=False)
    try:
        assert manager.request_shutdown(finished, "SIGUSR1", immediate=True) is False
    finally:
        manager._shutdown_lock.release()

    # The interrupted request completes and starts the shutdown, which
    # must not wait despite asking to.
    manager.request_shutdown(finished, "done", watchdog=30)
    _join_shutdown(manager)
    assert manager.panda.ended == 1


# --- teardown -------------------------------------------------------------- #

def test_teardown_completes_before_end_analysis(manager):
    """Not merely started before: uninit must *return* first, or the emulator
    stops with that plugin's final writes half done."""
    finished, lingering = manager.load_stubs(Finished, LingeringUninit)
    timeline = manager.get_arg("timeline")

    manager.request_shutdown(finished, "done")
    _join_shutdown(manager)

    assert timeline.index("uninit-start:LingeringUninit") < timeline.index("uninit:LingeringUninit")
    assert timeline.index("uninit:LingeringUninit") < timeline.index("end_analysis")


def test_plugins_are_uninited_exactly_once(manager):
    """A run reaches teardown by several paths -- the shutdown, panda's
    pre_shutdown callback, penguin_run's finally -- and a second uninit would
    re-run the final writes the first one just made."""
    finished, working = manager.load_stubs(Finished, Working)
    working.finish()

    manager.request_shutdown(finished, "done")
    _join_shutdown(manager)

    manager.unload_all()  # the pre_shutdown / finally paths
    manager.unload_all()

    assert finished.uninit_calls == 1
    assert working.uninit_calls == 1


def test_a_second_teardown_waits_for_an_uninit_in_flight(manager):
    """A teardown that has been claimed but not finished is not a teardown that
    is done. The second caller must block, or it reports the plugin torn down
    while its output is still being written."""
    blocking, = manager.load_stubs(BlockingUninit)
    timeline = manager.get_arg("timeline")

    first = threading.Thread(target=manager.unload_all, daemon=True)
    first.start()
    assert blocking.entered.wait(5), "first unload never reached uninit"

    returned = threading.Event()

    def second():
        manager.unload_all()
        timeline.append("second-unload-returned")
        returned.set()

    threading.Thread(target=second, daemon=True).start()
    assert not returned.wait(0.3), "second unload returned while uninit was still running"

    blocking.release.set()
    first.join(timeout=5)
    assert returned.wait(5), "second unload never returned"

    assert blocking.uninit_calls == 1
    assert timeline.index("uninit:BlockingUninit") < timeline.index("second-unload-returned")


def test_unload_from_inside_uninit_does_not_deadlock(manager):
    """The waiting teardown caller must not wait on its own thread."""
    reentrant, = manager.load_stubs(ReentrantUninit)

    done = threading.Thread(target=manager.unload_all, daemon=True)
    done.start()
    done.join(timeout=5)

    assert not done.is_alive(), "unload_all deadlocked on its own uninit"
    assert reentrant.uninit_calls == 1


def test_a_raising_uninit_still_ends_the_run(manager):
    """`end_analysis` is the only thing that ends a run, and `pre_shutdown`
    fires on it, so losing it to a failed teardown leaves no stop path at
    all, and the emulator runs forever."""
    # Loaded first is torn down last, so the raiser goes first here.
    finished, raising = manager.load_stubs(Finished, RaisingUninit)

    manager.request_shutdown(finished, "done")
    _join_shutdown(manager)

    assert raising.uninit_calls == 1
    assert manager.panda.ended == 1, "a raising uninit left the emulator running"
    assert finished.uninit_calls == 1, "one failed teardown skipped the other plugins"


def test_a_stuck_teardown_gives_up_instead_of_deadlocking(manager, monkeypatch):
    """Waiting for an in-flight uninit is right, but waiting forever is not:
    the thread running it may need a main loop that another end_analysis has
    already stopped, so it can never finish."""
    monkeypatch.setattr(plugin_manager, "UNLOAD_TEARDOWN_TIMEOUT", 0.3)
    blocking, = manager.load_stubs(BlockingUninit)

    first = threading.Thread(target=manager.unload_all, daemon=True)
    first.start()
    assert blocking.entered.wait(5), "first unload never reached uninit"

    started = time.monotonic()
    manager.unload_all()  # the second teardown path, which must come back
    elapsed = time.monotonic() - started

    assert elapsed >= 0.3, "returned before the wait could have expired"
    assert elapsed < 4, f"second unload blocked for {elapsed:.2f}s"

    blocking.release.set()
    first.join(timeout=5)
    assert blocking.uninit_calls == 1


def test_request_shutdown_declines_rather_than_blocking_on_itself(manager):
    """core's SIGUSR1 handler runs on the main thread, interrupting whatever it
    was doing, which is the same thread guest callbacks request shutdown
    from. Re-entering the lock there would wedge the process."""
    finished, = manager.load_stubs(Finished)

    assert manager._shutdown_lock.acquire(blocking=False)
    try:
        # Same thread, lock already held: decline, do not block.
        assert manager.request_shutdown(finished, "SIGUSR1") is False
    finally:
        manager._shutdown_lock.release()

    # And the real request still works afterwards.
    assert manager.request_shutdown(finished, "SIGUSR1 retry") is True
    _join_shutdown(manager)
    assert manager.panda.ended == 1


# --- teardown seals delivery before anyone's uninit runs ------------------- #

def test_an_event_mid_teardown_reaches_nobody(manager):
    """The guest runs until end_analysis, so events keep arriving through the
    unload sweep. One must not reach a plugin that has already written its
    final output, nor hand new work to a plugin about to write its own."""
    publisher, subscriber, blocking = manager.load_stubs(
        Publisher, Subscriber, BlockingUninit)

    # Loaded last, so unloaded first: the sweep is held open with the
    # subscriber still loaded and still subscribed.
    sweep = threading.Thread(target=manager.unload_all, daemon=True)
    sweep.start()
    assert blocking.entered.wait(5), "the sweep never reached uninit"

    manager.publish(publisher, "on_bind", 80)

    blocking.release.set()
    sweep.join(timeout=5)
    assert not sweep.is_alive(), "the unload sweep did not finish"
    assert subscriber.received == [], "an event was delivered during teardown"


def test_publishing_after_teardown_does_not_raise(manager):
    """Detaching empties the handler lists; it must not remove the keys.
    publish() raises on a missing key, and publishers keep running until the
    emulator stops."""
    publisher, subscriber = manager.load_stubs(Publisher, Subscriber)

    manager.unload_all()

    manager.publish(publisher, "on_bind", 80)
    assert subscriber.received == []
