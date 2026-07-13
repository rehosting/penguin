"""Host-side test of the crashes plugin (pyplugins/analysis/crashes.py) driven
through the `penguin.testing` harness — no PANDA, no guest, no per-arch boot.

The crashes plugin is signal-based: igloo_driver kretprobes `dequeue_signal`,
SignalMonitor publishes a "signal_deliver" event, and this plugin aggregates
fatal deliveries into crashes.yaml (dedup on (proc, signal, pc) with a count).
That aggregation is pure host logic, so we drive the subscribed handler with
synthetic events and assert on the file. The guest round-trip (kretprobe ->
hypercall -> SignalMonitor) stays the tests/integration/ fixture (crashes.yaml).
"""
from pathlib import Path

import yaml

from penguin.testing import load_pyplugin, snapshot_roundtrip

REPO_ROOT = Path(__file__).resolve().parents[2]
CRASHES = REPO_ROOT / "pyplugins" / "analysis" / "crashes.py"


class FakeSignals:
    """Double for the `signals` sibling: crashes.__init__ resolves each watched
    signal name to its guest number via plugins.signals.signal_name_to_num."""

    TABLE = {"SIGSEGV": 11, "SIGABRT": 6, "SIGBUS": 7, "SIGILL": 4,
             "SIGFPE": 8, "SIGSYS": 31, "SIGHUP": 1}

    def signal_name_to_num(self, name):
        return self.TABLE.get(name)


class FakeEvent:
    """The `struct signal_event` shape the SignalMonitor publishes."""

    def __init__(self, sig, comm, pid, pc, drop=False, regs=None):
        self.sig = sig
        self.comm = comm
        self.pid = pid
        self.pc = pc
        self.drop = drop
        self.regs = regs


def _load(tmp_path, signals=("SIGSEGV", "SIGABRT")):
    Path(tmp_path).mkdir(parents=True, exist_ok=True)  # crashes writes at init
    return load_pyplugin(
        str(CRASHES),
        outdir=str(tmp_path),
        args={"signals": list(signals)},
        doubles={"signals": FakeSignals()},
    )


def _records(tmp_path):
    with open(tmp_path / "crashes.yaml") as f:
        return yaml.safe_load(f)["crashes"]


def test_subscription_and_hooks_wired(tmp_path):
    lp = _load(tmp_path)
    # Subscribed to the delivery event, and resolved names -> guest numbers.
    assert "signal_deliver" in {ev for (_p, ev, _c) in lp.subscriptions}
    assert lp.plugin.signames == {11: "SIGSEGV", 6: "SIGABRT"}
    # Registered one guest hook per watched signal (recorded on the stub).
    hooked = [c for c in lp.calls if "register_hook" in c[0]]
    assert len(hooked) == 2


def test_empty_report_written_at_init(tmp_path):
    _load(tmp_path)
    assert _records(tmp_path) == []


def test_records_watched_delivery(tmp_path):
    lp = _load(tmp_path)
    lp.dispatch("signal_deliver", None, FakeEvent(11, "httpd", 412, 0x4013A8))
    (rec,) = _records(tmp_path)
    assert rec["proc"] == "httpd"
    assert rec["pid"] == 412
    assert rec["signal"] == 11
    assert rec["signame"] == "SIGSEGV"
    assert rec["pc"] == "0x004013a8"
    assert rec["count"] == 1


def test_dedupes_identical_proc_signal_pc(tmp_path):
    lp = _load(tmp_path)
    for _ in range(3):
        lp.dispatch("signal_deliver", None, FakeEvent(11, "httpd", 412, 0x4013A8))
    (rec,) = _records(tmp_path)
    assert rec["count"] == 3


def test_pid_and_time_are_first_occurrence(tmp_path):
    lp = _load(tmp_path)
    lp.dispatch("signal_deliver", None, FakeEvent(11, "httpd", 412, 0x4013A8))
    # Same (proc, signal, pc) from a respawned pid folds into the record.
    lp.dispatch("signal_deliver", None, FakeEvent(11, "httpd", 500, 0x4013A8))
    (rec,) = _records(tmp_path)
    assert rec["count"] == 2
    assert rec["pid"] == 412


def test_distinct_pc_or_signal_are_separate_records(tmp_path):
    lp = _load(tmp_path)
    lp.dispatch("signal_deliver", None, FakeEvent(11, "httpd", 412, 0x4013A8))
    lp.dispatch("signal_deliver", None, FakeEvent(11, "httpd", 412, 0x4013AC))
    lp.dispatch("signal_deliver", None, FakeEvent(6, "httpd", 412, 0x4013A8))
    recs = _records(tmp_path)
    assert len(recs) == 3
    assert all(r["count"] == 1 for r in recs)


def test_unwatched_signal_ignored(tmp_path):
    lp = _load(tmp_path)
    # SIGHUP is a real signal but not in the watched set for this run.
    lp.dispatch("signal_deliver", None, FakeEvent(1, "httpd", 412, 0x4013A8))
    assert _records(tmp_path) == []


def test_dropped_delivery_ignored(tmp_path):
    lp = _load(tmp_path)
    # A prior subscriber bypassed this delivery (event.drop) -> not a crash.
    lp.dispatch("signal_deliver", None, FakeEvent(11, "httpd", 412, 0x4013A8, drop=True))
    assert _records(tmp_path) == []


def test_finalize_rewrites_report(tmp_path):
    lp = _load(tmp_path)
    lp.dispatch("signal_deliver", None, FakeEvent(11, "httpd", 412, 0x4013A8))
    lp.finalize()  # uninit() rewrites crashes.yaml
    (rec,) = _records(tmp_path)
    assert rec["signame"] == "SIGSEGV"


# --------------------------------------------------------------------------- #
# Snapshot / restore
# --------------------------------------------------------------------------- #
def test_save_state_none_when_idle(tmp_path):
    lp = _load(tmp_path)
    assert lp.plugin.save_state() is None  # no crashes -> nothing to carry


def test_snapshot_restores_crash_records(tmp_path):
    # Producer: two SIGSEGVs at one site (count 2) and one SIGABRT elsewhere.
    src = _load(tmp_path / "a")
    src.dispatch("signal_deliver", None, FakeEvent(11, "httpd", 412, 0x4013A8))
    src.dispatch("signal_deliver", None, FakeEvent(11, "httpd", 412, 0x4013A8))
    src.dispatch("signal_deliver", None, FakeEvent(6, "ftpd", 77, 0x8000))

    # Consumer: restored run starts with an empty (wiped) report, then rehydrates.
    dst = _load(tmp_path / "b")
    assert _records(tmp_path / "b") == []
    snapshot_roundtrip(src, dst)

    recs = _records(tmp_path / "b")
    assert {(r["proc"], r["signal"], r["pc"], r["count"]) for r in recs} == {
        ("httpd", 11, "0x004013a8", 2), ("ftpd", 6, "0x00008000", 1)}
    # The dedup key was rebuilt: a further identical delivery folds in (count 3),
    # rather than creating a duplicate record.
    dst.dispatch("signal_deliver", None, FakeEvent(11, "httpd", 999, 0x4013A8))
    (httpd_rec,) = [r for r in _records(tmp_path / "b") if r["proc"] == "httpd"]
    assert httpd_rec["count"] == 3
