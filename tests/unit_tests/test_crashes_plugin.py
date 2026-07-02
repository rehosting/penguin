"""
Tests for the crashes plugin's aggregation logic (pyplugins/analysis/crashes.py):
dedupe/count of (proc, signal, pc), watched-set filtering, drop handling, and
the crashes.yaml on-disk format.
"""

import importlib.util
import logging
import os

import pytest
import yaml

PLUGIN_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../pyplugins/analysis/crashes.py")
)


def _load_crashes_module():
    spec = importlib.util.spec_from_file_location("crashes_plugin", PLUGIN_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


crashes_mod = _load_crashes_module()


class FakeEvent:
    def __init__(self, sig, comm, pid, pc, drop=False, regs=None):
        self.sig = sig
        self.comm = comm
        self.pid = pid
        self.pc = pc
        self.drop = drop
        self.regs = regs


@pytest.fixture
def plugin(tmp_path):
    """A Crashes instance with plugin-manager wiring bypassed: state set up
    directly, on_signal_deliver/write_report exercised as-is."""
    p = crashes_mod.Crashes.__new__(crashes_mod.Crashes)
    p.outdir = str(tmp_path)
    p.start_time = 0.0
    p.records = {}
    p.signames = {11: "SIGSEGV", 6: "SIGABRT"}
    p.logger = logging.getLogger("test.crashes")
    p.write_report()
    return p


def read_report(plugin):
    with open(os.path.join(plugin.outdir, crashes_mod.CRASHES_FILE)) as f:
        return yaml.safe_load(f)["crashes"]


def test_empty_report_written(plugin):
    assert read_report(plugin) == []


def test_records_watched_signal(plugin):
    plugin.on_signal_deliver(None, FakeEvent(11, "httpd", 412, 0x4013A8))
    (rec,) = read_report(plugin)
    assert rec["proc"] == "httpd"
    assert rec["pid"] == 412
    assert rec["signal"] == 11
    assert rec["signame"] == "SIGSEGV"
    assert rec["pc"] == "0x004013a8"
    assert rec["count"] == 1


def test_dedupes_identical_proc_signal_pc(plugin):
    for _ in range(3):
        plugin.on_signal_deliver(None, FakeEvent(11, "httpd", 412, 0x4013A8))
    (rec,) = read_report(plugin)
    assert rec["count"] == 3


def test_pid_and_time_are_first_occurrence(plugin):
    plugin.on_signal_deliver(None, FakeEvent(11, "httpd", 412, 0x4013A8))
    # Same (proc, signal, pc) from a respawned pid still folds into the record
    plugin.on_signal_deliver(None, FakeEvent(11, "httpd", 500, 0x4013A8))
    (rec,) = read_report(plugin)
    assert rec["count"] == 2
    assert rec["pid"] == 412


def test_distinct_pc_or_signal_are_separate_records(plugin):
    plugin.on_signal_deliver(None, FakeEvent(11, "httpd", 412, 0x4013A8))
    plugin.on_signal_deliver(None, FakeEvent(11, "httpd", 412, 0x4013AC))
    plugin.on_signal_deliver(None, FakeEvent(6, "httpd", 412, 0x4013A8))
    recs = read_report(plugin)
    assert len(recs) == 3
    assert all(r["count"] == 1 for r in recs)


def test_unwatched_signal_ignored(plugin):
    plugin.on_signal_deliver(None, FakeEvent(1, "httpd", 412, 0x4013A8))  # SIGHUP
    assert read_report(plugin) == []


def test_dropped_delivery_ignored(plugin):
    # A prior subscriber bypassed this delivery (event.drop set): not a crash.
    plugin.on_signal_deliver(None, FakeEvent(11, "httpd", 412, 0x4013A8, drop=True))
    assert read_report(plugin) == []
