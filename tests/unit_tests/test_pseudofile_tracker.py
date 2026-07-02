"""
Unit tests for the pure helpers in pyplugins/hyperfile/pseudofile_tracker.py:
impact ranking, model suggestion, crashes.yaml parsing/joining, and the
rendered output format.

The plugin module expects the in-container plugin runtime (penguin.plugins,
apis.syscalls) at import time, so it is imported here with those stubbed out;
the helpers under test are pure Python.
"""

import importlib.util
import logging
import sys
import types
from pathlib import Path

import pytest
import yaml as real_yaml

PLUGIN_PATH = (
    Path(__file__).resolve().parents[2]
    / "pyplugins" / "hyperfile" / "pseudofile_tracker.py"
)


class _Anything:
    """Attribute/call sink for plugin-runtime objects touched at import time."""

    def __getattr__(self, name):
        return _Anything()

    def __call__(self, *args, **kwargs):
        return _Anything()


def _import_tracker():
    stub_names = ["penguin", "apis", "apis.syscalls"]
    try:
        import pydantic  # noqa: F401
    except ImportError:
        stub_names.append("pydantic")
    saved = {name: sys.modules.get(name) for name in stub_names}

    penguin_stub = types.ModuleType("penguin")
    penguin_stub.Plugin = type("Plugin", (), {})
    penguin_stub.PluginArgs = type("PluginArgs", (), {})
    penguin_stub.yaml = real_yaml
    penguin_stub.plugins = _Anything()

    apis_stub = types.ModuleType("apis")
    syscalls_stub = types.ModuleType("apis.syscalls")
    syscalls_stub.ValueFilter = _Anything()

    sys.modules["penguin"] = penguin_stub
    sys.modules["apis"] = apis_stub
    sys.modules["apis.syscalls"] = syscalls_stub
    if "pydantic" in stub_names:
        pydantic_stub = types.ModuleType("pydantic")
        pydantic_stub.Field = lambda *args, **kwargs: None
        sys.modules["pydantic"] = pydantic_stub
    try:
        spec = importlib.util.spec_from_file_location(
            "pseudofile_tracker_under_test", PLUGIN_PATH
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        for name, mod in saved.items():
            if mod is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = mod
    return module


pt = _import_tracker()


# ---------------------------------------------------------------------------
# open_access_intents
# ---------------------------------------------------------------------------

def test_open_access_intents_rdonly():
    assert pt.open_access_intents(0o0) == {"read"}


def test_open_access_intents_wronly_with_extra_flags():
    O_CREAT_O_TRUNC = 0o1000 | 0o100
    assert pt.open_access_intents(0o1 | O_CREAT_O_TRUNC) == {"write"}


def test_open_access_intents_rdwr():
    assert pt.open_access_intents(0o2) == {"read", "write"}


# ---------------------------------------------------------------------------
# suggest_models
# ---------------------------------------------------------------------------

def test_suggest_read_for_open_with_unknown_intent():
    assert pt.suggest_models({"open": {"count": 1}}, set()) == {
        "read": {"model": "zero"}
    }


def test_suggest_write_discard_for_write_only_intent():
    assert pt.suggest_models({"open": {"count": 1}}, {"write"}) == {
        "write": {"model": "discard"}
    }


def test_suggest_read_and_write_for_rdwr():
    suggest = pt.suggest_models({"open": {"count": 1}}, {"read", "write"})
    assert suggest == {
        "read": {"model": "zero"},
        "write": {"model": "discard"},
    }


def test_suggest_ioctl_catchall():
    suggest = pt.suggest_models({"ioctl": {799: {"count": 2}}}, set())
    assert suggest == {"ioctl": {"*": {"model": "return_const", "val": 0}}}


def test_suggest_combined_open_and_ioctl():
    suggest = pt.suggest_models(
        {"open": {"count": 1}, "ioctl": {799: {"count": 2}}}, {"read", "write"}
    )
    assert set(suggest) == {"read", "write", "ioctl"}


def test_no_suggestion_without_failure_events():
    assert pt.suggest_models({}, set()) == {}
    # default_* events mean a model already serves the path; nothing to paste.
    assert pt.suggest_models({"default_read": {"count": 3}}, set()) == {}


# ---------------------------------------------------------------------------
# load_crashes
# ---------------------------------------------------------------------------

def test_load_crashes_missing_file(tmp_path):
    assert pt.load_crashes(str(tmp_path / "crashes.yaml")) == (set(), set())


def test_load_crashes_empty_and_malformed(tmp_path):
    f = tmp_path / "crashes.yaml"
    for content in ("", "crashes: []\n", "just a string\n", "crashes: 7\n"):
        f.write_text(content)
        assert pt.load_crashes(str(f)) == (set(), set())


def test_load_crashes_dict_form(tmp_path):
    f = tmp_path / "crashes.yaml"
    f.write_text(
        "crashes:\n"
        "- {proc: cat, pid: 77, signal: 11, signame: SIGSEGV,"
        " pc: '0x0040abcd', time: 3.2, count: 2}\n"
        "- {proc: httpd, signal: 6, signame: SIGABRT,"
        " pc: '0x00400000', time: 9.9, count: 1}\n"  # record without pid
    )
    pairs, names = pt.load_crashes(str(f))
    assert pairs == {("cat", 77)}
    assert names == {"cat", "httpd"}


def test_load_crashes_bare_list_form(tmp_path):
    f = tmp_path / "crashes.yaml"
    f.write_text("- {proc: cat, pid: 77, signal: 11}\n- {pid: 99}\n- notadict\n")
    pairs, names = pt.load_crashes(str(f))
    assert pairs == {("cat", 77)}
    assert names == {"cat"}


# ---------------------------------------------------------------------------
# count_crashing_callers
# ---------------------------------------------------------------------------

def test_count_crashing_exact_match():
    assert pt.count_crashing_callers({("cat", 77)}, {("cat", 77)}, {"cat"}) == (1, 0)


def test_count_crashing_name_only_fallback():
    # pid recycled: name matches a crash, pid does not
    assert pt.count_crashing_callers({("cat", 999)}, {("cat", 77)}, {"cat"}) == (0, 1)


def test_count_crashing_no_match():
    assert pt.count_crashing_callers({("init", 1)}, {("cat", 77)}, {"cat"}) == (0, 0)


def test_count_crashing_mixed_not_double_counted():
    callers = {("cat", 77), ("cat", 999), ("init", 1)}
    assert pt.count_crashing_callers(callers, {("cat", 77)}, {"cat"}) == (1, 1)


# ---------------------------------------------------------------------------
# impact_score
# ---------------------------------------------------------------------------

def _impact(hits=0, distinct=0, crashing=0, by_name=0):
    return {
        "hits": hits,
        "distinct_callers": distinct,
        "crashing_callers": crashing,
        "crashing_callers_by_name": by_name,
    }


def test_impact_score_arithmetic():
    assert pt.impact_score(_impact(hits=5)) == 5
    assert pt.impact_score(_impact(hits=2, distinct=3, crashing=1, by_name=1)) == (
        pt.SCORE_CRASHING_CALLER + pt.SCORE_CRASHING_BY_NAME
        + 3 * pt.SCORE_DISTINCT_CALLER + 2
    )


def test_impact_score_tier_ordering():
    # one distinct caller beats any realistic hit count
    assert pt.impact_score(_impact(distinct=1)) > pt.impact_score(_impact(hits=999))
    # one name-only crash beats several distinct callers
    assert pt.impact_score(_impact(by_name=1)) > pt.impact_score(_impact(distinct=9))
    # one exact crash beats dozens of name-only crashes
    assert pt.impact_score(_impact(crashing=1)) > pt.impact_score(_impact(by_name=99))


# ---------------------------------------------------------------------------
# end-to-end rendering through dump_results (no plugin runtime needed)
# ---------------------------------------------------------------------------

@pytest.fixture
def tracker(tmp_path):
    t = pt.PseudofileTracker.__new__(pt.PseudofileTracker)
    t.outdir = str(tmp_path)
    t.log_missing = True
    t.logger = logging.getLogger("test_pseudofile_tracker")
    t.file_failures = {}
    return t


def _dumped(tracker):
    tracker.dump_results()
    text = (Path(tracker.outdir) / pt.outfile_missing).read_text()
    return text, real_yaml.safe_load(text)


def test_dump_ranks_by_impact_and_emits_valid_yaml(tracker, tmp_path):
    (tmp_path / pt.crashes_file).write_text(
        "crashes:\n- {proc: watchdogd, pid: 412, signal: 11, signame: SIGSEGV,"
        " pc: '0x0040abcd', time: 3.2, count: 1}\n"
    )
    for _ in range(100):
        tracker.centralized_log("/proc/foo/missing", "open",
                                caller=("cat", 77), intents={"read"})
    tracker.centralized_log("/dev/watchdog", "open",
                            caller=("watchdogd", 412), intents={"read", "write"})
    tracker.centralized_log("/dev/watchdog", "open",
                            caller=("init", 1), intents={"read", "write"})
    for _ in range(5):
        tracker.log_ioctl_failure("/dev/watchdog", 0x80045700,
                                  caller=("watchdogd", 412))
    tracker.centralized_log("/sys/foo/missing", "open")

    text, data = _dumped(tracker)  # safe_load also proves comments don't break parsing
    assert list(data) == ["/dev/watchdog", "/proc/foo/missing", "/sys/foo/missing"]

    watchdog = data["/dev/watchdog"]
    assert watchdog["impact"] == {
        "hits": 7,
        "distinct_callers": 2,
        "crashing_callers": 1,
        "crashing_callers_by_name": 0,
    }
    assert watchdog["callers"] == ["init:1", "watchdogd:412"]
    assert watchdog["events"]["ioctl"][0x80045700]["count"] == 5
    assert watchdog["suggest"] == {
        "read": {"model": "zero"},
        "write": {"model": "discard"},
        "ioctl": {"*": {"model": "return_const", "val": 0}},
    }
    assert "# TODO" in text

    anonymous = data["/sys/foo/missing"]
    assert "callers" not in anonymous
    assert anonymous["impact"]["distinct_callers"] == 0


def test_record_default_hit_lands_in_events(tracker):
    tracker.record_default_hit("/dev/stub", "read")
    tracker.record_default_hit("/dev/stub", "ioctl", details="cmd 0x31f")
    _, data = _dumped(tracker)
    entry = data["/dev/stub"]
    assert entry["events"]["default_read"]["count"] == 1
    assert entry["events"]["default_ioctl"]["details"] == ["cmd 0x31f"]
    # default hits carry no caller identity and must not pollute callers
    assert "callers" not in entry
    assert entry["impact"]["hits"] == 2


def test_record_default_hit_filters_uninteresting_paths(tracker):
    tracker.record_default_hit("/etc/passwd", "read")
    _, data = _dumped(tracker)
    assert data == {}


def test_normalize_path_collapses_pids(tracker):
    assert tracker._normalize_path("/proc/1234/status") == "/proc/PID/status"
    assert tracker._normalize_path("/proc/tc3162/adsl_fwver") == "/proc/tc3162/adsl_fwver"
    assert tracker._normalize_path("/etc/passwd") is None
    assert tracker._normalize_path("/dev/pipe:[123]") is None
