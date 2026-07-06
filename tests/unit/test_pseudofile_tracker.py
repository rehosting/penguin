"""In-place harness coverage for the pseudofile tracker
(pyplugins/hyperfile/pseudofile_tracker.py), driven host-side with no
PANDA/guest.

The tracker sits behind the FFI-enum boundary (``from apis.syscalls import
ValueFilter``), so it loads with ``real_isf=``. Its host-side logic is what the
guest-boot matrix ultimately asserts on: the ``pseudofiles_failures.yaml``
impact ranking (crashing_callers >> crashing_callers_by_name >>
distinct_callers > hits), caller attribution, the crashes.yaml join, the
suggested starting models, and the default-model provenance events
(record_default_hit) that the Pseudofiles plugin forwards.

The -ENOENT/-ENOTTY syscall handlers are portal generators; they are driven
through ``dispatch_syscall`` with ``mem``/``osi`` generator doubles.
"""
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from penguin.testing import load_module, load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
TRACKER = str(REPO_ROOT / "pyplugins" / "hyperfile" / "pseudofile_tracker.py")

FAILURES = "pseudofiles_failures.yaml"


class _Mem:
    """plugins.mem double: read_str returns the path string under test."""

    def __init__(self, s=""):
        self.s = s

    def read_str(self, addr):
        yield from ()
        return self.s


class _Osi:
    """plugins.osi double: caller identity and fd-name resolution."""

    def __init__(self, name="cat", pid=77, fd_name=None):
        self.name, self.pid, self.fd_name = name, pid, fd_name

    def get_proc(self, pid=None):
        yield from ()
        return SimpleNamespace(name=self.name, pid=self.pid)

    def get_fd_name(self, fd):
        yield from ()
        return self.fd_name


def _load(tmp_path, isf, mem=None, osi=None, args=None):
    lp = load_pyplugin(
        TRACKER, outdir=tmp_path, real_isf=isf, args=dict(args or {}),
        doubles={"mem": mem or _Mem(), "osi": osi or _Osi()},
    )
    # The handlers normalize raw retvals via panda; tests pass signed values.
    lp.panda.from_unsigned_guest = lambda v: v
    return lp


def _syscall(retval=-2):
    return SimpleNamespace(retval=retval)


def _proto(name):
    return SimpleNamespace(name=name)


def _open_enoent(lp, flags=0, proto="sys_open", retval=-2):
    """Drive an arg0-style -ENOENT hook (open/stat family) through the pump."""
    lp.dispatch_syscall(proto, None, _proto(proto), _syscall(retval), 0xBEEF,
                        flags, on_return=True)


def _failures(lp):
    text = (Path(lp.plugin.outdir) / FAILURES).read_text()
    return text, yaml.safe_load(text)


@pytest.fixture
def tracker_mod(igloo_ko_isf):
    """The tracker *module* (for its pure helpers), loaded via the harness."""
    module, _manager = load_module(TRACKER, real_isf=igloo_ko_isf)
    return module


# --- load + hook registration ----------------------------------------------- #

def test_plugin_loads_behind_enum_boundary_and_registers_hooks(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    assert type(lp.plugin).__name__ == "PseudofileTracker"
    hooks = {h["name"] for h in lp.manager.syscall_hooks}
    # open/stat families at arg0 and arg1, plus the -ENOTTY ioctl hook
    assert {"open", "openat", "stat", "newfstatat", "ioctl"} <= hooks
    # init wrote an (empty) failures file so consumers can rely on it
    assert (Path(tmp_path) / FAILURES).exists()


# --- pure helpers ------------------------------------------------------------ #

def test_open_access_intents(tracker_mod):
    pt = tracker_mod
    assert pt.open_access_intents(0o0) == {"read"}
    assert pt.open_access_intents(0o1 | 0o1100) == {"write"}  # |O_CREAT|O_TRUNC
    assert pt.open_access_intents(0o2) == {"read", "write"}


def test_suggest_models(tracker_mod):
    pt = tracker_mod
    assert pt.suggest_models({"open": {"count": 1}}, set()) == {
        "read": {"model": "zero"}}
    assert pt.suggest_models({"open": {"count": 1}}, {"write"}) == {
        "write": {"model": "discard"}}
    assert pt.suggest_models({"open": {"count": 1}}, {"read", "write"}) == {
        "read": {"model": "zero"}, "write": {"model": "discard"}}
    assert pt.suggest_models({"ioctl": {799: {"count": 2}}}, set()) == {
        "ioctl": {"*": {"model": "return_const", "val": 0}}}
    assert pt.suggest_models({}, set()) == {}
    # default_* events mean a model already serves the path; nothing to paste
    assert pt.suggest_models({"default_read": {"count": 3}}, set()) == {}


def test_load_crashes_tolerates_all_forms(tracker_mod, tmp_path):
    pt = tracker_mod
    f = tmp_path / "c.yaml"
    assert pt.load_crashes(str(tmp_path / "absent.yaml")) == (set(), set())
    for content in ("", "crashes: []\n", "just a string\n", "crashes: 7\n"):
        f.write_text(content)
        assert pt.load_crashes(str(f)) == (set(), set())
    # dict form; one record lacks a pid
    f.write_text(
        "crashes:\n"
        "- {proc: cat, pid: 77, signal: 11, signame: SIGSEGV,"
        " pc: '0x0040abcd', time: 3.2, count: 2}\n"
        "- {proc: httpd, signal: 6}\n"
    )
    assert pt.load_crashes(str(f)) == ({("cat", 77)}, {"cat", "httpd"})
    # bare list form, with junk entries
    f.write_text("- {proc: cat, pid: 77}\n- {pid: 99}\n- notadict\n")
    assert pt.load_crashes(str(f)) == ({("cat", 77)}, {"cat"})


def test_count_crashing_callers_exact_vs_by_name(tracker_mod):
    pt = tracker_mod
    pairs, names = {("cat", 77)}, {"cat"}
    assert pt.count_crashing_callers({("cat", 77)}, pairs, names) == (1, 0)
    assert pt.count_crashing_callers({("cat", 999)}, pairs, names) == (0, 1)
    assert pt.count_crashing_callers({("init", 1)}, pairs, names) == (0, 0)
    # exact match is not double-counted as a name match
    assert pt.count_crashing_callers(
        {("cat", 77), ("cat", 999), ("init", 1)}, pairs, names) == (1, 1)


def test_impact_score_tier_ordering(tracker_mod):
    pt = tracker_mod

    def impact(hits=0, distinct=0, crashing=0, by_name=0):
        return {"hits": hits, "distinct_callers": distinct,
                "crashing_callers": crashing, "crashing_callers_by_name": by_name}

    assert pt.impact_score(impact(hits=5)) == 5
    assert pt.impact_score(impact(distinct=1)) > pt.impact_score(impact(hits=999))
    assert pt.impact_score(impact(by_name=1)) > pt.impact_score(impact(distinct=9))
    assert pt.impact_score(impact(crashing=1)) > pt.impact_score(impact(by_name=99))


# --- the -ENOENT open/stat generator handlers (syscall pump) ----------------- #

def test_open_enoent_records_caller_and_intent(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf, mem=_Mem("/dev/missing"),
               osi=_Osi("httpd", 42))
    _open_enoent(lp, flags=0o2)  # O_RDWR
    lp.finalize()
    _, data = _failures(lp)
    entry = data["/dev/missing"]
    assert entry["callers"] == ["httpd:42"]
    assert entry["impact"]["distinct_callers"] == 1
    assert entry["suggest"] == {"read": {"model": "zero"},
                                "write": {"model": "discard"}}


def test_stat_enoent_has_unknown_intent_suggests_read(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf, mem=_Mem("/sys/foo/missing"))
    lp.dispatch_syscall("sys_stat", None, _proto("sys_stat"), _syscall(-2),
                        0xBEEF, on_return=True)
    lp.finalize()
    _, data = _failures(lp)
    assert data["/sys/foo/missing"]["suggest"] == {"read": {"model": "zero"}}


def test_non_enoent_and_uninteresting_paths_ignored(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf, mem=_Mem("/etc/passwd"))
    _open_enoent(lp)                     # not a pseudofile path
    lp2 = _load(tmp_path, igloo_ko_isf, mem=_Mem("/dev/missing"))
    _open_enoent(lp2, retval=-13)        # -EACCES, not -ENOENT
    for plugin in (lp, lp2):
        plugin.finalize()
        _, data = _failures(plugin)
        assert data == {}


def test_relative_path_resolved_against_dfd(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf, mem=_Mem("watchdog"),
               osi=_Osi("wd", 9, fd_name="/dev"))
    lp.dispatch_syscall("sys_openat", None, _proto("sys_openat"), _syscall(-2),
                        3, 0xBEEF, 0o0, on_return=True)
    lp.finalize()
    _, data = _failures(lp)
    assert "/dev/watchdog" in data


def test_proc_pid_paths_collapse(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf, mem=_Mem("/proc/1234/missing"))
    _open_enoent(lp)
    lp.finalize()
    _, data = _failures(lp)
    assert "/proc/PID/missing" in data


def test_flush_is_eager_not_only_at_uninit(tmp_path, igloo_ko_isf):
    # Results must survive a run that never reaches uninit (SIGKILL, emulator
    # crash) -- see rehosting/penguin#175.
    lp = _load(tmp_path, igloo_ko_isf, mem=_Mem("/dev/missing"))
    _open_enoent(lp)
    _, data = _failures(lp)  # no finalize()
    assert "/dev/missing" in data


# --- the -ENOTTY ioctl generator handler ------------------------------------- #

def test_ioctl_enotty_recorded_with_suggestion(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf,
               osi=_Osi("wdog", 5, fd_name="/dev/watchdog"))
    lp.dispatch_syscall("sys_ioctl", None, _proto("sys_ioctl"), _syscall(-25),
                        4, 0x6700, 0, on_return=True)
    lp.finalize()
    _, data = _failures(lp)
    entry = data["/dev/watchdog"]
    assert entry["events"]["ioctl"][0x6700]["count"] == 1
    assert entry["callers"] == ["wdog:5"]
    assert entry["suggest"]["ioctl"] == {"*": {"model": "return_const", "val": 0}}


def test_ioctl_tty_cmds_and_proc_paths_ignored(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf, osi=_Osi(fd_name="/dev/ttyS0"))
    lp.dispatch_syscall("sys_ioctl", None, _proto("sys_ioctl"), _syscall(-25),
                        4, 0x5401, 0, on_return=True)  # TCGETS: TTY range
    lp2 = _load(tmp_path, igloo_ko_isf, osi=_Osi(fd_name="/proc/sys/foo"))
    lp2.dispatch_syscall("sys_ioctl", None, _proto("sys_ioctl"), _syscall(-25),
                         4, 0x6700, 0, on_return=True)
    for plugin in (lp, lp2):
        plugin.finalize()
        _, data = _failures(plugin)
        assert data == {}


# --- default-model provenance (record_default_hit) ---------------------------- #

def test_record_default_hit_lands_in_events(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    lp.plugin.record_default_hit("/dev/stub", "read")
    lp.plugin.record_default_hit("/dev/stub", "ioctl", details="cmd 0x31f")
    _, data = _failures(lp)  # record_default_hit flushes itself
    entry = data["/dev/stub"]
    assert entry["events"]["default_read"]["count"] == 1
    assert entry["events"]["default_ioctl"]["details"] == ["cmd 0x31f"]
    # default hits carry no caller identity and must not pollute callers
    assert "callers" not in entry
    assert entry["impact"]["hits"] == 2


def test_record_default_hit_filters_uninteresting_paths(tmp_path, igloo_ko_isf):
    lp = _load(tmp_path, igloo_ko_isf)
    lp.plugin.record_default_hit("/etc/passwd", "read")
    lp.finalize()
    _, data = _failures(lp)
    assert data == {}


# --- ranking + crashes.yaml join, end to end ---------------------------------- #

def test_ranking_by_impact_with_crash_join(tmp_path, igloo_ko_isf):
    (tmp_path / "crashes.yaml").write_text(
        "crashes:\n- {proc: watchdogd, pid: 412, signal: 11, signame: SIGSEGV,"
        " pc: '0x0040abcd', time: 3.2, count: 1}\n"
    )
    lp = _load(tmp_path, igloo_ko_isf)
    t = lp.plugin
    # many hits, one caller
    for _ in range(100):
        t.centralized_log("/proc/foo/missing", "open",
                          caller=("cat", 77), intents={"read"})
    # fewer hits, two callers, one of which crashed (exact proc+pid match)
    t.centralized_log("/dev/watchdog", "open",
                      caller=("watchdogd", 412), intents={"read", "write"})
    t.centralized_log("/dev/watchdog", "open", caller=("init", 1),
                      intents={"read", "write"})
    for _ in range(5):
        t.log_ioctl_failure("/dev/watchdog", 0x80045700,
                            caller=("watchdogd", 412))
    # name-only crash match (pid recycled)
    t.centralized_log("/dev/mtd", "open", caller=("watchdogd", 999))
    t.centralized_log("/sys/foo/missing", "open")  # no caller resolved
    lp.finalize()

    text, data = _failures(lp)  # safe_load also proves comments parse cleanly
    assert list(data) == ["/dev/watchdog", "/dev/mtd",
                          "/proc/foo/missing", "/sys/foo/missing"]
    assert data["/dev/watchdog"]["impact"] == {
        "hits": 7, "distinct_callers": 2,
        "crashing_callers": 1, "crashing_callers_by_name": 0}
    assert data["/dev/watchdog"]["callers"] == ["init:1", "watchdogd:412"]
    assert data["/dev/watchdog"]["events"]["ioctl"][0x80045700]["count"] == 5
    assert data["/dev/mtd"]["impact"]["crashing_callers_by_name"] == 1
    assert data["/dev/mtd"]["impact"]["crashing_callers"] == 0
    assert "callers" not in data["/sys/foo/missing"]
    assert "# TODO" in text
