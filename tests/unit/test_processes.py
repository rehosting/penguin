"""Host-side test of the processes plugin (pyplugins/analysis/processes.py)
driven through the `penguin.testing` harness -- no PANDA, no guest, no per-arch
boot.

Three host-side surfaces are exercised:

* **lifecycle -> event DB**: exec_event -> ProcStart, exit syscalls -> ProcExit.
  We stub the DB plugin and assert the rows the plugin emits.
* **derived artifact**: uninit() flushes + queries the DB and renders
  system_map.yaml. We feed canned ProcStart/ProcExit rows through the DB stub
  and assert the structured records + ASCII tree.
* **live query API** (get/tree/snapshot): portal generators whose only guest
  edge is plugins.OSI (get_proc / get_all_procs). Stubbed with a generator
  double so the ppid-join logic is tested without a real portal.
"""
from pathlib import Path
from types import SimpleNamespace

import yaml

from penguin.testing import load_pyplugin, drive
from pengutils.events import ProcStart, ProcExit

REPO_ROOT = Path(__file__).resolve().parents[2]
PROCESSES = REPO_ROOT / "pyplugins" / "analysis" / "processes.py"


# --------------------------------------------------------------------------- #
# Doubles
# --------------------------------------------------------------------------- #
def _proc(pid, ppid, create_time, name="", **extra):
    """An osi_proc-shaped attribute holder (for get_proc / get_all_procs)."""
    return SimpleNamespace(pid=pid, ppid=ppid, create_time=create_time,
                           name=name, uid=extra.get("uid", 0),
                           gid=extra.get("gid", 0), euid=extra.get("euid", 0),
                           egid=extra.get("egid", 0))


def _exec_event(pid, ppid, create_time, procname, argv, **kw):
    return SimpleNamespace(
        proc=_proc(pid, ppid, create_time, name=Path(procname).name, **kw),
        procname=procname, argv=argv)


def _syscall_evt(pid, create_time):
    """The syscall-event arg the driver denormalizes identity into."""
    return SimpleNamespace(pid=pid, create_time=create_time)


class FakeOSI:
    """Generator double for the OSI sibling used by the live query API."""

    def __init__(self, procs):
        self._procs = procs  # {pid -> osi_proc-shaped object}

    def get_proc(self, pid=None):
        yield from ()
        return self._procs.get(pid)

    def get_all_procs(self):
        # Bulk kernel-side walk: every proc in one shot.
        yield from ()
        return [self._procs[p] for p in sorted(self._procs)]


class FakeDB:
    """Double for the DB logger plugin: records add_event calls and serves
    canned rows back from query()."""

    def __init__(self, rows=None):
        self.events = []          # [(table_cls, data_dict)]
        self._rows = rows or {}   # {table_cls: [row_obj, ...]}
        self.flushed = 0

    def add_event(self, table_cls, data):
        self.events.append((table_cls, data))

    def flush(self):
        self.flushed += 1

    def query(self, table_cls):
        return self._rows.get(table_cls, [])

    def rows(self, table_cls):
        return [d for (c, d) in self.events if c is table_cls]


def _start_row(rid, pid, ppid, create_time, name, comm=None, **ids):
    return SimpleNamespace(id=rid, pid=pid, ppid=ppid, create_time=create_time,
                           procname=name, comm=comm or name,
                           uid=ids.get("uid", 0), gid=ids.get("gid", 0),
                           euid=ids.get("euid", 0), egid=ids.get("egid", 0))


def _exit_row(rid, pid, create_time, code, reason):
    return SimpleNamespace(id=rid, pid=pid, create_time=create_time,
                           code=code, reason=reason)


def _load(tmp_path, db=None, osi=None, **args):
    doubles = {"DB": db if db is not None else FakeDB()}
    if osi is not None:
        doubles["OSI"] = osi
    return load_pyplugin(str(PROCESSES), outdir=tmp_path, args=args,
                         doubles=doubles)


# --------------------------------------------------------------------------- #
# Lifecycle -> event DB
# --------------------------------------------------------------------------- #
def test_seed_map_written_on_init(tmp_path):
    _load(tmp_path)
    doc = yaml.safe_load((tmp_path / "system_map.yaml").read_text())
    assert doc["schema_version"] == 1
    assert doc["process_count"] == 0 and doc["processes"] == []
    assert "no processes observed" in doc["tree"]


def test_exec_event_emits_procstart(tmp_path):
    db = FakeDB()
    lp = _load(tmp_path, db=db)
    assert "exec_event" in {ev for (_p, ev, _c) in lp.subscriptions}

    lp.dispatch("exec_event", _exec_event(412, 1, 200, "/usr/sbin/httpd",
                                          ["httpd", "-f", "/etc/httpd.conf"],
                                          uid=33))
    starts = db.rows(ProcStart)
    assert len(starts) == 1
    row = starts[0]
    assert row["pid"] == 412 and row["ppid"] == 1
    assert row["create_time"] == 200 and row["procname"] == "httpd"
    assert row["uid"] == 33 and row["proc_id"] == 412


def test_exit_group_emits_procexit(tmp_path):
    db = FakeDB()
    lp = _load(tmp_path, db=db)
    lp.dispatch_syscall("exit_group", None, None, _syscall_evt(412, 200), 0)
    exits = db.rows(ProcExit)
    assert len(exits) == 1
    assert exits[0] == {"proc_id": 412, "procname": "", "pid": 412,
                        "create_time": 200, "code": 0, "reason": "exit_group"}


def test_exit_without_pid_is_skipped(tmp_path):
    # Older driver: syscall event lacks a denormalized pid -> nothing to record.
    db = FakeDB()
    lp = _load(tmp_path, db=db)
    lp.dispatch_syscall("exit", None, None, SimpleNamespace(), 3)
    assert db.rows(ProcExit) == []


def _sig_evt(sig, pid, drop=False):
    return SimpleNamespace(sig=sig, pid=pid, drop=drop)


def _exit_evt(pid, create_time, signaled, termsig=0, exit_status=0):
    """An exit_event-shaped holder (do_exit kprobe path)."""
    return SimpleNamespace(pid=pid, create_time=create_time, signaled=signaled,
                           termsig=termsig, exit_status=exit_status)


def test_do_exit_normal_exit_emits_procexit(tmp_path):
    # With the do_exit hook active, a normal exit is recorded from the kprobe
    # event (real status), and the exit/exit_group syscall hooks stand down.
    db = FakeDB()
    lp = _load(tmp_path, db=db, use_do_exit=True)
    lp.plugin.on_proc_exit(None, _exit_evt(412, 200, signaled=False,
                                           exit_status=7))
    exits = db.rows(ProcExit)
    assert len(exits) == 1
    assert exits[0] == {"proc_id": 412, "procname": "", "pid": 412,
                        "create_time": 200, "code": 7, "reason": "exit"}


def test_do_exit_signal_death_emits_procexit(tmp_path):
    # A fatal signal death is captured by the same hook with the real code --
    # no signal heuristic needed. (signals is stubbed, so the name falls back to
    # the number; on silicon it resolves to e.g. SIGSEGV.)
    db = FakeDB()
    lp = _load(tmp_path, db=db, use_do_exit=True)
    lp.plugin.on_proc_exit(None, _exit_evt(412, 200, signaled=True, termsig=11))
    exits = db.rows(ProcExit)
    assert len(exits) == 1
    assert exits[0] == {"proc_id": 412, "procname": "", "pid": 412,
                        "create_time": 200, "code": 128 + 11,
                        "reason": "signal:11"}


def test_do_exit_supersedes_syscall_hooks(tmp_path):
    # When use_do_exit is set, the exit/exit_group syscall hooks are not even
    # registered (do_exit owns exits) -- so dispatch finds no hook. This proves
    # we don't pay a redundant per-exit hook firing, not merely that it no-ops.
    import pytest
    lp = _load(tmp_path, use_do_exit=True)
    with pytest.raises(KeyError):
        lp.dispatch_syscall("exit_group", None, None, _syscall_evt(412, 200), 0)
    with pytest.raises(KeyError):
        lp.dispatch_syscall("exit", None, None, _syscall_evt(412, 200), 0)


def test_syscall_exit_hooks_registered_by_default(tmp_path):
    # With the default (do_exit off) the syscall exit hooks ARE registered.
    db = FakeDB()
    lp = _load(tmp_path, db=db)  # use_do_exit defaults False
    lp.dispatch_syscall("exit_group", None, None, _syscall_evt(412, 200), 0)
    assert len(db.rows(ProcExit)) == 1


def test_fatal_signal_emits_procexit(tmp_path):
    # A process killed by a fatal signal never calls exit/exit_group; the signal
    # monitor path must still close it out. (signals is stubbed in the harness,
    # so populate the watched set directly.)
    db = FakeDB()
    lp = _load(tmp_path, db=db)
    lp.plugin._fatal_signums = {11: "SIGSEGV"}
    # create_time is learned at exec, so the ProcExit pairs by (pid, create_time)
    lp.dispatch("exec_event", _exec_event(412, 1, 200, "/hard/faulter",
                                          ["faulter"]))
    lp.plugin.on_signal_deliver(None, _sig_evt(11, 412))
    exits = db.rows(ProcExit)
    assert len(exits) == 1
    assert exits[0] == {"proc_id": 412, "procname": "", "pid": 412,
                        "create_time": 200, "code": 128 + 11,
                        "reason": "signal:SIGSEGV"}


def test_fatal_signal_deduped_and_drop_skipped(tmp_path):
    db = FakeDB()
    lp = _load(tmp_path, db=db)
    lp.plugin._fatal_signums = {11: "SIGSEGV"}
    # a dropped delivery (another plugin bypassed it) is not a death
    lp.plugin.on_signal_deliver(None, _sig_evt(11, 500, drop=True))
    assert db.rows(ProcExit) == []
    # a non-watched signal is ignored
    lp.plugin.on_signal_deliver(None, _sig_evt(2, 500))
    assert db.rows(ProcExit) == []
    # first fatal delivery records; a second for the same pid is deduped
    lp.plugin.on_signal_deliver(None, _sig_evt(11, 500))
    lp.plugin.on_signal_deliver(None, _sig_evt(11, 500))
    assert len(db.rows(ProcExit)) == 1


# --------------------------------------------------------------------------- #
# Derived artifact: uninit() materializes system_map.yaml from the DB
# --------------------------------------------------------------------------- #
def test_uninit_materializes_map_from_db(tmp_path):
    starts = [
        _start_row(1, 1, 0, 100, "init"),
        _start_row(2, 400, 1, 200, "httpd"),
        _start_row(3, 517, 400, 300, "status.cgi"),
        # re-exec of pid 400 identity (same create_time) -> exec_count 2
        _start_row(4, 400, 1, 200, "httpd-worker"),
    ]
    exits = [_exit_row(5, 517, 300, 0, "exit_group")]
    db = FakeDB(rows={ProcStart: starts, ProcExit: exits})
    lp = _load(tmp_path, db=db)
    lp.finalize()  # uninit(): flush + query + render

    assert db.flushed >= 1  # flushed before querying
    doc = yaml.safe_load((tmp_path / "system_map.yaml").read_text())
    by_pid = {p["pid"]: p for p in doc["processes"]}
    assert doc["process_count"] == 3
    assert by_pid[400]["name"] == "httpd-worker"   # latest exec name wins
    assert by_pid[400]["exec_count"] == 2
    assert by_pid[517]["exit"] == {"code": 0, "reason": "exit_group"}

    tree = doc["tree"]
    lines = {ln.strip(): ln for ln in tree.splitlines()}
    assert "init (1)" in lines
    indent = {lbl: len(ln) - len(ln.lstrip()) for lbl, ln in lines.items()}
    assert indent["init (1)"] == 0
    assert indent["`- httpd-worker (400) [execs: 2]"] < \
        indent["`- status.cgi (517) [exit: 0]"]


# --------------------------------------------------------------------------- #
# Live query API: get / tree / snapshot (ppid join over the bulk walk)
# --------------------------------------------------------------------------- #
def test_live_get_returns_flat_record(tmp_path):
    osi = FakeOSI({412: _proc(412, 1, 200, name="httpd", uid=33)})
    lp = _load(tmp_path, osi=osi)
    rec = drive(lp.plugin.get(412))
    assert rec == {"pid": 412, "ppid": 1, "name": "httpd", "create_time": 200,
                   "start_time": 200, "uid": 33, "gid": 0, "euid": 0, "egid": 0}
    assert drive(lp.plugin.get(9999)) is None


def test_live_tree_joins_on_ppid(tmp_path):
    osi = FakeOSI({
        1: _proc(1, 0, 10, name="init"),
        412: _proc(412, 1, 20, name="httpd"),
        517: _proc(517, 412, 30, name="cgi"),
        900: _proc(900, 1, 40, name="telnetd"),
    })
    lp = _load(tmp_path, osi=osi)
    tree = drive(lp.plugin.tree())
    assert [r["pid"] for r in tree["roots"]] == [1]
    init = tree["roots"][0]
    assert [c["pid"] for c in init["children"]] == [412, 900]
    httpd = next(c for c in init["children"] if c["pid"] == 412)
    assert [c["pid"] for c in httpd["children"]] == [517]


def test_live_tree_orphan_becomes_root(tmp_path):
    osi = FakeOSI({
        412: _proc(412, 1, 20, name="httpd"),   # ppid 1 not present
        517: _proc(517, 412, 30, name="cgi"),
    })
    lp = _load(tmp_path, osi=osi)
    tree = drive(lp.plugin.tree())
    assert [r["pid"] for r in tree["roots"]] == [412]
    assert [c["pid"] for c in tree["roots"][0]["children"]] == [517]


def test_live_snapshot_shape(tmp_path):
    osi = FakeOSI({1: _proc(1, 0, 10, name="init"), 2: _proc(2, 1, 20, name="sh")})
    lp = _load(tmp_path, osi=osi)
    snap = drive(lp.plugin.snapshot())
    assert [p["pid"] for p in snap["processes"]] == [1, 2]
    assert [r["pid"] for r in snap["tree"]["roots"]] == [1]


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #
def _helpers(tmp_path):
    lp = _load(tmp_path)
    g = type(lp.plugin).tree.__globals__
    return g["_genealogy_from_rows"], g["_build_tree"]


def test_genealogy_resolves_parent_and_exit(tmp_path):
    _genealogy_from_rows, _ = _helpers(tmp_path)
    starts = [
        _start_row(1, 1, 0, 100, "init"),
        _start_row(2, 50, 1, 200, "sh"),
        _start_row(3, 50, 1, 200, "busybox"),   # re-exec, same identity
    ]
    exits = [_exit_row(4, 50, 0, 7, "exit")]     # create_time 0 -> pid fallback
    procs = _genealogy_from_rows(starts, exits)
    assert procs[(50, 200)]["exec_count"] == 2
    assert procs[(50, 200)]["name"] == "busybox"
    assert procs[(50, 200)]["parent_create_time"] == 100  # under init
    assert procs[(50, 200)]["exit"] == {"code": 7, "reason": "exit"}


def test_build_tree_breaks_cycles(tmp_path):
    _, _build_tree = _helpers(tmp_path)
    records = {
        5: {"pid": 5, "ppid": 6, "name": "a"},
        6: {"pid": 6, "ppid": 5, "name": "b"},
    }
    tree = _build_tree(records)
    assert {r["pid"] for r in tree["roots"]} == {5, 6}
