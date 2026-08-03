"""In-place harness coverage for the DB logger plugin
(pyplugins/loggers/db.py), driven host-side with no PANDA/guest.

The DB plugin is pure host infrastructure: it buffers events and flushes them
to a SQLite file via SQLAlchemy on a background thread. We load it through the
harness, add real event rows, and let ``finalize()`` (uninit) flush + join the
worker, then read the resulting ``plugins.db`` back with SQLAlchemy and assert
the rows survived the polymorphic split-insert path.
"""
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from pengutils.events import Base, Event, Exec, Read
from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
DB = REPO_ROOT / "pyplugins" / "loggers" / "db.py"


def _read_back(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'plugins.db'}")
    Base.metadata.create_all(engine)  # no-op: plugin already created it
    return Session(engine)


def test_db_flushes_events_on_uninit(tmp_path):
    lp = load_pyplugin(str(DB), outdir=tmp_path)
    lp.plugin.add_event(Exec, {"calltree": "", "argc": "1", "argv": "/bin/sh",
                               "envp": "", "euid": 0, "egid": 0, "procname": "sh"})
    lp.plugin.add_event(Read, {"procname": "sh", "fd": 3, "fname": "/f",
                               "buffer": b"hi"})
    lp.finalize()  # uninit(): flush + join the worker + dispose

    sess = _read_back(tmp_path)
    events = sess.query(Event).order_by(Event.id).all()
    assert [type(e) for e in events] == [Exec, Read]
    assert events[0].argv == "/bin/sh" and events[0].procname == "sh"
    assert events[1].fname == "/f" and events[1].buffer == b"hi"


def test_db_sanitizes_unsigned_addresses(tmp_path):
    """Addresses > INT64_MAX are wrapped to signed so SQLite can store them."""
    lp = load_pyplugin(str(DB), outdir=tmp_path)
    lp.plugin.add_event(Read, {"procname": "p", "fd": 0xFFFFFFFFFFFFFFFF,
                               "fname": "/x", "buffer": None})
    lp.finalize()

    sess = _read_back(tmp_path)
    row = sess.query(Read).one()
    assert row.fd == -1  # 0xFFFF... & MASK64 - 2**64


def test_db_defaults_proc_id_when_missing(tmp_path):
    lp = load_pyplugin(str(DB), outdir=tmp_path)
    lp.plugin.add_event(Exec, {"calltree": "", "argc": "0", "argv": "",
                               "envp": "", "euid": 0, "egid": 0})
    lp.finalize()

    sess = _read_back(tmp_path)
    assert sess.query(Event).one().proc_id == 0


def test_db_flush_then_query_is_visible(tmp_path):
    """flush() drains buffered events synchronously so query() can read them
    back mid-run -- the path the processes plugin uses at teardown."""
    from pengutils.events import ProcStart, ProcExit
    lp = load_pyplugin(str(DB), outdir=tmp_path)

    lp.plugin.add_event(ProcStart, {"procname": "httpd", "proc_id": 400,
                                    "pid": 400, "ppid": 1, "create_time": 200,
                                    "comm": "httpd", "uid": 0, "gid": 0,
                                    "euid": 0, "egid": 0})
    lp.plugin.add_event(ProcExit, {"procname": "", "proc_id": 400, "pid": 400,
                                   "create_time": 200, "code": 0,
                                   "reason": "exit_group"})

    lp.plugin.flush()  # synchronous drain
    starts = lp.plugin.query(ProcStart)
    exits = lp.plugin.query(ProcExit)
    assert [s.pid for s in starts] == [400]
    assert starts[0].ppid == 1 and starts[0].comm == "httpd"
    assert [(e.pid, e.code, e.reason) for e in exits] == [(400, 0, "exit_group")]
    lp.finalize()


def test_db_query_empty_table_returns_list(tmp_path):
    """query() of a table that never received a row yields [] (schema is
    ensured), not an error."""
    from pengutils.events import ProcExit
    lp = load_pyplugin(str(DB), outdir=tmp_path)
    assert lp.plugin.query(ProcExit) == []
    lp.finalize()
