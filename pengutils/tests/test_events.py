"""Host-side smoke tests for the pengutils event ORM.

Pure library code — no guest, no emulator. Exercises the SQLAlchemy models
against an in-memory SQLite DB and the ``__str__`` renderers.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from pengutils.events import Base, Event, Read, Write, Syscall, Exec


def _session():
    engine = create_engine("sqlite://")  # in-memory
    Base.metadata.create_all(engine)
    return Session(engine)


def test_polymorphic_roundtrip():
    """Inserted subclasses come back as their concrete types via the base query."""
    sess = _session()
    sess.add_all([
        Read(procname="p", proc_id=1, fd=3, fname="/f", buffer=b"hi"),
        Write(procname="p", proc_id=1, fd=4, fname="/g", buffer=b"bye"),
        Syscall(procname="p", proc_id=1, name="open", retno=0),
        Exec(procname="p", proc_id=1, calltree="", argc="1",
             argv="/bin/sh", envp="", euid=0, egid=0),
    ])
    sess.commit()

    events = sess.query(Event).order_by(Event.id).all()
    assert [type(e) for e in events] == [Read, Write, Syscall, Exec]
    assert [e.type for e in events] == ["read", "write", "syscall", "exec"]
    # Subclass-specific columns survive the round-trip.
    assert events[0].fname == "/f" and events[0].buffer == b"hi"
    assert events[1].fd == 4


def test_query_by_subclass_and_filter():
    sess = _session()
    sess.add_all([
        Read(procname="a", proc_id=1, fd=3, fname="/x", buffer=None),
        Read(procname="b", proc_id=2, fd=3, fname="/y", buffer=None),
    ])
    sess.commit()
    only_a = sess.query(Read).filter(Read.procname == "a").all()
    assert len(only_a) == 1 and only_a[0].fname == "/x"


def test_read_write_str():
    assert str(Read(fd=3, fname="/f", buffer=None)) == 'read(3, /f, "")'
    assert str(Write(fd=4, fname="/g", buffer=None)) == 'write(4, /g, "")'


def test_syscall_str_formats_hex_args_and_return():
    sc = Syscall(
        name="open", retno=0, retno_repr="OK",
        arg0=0x10, arg0_repr="path", arg1=0x1, arg1_repr="flags",
    )
    # Only set args render; ints are shown in hex, with their repr label.
    assert str(sc) == "open(path(0x10), flags(0x1)) = 0(OK)"
