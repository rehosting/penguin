"""In-place harness coverage for the RWLog logger plugin
(pyplugins/loggers/rw_logger.py), driven host-side with no PANDA/guest.

RWLog's ``read``/``write`` are *portal generators*: they ``yield from``
sibling API calls (``plugins.mem.read_bytes``, ``plugins.OSI.get_fd_name/get_args``)
and reinterpret the fd via ``self.panda.ffi.cast``. This is the first test to
exercise the harness's syscall pump: ``dispatch_syscall`` finds the
``on_sys_write_return`` hook and ``drive()`` runs the generator to completion,
with the sibling calls satisfied by small generator doubles.
"""
from pathlib import Path

from pengutils.events import Read, Write
from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
RWLOG = REPO_ROOT / "pyplugins" / "loggers" / "rw_logger.py"


class _FakeDB:
    def __init__(self):
        self.events = []

    def add_event(self, cls, data):
        self.events.append((cls, data))


class _Mem:
    def read_bytes(self, addr, size=None):
        yield from ()          # portal generator: no guest round-trips in a double
        return b"payload"[:size] if size else b"payload"


class _OSI:
    def get_fd_name(self, fd):
        yield from ()
        return "/tmp/f"

    def get_args(self, pid=None):
        yield from ()
        return ["/bin/cat", "x"]


class _Sys:
    def __init__(self, retval):
        self.retval = retval
        self.skip_syscall = False


def _load(tmp_path):
    db, osi = _FakeDB(), _OSI()
    lp = load_pyplugin(str(RWLOG), outdir=tmp_path,
                       doubles={"DB": db, "mem": _Mem(), "OSI": osi, "osi": osi})
    return lp, db


def test_write_return_records_write_event(tmp_path):
    lp, db = _load(tmp_path)
    lp.dispatch_syscall("write", None, None, _Sys(retval=7), 3, 0x1000, 7,
                        on_return=True)
    cls, data = db.events[0]
    assert cls is Write
    assert data["fd"] == 3 and data["fname"] == "/tmp/f"
    assert data["buffer"] == b"payload"
    assert data["procname"] == "/bin/cat"


def test_read_return_records_read_event(tmp_path):
    lp, db = _load(tmp_path)
    lp.dispatch_syscall("read", None, None, _Sys(retval=7), 4, 0x2000, 7,
                        on_return=True)
    cls, data = db.events[0]
    assert cls is Read and data["fd"] == 4


def test_zero_length_transfer_is_skipped(tmp_path):
    lp, db = _load(tmp_path)
    # retval 0 -> rv<=0 -> handler returns before touching the DB.
    lp.dispatch_syscall("write", None, None, _Sys(retval=0), 3, 0x1000, 0,
                        on_return=True)
    assert db.events == []


def test_negative_retval_falls_back_to_count(tmp_path):
    lp, db = _load(tmp_path)
    # retval<0 -> rv=count(5); still a positive transfer, so it logs.
    lp.dispatch_syscall("write", None, None, _Sys(retval=-1), 3, 0x1000, 5,
                        on_return=True)
    assert db.events and db.events[0][0] is Write
