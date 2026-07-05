"""In-place harness coverage for the ExecLog logger plugin
(pyplugins/loggers/exec_logger.py), driven host-side with no PANDA/guest.

ExecLog subscribes to exec_event and records each exec into the results DB. We
give it a fake DB double (plugins.DB) and assert the row it would persist.
"""
from pathlib import Path

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
EXECLOG = REPO_ROOT / "pyplugins" / "loggers" / "exec_logger.py"


class _FakeDB:
    def __init__(self):
        self.events = []

    def add_event(self, cls, data):
        self.events.append((cls, data))


def test_exec_logger_records_exec_row(tmp_path):
    db = _FakeDB()
    lp = load_pyplugin(str(EXECLOG), outdir=tmp_path, doubles={"DB": db})

    lp.dispatch("exec_event", {"argv": ["/bin/sh", "-c", "x"], "envp": {"A": "1"},
                               "parent": None})

    assert len(db.events) == 1
    cls, data = db.events[0]
    assert cls.__name__ == "Exec"
    assert data["argc"] == "3"
    assert data["argv"] == "['/bin/sh', '-c', 'x']"
    assert data["euid"] == -1 and data["egid"] == -1  # no parent -> fallback


def test_exec_logger_uses_parent_credentials(tmp_path):
    db = _FakeDB()
    lp = load_pyplugin(str(EXECLOG), outdir=tmp_path, doubles={"DB": db})

    class _Parent:
        euid, egid = 1000, 1000

    lp.dispatch("exec_event", {"argv": ["id"], "envp": {}, "parent": _Parent()})
    _cls, data = db.events[0]
    assert data["euid"] == 1000 and data["egid"] == 1000
