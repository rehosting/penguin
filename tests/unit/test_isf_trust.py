"""Host-side tests for compat/isf_trust.py: a lifted ISF's untrusted fields
(kernel-lift's two provenance formats) are absent to the trap and the OSI
layout."""
import json
from pathlib import Path

import pytest

from penguin.testing import load_module

PY = Path(__file__).resolve().parents[2] / "pyplugins"


@pytest.fixture
def trust(tmp_path, monkeypatch):
    offsets = tmp_path / "offsets.provenance.json"
    offsets.write_text(json.dumps({"fields": {
        "cred.euid": {"offset": 20, "trusted": True, "class": "target-verified"},
        "task_struct.start_time": {"offset": 600, "trusted": False,
                                   "class": "reference-carried"}}}))
    lift = tmp_path / "provenance.json"
    lift.write_text(json.dumps({"fields": {
        "fs_struct": {"reference-carried": ["root", "pwd"], "target-verified": {"lock": {}}},
        "vm_area_struct": {"inferred": ["vm_pgoff", "vm_flags"],
                           "collisions": {"vm_flags": {"offset": 32,
                                                       "status": "collides-with-verified"}}}}}))
    monkeypatch.setenv("PENGUIN_ISF_PROVENANCE", f"{offsets}:{lift}")
    mod, _ = load_module(str(PY / "compat" / "isf_trust.py"))
    mod._untrusted = None
    return mod


def test_untrusted_fields(trust):
    assert not trust.trusted("task_struct", "start_time")
    assert not trust.trusted("struct fs_struct", "root") and not trust.trusted("fs_struct", "pwd")
    assert trust.trusted("cred", "euid") and trust.trusted("fs_struct", "lock")
    assert trust.trusted("vm_area_struct", "vm_pgoff")      # inferred
    assert not trust.trusted("vm_area_struct", "vm_flags")  # inferred, but collides
    assert trust.trusted("task_struct", "pid")              # not named


def test_layout_drops_them(trust):
    lay, _ = load_module(str(PY / "compat" / "osi_layout.py"))

    class ISF:
        def offsetof(self, t, *path):
            return 8
    assert lay._off(ISF(), "task_struct", "start_time") == -1
    assert lay._off(ISF(), "task_struct", "pid") == 8


@pytest.fixture
def graded(tmp_path, monkeypatch):
    """the lift's files plus an L1 grade, the grade listed first: order must
    not matter"""
    lift = tmp_path / "provenance.json"
    lift.write_text(json.dumps({"fields": {
        "mm_struct": {"reference-carried": ["map_count", "exe_file", "pgd"]},
        "fdtable": {"reference-carried": ["fd"]}}}))
    offsets = tmp_path / "offsets.provenance.json"
    offsets.write_text(json.dumps({"fields": {
        "mm_struct.map_count": {"offset": 96, "trusted": False, "class": "reference-carried"}}}))
    grade = tmp_path / "k2-l1-graded.provenance.json"
    grade.write_text(json.dumps({"fields": {
        "mm_struct.map_count": {"offset": 88, "trusted": True, "class": "l1-graded"},
        "fdtable.fd": {"offset": 8, "trusted": True, "class": "l1-graded"},
        "fs_struct.root": {"offset": 24, "trusted": True, "class": "l1-graded-in-use"}}}))
    monkeypatch.setenv("PENGUIN_ISF_PROVENANCE", f"{grade}:{lift}:{offsets}")
    mod, _ = load_module(str(PY / "compat" / "isf_trust.py"))
    mod._untrusted = None
    return mod


def test_graded_fields_override_and_correct(graded):
    assert graded.offset("struct mm_struct", "map_count", 96) == 88   # the grade corrects it
    assert graded.offset("fdtable", "fd", 8) == 8                     # agrees: kept
    assert graded.offset("mm_struct", "pgd", 72) == -1                # carried, not graded
    assert graded.offset("mm_struct", "exe_file", 808) == -1
    assert graded.offset("fs_struct", "root", 24) == 24               # not untrusted anyway
    assert graded.offset("task_struct", "pid", 1048) == 1048          # not named
    assert graded.graded_used() == {"mm_struct.map_count", "fdtable.fd"}
    assert graded.trusted("mm_struct", "map_count") and not graded.trusted("mm_struct", "pgd")


def test_layout_takes_the_graded_offset(graded, monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "compat.isf_trust", graded)
    lay, _ = load_module(str(PY / "compat" / "osi_layout.py"))

    class ISF:
        OFF = {("mm_struct", "map_count"): 96, ("file", "f_path"): 16,
               ("file", "f_path", "dentry"): 24}

        def offsetof(self, t, *path):
            return self.OFF[(t.split()[-1],) + path]
    assert lay._off(ISF(), "mm_struct", "map_count") == 88
    assert lay._off(ISF(), "file", "f_path", "dentry") == 24          # nested, trusted


def test_hostosi_labels_l1_graded_offsets(graded, monkeypatch):
    import sys
    from compat.osi_label import Label
    monkeypatch.setitem(sys.modules, "compat.isf_trust", graded)
    assert Label("L0", "safe-point", "x").offsets == "isf"
    graded.offset("fdtable", "fd", 8)
    src = (PY / "apis" / "hostosi.py").read_text()
    assert '_judge("shared", "fds")' in src and '_judge("shared", "maps")' in src
    ns = {}
    exec(compile(src[src.index("_TASK = "):src.index("def _judge")], "hostosi", "exec"), ns)
    assert ns["_offsets"]("fds") == "l1-graded"
    assert ns["_offsets"]("args") == "isf"
