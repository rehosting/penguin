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
