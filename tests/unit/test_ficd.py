"""In-place harness coverage for the FICD analysis plugin
(pyplugins/analysis/ficd.py), driven host-side with no PANDA/guest.

FICD measures "firmware init done" by watching exec events: a newly-exec'd
process similar (Levenshtein ratio >= 0.5) to one already seen is "Not Unique".
The execve syscall handler just feeds strings to on_exec, which is the metric
logic we drive directly here.
"""
from pathlib import Path

from penguin import yaml
from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
FICD = REPO_ROOT / "pyplugins" / "analysis" / "ficd.py"


def test_ficd_marks_similar_procs_not_unique(tmp_path):
    lp = load_pyplugin(str(FICD), outdir=tmp_path)
    lp.plugin.on_exec("aaaaaaaaaa")   # first ever -> Unique
    lp.plugin.on_exec("aaaaaaaaab")   # ratio ~0.9 to a seen proc -> Not Unique
    lp.plugin.on_exec("zzzzzzzzzz")   # ratio ~0.0 -> Unique

    upt = lp.plugin.unique_proc_times
    assert upt["aaaaaaaaaa"][1] == "Unique"
    assert upt["aaaaaaaaab"][1] == "Not Unique"
    assert upt["zzzzzzzzzz"][1] == "Unique"
    # Not-Unique execs don't extend the seen set.
    assert lp.plugin.seen_procs == {"aaaaaaaaaa", "zzzzzzzzzz"}


def test_ficd_reports_ifin_not_reached_on_finalize(tmp_path):
    lp = load_pyplugin(str(FICD), outdir=tmp_path)
    lp.plugin.on_exec("init")
    lp.finalize()  # uninit() writes ficd.yaml
    out = yaml.safe_load((tmp_path / "ficd.yaml").read_text())
    assert out["ifin_reached"] is False  # no 300s exec gap in a unit test
