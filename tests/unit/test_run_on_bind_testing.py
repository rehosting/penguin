"""Host-side coverage for the RunOnBind test plugin
(pyplugins/testing/run_on_bind_testing.py), driven with no PANDA/guest.

The plugin's whole job is grading side effects, so the interesting logic is the
grading itself: a marker that never appears, one that appears empty (a failed
`wget -q -O file` leaves a 0-byte file behind), and one with real content.
`wait_timeout` is 1s throughout so the failing paths don't stall the suite.
"""
from pathlib import Path

import pytest

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
PLUGIN = REPO_ROOT / "pyplugins" / "testing" / "run_on_bind_testing.py"
RESULTS = "run_on_bind_test.txt"


def grade(tmp_path, **args):
    """Run the plugin's uninit-time checks and return its results artifact."""
    lp = load_pyplugin(str(PLUGIN), outdir=tmp_path, args={"wait_timeout": 1, **args})
    lp.finalize()
    return (tmp_path / RESULTS).read_text()


def test_marker_with_content_passes(tmp_path):
    marker = tmp_path / "marker.txt"
    marker.write_text("hello")
    assert "host_marker: passed" in grade(tmp_path, host_marker=str(marker))


def test_empty_marker_fails(tmp_path):
    marker = tmp_path / "marker.txt"
    marker.touch()  # what a failed `wget -q -O marker.txt <url>` leaves behind
    results = grade(tmp_path, host_marker=str(marker))
    assert "host_marker: failed (too small: 0 bytes, expected >= 1)" in results


def test_empty_marker_passes_when_min_size_is_zero(tmp_path):
    marker = tmp_path / "flag"
    marker.touch()  # a touch-style success flag, opted into explicitly
    results = grade(tmp_path, host_marker=str(marker), host_marker_min_size=0)
    assert "host_marker: passed" in results


def test_missing_marker_fails_as_not_found(tmp_path):
    results = grade(tmp_path, host_marker=str(tmp_path / "nope.txt"))
    assert "host_marker: failed (not found)" in results


def test_missing_marker_fails_even_with_min_size_zero(tmp_path):
    results = grade(
        tmp_path, host_marker=str(tmp_path / "nope.txt"), host_marker_min_size=0)
    assert "host_marker: failed (not found)" in results


def test_short_marker_fails_against_larger_min_size(tmp_path):
    marker = tmp_path / "marker.txt"
    marker.write_text("hi")
    results = grade(tmp_path, host_marker=str(marker), host_marker_min_size=64)
    assert "host_marker: failed (too small: 2 bytes, expected >= 64)" in results


def test_results_relative_marker_resolves_into_outdir(tmp_path):
    (tmp_path / "marker.txt").write_text("hello")
    results = grade(tmp_path, host_marker="results/marker.txt")
    assert "host_marker: passed" in results


def test_negative_min_size_rejected(tmp_path):
    with pytest.raises(ValueError, match="host_marker_min_size"):
        load_pyplugin(str(PLUGIN), outdir=tmp_path,
                      args={"host_marker": "x", "host_marker_min_size": -1})


def test_output_contains_still_uses_existence_only(tmp_path):
    (tmp_path / "run_on_bind_output.txt").write_text("uid=0(root)\n")
    results = grade(tmp_path, output_contains=["root", "uid=0"])
    assert "output_contains: passed" in results


def test_output_contains_reports_missing_strings(tmp_path):
    (tmp_path / "run_on_bind_output.txt").write_text("uid=1000(user)\n")
    results = grade(tmp_path, output_contains=["root"])
    assert "output_contains: failed (missing: root)" in results
