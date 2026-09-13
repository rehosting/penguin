"""The inlined trigger table in the guest-side plugin must match the manifest.

bugbench.py cannot import bugbench_truth.py: it is loaded as a plugins.d
drop-in inside the container, where this directory is not on sys.path. So the
triggers are duplicated, and a duplicate that drifts is the worst kind of bug
here -- every score would be computed against inputs that are not the ones the
manifest describes, every "bug not found" would be wrong, and no run could
reveal it because both halves would be internally consistent.

This is the check that makes the duplication safe. It is a host-side test; it
needs no guest.
"""
import pathlib
import re

import pytest

HERE = pathlib.Path(__file__).parent
PLUGIN = HERE / "bugbench.py"


def _plugin_triggers():
    """Exec just the trigger table out of the plugin, without importing it
    (importing would pull in penguin's plugin machinery, which is not present
    on the host)."""
    src = PLUGIN.read_text()
    m = re.search(r"^def _inp\(.*?^\]\n", src, re.S | re.M)
    assert m, "trigger table not found in %s" % PLUGIN
    ns = {}
    exec(m.group(0), ns)
    return ns["TRIGGERS"]


def test_plugin_triggers_match_manifest():
    import bugbench_truth as truth

    plugin = dict(_plugin_triggers())
    manifest = {b["id"]: b["trigger"] for b in truth.BUGS}

    assert set(plugin) == set(manifest), (
        "trigger sets differ: plugin has %s, manifest has %s"
        % (sorted(plugin), sorted(manifest)))
    for bid in sorted(manifest):
        assert plugin[bid] == manifest[bid], (
            "%s trigger drifted: plugin %s != manifest %s"
            % (bid, plugin[bid].hex(), manifest[bid].hex()))


def test_manifest_has_a_canary_and_a_negative_control():
    """Both are load-bearing for how a run is scored, so their absence must
    break the build rather than quietly change what a verdict means."""
    import bugbench_truth as truth

    canaries = [b for b in truth.BUGS if b.get("role") == "canary"]
    assert len(canaries) == 1, "exactly one canary expected, got %d" % len(canaries)
    assert truth.SAFE_OPCODE == 0x00
    assert truth.SAFE_FUNCS


def test_every_bug_has_a_distinct_faulting_function():
    """Two bugs reaching the same function cannot be told apart in a crash
    report, so 'found N of 7' would not be checkable."""
    import bugbench_truth as truth

    funcs = [b["func"] for b in truth.BUGS]
    assert len(set(funcs)) == len(funcs), "duplicate faulting functions: %s" % funcs


def test_scorer_rejects_a_fabricating_harness():
    import bugbench_truth as truth

    r = truth.score([b["func"] for b in truth.BUGS], saw_safe=True)
    assert "INVALID" in r["verdict"]


def test_scorer_calls_a_missing_canary_a_harness_failure():
    """A run that finds the hard bugs but not the trivial canary is not a
    strong result -- it is an impossible one, and must be reported as broken
    plumbing rather than scored."""
    import bugbench_truth as truth

    non_canary = [b["func"] for b in truth.BUGS if b.get("role") != "canary"]
    r = truth.score(non_canary)
    assert "HARNESS BROKEN" in r["verdict"]


def test_scorer_grades_a_valid_run_by_tier():
    import bugbench_truth as truth

    trivial = [b["func"] for b in truth.BUGS if b["tier"] == "trivial"]
    r = truth.score(trivial)
    assert r["verdict"].startswith("VALID")
    assert r["found"] == len(trivial)
    assert r["canary_hit"]
