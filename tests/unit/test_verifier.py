"""Host-side tests for the Verifier plugin (pyplugins/testing/verifier.py).

The verifier writes the JUnit `verifier.xml` that CI reads to decide whether a
run passed, so its pass/fail verdict is load-bearing. These tests pin the
verdict down at the boundaries: `all({}.values())` is `True` in Python, so a
verifier with nothing to check must be made to report a failure explicitly --
otherwise a misconfigured target reports the strongest possible false green.

Driven through `load_pyplugin`; no PANDA and no guest.
"""
import xml.etree.ElementTree as ET
from pathlib import Path

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = REPO_ROOT / "pyplugins" / "testing" / "verifier.py"


def _load(tmp_path, **args):
    return load_pyplugin(str(VERIFIER), outdir=tmp_path, args=args)


def _suite(tmp_path):
    """Parse the written verifier.xml into (tests, failures, {name: failed})."""
    root = ET.parse(tmp_path / "verifier.xml").getroot()
    tests = sum(int(s.get("tests", 0)) for s in root.iter("testsuite"))
    failures = sum(int(s.get("failures", 0)) for s in root.iter("testsuite"))
    cases = {
        tc.get("name"): tc.find("failure") is not None
        for tc in root.iter("testcase")
    }
    return tests, failures, cases


def _condition_file(tmp_path, name, text):
    (tmp_path / name).write_text(text)


# ---------------------------------------------------------------- empty sets

def test_zero_conditions_is_a_failure(tmp_path):
    """No conditions means nothing was verified -- never a pass."""
    lp = _load(tmp_path)
    lp.plugin.uninit()

    tests, failures, cases = _suite(tmp_path)
    # The suite must not be empty: tests="0" failures="0" passes every JUnit
    # consumer, including penguin's own integration check.
    assert tests == 1
    assert failures == 1
    assert cases == {"verifier.no_conditions": True}


def test_zero_conditions_does_not_claim_all_passed(tmp_path):
    lp = _load(tmp_path)
    lp.plugin.uninit()
    assert not lp.plugin._all_passed({})


def test_all_passed_gate(tmp_path):
    """The gate both call sites share: empty is not success."""
    gate = _load(tmp_path).plugin._all_passed
    assert gate({}) is False            # nothing checked
    assert gate({"a": True}) is True
    assert gate({"a": False}) is False
    assert gate({"a": True, "b": False}) is False


# ------------------------------------------------------- real conditions still work

def test_passing_condition_still_passes(tmp_path):
    _condition_file(tmp_path, "console.log", "hello world\n")
    lp = _load(tmp_path, conditions={
        "greets": {"type": "file_contains", "file": "console.log", "string": "hello"},
    })
    lp.plugin.uninit()

    tests, failures, cases = _suite(tmp_path)
    assert (tests, failures) == (1, 0)
    assert cases == {"greets": False}
    assert lp.plugin._all_passed({"greets": True})


def test_failing_condition_fails(tmp_path):
    _condition_file(tmp_path, "console.log", "hello world\n")
    lp = _load(tmp_path, conditions={
        "absent": {"type": "file_contains", "file": "console.log", "string": "nope"},
    })
    lp.plugin.uninit()

    tests, failures, cases = _suite(tmp_path)
    assert (tests, failures) == (1, 1)
    assert cases == {"absent": True}


# -------------------------------------------------------------- unknown types

def test_unknown_condition_type_is_a_failure(tmp_path):
    """A misspelled `type:` used to be skipped, leaving `results` empty."""
    lp = _load(tmp_path, conditions={
        "typo": {"type": "file_contians", "file": "console.log", "string": "x"},
    })
    _, results = lp.plugin.check_test_cases()
    assert results == {"typo": False}

    lp.plugin.uninit()
    tests, failures, cases = _suite(tmp_path)
    assert (tests, failures) == (1, 1)
    assert cases == {"typo": True}


def test_all_unknown_types_do_not_yield_a_vacuous_pass(tmp_path):
    """Every condition misspelled must still be red, not an empty green."""
    lp = _load(tmp_path, conditions={
        "a": {"type": "nope_one"},
        "b": {"type": "nope_two"},
    })
    lp.plugin.uninit()

    tests, failures, _ = _suite(tmp_path)
    assert (tests, failures) == (2, 2)


def test_mixed_known_and_unknown(tmp_path):
    _condition_file(tmp_path, "console.log", "hello\n")
    lp = _load(tmp_path, conditions={
        "good": {"type": "file_contains", "file": "console.log", "string": "hello"},
        "bogus": {"type": "not_a_test"},
    })
    lp.plugin.uninit()

    tests, failures, cases = _suite(tmp_path)
    assert (tests, failures) == (2, 1)
    assert cases == {"good": False, "bogus": True}
