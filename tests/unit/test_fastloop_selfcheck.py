"""Gate the fastsnap analysis self-check suites from pytest.

WHY THIS FILE EXISTS. `analysis/fastsnap/test_fastloop_statemachine.py` and
`test_snapfeed.py` are standalone scripts with a `main()` and a final `PASS`.
Nothing ran them. They were run by hand, and "I ran it" is not a gate: the
statemachine suite sat broken through several commits because a new accessor
(`fastsnap_cov_hits`) was added to the plugin and to the real ABI but not to
API_COVERAGE or to the fake, so the suite aborted in its FIRST test group and
every later group -- including every coverage assertion -- never executed. The
run still ended with a traceback rather than silence, so nothing was hidden;
it simply was not being looked at on a schedule.

A suite that is only ever run by hand is a suite that is green exactly as
often as someone remembers. These two hold the controls behind every number
this lane reports, so they are worth a pytest entry.
"""
import pathlib
import subprocess
import sys

import pytest

SUITES = ("test_fastloop_statemachine.py", "test_snapfeed.py")
ANALYSIS = (pathlib.Path(__file__).resolve().parents[2]
            / "analysis" / "fastsnap")


@pytest.mark.parametrize("script", SUITES)
def test_analysis_selfcheck(script):
    path = ANALYSIS / script
    if not path.exists():
        pytest.skip(f"{script} is not present in this checkout")
    r = subprocess.run([sys.executable, str(path)], cwd=str(ANALYSIS),
                       capture_output=True, text=True, timeout=1800)
    tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-40:])
    # BOTH conditions, and the second is the one that matters. These suites
    # assert their way through numbered groups and print PASS only after the
    # last one; a suite that exits 0 having run three of twenty groups would
    # satisfy the return code alone. Requiring the final marker is what makes
    # this gate the whole file rather than its beginning.
    assert r.returncode == 0, f"{script} exited {r.returncode}\n{tail}"
    assert "\nPASS" in r.stdout, (
        f"{script} exited 0 without reaching its PASS marker, so it stopped "
        f"early rather than passing\n{tail}")
