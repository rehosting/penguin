"""Host-side tests for the summary.json aggregator (penguin.run_summary).

run_summary is not a pyplugin — it's the post-run host aggregator the CLI
invokes after scoring — so it is exercised in two layers:

- **Producer contract, via the harness**: the real ``analysis/netbinds.py``
  pyplugin is loaded with ``penguin.testing.load_pyplugin``, driven with bind
  events, and finalized; ``write_run_summary`` then aggregates the directory
  the plugin actually wrote. No hand-rolled ``netbinds.csv`` fixture — if the
  plugin's CSV shape drifts, this test fails.
- **Format compatibility + optional artifacts, via fixtures**: the artifact
  shapes main produces (draft 01 ``crashes.yaml``, draft 03 ranked
  ``pseudofiles_failures.yaml``), the shapes it doesn't yet (draft 05
  lifecycle columns, draft 06 ``waitgraph.yaml``), and the absent-producer
  null semantics.
"""
import json
from pathlib import Path

from penguin.run_summary import (
    SUMMARY_SCHEMA_VERSION,
    build_run_summary,
    write_run_summary,
)
from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
NETBINDS = REPO_ROOT / "pyplugins" / "analysis" / "netbinds.py"

SCORES = {
    "execs": 427,
    "bound_sockets": 5,
    "devices_accessed": 199,
    "processes_run": 12,
    "modules_loaded": 3,
    "blocks_covered": 1000,
    "script_lines_covered": 50,
    "nopanic": 1,
    "blocked_signals": 0,
    "crashes": 0,
}

# Pre-pid netbinds.csv shape (no pid/state/closed_time columns).
NETBINDS_CSV = """\
procname,ipvn,domain,guest_ip,guest_port,time
docker,6,tcp,[::1],0,113.273
portmap,4,udp,0.0.0.0,111,114.317
httpd,4,tcp,0.0.0.0,80,120.5
"""

# Lifecycle netbinds.csv shape (draft 05): state pending|listening|transient|closed.
NETBINDS_LIFECYCLE_CSV = """\
procname,ipvn,domain,guest_ip,guest_port,pid,time,state,closed_time
httpd,4,tcp,0.0.0.0,80,412,120.5,listening,
dnsmasq,4,udp,0.0.0.0,53,300,90.1,closed,400.2
flappy,4,tcp,0.0.0.0,8080,500,95.0,transient,96.0
young,4,tcp,0.0.0.0,9090,501,119.9,pending,
"""

# Pre-ranking flat shape: path -> event -> {count}.
PSEUDOFILES_FAILURES_YAML = """\
/dev/gpio:
  open:
    count: 12
/proc/simple_config/lan_ip:
  open:
    count: 3
"""

# Ranked shape (draft 03): header comment block + path -> {impact, callers,
# events, suggest}. The top level is still path-keyed.
PSEUDOFILES_FAILURES_RANKED_YAML = """\
# Guest accesses to unmodeled /dev, /proc, and /sys paths, ranked by impact
# (crashing_callers >> distinct_callers > hits).
/dev/watchdog:
  impact: {hits: 243, distinct_callers: 2, crashing_callers: 0}
  callers: [init:1, watchdogd:412]
  events:
    ioctl:
      2147768064: {count: 240}
    open: {count: 3}
  suggest:
    read: {model: zero}
    ioctl: {'*': {model: return_const, val: 0}}
/proc/simple_config/lan_ip:
  impact: {hits: 3, distinct_callers: 1, crashing_callers: 0}
  callers: [httpd:300]
  events:
    open: {count: 3}
  suggest:
    read: {model: zero}
"""

# Shape written by analysis/crashes.py (pc is a hex string).
CRASHES_YAML = """\
crashes:
  - proc: httpd
    pid: 412
    signal: 11
    signame: SIGSEGV
    pc: '0x004013a8'
    time: 12.481
    count: 3
"""

WAITGRAPH_YAML = """\
trigger: timeout
wallclock_s: 120.0
threads:
  - tid: 412
    comm: httpd
    state: D
  - tid: 419
    comm: httpd
    state: S
"""


# --------------------------------------------------------------------------- #
# Producer contract: aggregate what the real netbinds plugin writes
# --------------------------------------------------------------------------- #
def test_summary_aggregates_real_netbinds_output(tmp_path):
    # Drive the real netbinds plugin host-side (see test_pyplugin_harness.py:
    # endianness="big" keeps the "port:pid" port value un-swapped).
    lp = load_pyplugin(
        str(NETBINDS), outdir=tmp_path,
        # announce_debounce_s=0: announce synchronously so the bind is recorded
        # (state listening) at dispatch time rather than held pending until a
        # timer/sweep -- otherwise finalize() with no elapsed time would leave
        # it pending and run_summary would (correctly) filter it as non-working.
        args={"shutdown_on_www": False, "announce_debounce_s": 0}, endianness="big",
    )
    lp.dispatch("igloo_ipv4_setup", None, "httpd", 0)     # sin_addr 0 -> 0.0.0.0
    lp.dispatch("igloo_ipv4_bind", None, "80:123", True)  # port:pid, TCP
    lp.dispatch("igloo_ipv4_setup", None, "dnsd", 0)
    lp.dispatch("igloo_ipv4_bind", None, "53:99", False)  # UDP
    lp.finalize()

    path = write_run_summary(str(tmp_path), SCORES, wallclock_s=41.2345)
    assert path == str(tmp_path / "summary.json")
    with open(path) as f:
        summary = json.load(f)

    assert summary["schema_version"] == SUMMARY_SCHEMA_VERSION
    assert summary["score"] == float(sum(SCORES.values()))
    assert summary["scores"] == SCORES

    # The binds come from the CSV the plugin actually wrote. It now emits the
    # draft-05 lifecycle columns: both binds were announced synchronously
    # (announce_debounce_s=0) and never released -> state listening, no close.
    for bind, expected in zip(summary["binds"], [
        {"proc": "httpd", "proto": "tcp", "ipvn": 4, "ip": "0.0.0.0", "port": 80,
         "pid": 123, "state": "listening", "closed_time": None},
        {"proc": "dnsd", "proto": "udp", "ipvn": 4, "ip": "0.0.0.0", "port": 53,
         "pid": 99, "state": "listening", "closed_time": None},
    ]):
        time = bind.pop("time")
        assert isinstance(time, float)
        assert bind == expected
    assert len(summary["binds"]) == 2

    assert summary["crashes"] == []
    assert summary["unmodeled_pseudofiles"] is None
    assert summary["stalled_threads"] is None
    assert summary["panic"] is False
    assert summary["wallclock_s"] == 41.234
    assert summary["suggest"] == []


# --------------------------------------------------------------------------- #
# netbinds.csv format compatibility
# --------------------------------------------------------------------------- #
def test_old_format_netbinds_all_rows_kept(tmp_path):
    # Pre-pid CSVs: no state column, all rows kept, no pid/lifecycle keys.
    (tmp_path / "netbinds.csv").write_text(NETBINDS_CSV)
    summary = build_run_summary(str(tmp_path), SCORES)
    assert summary["binds"] == [
        {"proc": "docker", "proto": "tcp", "ipvn": 6, "ip": "[::1]", "port": 0, "time": 113.273},
        {"proc": "portmap", "proto": "udp", "ipvn": 4, "ip": "0.0.0.0", "port": 111, "time": 114.317},
        {"proc": "httpd", "proto": "tcp", "ipvn": 4, "ip": "0.0.0.0", "port": 80, "time": 120.5},
    ]


def test_lifecycle_netbinds_filters_non_working(tmp_path):
    (tmp_path / "netbinds.csv").write_text(NETBINDS_LIFECYCLE_CSV)
    summary = build_run_summary(str(tmp_path), SCORES)

    # pending/transient must not read as working services (draft 05 contract).
    assert summary["binds"] == [
        {
            "proc": "httpd", "proto": "tcp", "ipvn": 4, "ip": "0.0.0.0",
            "port": 80, "pid": 412, "time": 120.5,
            "state": "listening", "closed_time": None,
        },
        {
            "proc": "dnsmasq", "proto": "udp", "ipvn": 4, "ip": "0.0.0.0",
            "port": 53, "pid": 300, "time": 90.1,
            "state": "closed", "closed_time": 400.2,
        },
    ]


def test_malformed_netbinds_row_skipped(tmp_path):
    (tmp_path / "netbinds.csv").write_text(
        "procname,ipvn,domain,guest_ip,guest_port,time\n"
        "httpd,4,tcp,0.0.0.0,80,120.5\n"
        "bad,notanint,tcp,0.0.0.0,x,y\n"
    )
    summary = build_run_summary(str(tmp_path), SCORES)
    assert len(summary["binds"]) == 1
    assert summary["binds"][0]["proc"] == "httpd"


# --------------------------------------------------------------------------- #
# Optional artifacts and null semantics
# --------------------------------------------------------------------------- #
def test_optional_artifacts_aggregated(tmp_path):
    (tmp_path / "pseudofiles_failures.yaml").write_text(PSEUDOFILES_FAILURES_YAML)
    (tmp_path / "crashes.yaml").write_text(CRASHES_YAML)
    (tmp_path / "waitgraph.yaml").write_text(WAITGRAPH_YAML)
    summary = build_run_summary(str(tmp_path), SCORES)

    assert summary["crashes"] == [
        {
            "proc": "httpd",
            "pid": 412,
            "signal": 11,
            "signame": "SIGSEGV",
            "pc": "0x004013a8",
            "time": 12.481,
            "count": 3,
        }
    ]
    assert summary["unmodeled_pseudofiles"] == 2
    assert summary["stalled_threads"] == 2


def test_missing_optional_artifacts(tmp_path):
    summary = build_run_summary(str(tmp_path), SCORES)

    assert summary["binds"] == []
    assert summary["crashes"] == []
    # Absent producer -> null, distinguishable from "ran and found nothing".
    assert summary["unmodeled_pseudofiles"] is None
    assert summary["stalled_threads"] is None
    assert summary["wallclock_s"] is None


def test_empty_pseudofiles_failures_is_zero(tmp_path):
    (tmp_path / "pseudofiles_failures.yaml").write_text("{}\n")
    summary = build_run_summary(str(tmp_path), SCORES)
    assert summary["unmodeled_pseudofiles"] == 0


def test_ranked_pseudofiles_failures_counts_paths(tmp_path):
    (tmp_path / "pseudofiles_failures.yaml").write_text(PSEUDOFILES_FAILURES_RANKED_YAML)
    summary = build_run_summary(str(tmp_path), SCORES)
    assert summary["unmodeled_pseudofiles"] == 2


def test_panic_derived_from_nopanic(tmp_path):
    scores = dict(SCORES, nopanic=0)
    summary = build_run_summary(str(tmp_path), scores)
    assert summary["panic"] is True
