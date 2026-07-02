import json

import pytest

from penguin.run_summary import (
    SUMMARY_SCHEMA_VERSION,
    build_run_summary,
    write_run_summary,
)

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
}

# Pre-lifecycle netbinds.csv shape (no pid/state/closed_time columns).
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

CRASHES_YAML = """\
crashes:
  - proc: httpd
    pid: 412
    signal: 11
    signame: SIGSEGV
    pc: 0x004013a8
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


@pytest.fixture
def full_run_dir(tmp_path):
    (tmp_path / "netbinds.csv").write_text(NETBINDS_CSV)
    (tmp_path / "pseudofiles_failures.yaml").write_text(PSEUDOFILES_FAILURES_YAML)
    (tmp_path / "crashes.yaml").write_text(CRASHES_YAML)
    (tmp_path / "waitgraph.yaml").write_text(WAITGRAPH_YAML)
    return tmp_path


def test_full_summary(full_run_dir):
    summary = build_run_summary(str(full_run_dir), SCORES, wallclock_s=41.2345)

    assert summary["schema_version"] == SUMMARY_SCHEMA_VERSION
    assert summary["score"] == float(sum(SCORES.values()))
    assert summary["scores"] == SCORES

    # Old-format CSV: no state column, all rows kept, no lifecycle keys.
    assert summary["binds"] == [
        {"proc": "docker", "proto": "tcp", "ipvn": 6, "ip": "[::1]", "port": 0, "time": 113.273},
        {"proc": "portmap", "proto": "udp", "ipvn": 4, "ip": "0.0.0.0", "port": 111, "time": 114.317},
        {"proc": "httpd", "proto": "tcp", "ipvn": 4, "ip": "0.0.0.0", "port": 80, "time": 120.5},
    ]

    assert summary["crashes"] == [
        {
            "proc": "httpd",
            "pid": 412,
            "signal": 11,
            "signame": "SIGSEGV",
            "pc": 0x004013A8,
            "time": 12.481,
            "count": 3,
        }
    ]

    assert summary["unmodeled_pseudofiles"] == 2
    assert summary["stalled_threads"] == 2
    assert summary["panic"] is False
    assert summary["wallclock_s"] == 41.234
    assert summary["suggest"] == []


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


def test_lifecycle_netbinds_filters_non_working(tmp_path):
    (tmp_path / "netbinds.csv").write_text(NETBINDS_LIFECYCLE_CSV)
    summary = build_run_summary(str(tmp_path), SCORES)

    # pending/transient must not read as working services (draft 05 contract).
    assert summary["binds"] == [
        {
            "proc": "httpd", "proto": "tcp", "ipvn": 4, "ip": "0.0.0.0",
            "port": 80, "time": 120.5,
            "state": "listening", "pid": 412, "closed_time": None,
        },
        {
            "proc": "dnsmasq", "proto": "udp", "ipvn": 4, "ip": "0.0.0.0",
            "port": 53, "time": 90.1,
            "state": "closed", "pid": 300, "closed_time": 400.2,
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


def test_write_run_summary_round_trips(full_run_dir):
    path = write_run_summary(str(full_run_dir), SCORES, wallclock_s=41.2)
    assert path == str(full_run_dir / "summary.json")
    with open(path) as f:
        on_disk = json.load(f)
    assert on_disk == build_run_summary(str(full_run_dir), SCORES, wallclock_s=41.2)
