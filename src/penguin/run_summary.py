"""
penguin.run_summary
===================

Aggregate a completed run's scattered output artifacts into a single
machine-readable ``summary.json`` in the result directory.

A run's signal is spread across many output files (``health_final.yaml``,
``netbinds.csv``, ``pseudofiles_failures.yaml``, ``scores.txt``, ...). This
module reads the artifacts that already exist — it never recomputes them —
and writes one digest that humans triaging a run and outer loops
(explore / CI / escalation) can parse without re-opening everything.

Schema (``schema_version`` 1)
-----------------------------

- ``score`` (float): total score, the sum of the ``scores`` values (same
  number written to ``score.txt``).
- ``scores`` (dict): the per-metric dict from ``calculate_score``, verbatim.
- ``binds`` (list): one entry per working service bind from ``netbinds.csv``:
  ``{proc, proto, ipvn, ip, port, time}`` plus ``pid`` when the CSV carries a
  pid column and ``{state, closed_time}`` when it carries lifecycle columns.
  Only ``listening``/``closed`` sockets are included — ``pending``/
  ``transient`` binds are not working services and are excluded.
- ``crashes`` (list): entries from ``crashes.yaml`` when present, else ``[]``.
- ``unmodeled_pseudofiles`` (int|null): number of distinct paths in
  ``pseudofiles_failures.yaml``; ``null`` if the tracker didn't run.
- ``stalled_threads`` (int|null): number of blocked threads reported in
  ``waitgraph.yaml``; ``null`` if stall diagnostics didn't run.
- ``panic`` (bool): kernel panic observed (derived from the ``nopanic``
  score metric).
- ``wallclock_s`` (float|null): wallclock duration of the emulation run,
  measured by the caller; ``null`` if unknown.
- ``suggest`` (list): remediation suggestions. Always present (stable key
  for consumers); currently always empty, populated as suggestion/escalation
  work lands.

Fields sourced from optional artifacts distinguish "producer didn't run"
(``null``) from "producer ran and found nothing" (``0`` / ``[]``).

``summary.json`` is written only for runs that completed and scored — outer
loops must treat a missing ``summary.json`` as "run did not complete".

This file is *what happened* in a run. Its sibling ``run_manifest.yaml``
(what was run: input hashes, config identity) is a separate artifact with a
different lifecycle — the manifest describes inputs and can be written even
when a run dies; the summary exists only once a run completed and scored.

Functions
---------
- build_run_summary
- write_run_summary
"""
import csv
import json
import os
from penguin import getColoredLogger
from .common import yaml

logger = getColoredLogger("penguin.run_summary")

SUMMARY_FILE = "summary.json"
SUMMARY_SCHEMA_VERSION = 1


def _load_yaml(path):
    """Load a YAML artifact, returning None if absent or unparseable."""
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except FileNotFoundError:
        return None
    except yaml.YAMLError as e:
        logger.warning(f"Could not parse {path}: {e}")
        return None


def _load_binds(result_dir: str) -> list[dict]:
    """Read first-seen binds from netbinds.csv (written by the netbinds plugin).

    Base columns: procname,ipvn,domain,guest_ip,guest_port,[pid,]time. The
    lifecycle rework adds state,closed_time, where state is one of
    pending|listening|transient|closed. Per the lifecycle contract a
    pending/transient socket must not read as a working service, so those rows
    are excluded from ``binds``; listening and (cleanly) closed sockets are
    kept. CSVs without a state column are read as before, all rows included.
    """
    binds = []
    path = os.path.join(result_dir, "netbinds.csv")
    try:
        with open(path, newline="") as f:
            for i, row in enumerate(csv.DictReader(f)):
                state = row.get("state") or None
                if state is not None and state not in ("listening", "closed"):
                    continue
                try:
                    bind = {
                        "proc": row["procname"],
                        "proto": row["domain"],
                        "ipvn": int(row["ipvn"]),
                        "ip": row["guest_ip"],
                        "port": int(row["guest_port"]),
                        "time": float(row["time"]),
                    }
                    pid = row.get("pid")
                    if pid:
                        bind["pid"] = int(pid)
                    if state is not None:
                        bind["state"] = state
                        closed_time = row.get("closed_time")
                        bind["closed_time"] = float(closed_time) if closed_time else None
                    binds.append(bind)
                except (KeyError, TypeError, ValueError) as e:
                    logger.warning(f"Skipping malformed row {i + 1} in {path}: {e}")
    except FileNotFoundError:
        pass
    except (IOError, csv.Error) as e:
        logger.warning(f"Could not read {path}: {e}")
    return binds


def _load_crashes(result_dir: str) -> list:
    """Read crash records from crashes.yaml (crash reporter) when present."""
    data = _load_yaml(os.path.join(result_dir, "crashes.yaml"))
    if data is None:
        return []
    # Written as {"crashes": [...]}; tolerate a bare list too.
    if isinstance(data, dict):
        data = data.get("crashes", [])
    return data if isinstance(data, list) else []


def _count_unmodeled_pseudofiles(result_dir: str):
    """Count distinct failing paths in pseudofiles_failures.yaml.

    Returns None when the pseudofile tracker didn't produce the file, so
    consumers can tell "tracker off" apart from "no failures".
    """
    path = os.path.join(result_dir, "pseudofiles_failures.yaml")
    if not os.path.isfile(path):
        return None
    data = _load_yaml(path)
    return len(data) if isinstance(data, dict) else 0


def _count_stalled_threads(result_dir: str):
    """Count blocked threads from waitgraph.yaml (stall diagnostics) when present."""
    path = os.path.join(result_dir, "waitgraph.yaml")
    if not os.path.isfile(path):
        return None
    data = _load_yaml(path)
    if isinstance(data, dict):
        threads = data.get("threads", [])
        return len(threads) if isinstance(threads, list) else 0
    return 0


def build_run_summary(
    result_dir: str, scores: dict[str, int], wallclock_s: float | None = None
) -> dict:
    """
    Aggregate a completed run's artifacts into the summary dict.

    :param result_dir: Directory containing the run's output artifacts.
    :param scores: Per-metric score dict from ``calculate_score`` (embedded
        verbatim; the total is derived from it, matching ``score.txt``).
    :param wallclock_s: Emulation wallclock seconds, if the caller measured it.
    :return: The summary dict (see module docstring for the schema).
    """
    return {
        "schema_version": SUMMARY_SCHEMA_VERSION,
        "score": float(sum(scores.values())),
        "scores": scores,
        "binds": _load_binds(result_dir),
        "crashes": _load_crashes(result_dir),
        "unmodeled_pseudofiles": _count_unmodeled_pseudofiles(result_dir),
        "stalled_threads": _count_stalled_threads(result_dir),
        "panic": scores.get("nopanic", 1) == 0,
        "wallclock_s": round(wallclock_s, 3) if wallclock_s is not None else None,
        "suggest": [],
    }


def write_run_summary(
    result_dir: str, scores: dict[str, int], wallclock_s: float | None = None
) -> str:
    """
    Build and write ``summary.json`` into ``result_dir``. Returns its path.
    """
    summary = build_run_summary(result_dir, scores, wallclock_s=wallclock_s)
    path = os.path.join(result_dir, SUMMARY_FILE)
    with open(path, "w") as f:
        json.dump(summary, f, indent=2)
        f.write("\n")
    return path
