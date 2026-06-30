"""
Structured diagnostic readers over a Penguin ``results/N/`` directory.

These functions parse the artifacts Penguin actually writes (verified against the
``loggers``/``analysis`` pyplugins) into plain Python/JSON structures, so an agent gets
the *answer* instead of a multi-KB file dump. They are deliberately dependency-free
(pyyaml + stdlib only) and defensive: a missing/!written file yields ``{"error": ...}``
rather than raising, because not every plugin runs every time.

Verified artifact names (do NOT use the stale ``*.txt`` names from old docs):
  console.log, health_final.yaml, env_missing.yaml, pseudofiles_failures.yaml,
  pseudofiles_modeled.yaml, netbinds.csv, netbinds_summary.csv, nvram.csv,
  uboot.log, plugins.db (SQLite).
"""

from __future__ import annotations

import csv
import os
import re
import sqlite3
from typing import Any, Optional

import yaml


def latest_results(proj_dir: str) -> Optional[str]:
    """Return the newest ``results/N`` dir for a project (resolving ``results/latest``)."""
    results_base = os.path.join(proj_dir, "results")
    latest = os.path.join(results_base, "latest")
    if os.path.islink(latest) or os.path.isdir(latest):
        return os.path.realpath(latest)
    if not os.path.isdir(results_base):
        return None
    nums = []
    for d in os.listdir(results_base):
        if d.isdigit() and os.path.isdir(os.path.join(results_base, d)):
            nums.append(int(d))
    if not nums:
        return None
    return os.path.join(results_base, str(max(nums)))


def _resolve(results_dir: Optional[str], proj_dir: Optional[str]) -> Optional[str]:
    if results_dir:
        return results_dir
    if proj_dir:
        return latest_results(proj_dir)
    return None


def _load_yaml(path: str) -> Any:
    with open(path) as f:
        return yaml.safe_load(f)


def _need(results_dir: Optional[str], proj_dir: Optional[str], name: str):
    rd = _resolve(results_dir, proj_dir)
    if not rd:
        return None, {"error": "no results dir found; pass results_dir or run first"}
    path = os.path.join(rd, name)
    if not os.path.exists(path):
        return None, {"error": f"{name} not present in {rd} (plugin may not have run)"}
    return path, None


def read_health(results_dir: str = None, proj_dir: str = None) -> dict:
    """The end-of-run health summary (score components, panic flag, counts)."""
    path, err = _need(results_dir, proj_dir, "health_final.yaml")
    if err:
        return err
    return {"health": _load_yaml(path)}


def read_missing_env(results_dir: str = None, proj_dir: str = None) -> dict:
    """Env vars / ``/proc/cmdline`` keys the firmware read but the config didn't provide."""
    path, err = _need(results_dir, proj_dir, "env_missing.yaml")
    if err:
        return err
    return {"missing_env": _load_yaml(path)}


def read_pseudofile_failures(results_dir: str = None, proj_dir: str = None) -> dict:
    """Missing/unmodeled /dev /proc /sys files the firmware touched, with op counts."""
    path, err = _need(results_dir, proj_dir, "pseudofiles_failures.yaml")
    if err:
        return err
    return {"pseudofile_failures": _load_yaml(path)}


def read_netbinds(results_dir: str = None, proj_dir: str = None) -> dict:
    """Listening sockets the guest opened (the success signal). Rows from netbinds.csv."""
    path, err = _need(results_dir, proj_dir, "netbinds.csv")
    if err:
        return err
    rows = []
    with open(path, newline="") as f:
        for row in csv.reader(f):
            if row:
                rows.append(row)
    return {"netbinds": rows, "count": len(rows)}


def grep_console(
    results_dir: str = None, proj_dir: str = None, pattern: str = None, max_lines: int = 100
) -> dict:
    """Return console.log lines matching a regex (or the tail if no pattern)."""
    path, err = _need(results_dir, proj_dir, "console.log")
    if err:
        return err
    with open(path, errors="replace") as f:
        lines = f.read().splitlines()
    if pattern:
        try:
            rx = re.compile(pattern)
        except re.error as e:
            return {"error": f"bad regex: {e}"}
        hits = [ln for ln in lines if rx.search(ln)]
    else:
        hits = lines
    truncated = len(hits) > max_lines
    return {"lines": hits[-max_lines:], "truncated": truncated, "total_matched": len(hits)}


def query_db(
    sql: str, results_dir: str = None, proj_dir: str = None, limit: int = 100
) -> dict:
    """Run a read-only SELECT against ``plugins.db`` (syscalls_logger/exec_logger events).

    The DB has a parent ``event`` table joined to ``syscall``/``read``/``write``/``exec`` on
    ``id`` (procname lives on ``event`` — you must JOIN). Only SELECT is allowed.
    """
    path, err = _need(results_dir, proj_dir, "plugins.db")
    if err:
        return err
    if not sql.lstrip().lower().startswith("select"):
        return {"error": "only SELECT queries are allowed"}
    if ";" in sql.rstrip().rstrip(";"):
        return {"error": "multiple statements are not allowed"}
    con = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        con.row_factory = sqlite3.Row
        cur = con.execute(sql)
        out = [dict(r) for r in cur.fetchmany(limit)]
        return {"rows": out, "count": len(out), "truncated": len(out) == limit}
    except sqlite3.Error as e:
        return {"error": f"sqlite: {e}"}
    finally:
        con.close()


def missing_files(
    results_dir: str = None, proj_dir: str = None, procname: str = None, limit: int = 30
) -> dict:
    """Canned query: files a process tried to open/stat that returned ENOENT (what to add)."""
    where = (
        "s.name IN ('sys_open','sys_openat','sys_stat64','sys_access','sys_faccessat') "
        "AND s.retno_repr LIKE '%ENOENT%'"
    )
    if procname:
        where += f" AND e.procname = '{procname}'"
    sql = (
        "SELECT e.procname, s.arg0_repr AS path, COUNT(*) AS n "
        "FROM syscall s JOIN event e ON e.id = s.id "
        f"WHERE {where} GROUP BY e.procname, s.arg0_repr ORDER BY n DESC"
    )
    return query_db(sql, results_dir=results_dir, proj_dir=proj_dir, limit=limit)
