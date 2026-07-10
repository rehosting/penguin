"""
Processes Plugin (processes.py) for Penguin
===========================================

A small, queryable model of the guest's **process tree** -- the first
consumer of the OSI suite that builds a system-wide view rather than reading
one pid at a time. This is *slice 1* of the "system cartography" epic
(threads/kthreads, fd/peer graph, maps, CPU and ptregs are deliberate
follow-ons -- see ``Follow-ons`` below).

Two audiences, one model
------------------------

**AI / the MCP agent** (#835) get a stable, documented, JSON-serializable query
API -- three **live** portal generators (drive with ``yield from`` while the
guest runs):

- ``processes.get(pid)``   -> one flat record (dict) or ``None``
- ``processes.tree()``     -> ``{"roots": [node, ...]}`` (nested; each node has ``children``)
- ``processes.snapshot()`` -> ``{"processes": [record, ...], "tree": {...}}``

These read the whole process set in **one** kernel-side walk
(``OSI.get_all_procs`` -> ``HYPER_OP_OSI_PROC_ALL``): the driver walks
``for_each_process`` under ``rcu_read_lock`` and returns a slim node (pid,
ppid, create_time, ids, comm) per process, so a tree snapshot is a single
RCU-consistent transaction rather than 1 + N per-pid reads that could tear.

**Users** get a legible artifact. Process lifecycle is recorded to the event
**database** (``plugins.db``) as it happens, and at teardown the plugin
materializes a derived ``system_map.yaml`` from it: structured per-process
records plus a rendered ASCII tree embedded as a literal block::

    schema_version: 1
    generated_by: processes
    process_count: 3
    processes:
    - {pid: 1, ppid: 0, name: init, create_time: 100, exec_count: 1, exit: null, ...}
    ...
    tree: |
      init (1)
      `- httpd (400)
         `- status.cgi (517)  [exit: 0]

Persistence model (DB-backed)
-----------------------------

The plugin depends on the ``DB`` logger plugin and emits two lean events
(``pengutils.events``):

- ``exec_event`` (from Execs) -> a ``ProcStart`` row (identity + genealogy:
  pid, ppid, create_time, comm, ids). argv/env stay on the existing ``Exec``
  event; this row carries only what the tree needs. Re-exec appends another
  ``ProcStart`` with the same ``(pid, create_time)``; the derived view
  coalesces by that key.
- ``exit`` / ``exit_group`` syscalls -> a ``ProcExit`` row. Identity comes off
  the syscall event (``syscall.pid`` / ``syscall.create_time``, denormalized by
  the driver from ``current``), so exit recording costs **zero** portal
  round-trips and never reads the dying task's memory.

``system_map.yaml`` is the derived view: ``ProcStart LEFT JOIN ProcExit`` on
``(pid, create_time)``, rendered at teardown. Because plugins unload in reverse
load order (this plugin's ``uninit`` runs before the DB's own final flush), the
teardown path calls ``plugins.db.flush()`` first to make buffered rows visible.

Driver-side safety
------------------

Both the live walk and the exit path touch only kernel ``task_struct`` state --
``get_all_procs`` copies ``task->comm`` (like ``get_proc``) and skips
``!task->mm`` (kthreads = slice 2); the exit path reads a denormalized pid. No
``access_remote_vm`` on userspace, so nothing faults on an exiting/stopped
context (the class of bug behind the rv130 ``read_procargs`` panic).

Arguments
---------

- ``outdir`` (str): output directory (supplied by the framework).
- ``write_map`` (bool, default True): write ``system_map.yaml`` at teardown.

Follow-ons (out of scope for slice 1)
-------------------------------------

Threads + kernel threads (the one further driver change), fd + peer/resource
graph, maps + loaded-lib inventory, CPU/scheduling, ``get_ptregs`` -- slices
2-6 of the epic.
"""

import os
from collections import defaultdict
from os.path import basename, join
from typing import Any, Dict, Generator, List, Optional, Tuple

import yaml

from penguin import Plugin, plugins, getColoredLogger
from pengutils.events import ProcStart, ProcExit

MAP_FILE = "system_map.yaml"
SCHEMA_VERSION = 1

# A process identity: (pid, create_time). create_time is the kernel task
# creation timestamp -- stable across execve, distinct across pid reuse.
ProcKey = Tuple[int, int]


def _int(obj: Any, name: str, default: int = 0) -> int:
    """Read an integer field from an osi_proc wrapper (or any attr holder),
    tolerating missing attributes so real wrappers and test doubles both work."""
    val = getattr(obj, name, default)
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


class Processes(Plugin):
    """Maintains and queries the guest process tree (slice 1: tree + get)."""

    def __init__(self) -> None:
        self.logger = getColoredLogger("plugins.processes")
        self.outdir = self.get_arg("outdir")
        self.write_map = self.get_arg_bool("write_map", True)

        # Hard dependency: lifecycle is recorded to the event DB.
        self.DB = plugins.DB

        plugins.subscribe(plugins.Execs, "exec_event", self.on_exec_event)

        # Seed an (empty) map so downstream consumers can rely on the file.
        self._write_map_file({})

    # ------------------------------------------------------------------ #
    # Lifecycle -> event DB
    # ------------------------------------------------------------------ #
    def on_exec_event(self, event: Any) -> None:
        """Record a process from an ``exec_event`` as a ``ProcStart`` row.

        The payload carries ``proc`` (osi_proc: pid/ppid/create_time/ids) and
        the new program's ``procname``/``argv``; identity is from ``proc``
        (stable kernel fields), the display name from the exec payload.
        """
        proc = getattr(event, "proc", None)
        if proc is None:
            self.logger.warning("processes: exec_event with no proc; ignoring")
            return

        exe = getattr(event, "procname", None) or ""
        argv = list(getattr(event, "argv", None) or [])
        comm = getattr(proc, "name", "") or ""
        name = basename(exe) if exe else (basename(argv[0]) if argv else comm)
        if not name:
            name = "[???]"

        pid = _int(proc, "pid")
        self.DB.add_event(ProcStart, {
            "proc_id": pid,
            "procname": name,
            "pid": pid,
            "ppid": _int(proc, "ppid"),
            "create_time": _int(proc, "create_time"),
            "comm": comm or name,
            "uid": _int(proc, "uid"),
            "gid": _int(proc, "gid"),
            "euid": _int(proc, "euid"),
            "egid": _int(proc, "egid"),
        })
        self.logger.info(f"processes: exec pid={pid} ppid={_int(proc, 'ppid')} "
                         f"name={name!r}")

    def _record_exit(self, syscall: Any, error_code: int, reason: str) -> None:
        """Emit a ``ProcExit`` row for the current process.

        Identity is read straight off the syscall event (``syscall.pid`` /
        ``syscall.create_time``), which the driver denormalizes from
        ``current`` -- zero portal round-trips, no read of the dying task. The
        derived view pairs it with a ``ProcStart`` by ``(pid, create_time)``.
        """
        pid = getattr(syscall, "pid", None)
        if pid is None:
            self.logger.debug(
                f"processes: {reason} without syscall.pid (old driver?); skip")
            return
        pid = int(pid)
        self.DB.add_event(ProcExit, {
            "proc_id": pid,
            "procname": "",  # name is carried by the paired ProcStart
            "pid": pid,
            "create_time": int(getattr(syscall, "create_time", 0) or 0),
            "code": int(error_code),
            "reason": reason,
        })
        self.logger.info(f"processes: {reason} pid={pid} status={error_code}")

    @plugins.syscalls.syscall("on_sys_exit_enter")
    def on_exit(self, regs: Any, proto: Any, syscall: Any,
                error_code: int) -> Generator[Any, None, None]:
        """Thread exit -> ProcExit row."""
        self._record_exit(syscall, error_code, "exit")
        yield from ()  # exit tracking needs no portal call; stay a generator

    @plugins.syscalls.syscall("on_sys_exit_group_enter")
    def on_exit_group(self, regs: Any, proto: Any, syscall: Any,
                      error_code: int) -> Generator[Any, None, None]:
        """Whole-process exit -> ProcExit row."""
        self._record_exit(syscall, error_code, "exit_group")
        yield from ()

    # ------------------------------------------------------------------ #
    # Live query API (MCP / interactive). Portal generators -- ``yield from``.
    # ------------------------------------------------------------------ #
    def get(self, pid: Optional[int] = None) -> Generator[Any, None, Optional[Dict[str, Any]]]:
        """Return a flat record for ``pid`` (or the current process if None).

        Live read via ``get_proc`` -- kernel ``task_struct``/``comm`` only, safe
        against exiting contexts. Returns ``None`` if the pid is not present.

        Return schema (all ints except ``name``)::

            {pid, ppid, name, create_time, start_time, uid, gid, euid, egid}
        """
        proc = yield from plugins.OSI.get_proc(pid)
        if proc is None:
            return None
        return _flatten_proc(proc)

    def _live_records(self) -> Generator[Any, None, Dict[int, Dict[str, Any]]]:
        """{pid -> live record} for every user process, via one kernel-side
        walk (``get_all_procs``) -- a single RCU-consistent snapshot rather than
        1 + N per-pid reads."""
        procs = yield from plugins.OSI.get_all_procs()
        records: Dict[int, Dict[str, Any]] = {}
        for proc in procs or []:
            rec = _flatten_proc(proc)
            records[rec["pid"]] = rec
        return records

    def tree(self) -> Generator[Any, None, Dict[str, Any]]:
        """Return the live process tree as ``{"roots": [node, ...]}``.

        Each node is a ``get()`` record plus a ``children`` list. A process
        whose parent is not among the reported leaders (or ``ppid`` 0) becomes a
        root. Cycles and self-parenting are broken defensively.
        """
        records = yield from self._live_records()
        return _build_tree(records)

    def snapshot(self) -> Generator[Any, None, Dict[str, Any]]:
        """Return ``{"processes": [flat records], "tree": {...}}`` -- the live
        "dump the whole process view" call for MCP/tooling."""
        records = yield from self._live_records()
        flat = [records[pid] for pid in sorted(records)]
        return {"processes": flat, "tree": _build_tree(records)}

    # ------------------------------------------------------------------ #
    # Derived artifact (materialized from the DB at teardown)
    # ------------------------------------------------------------------ #
    def _write_map_file(self, procs: Dict[ProcKey, Dict[str, Any]]) -> None:
        if not self.write_map or not self.outdir:
            return
        flat = _cache_flat(procs)
        header = {
            "schema_version": SCHEMA_VERSION,
            "generated_by": "processes",
            "process_count": len(flat),
            "processes": flat,
        }
        ascii_tree = _render_cache_tree(procs)
        tmp = join(self.outdir, MAP_FILE + ".tmp")
        try:
            with open(tmp, "w") as f:
                f.write(yaml.safe_dump(header, sort_keys=False, default_flow_style=False))
                # Embed the rendered tree as a YAML literal block so the file is
                # both machine-parseable and readable at a glance.
                f.write("tree: |\n")
                for line in (ascii_tree.splitlines() or [""]):
                    f.write(f"  {line}\n")
            os.replace(tmp, join(self.outdir, MAP_FILE))
        except OSError as e:
            self.logger.warning(f"processes: could not write {MAP_FILE}: {e}")

    def uninit(self) -> None:
        """Materialize ``system_map.yaml`` from the DB on unload.

        Flushes the DB first (plugins unload in reverse load order, so our
        ``uninit`` runs before the DB's own final flush) then derives the tree
        from the ``ProcStart``/``ProcExit`` rows.
        """
        if not self.write_map:
            return
        try:
            self.DB.flush()
            starts = self.DB.query(ProcStart)
            exits = self.DB.query(ProcExit)
        except Exception as e:  # DB unavailable / query failed -- keep the seed
            self.logger.warning(f"processes: could not read DB for map: {e}")
            return
        procs = _genealogy_from_rows(starts, exits)
        self._write_map_file(procs)


# ---------------------------------------------------------------------- #
# Pure helpers (host-only; unit-tested directly)
# ---------------------------------------------------------------------- #
def _flatten_proc(proc: Any) -> Dict[str, Any]:
    """One flat, JSON-serializable record from an osi_proc / osi_proc_node.

    Return schema (all ints except ``name``)::

        {pid, ppid, name, create_time, start_time, uid, gid, euid, egid}
    """
    ct = _int(proc, "create_time")
    return {
        "pid": _int(proc, "pid"),
        "ppid": _int(proc, "ppid"),
        "name": getattr(proc, "name", "") or "[???]",
        "create_time": ct,
        # Slim nodes carry only create_time; full osi_proc also has start_time.
        "start_time": _int(proc, "start_time", ct),
        "uid": _int(proc, "uid"),
        "gid": _int(proc, "gid"),
        "euid": _int(proc, "euid"),
        "egid": _int(proc, "egid"),
    }


def _genealogy_from_rows(starts: List[Any], exits: List[Any]) -> Dict[ProcKey, Dict[str, Any]]:
    """Derive the process genealogy from ``ProcStart``/``ProcExit`` rows.

    Coalesces ``ProcStart`` by ``(pid, create_time)`` (re-exec bumps
    ``exec_count``, latest name wins), resolves each process's parent identity
    by matching ``ppid`` to the parent ``ProcStart`` with the greatest
    ``create_time`` not after the child's, and applies ``ProcExit`` rows.
    """
    procs: Dict[ProcKey, Dict[str, Any]] = {}
    for s in sorted(starts, key=lambda r: getattr(r, "id", 0)):
        key: ProcKey = (int(s.pid), int(s.create_time))
        rec = procs.get(key)
        if rec is None:
            procs[key] = {
                "pid": int(s.pid),
                "ppid": int(s.ppid),
                "parent_create_time": 0,  # resolved below
                "name": s.procname or s.comm or "[???]",
                "create_time": int(s.create_time),
                "uid": int(s.uid), "gid": int(s.gid),
                "euid": int(s.euid), "egid": int(s.egid),
                "exec_count": 1,
                "exit": None,
            }
        else:
            rec["exec_count"] += 1
            rec["name"] = s.procname or s.comm or rec["name"]
            rec["ppid"] = int(s.ppid)

    # Resolve parent identity: the parent (ppid) instance that predates the child.
    cts_by_pid: Dict[int, List[int]] = defaultdict(list)
    for (pid, ct) in procs:
        cts_by_pid[pid].append(ct)
    for key, rec in procs.items():
        _pid, ct = key
        cands = [c for c in cts_by_pid.get(rec["ppid"], []) if c <= ct]
        rec["parent_create_time"] = max(cands) if cands else 0

    # Apply exits: exact (pid, create_time), else fall back to the pid.
    for e in exits:
        key = (int(e.pid), int(e.create_time))
        if key not in procs:
            same_pid = [k for k in procs if k[0] == int(e.pid)]
            if not same_pid:
                continue
            key = max(same_pid, key=lambda k: k[1])
        if procs[key]["exit"] is None:
            procs[key]["exit"] = {"code": int(e.code), "reason": e.reason}
    return procs


def _cache_flat(procs: Dict[ProcKey, Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Public-shaped flat records from a genealogy dict, pid-sorted."""
    out = []
    for rec in procs.values():
        out.append({
            "pid": rec["pid"],
            "ppid": rec["ppid"],
            "name": rec["name"],
            "create_time": rec["create_time"],
            "uid": rec["uid"], "gid": rec["gid"],
            "euid": rec["euid"], "egid": rec["egid"],
            "exec_count": rec["exec_count"],
            "exit": rec["exit"],
        })
    out.sort(key=lambda r: (r["pid"], r["create_time"]))
    return out


def _build_tree(records: Dict[int, Dict[str, Any]]) -> Dict[str, Any]:
    """Join live ``{pid -> record}`` into ``{"roots": [node...]}`` via ppid.

    Nodes are shallow copies with a ``children`` list. Roots are processes
    whose ppid is absent/0/self. A cycle (should not happen with real kernel
    data) is broken by treating the first-visited node as the ancestor.
    """
    nodes: Dict[int, Dict[str, Any]] = {
        pid: {**rec, "children": []} for pid, rec in records.items()
    }
    roots: List[Dict[str, Any]] = []
    for pid in sorted(nodes):
        node = nodes[pid]
        ppid = node["ppid"]
        parent = nodes.get(ppid)
        if parent is None or ppid == pid or _would_cycle(nodes, pid, ppid):
            roots.append(node)
        else:
            parent["children"].append(node)
    for node in nodes.values():
        node["children"].sort(key=lambda c: c["pid"])
    return {"roots": roots}


def _would_cycle(nodes: Dict[int, Dict[str, Any]], pid: int, ppid: int) -> bool:
    """True if attaching ``pid`` under ``ppid`` would form a cycle."""
    seen = {pid}
    cur = ppid
    while cur in nodes:
        if cur in seen:
            return True
        seen.add(cur)
        cur = nodes[cur]["ppid"]
    return False


def _render_cache_tree(procs: Dict[ProcKey, Dict[str, Any]]) -> str:
    """Render a genealogy dict (keyed by (pid, create_time)) as ASCII."""
    if not procs:
        return "(no processes observed)"

    children: Dict[ProcKey, List[ProcKey]] = {k: [] for k in procs}
    roots: List[ProcKey] = []
    for key, rec in procs.items():
        pkey: ProcKey = (rec["ppid"], rec["parent_create_time"])
        if pkey in procs and pkey != key:
            children[pkey].append(key)
        else:
            roots.append(key)
    for kids in children.values():
        kids.sort()
    roots.sort()

    lines: List[str] = []

    def label(key: ProcKey) -> str:
        rec = procs[key]
        s = f"{rec['name']} ({rec['pid']})"
        if rec["exec_count"] > 1:
            s += f" [execs: {rec['exec_count']}]"
        if rec["exit"] is not None:
            s += f" [exit: {rec['exit']['code']}]"
        return s

    def walk(key: ProcKey, prefix: str, is_last: bool, is_root: bool,
             stack: frozenset) -> None:
        if is_root:
            lines.append(label(key))
        else:
            lines.append(f"{prefix}{'`- ' if is_last else '|- '}{label(key)}")
        if key in stack:  # defensive cycle guard
            return
        stack = stack | {key}
        kids = children.get(key, [])
        child_prefix = prefix + ("" if is_root else ("   " if is_last else "|  "))
        for i, child in enumerate(kids):
            walk(child, child_prefix, i == len(kids) - 1, False, stack)

    for i, root in enumerate(roots):
        walk(root, "", i == len(roots) - 1, True, frozenset())
    return "\n".join(lines)
