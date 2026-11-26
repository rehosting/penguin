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

        # pid -> create_time, learned at exec, so a signal death (which carries
        # only a pid) can be paired with its ProcStart by (pid, create_time).
        self._create_time: Dict[int, int] = {}

        # Authoritative exit source: the igloo_driver do_exit kprobe (via
        # exit_monitor) fires on EVERY user-process death -- exit, exit_group,
        # AND fatal signals -- with the real wait(2)-status-encoded code. When
        # enabled it supersedes both the exit/exit_group syscall hooks and the
        # signal heuristic below: no caught-signal false positives, no missed
        # signal deaths, real exit codes, and create_time straight off the dying
        # task (pairs exactly with ProcStart). Opt-in until the driver carrying
        # the hook is the pinned release.
        self._use_do_exit = self.get_arg_bool("use_do_exit", False)
        if self._use_do_exit:
            try:
                plugins.exit_monitor.enable()
                plugins.subscribe(plugins.exit_monitor, "proc_exit",
                                  self.on_proc_exit)
            except Exception as e:
                self.logger.warning(
                    f"processes: do_exit hook unavailable ({e}); falling back "
                    "to syscall + signal exit tracking")
                self._use_do_exit = False

        # exit/exit_group syscall hooks: the cheap default exit source -- they
        # piggyback on already-firing syscall instrumentation and append a row
        # with no portal round-trip. Registered ONLY when the do_exit hook is not
        # active; otherwise do_exit owns every exit, so installing these would
        # both double-count and waste a hook firing per exit. Registered
        # imperatively (bound methods) so it can be conditional -- a class-body
        # decorator would always install them.
        if not self._use_do_exit:
            plugins.syscalls.syscall("on_sys_exit_enter")(self.on_exit)
            plugins.syscalls.syscall("on_sys_exit_group_enter")(self.on_exit_group)

        # A process killed by a fatal signal dies via the kernel's do_exit path
        # and calls neither exit nor exit_group, so the syscall hooks above miss
        # it -- it would look permanently alive. Close those out via the signal
        # monitor. Restricted by default to signals whose default action is
        # terminate and that are essentially never caught-and-survived (the
        # synchronous faults + abort/kill family); SIGTERM/SIGINT/SIGHUP are
        # excluded as they are commonly handled. Hooked by name for arch
        # portability (signal numbers differ on MIPS etc.).
        self.track_signal_exits = (self.get_arg_bool("track_signal_exits", True)
                                   and not self._use_do_exit)
        self._signal_exited: set = set()
        self._fatal_signums: Dict[int, str] = {}
        if self.track_signal_exits:
            names = self.get_arg("fatal_signals") or [
                "SIGILL", "SIGABRT", "SIGFPE", "SIGSEGV", "SIGBUS",
                "SIGSYS", "SIGXCPU", "SIGXFSZ", "SIGKILL", "SIGQUIT"]
            for name in names:
                num = plugins.signals.signal_name_to_num(name)
                # isinstance guard (not `is not None`) so the host test harness,
                # where signals is an undoubled stub, degrades to no-op cleanly.
                if isinstance(num, int):
                    self._fatal_signums[int(num)] = name
            if self._fatal_signums:
                plugins.subscribe(plugins.signal_monitor, "signal_deliver",
                                  self.on_signal_deliver)
                for num in self._fatal_signums:
                    plugins.signal_monitor.register_hook(sig=num)

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
        self._create_time[pid] = _int(proc, "create_time")
        self._signal_exited.discard(pid)  # a reused pid can die again
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
        self.logger.debug(f"processes: exec pid={pid} ppid={_int(proc, 'ppid')} "
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
        self.logger.debug(f"processes: {reason} pid={pid} status={error_code}")

    def on_signal_deliver(self, cpu: Any, event: Any) -> None:
        """Fatal-signal death -> ProcExit row.

        Covers the process kills that ``exit``/``exit_group`` never see (SIGSEGV
        and friends). Runs in the signal_monitor's (non-portal) publish, so it
        only appends a buffered row -- no guest read. ``event.drop`` means
        another subscriber bypassed the delivery (e.g. SIGILL emulation), so the
        process is not dying; skip it. Deduped per pid: the first fatal delivery
        wins (a dying process may be hit more than once)."""
        sig = int(getattr(event, "sig", 0))
        name = self._fatal_signums.get(sig)
        if name is None or getattr(event, "drop", False):
            return
        pid = getattr(event, "pid", None)
        if pid is None:
            return
        pid = int(pid)
        if pid in self._signal_exited:
            return
        self._signal_exited.add(pid)
        self.DB.add_event(ProcExit, {
            "proc_id": pid,
            "procname": "",
            "pid": pid,
            "create_time": int(self._create_time.get(pid, 0)),
            "code": 128 + sig,  # shell convention for signal death
            "reason": f"signal:{name}",
        })
        self.logger.debug(f"processes: {name} killed pid={pid} (ProcExit)")

    def on_proc_exit(self, cpu: Any, event: Any) -> None:
        """Authoritative task-exit -> ``ProcExit`` row (do_exit kprobe).

        Fires once per user-process death for exit, exit_group, AND fatal
        signals alike, carrying the real exit code (wait-status encoded) and the
        dying task's ``create_time`` -- so it needs no ``(pid, create_time)``
        reconstruction and cannot false-positive on a caught-and-survived
        signal. Active only when ``use_do_exit`` is set; supersedes the syscall
        hooks and the signal heuristic."""
        pid = int(getattr(event, "pid", 0) or 0)
        if not pid:
            return
        if getattr(event, "signaled", False):
            sig = int(event.termsig)
            name = None
            try:
                name = plugins.signals.signal_num_to_name(sig)
            except Exception:
                pass
            if not isinstance(name, str):  # undoubled stub in the test harness
                name = None
            reason, code = f"signal:{name or sig}", 128 + sig
        else:
            reason, code = "exit", int(getattr(event, "exit_status", 0))
        self.DB.add_event(ProcExit, {
            "proc_id": pid,
            "procname": "",  # name is carried by the paired ProcStart
            "pid": pid,
            "create_time": int(getattr(event, "create_time", 0) or 0),
            "code": int(code),
            "reason": reason,
        })
        self.logger.debug(f"processes: {reason} pid={pid} code={code}")

    def on_exit(self, regs: Any, proto: Any, syscall: Any,
                error_code: int) -> Generator[Any, None, None]:
        """Thread exit -> ProcExit row. Registered in ``__init__`` only when the
        do_exit hook is not in use; do_exit supersedes it otherwise."""
        self._record_exit(syscall, error_code, "exit")
        yield from ()  # exit tracking needs no portal call; stay a generator

    def on_exit_group(self, regs: Any, proto: Any, syscall: Any,
                      error_code: int) -> Generator[Any, None, None]:
        """Whole-process exit -> ProcExit row. Registered in ``__init__`` only
        when the do_exit hook is not in use."""
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
    # Slice 2: fds / resources / socket peers (live; portal generators)
    # ------------------------------------------------------------------ #
    def fds(self, pid: Optional[int] = None) -> Generator[Any, None, List[Dict[str, Any]]]:
        """Open file descriptors for ``pid``, classified.

        Each record is ``{fd, path, kind, inode}``; ``kind`` is
        ``socket``/``pipe``/``anon``/``file``. Paths come from the driver's
        ``d_path`` render (identical to ``/proc/<pid>/fd``), so socket and pipe
        fds carry their inode in the path text and it is parsed out here --
        that inode is the join key for :meth:`peers`.

        NOTE on cost: the driver's read_fds op returns ONE fd per portal
        round-trip, so this is O(fds) exits for a single process. Fine
        interactively; the bulk op that fixes it is Phase-2 work (roadmap 11).
        """
        entries = yield from plugins.OSI.get_fds(pid)
        return [_classify_fd(getattr(e, "fd", 0), getattr(e, "name", "") or "")
                for e in (entries or [])]

    def _fds_by_pid(self, pids: List[int]
                    ) -> Generator[Any, None, Dict[int, List[Dict[str, Any]]]]:
        """``{pid: [fd record]}`` for each pid, skipping ones that vanish.

        A process can exit between the walk and its fd read; that is expected
        churn, not an error, so it is dropped from the result rather than
        raising.
        """
        out: Dict[int, List[Dict[str, Any]]] = {}
        for pid in pids:
            try:
                recs = yield from self.fds(pid)
            except Exception as e:  # pragma: no cover - guest-side raciness
                self.logger.debug(f"processes: fds({pid}) failed: {e}")
                continue
            if recs:
                out[pid] = recs
        return out

    def resources(self) -> Generator[Any, None, Dict[str, Any]]:
        """System-wide "who holds what", most-shared first.

        Returns ``{"resources": [{kind, key, holders: [{pid, fd}],
        holder_count}]}``. Keyed by inode for socket/pipe fds and by path
        otherwise, so the same pipe held by two processes is one resource.
        """
        records = yield from self._live_records()
        fds_by_pid = yield from self._fds_by_pid(sorted(records))
        return {"resources": _build_resource_index(fds_by_pid)}

    def _socket_table(self) -> Generator[Any, None, Dict[int, Dict[str, Any]]]:
        """``{socket inode: endpoint}`` from the guest's own /proc/net tables.

        The driver's fd listing gives pid -> socket inode but no addresses (see
        ``struct osi_fd_entry`` -- fd + name only), so the endpoints have to come
        from somewhere. /proc/net/{tcp,tcp6,udp,udp6,unix} publish exactly the
        inode -> endpoint mapping needed, and reading them costs nothing new: it
        is the same portal file read any other plugin uses. A table that is
        absent (no IPv6, no procfs yet) is skipped, not fatal.
        """
        table: Dict[int, Dict[str, Any]] = {}
        for path, proto in (("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6"),
                            ("/proc/net/udp", "udp"), ("/proc/net/udp6", "udp6")):
            try:
                data = yield from plugins.fs.read_file(path, size=65536)
            except Exception:
                continue
            if data:
                table.update(_parse_proc_net(
                    data.decode("latin-1", "replace"), proto))
        try:
            data = yield from plugins.fs.read_file("/proc/net/unix", size=65536)
        except Exception:
            data = None
        if data:
            table.update(_parse_proc_net_unix(data.decode("latin-1", "replace")))
        return table

    def peers(self) -> Generator[Any, None, Dict[str, Any]]:
        """The socket peer graph: which process is talking to which.

        Returns ``{"sockets": [...], "edges": [...], "unresolved": n}``. An
        edge is ``connected`` when one socket's local endpoint is another's
        remote endpoint (the two ends of one in-guest conversation) or
        ``shared`` when two processes hold the same socket inode (fork, or an
        accept()ed fd passed to a worker). ``unresolved`` counts socket fds with
        no /proc/net row, so a sparse graph reads as sparse rather than empty.

        This is the composition slice 1 deliberately left out: the tree says who
        exists, this says what they depend on.
        """
        records = yield from self._live_records()
        fds_by_pid = yield from self._fds_by_pid(sorted(records))
        sockets = yield from self._socket_table()
        graph = _build_peer_graph(fds_by_pid, sockets)
        # Name the endpoints so a caller does not have to re-join against tree().
        names = {pid: records[pid]["name"] for pid in records}
        for s in graph["sockets"]:
            s["name"] = names.get(s["pid"], "")
        for e in graph["edges"]:
            e["a_name"] = names.get(e["a"], "")
            e["b_name"] = names.get(e["b"], "")
        return graph

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
        # One line per run instead of two per process: the per-event detail is at
        # debug level, so this is the only thing the console sees by default.
        self.logger.info(f"processes: {len(procs)} processes "
                         f"({len(starts)} starts, {len(exits)} exits) -> {MAP_FILE}")


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


# ---------------------------------------------------------------------- #
# Slice 2: fd / resource / socket-peer composition (pure helpers)
# ---------------------------------------------------------------------- #
# The driver renders every fd with d_path() on file->f_path (portal_osi.c,
# handle_op_read_fds), exactly like /proc/<pid>/fd. So non-file objects arrive
# in their kernel textual form -- ``socket:[12345]``, ``pipe:[678]``,
# ``anon_inode:[eventfd]`` -- and the number in the brackets IS the inode. That
# is what makes the peer graph possible without any driver change: the fd
# listing gives pid -> socket inode, and the guest's own /proc/net/* tables give
# socket inode -> endpoints. Cross-matching the two joins processes to each
# other through the sockets they hold.
_BRACKET_KINDS = {"socket": "socket", "pipe": "pipe"}


def _classify_fd(fd: int, path: str) -> Dict[str, Any]:
    """One fd record: ``{fd, path, kind, inode}``.

    ``kind`` is ``socket`` / ``pipe`` / ``anon`` / ``file``; ``inode`` is the
    bracketed inode for socket and pipe fds (the only kinds that carry one in
    d_path form) and 0 otherwise.
    """
    path = path or ""
    kind, inode = "file", 0
    head, _, rest = path.partition(":")
    if head in _BRACKET_KINDS and rest.startswith("[") and rest.endswith("]"):
        body = rest[1:-1]
        if body.isdigit():
            kind, inode = _BRACKET_KINDS[head], int(body)
    elif head == "anon_inode":
        kind = "anon"
    return {"fd": int(fd), "path": path, "kind": kind, "inode": inode}


def _hex_endpoint(token: str) -> Tuple[str, int]:
    """``"0100007F:1F90"`` -> ``("127.0.0.1", 8080)``.

    /proc/net/{tcp,udp} print the address as a little-endian hex word (v4) or
    four of them (v6), and the port as big-endian hex. Returns ``("", 0)`` on
    anything unparseable rather than raising -- a malformed line must not take
    out the whole graph.
    """
    addr_hex, _, port_hex = token.partition(":")
    try:
        port = int(port_hex, 16)
    except ValueError:
        return ("", 0)
    try:
        if len(addr_hex) == 8:            # IPv4, LE word
            v = int(addr_hex, 16)
            addr = ".".join(str((v >> (8 * i)) & 0xFF) for i in range(4))
        elif len(addr_hex) == 32:         # IPv6, four LE words
            words = [addr_hex[i:i + 8] for i in range(0, 32, 8)]
            groups = []
            for w in words:
                v = int(w, 16)
                be = bytes((v >> (8 * i)) & 0xFF for i in range(4))
                groups += [f"{be[0]:02x}{be[1]:02x}", f"{be[2]:02x}{be[3]:02x}"]
            addr = ":".join(groups)
        else:
            return ("", port)
    except ValueError:
        return ("", port)
    return (addr, port)


# /proc/net/tcp state field (hex) -> name. Only the ones worth reporting.
_TCP_STATES = {1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
               5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
               9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING"}


def _parse_proc_net(text: str, proto: str) -> Dict[int, Dict[str, Any]]:
    """Parse /proc/net/{tcp,tcp6,udp,udp6} -> ``{inode: endpoint record}``.

    Columns are stable across the kernels penguin runs: ``sl local_address
    rem_address st ... inode``, header line first, inode at index 9.
    """
    out: Dict[int, Dict[str, Any]] = {}
    for line in (text or "").splitlines()[1:]:
        f = line.split()
        if len(f) < 10:
            continue
        try:
            inode = int(f[9])
            state = int(f[3], 16)
        except ValueError:
            continue
        if not inode:
            continue           # unbound / no socket inode -> nothing to join on
        laddr, lport = _hex_endpoint(f[1])
        raddr, rport = _hex_endpoint(f[2])
        out[inode] = {"inode": inode, "proto": proto,
                      "local": {"addr": laddr, "port": lport},
                      "remote": {"addr": raddr, "port": rport},
                      "state": _TCP_STATES.get(state, str(state))}
    return out


def _parse_proc_net_unix(text: str) -> Dict[int, Dict[str, Any]]:
    """Parse /proc/net/unix -> ``{inode: {proto, path, state}}``.

    Columns: ``Num RefCount Protocol Flags Type St Inode Path`` (Path absent for
    unnamed sockets). Note /proc/net/unix does NOT publish the peer pointer, so
    unix pairing can only be inferred from a shared path -- see
    ``_build_peer_graph``, which labels those edges differently for that reason.
    """
    out: Dict[int, Dict[str, Any]] = {}
    for line in (text or "").splitlines()[1:]:
        f = line.split()
        if len(f) < 7:
            continue
        try:
            inode = int(f[6])
        except ValueError:
            continue
        if not inode:
            continue
        out[inode] = {"inode": inode, "proto": "unix",
                      "path": f[7] if len(f) > 7 else "",
                      "state": f[5]}
    return out


def _build_resource_index(fds_by_pid: Dict[int, List[Dict[str, Any]]]
                          ) -> List[Dict[str, Any]]:
    """Invert ``{pid: [fd record]}`` into a holder index, most-held first.

    The key is the inode for socket/pipe fds (so two processes holding the same
    pipe collapse to one resource even though the fd numbers differ) and the
    path for everything else.
    """
    holders: Dict[Tuple[str, Any], List[Dict[str, Any]]] = defaultdict(list)
    kinds: Dict[Tuple[str, Any], str] = {}
    for pid in sorted(fds_by_pid):
        for rec in fds_by_pid[pid]:
            key = ((rec["kind"], rec["inode"]) if rec["inode"]
                   else (rec["kind"], rec["path"]))
            holders[key].append({"pid": pid, "fd": rec["fd"]})
            kinds[key] = rec["kind"]
    out = []
    for key, hs in holders.items():
        out.append({"kind": kinds[key], "key": key[1], "holders": hs,
                    "holder_count": len(hs)})
    out.sort(key=lambda r: (-r["holder_count"], str(r["kind"]), str(r["key"])))
    return out


def _build_peer_graph(fds_by_pid: Dict[int, List[Dict[str, Any]]],
                      sockets: Dict[int, Dict[str, Any]]) -> Dict[str, Any]:
    """Join pid->socket-inode against inode->endpoint into a peer graph.

    Returns ``{"sockets": [...], "edges": [...], "unresolved": n}``:

    * ``sockets`` -- every socket fd we could resolve to an endpoint, annotated
      with its holder (pid, fd).
    * ``edges``   -- ``{a, b, via, kind}`` process pairs. ``kind`` is
      ``connected`` when one socket's *local* endpoint equals another's
      *remote* endpoint (a genuine in-guest connection: the two ends of the
      same conversation, e.g. a client talking to a local daemon), or
      ``shared`` when two processes hold the *same* socket inode (post-fork
      sharing / an accept()ed fd handed to a worker).
    * ``unresolved`` -- socket fds with no /proc/net row (kernel sockets, or a
      table we did not read). Reported, never silently dropped, so a thin graph
      is visibly thin rather than looking like "no connections exist".
    """
    holder: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for pid in sorted(fds_by_pid):
        for rec in fds_by_pid[pid]:
            if rec["kind"] == "socket" and rec["inode"]:
                holder[rec["inode"]].append({"pid": pid, "fd": rec["fd"]})

    resolved, unresolved = [], 0
    for inode in sorted(holder):
        ep = sockets.get(inode)
        if ep is None:
            unresolved += len(holder[inode])
            continue
        for h in holder[inode]:
            resolved.append({**ep, "pid": h["pid"], "fd": h["fd"]})

    edges = []
    # Same inode in two processes -> a shared socket (fork / handed-off accept).
    for inode in sorted(holder):
        hs = holder[inode]
        for i in range(len(hs)):
            for j in range(i + 1, len(hs)):
                if hs[i]["pid"] != hs[j]["pid"]:
                    edges.append({"a": hs[i]["pid"], "b": hs[j]["pid"],
                                  "via": inode, "kind": "shared"})
    # local(A) == remote(B) -> the two ends of one connection, both in-guest.

    def _key(e):
        return (e["addr"], e["port"])
    by_local = defaultdict(list)
    for s in resolved:
        # A LISTEN socket is deliberately NOT indexed: its local endpoint also
        # equals the client's remote endpoint, so indexing it would pair the
        # client with the listener as well as with the accepted socket -- two
        # edges for one conversation, the second of them wrong (the listener is
        # not the far end of anything). Only endpoints of an actual connection
        # are candidates.
        if s.get("local", {}).get("port") and s.get("state") != "LISTEN":
            by_local[_key(s["local"])].append(s)
    seen = set()
    for s in resolved:
        rem = s.get("remote", {})
        if not rem.get("port"):
            continue
        for peer in by_local.get(_key(rem), []):
            if peer["pid"] == s["pid"] and peer["inode"] == s["inode"]:
                continue
            pair = tuple(sorted((s["inode"], peer["inode"])))
            if pair in seen:
                continue
            seen.add(pair)
            edges.append({"a": s["pid"], "b": peer["pid"],
                          "via": f"{rem['addr']}:{rem['port']}",
                          "kind": "connected"})
    return {"sockets": resolved, "edges": edges, "unresolved": unresolved}
