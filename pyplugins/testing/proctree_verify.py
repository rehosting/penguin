"""Integration check: the `processes` model must match the guest's own /proc.

Fires once at steady state and, inside a single portal-driven syscall hook (so
the guest is paused), grabs two INDEPENDENT views back-to-back:

  * model  -- ``plugins.OSI.get_all_procs()`` (kernel ``for_each_process`` walk,
               behind ``HYPER_OP_OSI_PROC_ALL``)
  * ground -- the guest's own ``/proc/<pid>/stat`` + ``/status`` via the portal
              file-read op (procfs seq_file -- a *different* kernel path)

and asserts they agree for every stable thread-group leader. Two model walks
bracket the /proc scan so procs spawned/reaped mid-scan (transients) are set
aside rather than failing the run; ``/proc`` is filtered to leaders (``Tgid ==
pid``) because ``/proc/<tid>`` also resolves for non-leader threads, which the
walk correctly omits.

Writes ``proctree_verify.txt`` with ``PROCTREE_VERIFY=PASS`` iff clean; the
`verifier` fixture asserts that string. Invariants checked (all arch-robust):
existence, ppid, comm, parent-strictly-before-child (fork must not carry a
stale/inherited create_time), and model create_time ordering == /proc starttime
ordering. (The stronger dns320 finding -- create_time numerically equal to
/proc starttime -- is HZ-dependent, so it is reported, not gated.)
"""
import time
from os.path import join

from penguin import Plugin, plugins


class ProctreeVerify(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.settle = float(self.get_arg("settle_seconds") or 15)
        self.max_wait = float(self.get_arg("max_wait_seconds") or 120)
        self.scan_cap = int(self.get_arg("scan_cap") or 512)
        self._t0 = time.time()
        self.done = False

        @plugins.syscalls.syscall("on_all_sys_enter")
        def _tick(*args, **kwargs):
            if self.done:
                return
            elapsed = time.time() - self._t0
            if elapsed < self.settle:
                return
            yield from self._maybe_verify(elapsed)

    def _read_leader(self, pid):
        """(comm, state, ppid, starttime) if /proc/<pid> is a thread-group
        leader (Tgid==pid); None otherwise / if absent."""
        try:
            data = yield from plugins.fs.read_file(f"/proc/{pid}/stat", size=4096)
        except Exception:
            return None
        if not data:
            return None
        raw = data.decode("latin-1", "replace")
        lp, rp = raw.find("("), raw.rfind(")")
        if lp < 0 or rp < 0 or rp < lp:
            return None
        comm = raw[lp + 1:rp]
        rest = raw[rp + 1:].split()
        if len(rest) < 20:
            return None
        try:
            ppid, starttime = int(rest[1]), int(rest[19])
        except ValueError:
            return None
        tgid = pid
        try:
            status = yield from plugins.fs.read_file(f"/proc/{pid}/status", size=4096)
            for line in status.decode("latin-1", "replace").splitlines():
                if line.startswith("Tgid:"):
                    tgid = int(line.split()[1])
                    break
        except Exception:
            pass
        if tgid != pid:
            return None  # non-leader thread; the walk models leaders only
        return (comm, rest[0], ppid, starttime)

    def _walk(self):
        procs = yield from plugins.OSI.get_all_procs()
        return {int(p.pid): {"ppid": int(p.ppid), "comm": str(p.name),
                             "create_time": int(p.create_time)}
                for p in (procs or [])}

    def _maybe_verify(self, elapsed):
        model1 = yield from self._walk()
        if not model1 and elapsed < self.max_wait:
            return  # not booted enough yet; try again on a later syscall

        proc = {}
        for pid in sorted(set(model1) | set(range(1, self.scan_cap + 1))):
            st = yield from self._read_leader(pid)
            if st is not None:
                comm, state, ppid, starttime = st
                proc[pid] = {"comm": comm, "state": state, "ppid": ppid,
                             "starttime": starttime}
        # procfs may mount after the first execs (esp. on the synthetic
        # empty_fs target): if the model has procs but /proc reads nothing yet,
        # it isn't ready -- retry rather than falsely fail, until max_wait.
        if model1 and not proc and elapsed < self.max_wait:
            return
        self.done = True
        model2 = yield from self._walk()

        # stable = leaders the walk agrees on across the scan; transients dropped
        stable = set(model1) & set(model2)
        transient = set(model1) ^ set(model2)
        model = {p: model1[p] for p in stable}
        mp, pp = set(model), set(proc)

        def is_kthread(pid):
            cur, seen = pid, set()
            while cur not in (0, 1) and cur not in seen:
                seen.add(cur)
                if cur == 2:
                    return True
                cur = proc.get(cur, {}).get("ppid")
                if cur is None:
                    return False
            return cur == 2

        phantom = sorted(p for p in (mp - pp) if p not in transient)
        omitted = (pp - mp) - transient
        missed = sorted(p for p in omitted
                        if proc[p]["state"] != "Z" and not is_kthread(p) and p != 2)

        ppid_bad, comm_bad = [], []
        for p in sorted(mp & pp):
            if model[p]["ppid"] != proc[p]["ppid"]:
                ppid_bad.append(p)
            if model[p]["comm"] != proc[p]["comm"]:
                comm_bad.append(p)

        # --- model-internal invariants (need no procfs) --------------- #
        # A child is never created before its parent.
        time_bad = []
        for p, m in model.items():
            par = m["ppid"]
            if par in model and par != 0 and m["create_time"] < model[par]["create_time"]:
                time_bad.append(p)
        # snapshot() (the MCP surface) must agree with the raw walk and yield a
        # well-formed tree (>=1 root, every pid reachable -> no lost/cyclic node).
        snap_ok, snap_note = True, ""
        try:
            snap = yield from plugins.processes.snapshot()
            snap_pids = {int(r["pid"]) for r in snap.get("processes", [])}
            roots = snap.get("tree", {}).get("roots", [])

            def _count(nodes):
                n = 0
                for nd in nodes:
                    n += 1 + _count(nd.get("children", []))
                return n
            reachable = _count(roots)
            snap_ok = (bool(snap_pids) and len(roots) >= 1
                       and reachable == len(snap_pids))
            if not snap_ok:
                snap_note = f"(pids={len(snap_pids)} roots={len(roots)} reach={reachable})"
        except Exception as e:  # pragma: no cover - defensive
            snap_ok, snap_note = False, f"(err {e})"

        # --- procfs cross-check (only when procfs is actually present) - #
        proc_available = len(pp) > 0
        inversions = 0
        if proc_available:
            shared = sorted(mp & pp)
            for i in range(len(shared)):
                for j in range(i + 1, len(shared)):
                    a, b = shared[i], shared[j]
                    dm = model[a]["create_time"] - model[b]["create_time"]
                    dp = proc[a]["starttime"] - proc[b]["starttime"]
                    if dm and dp and (dm > 0) != (dp > 0):
                        inversions += 1
            proc_ok = not (phantom or missed or ppid_bad or comm_bad or inversions)
        else:
            # No real procfs on this target (e.g. the synthetic empty_fs): the
            # /proc ground-truth is unavailable, so gate on model-internal
            # invariants only. Real-firmware targets exercise the full check.
            proc_ok = True

        ok = bool(model) and not time_bad and snap_ok and proc_ok
        detail = (f"proc_checked={'yes' if proc_available else 'no'} "
                  f"model_leaders={len(mp)} proc_leaders={len(pp)} "
                  f"matched={len(mp & pp)} phantom={len(phantom)} missed={len(missed)} "
                  f"ppid_bad={len(ppid_bad)} comm_bad={len(comm_bad)} "
                  f"parent_time_bad={len(time_bad)} order_inversions={inversions} "
                  f"snapshot_ok={snap_ok}{snap_note} transients={len(transient)}")
        result = f"PROCTREE_VERIFY={'PASS' if ok else 'FAIL'} {detail}"
        # Console stays quiet on the happy path: one short line on PASS, the
        # full field dump only when something actually failed (and always in
        # the marker file, which is what a post-mortem reads).
        if ok:
            self.logger.info(f"PROCTREE_VERIFY=PASS "
                             f"(model={len(mp)} matched={len(mp & pp)})")
        else:
            self.logger.error(result)
        try:
            with open(join(self.outdir, "proctree_verify.txt"), "w") as f:
                f.write(result + "\n")
        except OSError as e:
            self.logger.error(f"proctree_verify: cannot write marker: {e}")
