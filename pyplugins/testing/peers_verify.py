"""Integration check: the socket peer graph must find a real guest conversation.

The guest workload (``patches/tests/peers.yaml``) starts a listener and a
client talking to it over loopback. This asserts ``processes.peers()`` reports
exactly that: a ``connected`` edge between the two pids, via the expected port.

Why this exists rather than a self-consistency check: ``peers()`` composes two
sources -- fd inodes from the driver's ``d_path`` render, and endpoints from the
guest's own ``/proc/net/*``. A check that re-reads those same sources would
confirm the same data twice and could not catch a wrong edge. A conversation we
*caused* is ground truth the model has to find.

The marker distinguishes failure modes on purpose, because they mean different
things:

  * ``proc_net=no``  -- the /proc/net table could not be read through the portal
    at all, so no host-side join is possible. That is a plumbing verdict about
    the transport, NOT evidence about the graph logic, and it is exactly the
    limitation the planned bulk fd op (kernel-side ``sk`` read, no procfs)
    removes.
  * ``sockets=0``    -- tables read, but no socket fd resolved to an endpoint.
  * ``edge=no``      -- sockets resolved but the conversation was not joined.

Writes ``peers_verify.txt``; the ``verifier`` fixture asserts ``PEERS_VERIFY=PASS``.
"""
import time
from os.path import join

from penguin import Plugin, plugins


class PeersVerify(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.port = int(self.get_arg("port") or 9999)
        self.settle = float(self.get_arg("settle_seconds") or 3)
        self.max_wait = float(self.get_arg("max_wait_seconds") or 25)
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

    def _proc_net_readable(self):
        """True if /proc/net/tcp came back with a parseable header.

        Read directly rather than trusting peers(): if this fails, the graph is
        empty for a transport reason and the marker has to say so.
        """
        try:
            data = yield from plugins.fs.read_file("/proc/net/tcp", size=4096)
        except Exception:
            return False
        return bool(data) and b"local_address" in data

    def _maybe_verify(self, elapsed):
        proc_net = yield from self._proc_net_readable()
        graph = yield from plugins.processes.peers()
        sockets = graph.get("sockets", [])
        edges = graph.get("edges", [])
        connected = [e for e in edges if e.get("kind") == "connected"
                     and str(self.port) in str(e.get("via", ""))]

        # Keep retrying while the workload may still be coming up; a connection
        # takes an unpredictable number of guest ms to reach ESTABLISHED.
        if not connected and elapsed < self.max_wait:
            return
        self.done = True

        ok = bool(connected)
        result = (f"PEERS_VERIFY={'PASS' if ok else 'FAIL'} "
                  f"proc_net={'yes' if proc_net else 'no'} "
                  f"sockets={len(sockets)} edges={len(edges)} "
                  f"connected_on_{self.port}={'yes' if connected else 'no'} "
                  f"unresolved={graph.get('unresolved', 0)}")
        if ok:
            e = connected[0]
            result += f" pair={e['a']}({e.get('a_name','')})<->{e['b']}({e.get('b_name','')})"
            self.logger.info(result)
        else:
            self.logger.error(result)
        try:
            with open(join(self.outdir, "peers_verify.txt"), "w") as f:
                f.write(result + "\n")
        except OSError as e:
            self.logger.error(f"peers_verify: cannot write marker: {e}")
