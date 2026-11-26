"""Host-side tests for slice 2 of the processes model: fds(), resources() and
the socket peer graph (peers()).

No PANDA, no guest. The two guest edges are stubbed:

* ``plugins.OSI.get_fds(pid)`` -- the driver's per-pid fd listing, whose names
  are d_path renders (so sockets arrive as ``socket:[inode]``).
* ``plugins.fs.read_file`` -- the guest's own /proc/net/{tcp,udp,unix} tables,
  which are the only source of socket endpoints (``struct osi_fd_entry`` carries
  fd + name only).

The point of the peer graph is the JOIN between those two, so the tests feed a
realistic pair of tables and assert the edges that fall out.
"""
from pathlib import Path
from types import SimpleNamespace

from penguin.testing import load_pyplugin, drive

REPO_ROOT = Path(__file__).resolve().parents[2]
PROCESSES = REPO_ROOT / "pyplugins" / "analysis" / "processes.py"


def _proc(pid, ppid, name):
    return SimpleNamespace(pid=pid, ppid=ppid, create_time=pid * 10, name=name,
                           uid=0, gid=0, euid=0, egid=0)


def _fd(fd, name):
    return SimpleNamespace(fd=fd, name=name)


class FakeOSI:
    def __init__(self, procs, fds):
        self._procs, self._fds = procs, fds

    def get_all_procs(self):
        yield from ()
        return [self._procs[p] for p in sorted(self._procs)]

    def get_proc(self, pid=None):
        yield from ()
        return self._procs.get(pid)

    def get_fds(self, pid=None, start_fd=0, count=None):
        yield from ()
        return self._fds.get(pid, [])


class FakeFS:
    """Double for plugins.fs: serves canned /proc/net tables."""

    def __init__(self, files):
        self.files = files
        self.reads = []

    def read_file(self, path, size=None):
        yield from ()
        self.reads.append(path)
        data = self.files.get(path)
        if data is None:
            raise FileNotFoundError(path)
        return data.encode()


# A client (pid 300) connected to a local daemon (pid 200) listening on :80.
# httpd holds the listening socket (inode 1000) and the accepted one (1001);
# the client holds 1002. Ports/addresses are in /proc/net/tcp hex form:
# 0100007F = 127.0.0.1 (LE), 0050 = 80, EA60 = 60000.
PROC_NET_TCP = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    "   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1000 1\n"
    "   1: 0100007F:0050 0100007F:EA60 01 00000000:00000000 00:00000000 00000000     0        0 1001 1\n"
    "   2: 0100007F:EA60 0100007F:0050 01 00000000:00000000 00:00000000 00000000     0        0 1002 1\n"
)

PROC_NET_UNIX = (
    "Num       RefCount Protocol Flags    Type St Inode Path\n"
    "0000000000000000: 00000002 00000000 00010000 0001 01  2000 /var/run/log\n"
)


def _load(tmp_path, procs, fds, files):
    osi, fs = FakeOSI(procs, fds), FakeFS(files)
    lp = load_pyplugin(str(PROCESSES), outdir=tmp_path,
                       args={"write_map": False},
                       doubles={"OSI": osi, "fs": fs})
    return lp, fs


def test_fds_classifies_sockets_pipes_and_files(tmp_path):
    procs = {200: _proc(200, 1, "httpd")}
    fds = {200: [_fd(0, "/dev/null"), _fd(3, "socket:[1000]"),
                 _fd(4, "pipe:[777]"), _fd(5, "anon_inode:[eventfd]")]}
    lp, _ = _load(tmp_path, procs, fds, {})

    got, _ = drive(lp.plugin.fds(200), responses=[], collect=True)
    assert [(r["fd"], r["kind"], r["inode"]) for r in got] == [
        (0, "file", 0), (3, "socket", 1000), (4, "pipe", 777), (5, "anon", 0)]


def test_resources_groups_holders_of_the_same_inode(tmp_path):
    # Parent and child share one pipe (same inode, different fd numbers) --
    # the index must collapse them into a single 2-holder resource.
    procs = {200: _proc(200, 1, "sh"), 201: _proc(201, 200, "gzip")}
    fds = {200: [_fd(3, "pipe:[777]"), _fd(4, "/etc/passwd")],
           201: [_fd(0, "pipe:[777]")]}
    lp, _ = _load(tmp_path, procs, fds, {})

    out, _ = drive(lp.plugin.resources(), responses=[], collect=True)
    top = out["resources"][0]
    assert top["kind"] == "pipe" and top["key"] == 777
    assert top["holder_count"] == 2
    assert sorted(h["pid"] for h in top["holders"]) == [200, 201]


def test_peers_joins_fd_inodes_to_proc_net_endpoints(tmp_path):
    procs = {200: _proc(200, 1, "httpd"), 300: _proc(300, 1, "wget")}
    fds = {200: [_fd(3, "socket:[1000]"), _fd(4, "socket:[1001]")],
           300: [_fd(3, "socket:[1002]")]}
    lp, fs = _load(tmp_path, procs, fds,
                   {"/proc/net/tcp": PROC_NET_TCP})

    graph, _ = drive(lp.plugin.peers(), responses=[], collect=True)

    # Every socket resolved, and the listener is reported as LISTEN.
    by_inode = {s["inode"]: s for s in graph["sockets"]}
    assert set(by_inode) == {1000, 1001, 1002}
    assert by_inode[1000]["state"] == "LISTEN"
    assert by_inode[1000]["local"] == {"addr": "127.0.0.1", "port": 80}
    assert by_inode[1000]["pid"] == 200 and by_inode[1000]["name"] == "httpd"

    # The decisive fact: wget:1002 <-> httpd:1001 is one conversation, found by
    # matching local(A) == remote(B), not by anything in the fd listing alone.
    connected = [e for e in graph["edges"] if e["kind"] == "connected"]
    assert len(connected) == 1
    e = connected[0]
    assert {e["a"], e["b"]} == {200, 300}
    assert {e["a_name"], e["b_name"]} == {"httpd", "wget"}
    assert graph["unresolved"] == 0


def test_peers_reports_shared_sockets_and_unresolved(tmp_path):
    # Two workers share one accepted socket (inode 1001 -> "shared" edge), and
    # pid 400 holds a socket with no /proc/net row -> counted, not dropped.
    procs = {200: _proc(200, 1, "httpd"), 201: _proc(201, 200, "httpd"),
             400: _proc(400, 1, "odd")}
    fds = {200: [_fd(4, "socket:[1001]")], 201: [_fd(4, "socket:[1001]")],
           400: [_fd(3, "socket:[9999]")]}
    lp, _ = _load(tmp_path, procs, fds, {"/proc/net/tcp": PROC_NET_TCP})

    graph, _ = drive(lp.plugin.peers(), responses=[], collect=True)
    shared = [e for e in graph["edges"] if e["kind"] == "shared"]
    assert len(shared) == 1 and {shared[0]["a"], shared[0]["b"]} == {200, 201}
    assert shared[0]["via"] == 1001
    assert graph["unresolved"] == 1


def test_peers_survives_missing_proc_net_tables(tmp_path):
    # No procfs at all: the graph must come back empty-but-honest (every socket
    # counted as unresolved) rather than raising.
    procs = {200: _proc(200, 1, "httpd")}
    fds = {200: [_fd(3, "socket:[1000]")]}
    lp, fs = _load(tmp_path, procs, fds, {})

    graph, _ = drive(lp.plugin.peers(), responses=[], collect=True)
    assert graph["sockets"] == [] and graph["edges"] == []
    assert graph["unresolved"] == 1
    assert "/proc/net/tcp" in fs.reads    # it tried


def test_unix_socket_table_is_parsed(tmp_path):
    procs = {500: _proc(500, 1, "syslogd")}
    fds = {500: [_fd(3, "socket:[2000]")]}
    lp, _ = _load(tmp_path, procs, fds, {"/proc/net/unix": PROC_NET_UNIX})

    graph, _ = drive(lp.plugin.peers(), responses=[], collect=True)
    assert len(graph["sockets"]) == 1
    s = graph["sockets"][0]
    assert s["proto"] == "unix" and s["path"] == "/var/run/log"
    assert s["pid"] == 500


def test_listener_alone_yields_no_connected_edge(tmp_path):
    """A client talking to a listener must produce exactly ONE conversation
    edge -- to the accepted socket, not a second one to the listening socket.

    Regression: indexing LISTEN sockets by local endpoint made every connection
    match the listener too, so one conversation reported two peers and the
    extra one was wrong. Here only the listener and the client exist (no
    accepted socket), so the honest answer is no connected edge at all.
    """
    procs = {200: _proc(200, 1, "httpd"), 300: _proc(300, 1, "wget")}
    fds = {200: [_fd(3, "socket:[1000]")], 300: [_fd(3, "socket:[1002]")]}
    lp, _ = _load(tmp_path, procs, fds, {"/proc/net/tcp": PROC_NET_TCP})

    graph, _ = drive(lp.plugin.peers(), responses=[], collect=True)
    assert [e for e in graph["edges"] if e["kind"] == "connected"] == []
