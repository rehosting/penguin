"""Host-side tests for NetBinds' syscall-backed source (source: syscalls), which
builds bind/release events from the guest's socket/bind/listen/close syscalls
for kernels without igloo's socket hooks. Drives the real plugin through the
penguin.testing harness; announcements are immediate (announce_debounce_s 0)."""
import socket
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
NETBINDS = REPO_ROOT / "pyplugins" / "analysis" / "netbinds.py"


class FakeMem:
    """plugins.mem double: guest addresses map to byte strings."""

    def __init__(self):
        self.data = {}

    def read_bytes(self, addr, size):
        return self.data[addr][:size]
        yield  # a generator, like the real portal call


class FakeOsi:
    def __init__(self, name="httpd"):
        self.name = name

    def get_proc_name(self, pid=None):
        return self.name
        yield


def _sin(ip, port):
    return struct.pack("<H", socket.AF_INET) + struct.pack(">H", port) + socket.inet_aton(ip) + bytes(8)


def _sin6(ip, port):
    return (struct.pack("<H", socket.AF_INET6) + struct.pack(">H", port) + bytes(4)
            + socket.inet_pton(socket.AF_INET6, ip) + bytes(4))


def _load(tmp_path, **args):
    args.setdefault("source", "syscalls")
    args.setdefault("announce_debounce_s", 0)
    args.setdefault("debounce_period", 0)
    Path(tmp_path).mkdir(parents=True, exist_ok=True)
    mem = FakeMem()
    lp = load_pyplugin(str(NETBINDS), outdir=tmp_path, args=args,
                       doubles={"mem": mem, "osi": FakeOsi()})
    return lp, mem


def _sc(retval, pid=100):
    return SimpleNamespace(retval=retval, pid=pid)


def _socket(lp, fd, family=2, type_=1, pid=100):
    lp.dispatch_syscall("socket", None, None, _sc(fd, pid), family, type_, 0)


def _bind(lp, mem, fd, sa, ret=0, pid=100, addr=0x1000):
    mem.data[addr] = sa
    lp.dispatch_syscall("bind", None, None, _sc(ret, pid), fd, addr, len(sa))


def _listen(lp, fd, ret=0, pid=100):
    lp.dispatch_syscall("listen", None, None, _sc(ret, pid), fd, 5)


def _close(lp, fd, ret=0, pid=100):
    lp.dispatch_syscall("close", None, None, _sc(ret, pid), fd)


def _announced(lp):
    return [args for (_p, ev, args, _k) in lp.published if ev == "on_bind"]


def _states(lp):
    return {(r["sock_type"], r["ip"], r["port"]): r["state"] for r in lp.plugin.sockets.values()}


# ---- source selection ----

def test_pick_source(tmp_path):
    lp, _ = _load(tmp_path)
    pick = type(lp.plugin).__init__.__globals__["pick_source"]
    assert pick(None) == "igloo"
    assert pick("igloo") == "igloo"
    assert pick("syscalls") == "syscalls"
    with pytest.raises(ValueError):
        pick("auto")


def test_syscalls_source_hooks_syscalls_not_igloo_events(tmp_path):
    lp, _ = _load(tmp_path)
    hooked = {h["name"] for h in lp.manager.syscall_hooks}
    assert hooked == {"socket", "bind", "listen", "close"}
    assert not [ev for (_p, ev, _c) in lp.subscriptions if ev.startswith("igloo_ipv")]


def test_igloo_source_is_unchanged(tmp_path):
    lp, _ = _load(tmp_path, source="igloo")
    assert not lp.manager.syscall_hooks
    assert "igloo_ipv4_bind" in {ev for (_p, ev, _c) in lp.subscriptions}


# ---- decoding ----

def test_decode_sockaddr(tmp_path):
    lp, _ = _load(tmp_path)
    decode = type(lp.plugin).__init__.__globals__["decode_sockaddr"]
    assert decode(_sin("192.168.1.1", 80), True) == (4, "192.168.1.1", 80)
    assert decode(_sin6("::", 443), True) == (6, "[::]", 443)
    big = struct.pack(">H", socket.AF_INET) + _sin("10.0.0.1", 53)[2:]
    assert decode(big, False) == (4, "10.0.0.1", 53)
    assert decode(struct.pack("<H", 1) + bytes(14), True) is None  # AF_UNIX
    assert decode(b"\x02", True) is None


# ---- lifecycle ----

def test_tcp_and_udp_binds_are_typed_by_socket(tmp_path):
    lp, mem = _load(tmp_path)
    _socket(lp, 3, type_=1)
    _bind(lp, mem, 3, _sin("192.168.1.1", 80))
    _socket(lp, 4, type_=2 | 0x80000)  # SOCK_DGRAM | SOCK_CLOEXEC
    _bind(lp, mem, 4, _sin("0.0.0.0", 53))
    assert _announced(lp) == [("tcp", 4, "192.168.1.1", 80, "httpd"),
                              ("udp", 4, "0.0.0.0", 53, "httpd")]
    rec = next(r for r in lp.plugin.sockets.values() if r["port"] == 80)
    assert rec["pid"] == 100


def test_ipv6_bind(tmp_path):
    lp, mem = _load(tmp_path)
    _socket(lp, 3, family=10)
    _bind(lp, mem, 3, _sin6("::", 22))
    assert _announced(lp) == [("tcp", 6, "[::]", 22, "httpd")]


def test_skips_failures_port_zero_and_other_families(tmp_path):
    lp, mem = _load(tmp_path)
    _socket(lp, 3)
    _bind(lp, mem, 3, _sin("0.0.0.0", 80), ret=-98)  # EADDRINUSE
    _bind(lp, mem, 3, _sin("0.0.0.0", 0))           # kernel picks the port
    _socket(lp, 5, family=1)                         # AF_UNIX
    _bind(lp, mem, 5, struct.pack("<H", 1) + b"/tmp/sock\0")
    _socket(lp, -24)                                 # EMFILE
    assert _announced(lp) == []


def test_close_releases_only_the_binding_fd(tmp_path):
    lp, mem = _load(tmp_path)
    _socket(lp, 3)
    _bind(lp, mem, 3, _sin("0.0.0.0", 80))
    _close(lp, 3, pid=101)  # a forked child closing its copy
    _close(lp, 7)           # some other fd
    assert _states(lp) == {("tcp", "0.0.0.0", 80): "listening"}
    _close(lp, 3)
    lp.finalize()
    assert _states(lp) == {("tcp", "0.0.0.0", 80): "closed"}


def test_fd_reuse_forgets_the_old_socket(tmp_path):
    lp, mem = _load(tmp_path)
    _socket(lp, 3, type_=2)
    _bind(lp, mem, 3, _sin("0.0.0.0", 53))
    _close(lp, 3)
    _socket(lp, 3, type_=1)  # fd 3 reused for a TCP client: no bind
    _close(lp, 3)
    lp.finalize()
    assert _states(lp) == {("udp", "0.0.0.0", 53): "closed"}


def test_untyped_bind_is_tcp_once_it_listens(tmp_path):
    lp, mem = _load(tmp_path)
    _bind(lp, mem, 9, _sin("127.0.0.1", 5152))  # socket() not seen
    _bind(lp, mem, 10, _sin("0.0.0.0", 9999))   # never listens: dropped
    assert _announced(lp) == []
    _listen(lp, 9)
    assert _announced(lp) == [("tcp", 4, "127.0.0.1", 5152, "httpd")]
    _close(lp, 9)
    lp.finalize()
    assert _states(lp) == {("tcp", "127.0.0.1", 5152): "closed"}


def test_fd_tables_survive_a_restore(tmp_path):
    lp, mem = _load(tmp_path / "a")
    _socket(lp, 3)
    _bind(lp, mem, 3, _sin("0.0.0.0", 80))
    _socket(lp, 4, type_=2)
    state = lp.plugin.save_state()

    lp2, mem2 = _load(tmp_path / "b")
    lp2.plugin.load_state(state)
    lp2.plugin.on_restore("warm")
    assert _states(lp2) == {("tcp", "0.0.0.0", 80): "listening"}
    _bind(lp2, mem2, 4, _sin("0.0.0.0", 53))  # socket() was before the save
    _close(lp2, 3)
    lp2.finalize()
    assert _states(lp2) == {("tcp", "0.0.0.0", 80): "closed",
                            ("udp", "0.0.0.0", 53): "listening"}


def test_default_source_is_igloo(tmp_path):
    lp = load_pyplugin(str(NETBINDS), outdir=tmp_path, args={})
    assert lp.plugin.source == "igloo"
    assert not lp.manager.syscall_hooks
    assert "igloo_ipv4_release" in {ev for (_p, ev, _c) in lp.subscriptions}
