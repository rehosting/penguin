"""Host-side tests for the guest ``penguest`` binding (draft 16, Slice 0).

``penguest`` is guest code, but its host-testable contract is that
:func:`penguest.portal_call` packs the ``sendto`` syscall exactly like
``penguin/guest-utils/native/portal_call.h`` -- so the host portalcall
dispatcher (``pyplugins/apis/portalcall.py``) reads it back correctly and lands
at the matching ``@portalcall`` handler.

Two levels:
  * packing (always runs): substitute ``penguest._syscall`` and assert the
    register values + the in-memory arg array match the ABI.
  * round-trip (skips offline): let ``penguest`` pack a real buffer and feed the
    SAME pointer to the *real* ``portalcall.py`` dispatcher via the test harness,
    proving both ends agree. The in-guest boot round-trip is an integration
    fixture that comes once the module + interpreter are staged (Steps 3/4).

The interpreter running these tests is the host's own CPython (it has ctypes and
libc), which is enough to exercise the packing without any guest.
"""
import ctypes
import importlib.util
import os
import socket
import sys
import tarfile
import tempfile
import textwrap
import threading
import time
from pathlib import Path

import pytest

import penguin.penguin_config as pc

REPO_ROOT = Path(__file__).resolve().parents[2]
PENGUEST_SRC = REPO_ROOT / "src" / "resources" / "penguest" / "__init__.py"
PORTALCALL = str(REPO_ROOT / "pyplugins" / "apis" / "portalcall.py")
PENGUEST_HOST = str(REPO_ROOT / "pyplugins" / "apis" / "penguest.py")
PENGUEST_VSOCK = str(REPO_ROOT / "pyplugins" / "apis" / "penguest_vsock.py")
PENGUEST_TEST_PLUGIN = str(REPO_ROOT / "pyplugins" / "testing" / "penguest_test.py")

DEMO_MAGIC = 0x70656E67  # "peng"; a 32-bit user_magic


def demo_sum_handler(a, b):
    """Demo @portalcall handler: sum the two args (module-level so its bare
    ``__qualname__`` isn't mistaken for a ``Class.method`` to re-resolve)."""
    return (a + b) & 0xFFFFFFFF


def _load_penguest():
    # Load as a package so `from . import vsock` resolves against the submodule.
    spec = importlib.util.spec_from_file_location(
        "penguest", PENGUEST_SRC,
        submodule_search_locations=[str(PENGUEST_SRC.parent)])
    mod = importlib.util.module_from_spec(spec)
    sys.modules["penguest"] = mod  # so the relative import finds the package
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def penguest():
    return _load_penguest()


# --------------------------------------------------------------------------- #
# sendto syscall-number resolution
# --------------------------------------------------------------------------- #
def test_sendto_nr_env_override_wins(penguest, monkeypatch):
    monkeypatch.setenv("PENGUEST_SYS_SENDTO", "1234")
    assert penguest._resolve_sendto_nr() == 1234
    monkeypatch.setenv("PENGUEST_SYS_SENDTO", "0x2c")
    assert penguest._resolve_sendto_nr() == 0x2C


def test_sendto_nr_table_by_machine(penguest, monkeypatch):
    monkeypatch.delenv("PENGUEST_SYS_SENDTO", raising=False)
    cases = {
        "x86_64": 44, "aarch64": 206, "armv7l": 290, "riscv64": 206,
        "mips": 4183, "mips64": 5045, "ppc64le": 335, "loongarch64": 206,
    }
    for machine, expected in cases.items():
        monkeypatch.setattr(penguest.os, "uname",
                            lambda m=machine: type("U", (), {"machine": m})())
        assert penguest._resolve_sendto_nr() == expected, machine


def test_sendto_nr_unknown_arch_raises(penguest, monkeypatch):
    monkeypatch.delenv("PENGUEST_SYS_SENDTO", raising=False)
    monkeypatch.setattr(penguest.os, "uname",
                        lambda: type("U", (), {"machine": "s390x"})())
    with pytest.raises(penguest.PortalError):
        penguest._resolve_sendto_nr()


# --------------------------------------------------------------------------- #
# packing: portal_call lowers exactly like portal_call.h
# --------------------------------------------------------------------------- #
def test_portal_call_packs_like_portal_call_h(penguest, monkeypatch):
    monkeypatch.setenv("PENGUEST_SYS_SENDTO", "44")  # x86_64
    seen = {}

    def fake_syscall(nr, magic, user_magic, argc, argsptr, a4, a5):
        # Read the packed args now, while portal_call's buffer is still alive.
        arr = (ctypes.c_uint64 * argc).from_address(argsptr) if argc else []
        seen.update(nr=nr, magic=magic, user_magic=user_magic, argc=argc,
                    argv=[int(arr[i]) for i in range(argc)], a4=a4, a5=a5)
        return 0

    monkeypatch.setattr(penguest, "_syscall", fake_syscall)
    penguest.portal_call(DEMO_MAGIC, 0x11, 0xDEADBEEFF1F1F1F1)

    assert seen["nr"] == 44
    assert seen["magic"] == penguest.PORTAL_MAGIC        # arg0 = PORTAL_MAGIC
    assert seen["user_magic"] == DEMO_MAGIC              # arg1 = user_magic
    assert seen["argc"] == 2                             # arg2 = argc
    assert seen["argv"] == [0x11, 0xDEADBEEFF1F1F1F1]    # arg3 -> &args[]
    assert seen["a4"] == 0 and seen["a5"] == 0           # dest_addr, addrlen


def test_portal_call_zero_args_ok(penguest, monkeypatch):
    monkeypatch.setenv("PENGUEST_SYS_SENDTO", "44")
    seen = {}
    monkeypatch.setattr(penguest, "_syscall",
                        lambda nr, m, um, argc, p, a4, a5: seen.update(argc=argc) or 7)
    assert penguest.portal_call(DEMO_MAGIC) == 7
    assert seen["argc"] == 0


def test_portal_call_rejects_too_many_args(penguest, monkeypatch):
    monkeypatch.setattr(penguest, "_syscall", lambda *a: 0)
    with pytest.raises(penguest.PortalError):
        penguest.portal_call(DEMO_MAGIC, *range(penguest._MAX_ARGS + 1))


# --------------------------------------------------------------------------- #
# round-trip: penguest packs -> real portalcall.py dispatches -> handler runs
# --------------------------------------------------------------------------- #
class _MemDouble:
    """Satisfies portalcall's ``plugins.mem.read_uint64_array`` by reading the
    guest arg array straight out of the host address penguest packed it at."""

    def read_uint64_array(self, addr, count):
        arr = (ctypes.c_uint64 * count).from_address(addr)
        vals = [int(arr[i]) for i in range(count)]
        if False:  # make this a generator (the caller does `yield from`)
            yield
        return vals


def test_roundtrip_penguest_to_portalcall_handler(penguest, monkeypatch, tmp_path,
                                                  igloo_ko_isf):
    from penguin.testing import drive, load_pyplugin

    monkeypatch.setenv("PENGUEST_SYS_SENDTO", "44")
    lp = load_pyplugin(PORTALCALL, outdir=tmp_path,
                       doubles={"mem": _MemDouble()}, real_isf=igloo_ko_isf)

    # The demo handler: sum the args (exercises the arg-array read path).
    lp.plugin.portalcall(DEMO_MAGIC)(demo_sum_handler)

    box = {}

    def fake_syscall(nr, magic, user_magic, argc, argsptr, a4, a5):
        # Dispatch on the host while penguest's buffer is still alive. This is
        # the genuine host code path: read_uint64_array -> registered handler.
        ret, _ = drive(lp.plugin._dispatch_portalcall(user_magic, argc, argsptr),
                       responses=[], collect=True)
        box["ret"] = ret
        return ret

    monkeypatch.setattr(penguest, "_syscall", fake_syscall)
    rv = penguest.portal_call(DEMO_MAGIC, 0x11, 0x22)
    assert rv == 0x33
    assert box["ret"] == 0x33


# --------------------------------------------------------------------------- #
# staging: penguest lands in static_files under /igloo/pylib (Slice 1)
# --------------------------------------------------------------------------- #
def test_penguest_staged_into_guest_pylib():
    with tempfile.TemporaryDirectory() as tmp:
        proj = Path(tmp, "proj")
        (proj / "base").mkdir(parents=True)
        with tarfile.open(proj / "base" / "fs.tar.gz", "w"):
            pass
        (proj / "config.yaml").write_text(textwrap.dedent("""
            core: {arch: armel, version: 2}
            env: {}
            pseudofiles: {}
            nvram: {}
            lib_inject: {}
            static_files: {}
            plugins: {}
        """))
        cfg = pc.load_config(
            str(proj), str(proj / "config.yaml"), validate=True,
            resolved_kernel="/igloo_static/kernels/6.13/zImage.armel",
        )

    entry = cfg["static_files"]["/igloo/pylib/penguest/__init__.py"]
    assert entry["type"] == "host_file"
    assert entry["mode"] == 0o644
    assert entry["host_path"] == str(PENGUEST_SRC)
    # The whole package is staged, not just __init__ -- vsock.py too.
    vs = cfg["static_files"]["/igloo/pylib/penguest/vsock.py"]
    assert vs["type"] == "host_file"
    assert vs["host_path"] == str(PENGUEST_SRC.parent / "vsock.py")


# --------------------------------------------------------------------------- #
# penguest.vsock: AF_VSOCK wrapper (guest transport)
# --------------------------------------------------------------------------- #
def test_vsock_json_framing_roundtrip(penguest):
    # A real AF_UNIX stream pair stands in for the vsock stream; the framing
    # (4-byte length prefix + JSON) is transport-agnostic.
    a, b = socket.socketpair()
    try:
        ca, cb = penguest.vsock.VsockConn(a), penguest.vsock.VsockConn(b)
        ca.send_json({"op": "ping", "n": 5, "s": "héllo"})
        assert cb.recv_json() == {"op": "ping", "n": 5, "s": "héllo"}
        cb.send_json([1, 2, 3])
        assert ca.recv_json() == [1, 2, 3]
    finally:
        a.close()
        b.close()


def test_vsock_recv_json_raises_on_short_stream(penguest):
    a, b = socket.socketpair()
    try:
        # Send a length header claiming 10 bytes, then close with none sent.
        a.sendall(penguest.vsock._LEN.pack(10))
        a.close()
        with pytest.raises(penguest.vsock.VsockError):
            penguest.vsock.VsockConn(b).recv_json()
    finally:
        b.close()


def test_vsock_connect_without_af_vsock_raises(penguest, monkeypatch):
    monkeypatch.delattr(socket, "AF_VSOCK", raising=False)
    with pytest.raises(penguest.vsock.VsockError, match="AF_VSOCK"):
        penguest.vsock.connect(port=9999)


def test_vsock_connect_targets_host_cid(penguest, monkeypatch):
    calls = {}

    class _FakeSock:
        def __init__(self, family, type_):
            calls["family"], calls["type"] = family, type_

        def settimeout(self, t):
            calls["timeout"] = t

        def connect(self, addr):
            calls["addr"] = addr

        def close(self):
            calls["closed"] = True

    monkeypatch.setattr(socket, "AF_VSOCK", 40, raising=False)
    monkeypatch.setattr(penguest.vsock.socket, "socket",
                        lambda fam, typ: _FakeSock(fam, typ))
    conn = penguest.vsock.connect(port=9999, timeout=3)
    assert calls["family"] == 40                       # AF_VSOCK
    assert calls["type"] == socket.SOCK_STREAM
    assert calls["addr"] == (penguest.vsock.VMADDR_CID_HOST, 9999)  # host = CID 2
    assert calls["timeout"] == 3
    assert isinstance(conn, penguest.vsock.VsockConn)


# --------------------------------------------------------------------------- #
# penguest.log / report: pack a string over the portal
# --------------------------------------------------------------------------- #
def test_log_packs_string_pointer_and_level(penguest, monkeypatch):
    monkeypatch.setenv("PENGUEST_SYS_SENDTO", "44")
    seen = {}

    def fake_syscall(nr, magic, user_magic, argc, argsptr, a4, a5):
        arr = (ctypes.c_uint64 * argc).from_address(argsptr)
        strptr, length, level = int(arr[0]), int(arr[1]), int(arr[2])
        raw = ctypes.string_at(strptr, length)
        seen.update(magic=magic, user_magic=user_magic, argc=argc,
                    text=raw.decode(), level=level)
        return 0

    monkeypatch.setattr(penguest, "_syscall", fake_syscall)
    penguest.log("boot reached stage 2", level="warning")

    assert seen["magic"] == penguest.PORTAL_MAGIC
    assert seen["user_magic"] == penguest.PENGUEST_LOG_MAGIC
    assert seen["argc"] == 3
    assert seen["text"] == "boot reached stage 2"
    assert seen["level"] == penguest._LOG_LEVELS["warning"]


def test_report_uses_finding_level(penguest, monkeypatch):
    monkeypatch.setenv("PENGUEST_SYS_SENDTO", "44")
    seen = {}
    monkeypatch.setattr(penguest, "_syscall",
                        lambda nr, m, um, argc, p, a4, a5:
                        seen.update(level=int((ctypes.c_uint64 * argc)
                                              .from_address(p)[2])) or 0)
    penguest.report("suspicious write to /dev/mtd0")
    assert seen["level"] == penguest._LOG_LEVELS["finding"]


# --------------------------------------------------------------------------- #
# host bridge: handle_log reads guest memory and logs (Penguest pyplugin)
# --------------------------------------------------------------------------- #
class _MemBytesDouble:
    def read_bytes(self, addr, size):
        data = ctypes.string_at(addr, size)
        if False:  # generator (caller does `yield from`)
            yield
        return data


class _CapturingLogger:
    def __init__(self):
        self.records = []

    def _rec(self, level):
        # Match logging.Logger.<level>(msg, *args): args are %-formatted.
        def rec(msg, *args):
            self.records.append((level, (msg % args) if args else msg))
        return rec

    def __getattr__(self, level):
        return self._rec(level)


def test_host_bridge_handle_log_reads_and_logs(tmp_path):
    from penguin.testing import drive, load_pyplugin

    lp = load_pyplugin(PENGUEST_HOST, outdir=tmp_path,
                       doubles={"mem": _MemBytesDouble()})
    logger = _CapturingLogger()
    lp.plugin.logger = logger

    data = b"hello from guest"
    buf = ctypes.create_string_buffer(data, len(data))
    ret, _ = drive(lp.plugin.handle_log(ctypes.addressof(buf), len(data), 4),
                   collect=True)  # level 4 = finding
    assert ret == 0
    assert logger.records == [("info", "[guest finding] hello from guest")]


def test_host_bridge_handle_log_zero_length(tmp_path):
    from penguin.testing import drive, load_pyplugin

    lp = load_pyplugin(PENGUEST_HOST, outdir=tmp_path,
                       doubles={"mem": _MemBytesDouble()})
    logger = _CapturingLogger()
    lp.plugin.logger = logger
    ret, _ = drive(lp.plugin.handle_log(0, 0, 1), collect=True)  # level 1 = info
    assert ret == 0
    assert logger.records == [("info", "[guest] ")]


def test_host_bridge_persists_guest_log_to_file(tmp_path):
    from penguin.testing import drive, load_pyplugin

    lp = load_pyplugin(PENGUEST_HOST, outdir=tmp_path,
                       doubles={"mem": _MemBytesDouble()})
    lp.plugin.logger = _CapturingLogger()

    msg = b"a finding worth keeping"
    buf = ctypes.create_string_buffer(msg, len(msg))
    drive(lp.plugin.handle_log(ctypes.addressof(buf), len(msg), 4), collect=True)

    log_file = tmp_path / "penguest_guest.log"
    assert log_file.exists()
    assert log_file.read_text() == "finding\ta finding worth keeping\n"


# --------------------------------------------------------------------------- #
# penguest_test integration plugin: host handler logic
# --------------------------------------------------------------------------- #
# These mirror PENGUEST_ARG1/2 in pyplugins/testing/penguest_test.py and the
# /tests/penguest.py driver in penguest.yaml; they must stay in sync.
_TEST_A1 = 0xDEADBEEFF1F1F1F1
_TEST_A2 = 0x1337C0DEFEEDC0DE


def test_penguest_test_plugin_writes_pass_on_correct_args(tmp_path):
    from penguin.testing import load_pyplugin

    lp = load_pyplugin(PENGUEST_TEST_PLUGIN, outdir=tmp_path)
    assert lp.plugin.handle_test(_TEST_A1, _TEST_A2) == 13
    assert (tmp_path / "penguest_test.txt").read_text() == "PENGUEST test: passed\n"


def test_penguest_test_plugin_writes_fail_on_wrong_args(tmp_path):
    from penguin.testing import load_pyplugin

    lp = load_pyplugin(PENGUEST_TEST_PLUGIN, outdir=tmp_path)
    lp.plugin.logger = _CapturingLogger()
    assert lp.plugin.handle_test(0x1, 0x2) == 13
    assert (tmp_path / "penguest_test.txt").read_text() == "PENGUEST test: failed\n"


# --------------------------------------------------------------------------- #
# host vsock endpoint: dispatch + guest-client round-trip (Slice 3)
# --------------------------------------------------------------------------- #
def _boom(req):
    raise RuntimeError("boom")


def test_vsock_endpoint_dispatch(tmp_path):
    from penguin.testing import load_pyplugin

    lp = load_pyplugin(PENGUEST_VSOCK, outdir=tmp_path, args={"vpn_enabled": False})
    lp.plugin.logger = _CapturingLogger()
    assert lp.plugin.dispatch({"op": "ping"}) == {"pong": True}
    assert lp.plugin.dispatch({"op": "echo", "data": [1, 2]}) == {"echo": [1, 2]}
    assert "error" in lp.plugin.dispatch({"op": "nope"})
    assert "error" in lp.plugin.dispatch("not-a-dict")
    lp.plugin.register("boom", _boom)
    assert lp.plugin.dispatch({"op": "boom"}) == {"error": "boom"}
    # Disabled (no vsock) -> no listener thread was started.
    assert lp.plugin._thread is None


def test_vsock_endpoint_serves_guest_client(tmp_path):
    from penguin.testing import load_pyplugin

    penguest = _load_penguest()
    lp = load_pyplugin(PENGUEST_VSOCK, outdir=tmp_path, args={"vpn_enabled": False})
    # Guest client (penguest.vsock) and host endpoint agree on the port + framing.
    assert lp.plugin.port == penguest.vsock.PENGUEST_VSOCK_PORT

    a, b = socket.socketpair()
    t = threading.Thread(target=lp.plugin._serve_conn, args=(a,), daemon=True)
    t.start()
    try:
        client = penguest.vsock.VsockConn(b)
        client.send_json({"op": "ping"})
        assert client.recv_json() == {"pong": True}
        client.send_json({"op": "echo", "data": {"k": "v"}})
        assert client.recv_json() == {"echo": {"k": "v"}}
    finally:
        b.close()          # EOF -> _serve_conn returns
        t.join(timeout=2)
        a.close()
    assert not t.is_alive()


def test_vsock_endpoint_live_listener_and_teardown(tmp_path):
    # Exercise the real accept loop + teardown: with vsock "enabled", the plugin
    # binds <uds_path>_<port> (a plain AF_UNIX socket here) and serves clients on
    # a background thread. This is exactly what vhost-device-vsock connects to for
    # a guest-initiated connection.
    from penguin.testing import load_pyplugin

    penguest = _load_penguest()
    uds = tmp_path / "vsocket"
    lp = load_pyplugin(PENGUEST_VSOCK, outdir=tmp_path,
                       args={"vpn_enabled": True, "uds_path": str(uds)})
    lp.plugin.logger = _CapturingLogger()
    sock_path = f"{uds}_{penguest.vsock.PENGUEST_VSOCK_PORT}"
    try:
        assert lp.plugin._thread is not None
        for _ in range(200):                     # wait for bind()/listen()
            if os.path.exists(sock_path):
                break
            time.sleep(0.005)
        assert os.path.exists(sock_path)

        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(sock_path)
        client = penguest.vsock.VsockConn(c)
        client.send_json({"op": "echo", "data": "roundtrip"})
        assert client.recv_json() == {"echo": "roundtrip"}
        c.close()
    finally:
        lp.plugin.uninit()

    assert not lp.plugin._thread.is_alive()      # thread joined
    assert not os.path.exists(sock_path)         # socket unlinked


def test_vsock_endpoint_stalled_conn_does_not_wedge(tmp_path):
    # A guest that connects and stalls mid-frame must not block other clients
    # (per-connection workers) -- the hardening that matters most for untrusted
    # guest input.
    from penguin.testing import load_pyplugin

    penguest = _load_penguest()
    uds = tmp_path / "vsocket"
    lp = load_pyplugin(PENGUEST_VSOCK, outdir=tmp_path,
                       args={"vpn_enabled": True, "uds_path": str(uds)})
    lp.plugin.logger = _CapturingLogger()
    sock_path = f"{uds}_{penguest.vsock.PENGUEST_VSOCK_PORT}"
    stalled = None
    try:
        for _ in range(200):
            if os.path.exists(sock_path):
                break
            time.sleep(0.005)
        # Connection 1: send a length header, then nothing (stall mid-frame).
        stalled = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        stalled.connect(sock_path)
        stalled.sendall(b"\x00\x00\x00\x10")  # promises 16 bytes, sends none

        # Connection 2 must still be served concurrently.
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(sock_path)
        client = penguest.vsock.VsockConn(c)
        client.send_json({"op": "ping"})
        assert client.recv_json() == {"pong": True}
        c.close()
    finally:
        if stalled is not None:
            stalled.close()
        lp.plugin.uninit()


def test_vsock_endpoint_connection_cap(tmp_path):
    from penguin.testing import load_pyplugin

    penguest = _load_penguest()
    uds = tmp_path / "vsocket"
    lp = load_pyplugin(PENGUEST_VSOCK, outdir=tmp_path,
                       args={"vpn_enabled": True, "uds_path": str(uds),
                             "vsock_max_conns": 1})
    lp.plugin.logger = _CapturingLogger()
    sock_path = f"{uds}_{penguest.vsock.PENGUEST_VSOCK_PORT}"
    hold = None
    try:
        for _ in range(200):
            if os.path.exists(sock_path):
                break
            time.sleep(0.005)
        # Hold the one allowed slot open (stalled mid-frame).
        hold = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        hold.connect(sock_path)
        hold.sendall(b"\x00\x00\x00\x10")
        time.sleep(0.05)  # let the worker acquire the sole slot

        # Over the cap -> the endpoint drops the connection (closes it).
        over = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        over.connect(sock_path)
        client = penguest.vsock.VsockConn(over)
        # Server dropped it (over cap) -> the send or the read hits the closed
        # peer; either way the guest surfaces a VsockError.
        with pytest.raises(penguest.vsock.VsockError):
            client.send_json({"op": "ping"})
            client.recv_json()
        over.close()
    finally:
        if hold is not None:
            hold.close()
        lp.plugin.uninit()


# --------------------------------------------------------------------------- #
# host bridge hardening: sanitize guest-controlled log text + bound the file
# --------------------------------------------------------------------------- #
def test_host_bridge_sanitizes_control_chars(tmp_path):
    from penguin.testing import drive, load_pyplugin

    lp = load_pyplugin(PENGUEST_HOST, outdir=tmp_path,
                       doubles={"mem": _MemBytesDouble()})
    logger = _CapturingLogger()
    lp.plugin.logger = logger

    # newline (log-line forgery) + ANSI escape (terminal injection) + NUL.
    evil = b"line1\nFAKE level\x1b[31mred\x00end"
    buf = ctypes.create_string_buffer(evil, len(evil))
    drive(lp.plugin.handle_log(ctypes.addressof(buf), len(evil), 1), collect=True)

    level, msg = logger.records[0]
    assert level == "info"
    assert "\n" not in msg and "\x1b" not in msg and "\x00" not in msg
    assert msg == "[guest] line1�FAKE level�[31mred�end"
    # The persisted line is single-line (no injected newline before its own).
    assert (tmp_path / "penguest_guest.log").read_text().count("\n") == 1


def test_host_bridge_log_file_is_bounded(tmp_path):
    from penguin.testing import drive, load_pyplugin

    lp = load_pyplugin(PENGUEST_HOST, outdir=tmp_path,
                       args={"guest_log_max_bytes": 64},
                       doubles={"mem": _MemBytesDouble()})
    lp.plugin.logger = _CapturingLogger()

    chunk = b"x" * 40
    buf = ctypes.create_string_buffer(chunk, len(chunk))
    for _ in range(5):  # 5 * ~48 bytes > 64-byte cap
        drive(lp.plugin.handle_log(ctypes.addressof(buf), len(chunk), 1),
              collect=True)

    assert lp.plugin._log_capped
    assert (tmp_path / "penguest_guest.log").stat().st_size <= 64
