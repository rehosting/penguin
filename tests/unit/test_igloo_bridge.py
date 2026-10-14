"""Host-side tests of the igloo_bridge pyplugin's wire protocol (the records
igloo.ko's kl_bridge exchanges over its hypercall). Protocol state only: no
QEMU, no sockets, no guest."""
import importlib.util
import socket
import struct
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]


def _bridge_module():
    spec = importlib.util.spec_from_file_location(
        "igloo_bridge_under_test",
        REPO_ROOT / "pyplugins" / "actuation" / "igloo_bridge.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def bridge():
    mod = _bridge_module()
    b = object.__new__(mod.IglooBridge)   # protocol state only, no QEMU
    b.conns, b.rst, b.next_id = {}, [], 0
    return mod, b


def _recs(mod, rx):
    out, off = [], 0
    while off < len(rx):
        typ, flags, ln, cid = mod.REC.unpack_from(rx, off)
        out.append((typ, flags, cid, bytes(rx[off + 8: off + 8 + ln])))
        off += 8 + mod._align(ln)
    return out


def _tx(mod, *recs):
    b = bytearray()
    for typ, flags, cid, payload in recs:
        b += mod.REC.pack(typ, flags, len(payload), cid) + payload
        b += b"\0" * (mod._align(len(payload)) - len(payload))
    return bytes(b)


def test_bridge_open_data_ack_close(bridge):
    mod, b = bridge
    c = mod._Conn(7, None, False, socket.inet_aton("127.0.0.1"), 80)
    b.conns[7] = c

    # host asks the guest to open 127.0.0.1:80
    (rec,) = _recs(mod, b._fill_rx())
    assert rec[:3] == (mod.H_OPEN, 0, 7)
    assert rec[3] == socket.inet_aton("127.0.0.1") + struct.pack(">H", 80) + b"\x06\0"

    # guest says opened, sends 5 bytes; host queues them for the client
    b._take_tx(_tx(mod, (mod.G_OPENED, 0, 7, struct.pack("<i", 0)),
                   (mod.G_DATA, 0, 7, b"hello")))
    assert c.state == mod.OPEN and bytes(c.out) == b"hello"

    # client data goes to the guest within the window; written bytes are acked
    c.inb += b"x" * 20000
    c.ack_owed = 5
    recs = _recs(mod, b._fill_rx())
    assert recs[0] == (mod.H_ACK, 0, 7, struct.pack("<I", 5))
    assert [r[0] for r in recs[1:]] == [mod.H_DATA, mod.H_DATA]
    assert sum(len(r[3]) for r in recs[1:]) == 20000
    assert c.guest_win == mod.WIN - 20000

    # client EOF becomes H_CLOSE once its data is out
    c.client_eof = True
    assert _recs(mod, b._fill_rx()) == [(mod.H_CLOSE, 0, 7, b"")]
    b._take_tx(_tx(mod, (mod.G_CLOSED, 0, 7, b"")))
    c.out.clear()
    assert c.done()


def test_bridge_ctl_refused(bridge):
    mod, b = bridge
    c = mod._Conn(1, None, True)
    c.line = bytearray(b"CONNECT 127.0.0.1 9")
    assert b._connect_line(c)
    c.state = mod.OPENING
    b.conns[1] = c
    b._fill_rx()
    b._take_tx(_tx(mod, (mod.G_OPENED, 0, 1, struct.pack("<i", -111))))
    assert bytes(c.out) == b"ERR -111\n" and c.out_noack == len(c.out)
    assert c.guest_eof and c.close_sent


def test_bridge_unknown_conn_gets_rst(bridge):
    mod, b = bridge
    b._take_tx(_tx(mod, (mod.G_DATA, 0, 42, b"stale"),
                   (mod.G_CLOSED, mod.RST, 43, b"")))
    assert _recs(mod, b._fill_rx()) == [(mod.H_CLOSE, mod.RST, 42, b"")]


def test_bridge_connect_line_parsing(bridge):
    mod, b = bridge
    for line, ok in ((b"CONNECT 80", True), (b"CONNECT 10.0.0.2 22\r", True),
                     (b"CONNECT", False), (b"CONNECT x 80", False),
                     (b"OPEN 80", False), (b"CONNECT 70000", False)):
        c = mod._Conn(1, None, True)
        c.line = bytearray(line)
        assert b._connect_line(c) is ok, line


class _Sock:
    closed = False

    def close(self):
        self.closed = True


def _with_snapshot_state(b):
    import logging
    import threading
    b.lock, b.saved, b.logger = threading.Lock(), {}, logging.getLogger("t")
    b._wake = lambda: None
    return b


def test_bridge_restore_resets_stale_conns(bridge):
    mod, b = bridge
    _with_snapshot_state(b)
    c = mod._Conn(5, _Sock(), False, socket.inet_aton("127.0.0.1"), 80)
    c.open_sent = True
    b.conns[5] = c
    b.conns[6] = mod._Conn(6, _Sock(), True)   # still in its handshake
    b.next_id = 6
    state = b.save_state()
    assert state == {"next_id": 6, "open": [5]}

    # a new process restores the snapshot; it already has a connection of its
    # own that the restored guest never saw
    _, b2 = bridge[0], object.__new__(mod.IglooBridge)
    b2.conns, b2.rst, b2.next_id = {}, [], 1
    _with_snapshot_state(b2)
    mine = mod._Conn(1, _Sock(), False, socket.inet_aton("127.0.0.1"), 80)
    mine.open_sent = True
    b2.conns[1] = mine
    b2.load_state(state)
    b2.on_restore("warm")
    assert b2.conns == {} and mine.sock.closed
    assert _recs(mod, b2._fill_rx()) == [(mod.H_CLOSE, mod.RST, 1, b""),
                                         (mod.H_CLOSE, mod.RST, 5, b"")]
    assert b2.next_id == 6   # new ids never reuse one the guest may hold
