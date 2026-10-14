"""
igloo_bridge: host end of igloo.ko's TCP bridge
===============================================

A stand-in for the vsock VPN on guest kernels that cannot have vsock (before
Linux 3.9, ``AF_MAX`` is compiled in below ``AF_VSOCK``; or no virtio
transport on the board). igloo.ko's ``kl_bridge`` thread opens TCP connections
*inside* the guest with in-kernel sockets and moves the bytes over one
guest-polled hypercall, so nothing runs in guest userspace and loopback-only
services are reachable.

This plugin serves that hypercall under penguin. The same protocol is served
by QEMU's ``-device igloo-bridge`` in runs without penguin.

Wire protocol (shared with the guest module, ``igloo_bridge_proto.h``): the
guest calls ``nr=IGLOO_BRIDGE_HC, r0=MAGIC, r1=tx phys, r2=tx len,
r3=rx phys``; the host consumes the tx records, writes rx records and
returns their length. A record is ``{u8 type, u8 flags, u16 len, u32 conn}``
plus payload padded to 4. Flow control is a per-connection credit window
returned with ACK records; close is a half close; RST aborts.

Arguments
---------

- ``fwd`` (list or str): forwards ``HOSTPORT-[GUESTIP:]GUESTPORT``; a string
  may hold several separated by ``+``. Each listens on ``host`` and
  connects inside the guest to GUESTIP (default 127.0.0.1).
- ``host`` (str): address the forwards listen on (default 0.0.0.0, i.e.
  reachable at the container's address).
- ``ctl`` (str): unix socket speaking the vhost-user-vsock handshake
  (``CONNECT [GUESTIP ]PORT\\n`` -> ``OK PORT\\n`` / ``ERR n\\n``, then the
  stream). Relative paths are under the run's output directory. Default
  ``bridge.sock``; empty disables it.

Writes ``bridge_endpoints.txt`` in the output directory.

Snapshots: the protocol carries its buffer addresses on every poll, so a
restored guest picks the bridge back up by itself. Its connections are another
matter: the guest's bridge thread comes back holding the ones it had at save
time, whose host sockets are gone. On restore the plugin resets those (their
ids are saved with the snapshot), drops its own connections, which the
restored guest never saw, and keeps ids increasing so a new connection never
reuses a stale one.
"""

import errno
import os
import selectors
import socket
import struct
import threading

import cffi

from penguin import Plugin, plugins

HC = 0x62726467           # "brdg"
MAGIC = 0x42524447        # "BRDG"
BUF = 65536
WIN = 65536
CHUNK = 16384

G_OPENED, G_DATA, G_CLOSED, G_ACK = 0x01, 0x02, 0x03, 0x04
H_OPEN, H_DATA, H_CLOSE, H_ACK = 0x81, 0x82, 0x83, 0x84
RST = 0x01

REC = struct.Struct("<BBHI")

HANDSHAKE, OPENING, OPEN = range(3)


def _align(n: int) -> int:
    return (n + 3) & ~3


class _Conn:
    def __init__(self, cid, sock, ctl, addr=b"", port=0):
        self.id = cid
        self.sock = sock
        self.ctl = ctl
        self.state = HANDSHAKE if ctl else OPENING
        self.addr = addr            # 4 bytes, network order
        self.port = port            # host order
        self.inb = bytearray()      # client -> guest, not yet sent
        self.out = bytearray()      # guest -> client, not yet written
        self.out_noack = 0          # leading bytes of out that are ours
        self.guest_win = WIN
        self.ack_owed = 0
        self.open_sent = self.client_eof = self.close_sent = False
        self.guest_eof = self.shut_wr = False
        self.host_rst = self.guest_rst = False
        self.line = bytearray()

    def reply(self, msg: str):
        b = msg.encode()
        self.out += b
        self.out_noack += len(b)

    def done(self) -> bool:
        if self.guest_rst:
            return True
        if self.host_rst:
            return self.close_sent or not self.open_sent
        return self.guest_eof and self.close_sent and not self.out


class IglooBridge(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.lock = threading.Lock()
        self.conns = {}
        self.rst = []
        # Connection ids start at a random base, so after a restore that
        # brought no saved state a new id is unlikely to hit one the guest
        # still holds.
        self.next_id = int.from_bytes(os.urandom(3), "little") << 4
        self.saved = {}
        self.attached = False
        self.listeners = {}         # sock -> (ctl, addr, port)
        self.endpoints = []

        self.ffi = cffi.FFI()
        self.ffi.cdef(
            "void physical_memory_read(uint64_t addr, void *buf, uint64_t len);"
            "void physical_memory_write(uint64_t addr, const void *buf, uint64_t len);")
        self.qlib = self.ffi.dlopen(str(self.panda.lib_path))

        host = self.get_arg("host") or "0.0.0.0"
        fwd = self.get_arg("fwd") or []
        if isinstance(fwd, str):
            fwd = [f for f in fwd.split("+") if f]
        for spec in fwd:
            self._add_fwd(host, str(spec))
        ctl = self.get_arg("ctl")
        if ctl is None:
            ctl = "bridge.sock"
        if ctl:
            if not os.path.isabs(ctl):
                ctl = os.path.join(self.outdir, ctl)
            self._add_ctl(ctl)
        if not self.listeners:
            raise ValueError("igloo_bridge: needs fwd and/or ctl")
        with open(os.path.join(self.outdir, "bridge_endpoints.txt"), "w") as f:
            f.write("".join(e + "\n" for e in self.endpoints))

        self.wake_r, self.wake_w = os.pipe()
        os.set_blocking(self.wake_r, False)
        os.set_blocking(self.wake_w, False)
        self.stopping = False
        self.thread = threading.Thread(target=self._io, name="igloo_bridge",
                                       daemon=True)
        self.thread.start()
        plugins.hypercall.register(HC, self._hypercall)

    # ---- setup ----

    def _add_fwd(self, host, spec):
        hp, sep, g = spec.partition("-")
        try:
            hport = int(hp)
            gip, _, gport = g.rpartition(":")
            gport = int(gport)
            addr = socket.inet_aton(gip or "127.0.0.1")
        except (ValueError, OSError):
            raise ValueError(f"igloo_bridge: bad fwd '{spec}' "
                             "(want HOSTPORT-[GUESTIP:]GUESTPORT)")
        if not sep or not (0 < hport < 65536 and 0 < gport < 65536):
            raise ValueError(f"igloo_bridge: bad fwd '{spec}'")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, hport))
        s.listen(16)
        s.setblocking(False)
        self.listeners[s] = (False, addr, gport)
        ep = f"tcp {host}:{hport} -> guest {socket.inet_ntoa(addr)}:{gport}"
        self.endpoints.append(ep)
        self.logger.info("igloo_bridge: %s", ep)

    def _add_ctl(self, path):
        if os.path.exists(path):
            os.unlink(path)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(path)
        s.listen(16)
        s.setblocking(False)
        self.listeners[s] = (True, b"", 0)
        self.endpoints.append(f"ctl {path}")
        self.logger.info("igloo_bridge: control socket %s", path)

    def _wake(self):
        try:
            os.write(self.wake_w, b"\0")
        except BlockingIOError:
            pass

    # ---- vCPU side: one exchange per guest poll ----

    def _hypercall(self, cpu):
        arg = self.panda.arch.get_arg
        if arg(cpu, 1, convention="syscall") & 0xFFFFFFFF != MAGIC:
            return None
        tx_pa = arg(cpu, 2, convention="syscall")
        tx_len = arg(cpu, 3, convention="syscall")
        rx_pa = arg(cpu, 4, convention="syscall")
        if tx_len > BUF:
            return None
        tx = b""
        if tx_len:
            buf = self.ffi.new("char[]", tx_len)
            self.qlib.physical_memory_read(tx_pa, buf, tx_len)
            tx = self.ffi.buffer(buf, tx_len)[:]
        with self.lock:
            if not self.attached:
                self.attached = True
                self.logger.info("igloo_bridge: guest attached (tx %#x rx %#x)",
                                 tx_pa, rx_pa)
            self._take_tx(tx)
            rx = self._fill_rx()
        if rx:
            self.qlib.physical_memory_write(rx_pa, bytes(rx), len(rx))
        if tx or rx:
            self._wake()
        return len(rx)

    def _take_tx(self, tx):
        off = 0
        while off + REC.size <= len(tx):
            typ, flags, ln, cid = REC.unpack_from(tx, off)
            p = tx[off + REC.size: off + REC.size + ln]
            if off + REC.size + ln > len(tx):
                break
            off += REC.size + _align(ln)
            c = self.conns.get(cid)
            if c is None:
                # gone here: retire it there
                if not (typ == G_CLOSED and flags & RST):
                    self.rst.append(cid)
                continue
            if typ == G_OPENED:
                (v,) = struct.unpack_from("<i", p)
                if c.state != OPENING:
                    continue
                if v == 0:
                    c.state = OPEN
                    if c.ctl:
                        c.reply(f"OK {c.port}\n")
                else:
                    if c.ctl:
                        c.reply(f"ERR {v}\n")
                    c.guest_eof = c.close_sent = True
            elif typ == G_DATA:
                c.out += p
            elif typ == G_ACK:
                (v,) = struct.unpack_from("<I", p)
                c.guest_win += v
            elif typ == G_CLOSED:
                c.guest_eof = True
                if flags & RST:
                    c.guest_rst = True

    def _fill_rx(self):
        rx = bytearray()

        def put(typ, flags, cid, payload=b""):
            need = REC.size + _align(len(payload))
            if len(rx) + need > BUF:
                return False
            rx.extend(REC.pack(typ, flags, len(payload), cid))
            rx.extend(payload)
            rx.extend(b"\0" * (_align(len(payload)) - len(payload)))
            return True

        while self.rst and put(H_CLOSE, RST, self.rst[0]):
            self.rst.pop(0)
        for c in list(self.conns.values()):
            if c.guest_rst:
                continue
            if c.host_rst:
                if c.open_sent and not c.close_sent and put(H_CLOSE, RST, c.id):
                    c.close_sent = True
                continue
            if c.state == OPENING and not c.open_sent:
                o = c.addr + struct.pack(">H", c.port) + bytes((6, 0))
                if put(H_OPEN, 0, c.id, o):
                    c.open_sent = True
                continue
            if c.state != OPEN:
                continue
            if c.ack_owed and put(H_ACK, 0, c.id, struct.pack("<I", c.ack_owed)):
                c.ack_owed = 0
            while c.inb and c.guest_win:
                n = min(len(c.inb), c.guest_win, CHUNK)
                if not put(H_DATA, 0, c.id, bytes(c.inb[:n])):
                    break
                del c.inb[:n]
                c.guest_win -= n
            if c.client_eof and not c.inb and not c.close_sent \
                    and put(H_CLOSE, 0, c.id):
                c.close_sent = True
        return rx

    # ---- I/O thread: host sockets ----

    def _accept(self, ls):
        ctl, addr, port = self.listeners[ls]
        try:
            s, _ = ls.accept()
        except OSError:
            return
        s.setblocking(False)
        self.next_id += 1
        self.conns[self.next_id] = _Conn(self.next_id, s, ctl, addr, port)

    def _connect_line(self, c):
        w = c.line.decode(errors="replace").replace("\r", "").split()
        if len(w) not in (2, 3) or w[0] != "CONNECT":
            return False
        try:
            c.addr = socket.inet_aton(w[1] if len(w) == 3 else "127.0.0.1")
            c.port = int(w[-1])
        except (ValueError, OSError):
            return False
        return 0 < c.port < 65536

    def _read(self, c):
        if c.state == HANDSHAKE:
            # byte at a time, so stream bytes after the line stay queued
            while len(c.line) < 63:
                try:
                    ch = c.sock.recv(1)
                except BlockingIOError:
                    return
                except OSError:
                    c.host_rst = True
                    return
                if not ch:
                    c.host_rst = True
                    return
                if ch == b"\n":
                    if self._connect_line(c):
                        c.state = OPENING
                    else:
                        c.reply("ERR bad request\n")
                        c.guest_eof = c.close_sent = True
                    return
                c.line += ch
            c.reply("ERR bad request\n")
            c.guest_eof = c.close_sent = True
            return
        n = min(16384, WIN - len(c.inb))
        if n <= 0:
            return
        try:
            d = c.sock.recv(n)
        except BlockingIOError:
            return
        except OSError:
            c.host_rst = True
            return
        if d:
            c.inb += d
        else:
            c.client_eof = True

    def _write(self, c):
        try:
            n = c.sock.send(c.out)
        except BlockingIOError:
            return
        except OSError as e:
            if e.errno not in (errno.EAGAIN, errno.EINTR):
                c.host_rst = True
            return
        if n <= c.out_noack:
            c.out_noack -= n
        else:
            c.ack_owed += n - c.out_noack
            c.out_noack = 0
        del c.out[:n]

    def _io(self):
        sel = selectors.DefaultSelector()
        while not self.stopping:
            for key in list(sel.get_map().values()):
                sel.unregister(key.fileobj)
            sel.register(self.wake_r, selectors.EVENT_READ, None)
            with self.lock:
                for ls in self.listeners:
                    sel.register(ls, selectors.EVENT_READ, ("l", ls))
                for c in self.conns.values():
                    ev = 0
                    if not c.client_eof and not c.host_rst and len(c.inb) < WIN:
                        ev |= selectors.EVENT_READ
                    if c.out:
                        ev |= selectors.EVENT_WRITE
                    if ev:
                        sel.register(c.sock, ev, ("c", c))
            ready = sel.select(0.5)
            with self.lock:
                for key, ev in ready:
                    if key.data is None:
                        try:
                            while os.read(self.wake_r, 64):
                                pass
                        except BlockingIOError:
                            pass
                    elif key.data[0] == "l":
                        self._accept(key.data[1])
                    else:
                        c = key.data[1]
                        if ev & selectors.EVENT_READ:
                            self._read(c)
                        if c.out and ev & selectors.EVENT_WRITE:
                            self._write(c)
                for cid, c in list(self.conns.items()):
                    if c.guest_eof and not c.out and not c.shut_wr:
                        try:
                            c.sock.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                        c.shut_wr = True
                    if c.done():
                        c.sock.close()
                        del self.conns[cid]

    # ---- snapshots ----

    def save_state(self):
        with self.lock:
            self.saved = {"next_id": self.next_id,
                          "open": sorted(c.id for c in self.conns.values()
                                         if c.open_sent)}
            return dict(self.saved)

    def load_state(self, data) -> None:
        self.saved = data or {}

    def on_restore(self, tag: str) -> None:
        """Reset the guest's connections from save time, close ours."""
        with self.lock:
            stale = set(self.saved.get("open", ()))
            for c in self.conns.values():
                if c.open_sent:
                    stale.add(c.id)
                try:
                    c.sock.close()
                except OSError:
                    pass
            self.conns.clear()
            self.rst.extend(sorted(stale - set(self.rst)))
            self.next_id = max(self.next_id, int(self.saved.get("next_id", 0)))
        self.logger.info("igloo_bridge: restored '%s', reset %d connection(s)",
                         tag, len(stale))
        self._wake()

    def uninit(self):
        self.stopping = True
        self._wake()
