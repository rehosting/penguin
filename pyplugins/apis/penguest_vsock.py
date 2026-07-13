"""Host vsock endpoint for the guest ``penguest.vsock`` client (draft 16, Slice 3).

The guest connects out to ``(CID 2, PENGUEST_VSOCK_PORT)`` (see
``penguest.vsock.connect``). With vhost-device-vsock a guest-initiated connection
to port P is forwarded to a host Unix socket at ``<uds_path>_<P>`` -- so this
plugin *listens* on that path, accepts connections, and serves length-prefixed
JSON requests off a background thread. It is the structured/streaming complement
to the synchronous ``portalcall`` path.

Register handlers by op name from any plugin::

    @plugins.penguest_vsock.endpoint("whoami")
    def _whoami(req):
        return {"pid": req.get("pid")}

Built-ins ``ping`` and ``echo`` give an out-of-the-box round-trip. The endpoint
is a no-op when vsock isn't enabled for the run.
"""

import json
import os
import socket
import struct
import threading

from penguin import Plugin

# Guest-visible vsock port for this endpoint. Must match PENGUEST_VSOCK_PORT in
# src/resources/penguest/vsock.py.
PENGUEST_VSOCK_PORT = 0xC1D1  # 49617

# Frame = 4-byte big-endian length + JSON. Must match src/resources/penguest/vsock.py.
# The cap here is a receiver-side sanity limit against a hostile guest; these are
# control-plane messages, so it is deliberately small (the guest's own cap can be
# larger -- each side bounds its own recv).
_LEN = struct.Struct("!I")
_MAX_FRAME = 4 * 1024 * 1024

# Defaults for the untrusted-input server (overridable via plugin args).
_DEFAULT_CONN_TIMEOUT = 10.0   # seconds; drop an idle/stalled guest connection
_DEFAULT_MAX_CONNS = 16        # concurrent connection cap


def _recvn(sock, n):
    chunks, remaining = [], n
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_frame(sock):
    """Read one framed JSON message, or None on clean EOF."""
    header = _recvn(sock, _LEN.size)
    if header is None:
        return None
    (length,) = _LEN.unpack(header)
    if length > _MAX_FRAME:
        raise ValueError(f"incoming frame too large: {length} bytes")
    body = _recvn(sock, length)
    if body is None:
        return None
    return json.loads(body.decode("utf-8"))


def _write_frame(sock, obj):
    payload = json.dumps(obj).encode("utf-8")
    sock.sendall(_LEN.pack(len(payload)) + payload)


class PenguestVsock(Plugin):
    """Host side of the guest ``penguest.vsock`` channel."""

    def __init__(self):
        self._handlers = {}
        self._stop = threading.Event()
        self._thread = None
        self._listen_sock = None
        self._sock_path = None

        # Built-in handlers so the channel round-trips out of the box.
        self.register("ping", lambda req: {"pong": True})
        self.register("echo", lambda req: {"echo": req.get("data")})

        self.port = int(self.get_arg("vsock_endpoint_port") or PENGUEST_VSOCK_PORT)
        self._conn_timeout = float(
            self.get_arg("vsock_conn_timeout") or _DEFAULT_CONN_TIMEOUT)
        self._max_conns = int(self.get_arg("vsock_max_conns") or _DEFAULT_MAX_CONNS)
        self._conn_sem = threading.Semaphore(self._max_conns)
        uds_path = self.get_arg("uds_path")
        if not self.get_arg_bool("vpn_enabled") or not uds_path:
            self.logger.debug(
                "penguest vsock endpoint disabled (no vsock/uds_path for this run)")
            return
        self._sock_path = f"{uds_path}_{self.port}"
        self._start_listener()

    # -- handler registry --------------------------------------------------- #
    def register(self, op, handler):
        """Register ``handler(request_dict) -> response_dict`` for op ``op``."""
        self._handlers[op] = handler
        return handler

    def endpoint(self, op):
        """Decorator form of :meth:`register`."""
        def deco(fn):
            self.register(op, fn)
            return fn
        return deco

    def dispatch(self, request):
        """Route one request dict to its handler; never raises."""
        if not isinstance(request, dict):
            return {"error": "request must be a JSON object"}
        op = request.get("op")
        handler = self._handlers.get(op)
        if handler is None:
            return {"error": f"unknown op {op!r}"}
        try:
            return handler(request)
        except Exception as e:  # a handler bug must not kill the accept loop
            self.logger.error(f"penguest vsock handler {op!r} raised: {e}")
            return {"error": str(e)}

    # -- transport ---------------------------------------------------------- #
    def _start_listener(self):
        try:
            if os.path.exists(self._sock_path):
                os.unlink(self._sock_path)
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(self._sock_path)
            sock.listen(8)
        except OSError as e:
            self.logger.error(
                f"penguest vsock endpoint: cannot listen on {self._sock_path}: {e}")
            return
        self._listen_sock = sock
        self._thread = threading.Thread(
            target=self._accept_loop, name="penguest-vsock", daemon=True)
        self._thread.start()
        self.logger.info(
            f"penguest vsock endpoint listening on {self._sock_path} "
            f"(guest port {self.port})")

    def _accept_loop(self):
        # A timeout makes accept() return periodically so shutdown is deterministic
        # -- closing the socket from another thread does NOT reliably wake a blocked
        # accept() on Linux.
        self._listen_sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self._listen_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break  # listener closed during shutdown
            try:
                # Hand each connection to a short-lived worker so one slow/hostile
                # guest can't wedge the accept loop, and cap concurrency so it
                # can't spawn unbounded threads. Over the cap -> drop immediately.
                if not self._conn_sem.acquire(blocking=False):
                    self.logger.warning(
                        "penguest vsock: connection cap (%d) reached; dropping",
                        self._max_conns)
                    conn.close()
                    continue
                threading.Thread(target=self._handle_conn, args=(conn,),
                                 name="penguest-vsock-conn", daemon=True).start()
            except Exception as e:  # never let one bad connection kill the loop
                self.logger.debug(f"penguest vsock accept error: {e}")
                conn.close()

    def _handle_conn(self, conn):
        try:
            # A per-connection timeout means a guest that connects and stalls
            # mid-frame is dropped rather than blocking a worker forever.
            conn.settimeout(self._conn_timeout)
            self._serve_conn(conn)
        except (OSError, ValueError) as e:
            self.logger.debug(f"penguest vsock connection error: {e}")
        finally:
            conn.close()
            self._conn_sem.release()

    def _serve_conn(self, conn):
        """Serve framed request/response exchanges until the client closes."""
        while True:
            request = _read_frame(conn)
            if request is None:
                return
            _write_frame(conn, self.dispatch(request))

    def uninit(self):
        self._stop.set()
        if self._listen_sock is not None:
            try:
                self._listen_sock.close()  # unblocks accept()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=2)
        if self._sock_path and os.path.exists(self._sock_path):
            try:
                os.unlink(self._sock_path)
            except OSError:
                pass
