"""penguest.vsock -- guest-side AF_VSOCK wrappers.

For payloads bigger or streamier than a portalcall's register args, guest scripts
talk to the host over vsock (the transport is already wired: the custom QEMU
builds ``CONFIG_AF_VSOCK`` and Penguin launches ``vhost-device-vsock`` for the
guest, see ``pyplugins/actuation/vpn.py``). From inside the guest the host is
always CID ``2`` (``VMADDR_CID_HOST``).

It frames messages as length-prefixed JSON and, by default, connects to the host
``penguest`` vsock endpoint (``pyplugins/apis/penguest_vsock.py``), which serves
JSON request/response over ``PENGUEST_VSOCK_PORT``.

Example::

    import penguest
    with penguest.vsock.connect() as c:        # -> host penguest endpoint (CID 2)
        c.send_json({"op": "ping"})
        reply = c.recv_json()                  # {"pong": True}
"""

import json
import socket
import struct

__all__ = [
    "VMADDR_CID_HOST", "VMADDR_CID_ANY", "PENGUEST_VSOCK_PORT",
    "VsockError", "VsockConn", "connect",
]

# CIDs, from a guest's point of view. The host is always CID 2.
VMADDR_CID_HOST = 2
VMADDR_CID_ANY = 0xFFFFFFFF

# Default port of the host penguest vsock endpoint. Must match
# PENGUEST_VSOCK_PORT in pyplugins/apis/penguest_vsock.py.
PENGUEST_VSOCK_PORT = 0xC1D1  # 49617

# 4-byte big-endian length prefix on each JSON frame.
_LEN = struct.Struct("!I")
_MAX_FRAME = 64 * 1024 * 1024  # sanity cap so a bad length can't allocate wildly


class VsockError(RuntimeError):
    """Raised for vsock setup/transport problems (incl. no AF_VSOCK support)."""


class VsockConn:
    """A framed connection to a host vsock endpoint.

    Wraps a connected stream socket. ``send``/``recv`` move raw bytes;
    ``send_json``/``recv_json`` add a 4-byte big-endian length prefix so a
    receiver can recover message boundaries on a byte stream.
    """

    def __init__(self, sock):
        self._sock = sock

    # -- raw bytes ---------------------------------------------------------- #
    def send(self, data):
        try:
            self._sock.sendall(data)
        except OSError as e:
            raise VsockError(f"send failed: {e}")

    def _recvn(self, n):
        """Read exactly ``n`` bytes; raise :class:`VsockError` on EOF/error."""
        chunks = []
        remaining = n
        while remaining:
            try:
                chunk = self._sock.recv(remaining)
            except OSError as e:
                raise VsockError(f"recv failed: {e}")
            if not chunk:
                raise VsockError(
                    f"connection closed with {remaining} of {n} bytes unread")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    # -- framed JSON -------------------------------------------------------- #
    def send_json(self, obj):
        payload = json.dumps(obj).encode("utf-8")
        if len(payload) > _MAX_FRAME:
            raise VsockError(f"frame too large: {len(payload)} bytes")
        try:
            self._sock.sendall(_LEN.pack(len(payload)) + payload)
        except OSError as e:
            raise VsockError(f"send failed: {e}")

    def recv_json(self):
        (length,) = _LEN.unpack(self._recvn(_LEN.size))
        if length > _MAX_FRAME:
            raise VsockError(f"incoming frame too large: {length} bytes")
        return json.loads(self._recvn(length).decode("utf-8"))

    # -- lifecycle ---------------------------------------------------------- #
    def close(self):
        self._sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def connect(port=PENGUEST_VSOCK_PORT, cid=VMADDR_CID_HOST, timeout=None):
    """Open a framed vsock connection to ``(cid, port)`` -- the host penguest
    endpoint by default.

    Raises :class:`VsockError` if this Python build lacks AF_VSOCK support or the
    connection fails.
    """
    if not hasattr(socket, "AF_VSOCK"):
        raise VsockError("this Python build has no AF_VSOCK support")
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    try:
        if timeout is not None:
            sock.settimeout(timeout)
        sock.connect((cid, port))
    except OSError as e:
        sock.close()
        raise VsockError(f"vsock connect to (cid={cid}, port={port}) failed: {e}")
    return VsockConn(sock)
