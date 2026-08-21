"""Host-side tests for penguin's telnet-port probe (penguin.penguin_run).

Penguin does not own the root-shell telnet listener -- QEMU does, via
``-serial telnet:0.0.0.0:<port>,server,nowait`` (penguin_run.py). What penguin
owns is the *probe* that picks the port: ``_port_is_free`` / ``_random_free_port``
and the ``find_free_port`` search over them.

The bug these tests pin (draft 26 slice 0): the probe used a bare ``bind()``
with no ``SO_REUSEADDR``, so a port left in TIME_WAIT by a prior run's accepted
connection reported as busy even though QEMU (which sets SO_REUSEADDR on its
listener) could rebind it. That false negative made find_free_port skip usable
ports. The fix sets SO_REUSEADDR on the probe sockets to match QEMU.
"""
import socket

from contextlib import closing

from penguin.penguin_run import _port_is_free, _random_free_port


def test_port_is_free_true_for_unbound_port():
    port = _random_free_port()
    assert _port_is_free(port) is True


def test_port_is_free_false_while_listener_holds_it():
    # A live listener (SO_REUSEADDR set, as QEMU does) genuinely owns the port;
    # the probe must report it busy.
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        assert _port_is_free(port) is False


def test_port_in_time_wait_is_reported_free():
    """The regression: a TIME_WAIT port must probe as free (QEMU can rebind it).

    We manufacture a TIME_WAIT socket by completing then closing the active
    side of a loopback connection while the passive side is closed first, which
    parks the connecting socket's 4-tuple in TIME_WAIT. With SO_REUSEADDR on the
    probe, binding that local port succeeds; without it, it would raise
    EADDRINUSE and the probe would return a false negative.
    """
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        server_port = server.getsockname()[1]

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.bind(("127.0.0.1", 0))
        client_port = client.getsockname()[1]
        client.connect(("127.0.0.1", server_port))

        conn, _ = server.accept()
        # Close the accepted (passive) side first, then the active side: the
        # active side is the one that ends up in TIME_WAIT on its local port.
        conn.close()
        client.close()

        # The client's local port is now TIME_WAIT-encumbered. The probe must
        # still call it free because it sets SO_REUSEADDR.
        assert _port_is_free(client_port) is True
