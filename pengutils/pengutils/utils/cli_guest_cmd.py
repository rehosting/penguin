"""
Guest Command CLI
================

This script provides a command-line interface (CLI) for running a command in a rehosted guest via a vsock Unix socket.
It is inspired by guest_cmd.py and uses Click for the CLI interface.

Example usage
-------------

.. code-block:: bash

    cli_guest_cmd.py --socket /tmp/vsocket --port 12341234 "ls -l /"

Options
-------
- ``--socket``: Path to vsock Unix socket (default: auto-search for 'vsocket' in /tmp/*)
- ``--port``: Vsock port number (default: 12341234)
- ``command``: Command to run in the guest (required)

"""

import click
import socket as sock
import sys
import json
from pathlib import Path
from rich import print


def _resolve_vsocket(socket_path):
    """Helper to find the vsocket path."""
    if socket_path is None:
        unix_socket = list(Path('/tmp').glob('*/vsocket'))
    else:
        unix_socket = socket_path

    if unix_socket is None:
        return None, "[red]No vsocket found and no socket provided[/red]"

    if isinstance(unix_socket, list):
        if len(unix_socket) == 0:
            return None, "[red]No vsocket found in /tmp/*/[/red]"
        elif len(unix_socket) > 1:
            msg = "[red]Multiple vsockets found in /tmp/*/. Please specify with --socket[/red]\n"
            for s in unix_socket:
                msg += f" - {s}\n"
            return None, msg
        else:
            return str(unix_socket[0]), None

    return str(unix_socket), None


def _send_command(unix_socket, port, cmd_str):
    """Helper to send command over socket and parse JSON result."""
    s = None
    try:
        s = sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
        s.connect(unix_socket)
        s.settimeout(None)
        # Handshake
        connect_command = f"CONNECT {port}\n"
        s.sendall(connect_command.encode('utf-8'))
        response = s.recv(4096).decode('utf-8')
        if f"OK {port}" not in response:
            return 1, "", f"OK not received from vsock unix socket (Got: {response})"
        # Send Command
        s.sendall(cmd_str.encode('utf-8'))
        # Read Response
        output = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            output += chunk
        received_json = output.decode('utf-8')
        result = json.loads(received_json)
        return result["exit_code"], result["stdout"], result["stderr"]

    except OSError as e:
        return 1, "", f"Socket error: {e}"
    except Exception as e:
        return 1, "", str(e)
    finally:
        if s:
            try:
                s.close()
            except:
                pass


@click.command(context_settings=dict(
    ignore_unknown_options=True,
))
@click.option("--socket", default=None, help="Unix socket made by vhost-device-vsock. Defaults to searching for 'vsocket' in /tmp/*/")
@click.option("--port", default=12341234, type=int, help="Vsock port number to connect to. Defaults to 12341234")
@click.argument("command", nargs=-1, required=True)
@click.pass_context
def guest_cmd(ctx, socket, port, command):
    """
    Run a command in a rehosted guest via vsock Unix socket.
    """
    # 1. Resolve Socket
    unix_socket, err = _resolve_vsocket(socket)
    if err:
        print(err)
        ctx.exit(1)

    # 2. Run Command
    cmd_str = ' '.join(command)
    exit_code, stdout, stderr = _send_command(unix_socket, port, cmd_str)

    # 3. Output
    if stdout:
        print(stdout, end='')
    if stderr:
        print(stderr, file=sys.stderr, end='')

    ctx.exit(exit_code)


if __name__ == "__main__":
    guest_cmd()
