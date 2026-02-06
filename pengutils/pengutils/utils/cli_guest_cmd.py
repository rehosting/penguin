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
import os
from pathlib  import Path
from rich import print

@click.command()
@click.option("--socket", default=None, help="Unix socket made by vhost-device-vsock. Defaults to searching for 'vsocket' in /tmp/*/")
@click.option("--port", default=12341234, type=int, help="Vsock port number to connect to. Defaults to 12341234")
@click.argument("command", nargs=-1, required=True)
def guest_cmd(socket, port, command):
    """
    Run a command in a rehosted guest via vsock Unix socket.
    """
    if socket is None:
        unix_socket = list(Path('/tmp').glob('*/vsocket'))
    else:
        unix_socket = socket
    if unix_socket is None:
        print("[red]No vsocket found and no socket provided[/red]")
        sys.exit(1)
    if isinstance(unix_socket, list):
        if len(unix_socket) == 0:
            print("[red]No vsocket found in /tmp/*/[/red]")
            sys.exit(1)
        elif len(unix_socket) > 1:
            print("[red]Multiple vsockets found in /tmp/*/. Please specify with --socket[/red]")
            for s in unix_socket:
                print(f" - {s}")
            sys.exit(1)
        else:
            unix_socket = str(unix_socket[0])

    cmd_str = ' '.join(command)
    try:
        s = sock.socket(sock.AF_UNIX, sock.SOCK_STREAM)
        s.connect(unix_socket)
        s.settimeout(None)
        connect_command = f"CONNECT {port}\n"
        s.sendall(connect_command.encode('utf-8'))
        response = s.recv(4096).decode('utf-8')
        assert f"OK {port}" in response, "OK not received from vsock unix socket"
        s.sendall(cmd_str.encode('utf-8'))
        output = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            output += chunk
        received_json = output.decode('utf-8')
        result = json.loads(received_json)
        print(result["stdout"], end='')
        if result["stderr"]:
            print(result["stderr"], file=sys.stderr, end='')
        sys.exit(result["exit_code"])
    except OSError as e:
        print(f"Socket error: {e}", file=sys.stderr)
        sys.exit(1)
    except AssertionError as e:
        print(f"[red]{e}[/red]", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[red]{e}[/red]", file=sys.stderr)
        sys.exit(1)
    finally:
        try:
            s.close()
        except Exception:
            pass

if __name__ == "__main__":
    guest_cmd()
