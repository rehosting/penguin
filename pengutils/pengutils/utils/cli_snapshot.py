"""
Snapshot CLI
============

Host-driven VM snapshotting via the Penguin RemoteCtrl Plugin Unix socket.
Requests are *armed* at a safe execution boundary (default: the next syscall
return) rather than captured at the instant the command is received.

Example usage
-------------

.. code-block:: bash

    # Save at the next syscall boundary (default), tag "warm"
    cli_snapshot.py save --tag warm

    # Save at the next syscall boundary in a specific process
    cli_snapshot.py save --tag warm --proc lighttpd

    # Save when execution reaches a symbol
    cli_snapshot.py save --tag warm --when symbol --symbol main --proc lighttpd

    # Save immediately (next main-loop tick)
    cli_snapshot.py save --tag warm --when now

    # Restore a snapshot into the running guest
    cli_snapshot.py load --tag warm

Options
-------
- ``--sock``: Path to plugin socket (default: results/latest/remotectrl.sock)
"""

import click
from rich import print
from pengutils.utils.util_events import get_default_socket_path, send_command


def _send(ctx, sock, cmd):
    if not sock:
        sock = get_default_socket_path()
    try:
        resp = send_command(cmd, sock=sock)
        if not resp:
            print(f"[red]No response from socket {sock}[/red]")
            ctx.exit(1)
        if resp.get("status") == "success":
            print(f"[green]{resp.get('message', 'OK')}[/green]")
            ctx.exit(0)
        print(f"[red]Failed: {resp.get('message')}[/red]")
        ctx.exit(1)
    except click.exceptions.Exit:
        raise
    except Exception as e:
        print(f"[red]{e}[/red]")
        print("[red]Is the remotectrl plugin loaded and snapshot configured?[/red]")
        ctx.exit(1)


@click.group(name="snapshot")
def snapshot_cli():
    """VM snapshot save/restore commands."""
    pass


@snapshot_cli.command()
@click.option("--sock", default=None, help="Path to plugin socket (default: results/latest/remotectrl.sock)")
@click.option("--tag", default=None, help="Snapshot tag (defaults to the configured core.snapshot.tag)")
@click.option("--when", default="next_syscall",
              type=click.Choice(["next_syscall", "symbol", "now"]),
              help="When to actually capture (default: next_syscall)")
@click.option("--proc", default=None, help="Process-name filter for the boundary")
@click.option("--symbol", default=None, help="Symbol to capture at (when --when symbol)")
@click.pass_context
def save(ctx, sock, tag, when, proc, symbol):
    """Arm a savevm at a safe execution boundary."""
    cmd = {"type": "snapshot", "action": "save", "when": when}
    if tag:
        cmd["tag"] = tag
    if proc:
        cmd["proc"] = proc
    if symbol:
        cmd["symbol"] = symbol
    _send(ctx, sock, cmd)


@snapshot_cli.command()
@click.option("--sock", default=None, help="Path to plugin socket (default: results/latest/remotectrl.sock)")
@click.option("--tag", default=None, help="Snapshot tag to restore (defaults to the configured core.snapshot.tag)")
@click.pass_context
def load(ctx, sock, tag):
    """Restore a snapshot into the running guest (loadvm)."""
    cmd = {"type": "snapshot", "action": "load"}
    if tag:
        cmd["tag"] = tag
    _send(ctx, sock, cmd)


if __name__ == "__main__":
    snapshot_cli()
