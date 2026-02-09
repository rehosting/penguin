"""
Uprobe CLI
==========

This script provides a command-line interface (CLI) for setting up a uprobe via the Penguin DynEvents Plugin Unix socket.
It is modeled after the uprobe command in penguin_ctrl.py and uses Click for the CLI interface.

Example usage
-------------

.. code-block:: bash

    cli_uprobe.py --sock results/latest/penguin_events.sock --path /lib/libc.so.6 --symbol malloc --action "print %d" --output /tmp/uprobe_output.txt

Options
-------
- ``--sock``: Path to plugin socket (default: results/latest/penguin_events.sock)
- ``--path``: Path to library or binary (required)
- ``--symbol``: Symbol to probe (required)
- ``--action``: Action string (required)
- ``--proc``: Process name filter (optional)
- ``--pid``: PID filter (optional)
- ``--output``: Output file for action (optional)

"""

import click
import sys
from rich import print
from pengutils.utils.util_events import send_command


@click.command()
@click.option("--sock", default="results/latest/penguin_events.sock", help="Path to plugin socket (default: results/latest/penguin_events.sock)")
@click.option("--path", required=True, help="Path to library or binary")
@click.option("--symbol", required=True, help="Symbol to probe")
@click.option("--action", required=True, help="Action string")
@click.option("--proc", default=None, help="Process name filter")
@click.option("--pid", default=None, type=int, help="PID filter")
@click.option("--output", default=None, help="Output file for action")
@click.pass_context
def uprobe(ctx, sock, path, symbol, action, proc, pid, output):
    """
    Set up a uprobe via the Penguin DynEvents Plugin Unix socket.
    """
    cmd = {
        "type": "uprobe",
        "path": path,
        "symbol": symbol,
        "action": action,
        "process_filter": proc,
        "pid_filter": pid,
    }
    if output:
        cmd["output"] = output
    try:
        resp = send_command(cmd, sock=sock)
        if not resp:
            print(f"[red]No response from socket {sock}[/red]")
            ctx.exit(1)
        if resp.get("status") == "success":
            if "message" in resp:
                print(f"[green]{resp['message']}[/green]")
            else:
                print(f"[green]Success: ID {resp.get('id')}[/green]")
            ctx.exit(0)
        else:
            print(f"[red]Failed: {resp.get('message')}[/red]")
            ctx.exit(1)
    except click.exceptions.Exit:
        raise
    except Exception as e:
        print(f"[red]{e}[/red]")
        ctx.exit(1)


if __name__ == "__main__":
    uprobe()
