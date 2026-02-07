"""
Syscall CLI
===========

This script provides a command-line interface (CLI) for setting up a syscall trace via the Penguin DynEvents Plugin Unix socket.
It is modeled after the syscall command in penguin_ctrl.py and uses Click for the CLI interface.

Example usage
-------------

.. code-block:: bash

    cli_syscall.py --sock results/latest/penguin_events.sock --name sys_write --action "print %fd, %s, %d" --output /tmp/syscall_output.txt

Options
-------
- ``--sock``: Path to plugin socket (default: results/latest/penguin_events.sock)
- ``--name``: Syscall name (required)
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
@click.option("--name", required=True, help="Syscall name")
@click.option("--action", required=True, help="Action string")
@click.option("--proc", default=None, help="Process name filter")
@click.option("--pid", default=None, type=int, help="PID filter")
@click.option("--output", default=None, help="Output file for action")
@click.pass_context
def syscall(ctx, sock, name, action, proc, pid, output):
    """
    Set up a syscall trace via the Penguin DynEvents Plugin Unix socket.
    """
    cmd = {
        "type": "syscall",
        "name": name,
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
    except Exception as e:
        print(f"[red]{e}[/red]")
        ctx.exit(1)

if __name__ == "__main__":
    syscall()
