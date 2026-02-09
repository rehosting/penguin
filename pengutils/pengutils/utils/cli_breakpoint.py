"""
Breakpoint CLI
==============

This script provides a command-line interface (CLI) for listing and disabling breakpoints via the Penguin DynEvents Plugin Unix socket.
It is modeled after the list and disable commands in penguin_ctrl.py and uses Click for the CLI interface.

Example usage
-------------

.. code-block:: bash

    cli_breakpoint.py list --sock results/latest/penguin_events.sock
    cli_breakpoint.py disable --sock results/latest/penguin_events.sock --id 3

Options
-------
- ``--sock``: Path to plugin socket (default: results/latest/penguin_events.sock)
- ``--id``: Breakpoint ID to disable (optional for disable)

"""

import click
from rich import print
from pengutils.utils.util_events import send_command


@click.group(name="breakpoint")
def breakpoint_cli():
    """Breakpoint management commands."""
    pass

@breakpoint_cli.command()
@click.option("--sock", default="results/latest/penguin_events.sock", help="Path to plugin socket (default: results/latest/penguin_events.sock)")
@click.pass_context
def list(ctx, sock):
    """List all breakpoints/hooks."""
    cmd = {"type": "list"}
    try:
        resp = send_command(cmd, sock=sock)
        if not resp:
            print(f"[red]No response from socket {sock}[/red]")
            ctx.exit(1)
        if resp.get("status") == "success" and "hooks" in resp:
            print(f"{'ID':<4} {'Type':<12} {'Target':<30} {'Action'}")
            print("-" * 60)
            for h in resp['hooks']:
                t = h.get('target') or "?"
                if len(t) > 28:
                    t = t[:25] + "..."
                print(f"{h['id']:<4} {h['type']:<12} {t:<30} {h['action']}")
            ctx.exit(0)
        elif resp.get("status") == "success" and "message" in resp:
            print(f"[green]{resp['message']}[/green]")
            ctx.exit(0)
        else:
            print(f"[red]Failed: {resp.get('message')}[/red]")
            ctx.exit(1)
    except click.exceptions.Exit:
        raise
    except Exception as e:
        print(f"[red]{e}[/red]")
        ctx.exit(1)

@breakpoint_cli.command()
@click.option("--sock", default="results/latest/penguin_events.sock", help="Path to plugin socket (default: results/latest/penguin_events.sock)")
@click.option("--id", default=None, type=int, help="Breakpoint ID to disable (optional)")
@click.pass_context
def disable(ctx, sock, id):
    """Disable a breakpoint/hook by ID, or all if no ID is given."""
    cmd = {"type": "disable"}
    if id is not None:
        cmd["id"] = id
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
    breakpoint_cli()
