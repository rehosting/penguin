"""
Breakpoint CLI
==============

This script provides a command-line interface (CLI) for managing breakpoints, syscall traces, and uprobes via the Penguin DynEvents Plugin Unix socket.
It combines functionality for listing, disabling, and creating various event hooks.

Example usage
-------------

.. code-block:: bash

    # List breakpoints
    cli_breakpoint.py list --sock results/latest/penguin_events.sock

    # Disable a breakpoint
    cli_breakpoint.py disable --sock results/latest/penguin_events.sock --id 3

    # Add a syscall trace
    cli_breakpoint.py syscall --name sys_write --action "print %fd, %s, %d"

    # Add a uprobe
    cli_breakpoint.py uprobe --path /lib/libc.so.6 --symbol malloc --action "print %d"

Options
-------
Common options:
- ``--sock``: Path to plugin socket (default: results/latest/penguin_events.sock)

See individual commands for specific options.
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
@click.argument("arg_id", required=False, type=int)
@click.pass_context
def disable(ctx, sock, id, arg_id):
    """Disable a breakpoint/hook by ID, or all if no ID is given."""
    # Allow passing ID as an argument or flag
    id_val = arg_id if arg_id is not None else id
    cmd = {"type": "disable"}
    if id_val is not None:
        cmd["id"] = id_val
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


@breakpoint_cli.command()
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
    except click.exceptions.Exit:
        raise
    except Exception as e:
        print(f"[red]{e}[/red]")
        ctx.exit(1)


@breakpoint_cli.command()
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
    breakpoint_cli()
