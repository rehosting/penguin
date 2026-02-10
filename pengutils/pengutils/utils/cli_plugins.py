"""
Plugins CLI
===========

This script provides a command-line interface (CLI) for managing plugins via the Penguin DynEvents Plugin Unix socket.
It uses Click for the CLI interface.

Example usage
-------------

.. code-block:: bash

    plugins load plugin_name
    plugins enable plugin_name
    plugins disable plugin_name

Options
-------
- ``--sock``: Path to plugin socket (default: /workspace/results/latest/penguin_events.sock)
"""

import click
from rich import print
from pengutils.utils.util_events import send_command


@click.group()
@click.option(
    "--sock",
    default="/workspace/results/latest/penguin_events.sock",
    help="Path to plugin socket (default: /workspace/results/latest/penguin_events.sock)",
)
@click.pass_context
def plugins(ctx, sock):
    """
    Manage plugins via the Penguin DynEvents Plugin Unix socket.
    """
    ctx.ensure_object(dict)
    ctx.obj['sock'] = sock


def _send_plugin_cmd(ctx, cmd_type, plugin_name):
    sock = ctx.obj['sock']
    cmd = {"type": cmd_type, "name": plugin_name}
    try:
        resp = send_command(cmd, sock=sock)
        if not resp:
            print(f"[red]No response from socket {sock}[/red]")
            print("[red]Is the dyn_events plugin loaded?[/red]")
            ctx.exit(1)
        if resp.get("status") == "success":
            if "message" in resp:
                print(f"[green]{resp['message']}[/green]")
            else:
                print("[green]Success![/green]")
            ctx.exit(0)
        else:
            print(f"[red]Failed: {resp.get('message')}[/red]")
            ctx.exit(1)
    except click.exceptions.Exit:
        raise
    except Exception as e:
        print(f"[red]{e}[/red]")
        print("[red]Is the dyn_events plugin loaded?[/red]")
        ctx.exit(1)


@plugins.command()
@click.argument("plugin_name")
@click.pass_context
def load(ctx, plugin_name):
    """Load a plugin."""
    _send_plugin_cmd(ctx, "load_plugin", plugin_name)


@plugins.command()
@click.argument("plugin_name")
@click.pass_context
def enable(ctx, plugin_name):
    """Enable a plugin (calls .enable())."""
    _send_plugin_cmd(ctx, "enable_plugin", plugin_name)


@plugins.command()
@click.argument("plugin_name")
@click.pass_context
def disable(ctx, plugin_name):
    """Disable a plugin (calls .disable())."""
    _send_plugin_cmd(ctx, "disable_plugin", plugin_name)


if __name__ == "__main__":
    plugins()