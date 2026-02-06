"""
Load Plugin CLI
===============

This script provides a command-line interface (CLI) for loading a plugin via the Penguin DynEvents Plugin Unix socket.
It uses Click for the CLI interface.

Example usage
-------------

.. code-block:: bash

    cli_load_plugin.py --sock results/latest/penguin_events.sock plugin_name

Options
-------
- ``--sock``: Path to plugin socket (default: results/latest/penguin_events.sock)
- ``plugin_name``: Name of the plugin to load (required)

"""


import click
import sys
from rich import print
from pengutils.utils.util_events import send_command

@click.command()
@click.argument("plugin_name")
@click.option(
    "--sock",
    default="results/latest/penguin_events.sock",
    help="Path to plugin socket (default: results/latest/penguin_events.sock)",
)
def load_plugin(sock, plugin_name):
    """
    Load a plugin by name via the Penguin DynEvents Plugin Unix socket.
    """
    cmd = {"type": "load_plugin", "name": plugin_name}
    try:
        resp = send_command(cmd, sock=sock)
        if not resp:
            print(f"[red]No response from socket {sock}[/red]")
            print(f"[red]Is the dyn_events plugin loaded?[/red]")
            sys.exit(1)
        if resp.get("status") == "success":
            if "message" in resp:
                print(f"[green]{resp['message']}[/green]")
            else:
                print(f"[green]Success![/green]")
        else:
            print(f"[red]Failed: {resp.get('message')}[/red]")
            sys.exit(1)
    except Exception as e:
        print(f"[red]{e}[/red]")
        print(f"[red]Is the dyn_events plugin loaded?[/red]")
        sys.exit(1)

if __name__ == "__main__":
    load_plugin()
