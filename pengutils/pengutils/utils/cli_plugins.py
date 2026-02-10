"""
Plugins CLI
===========

This script provides a command-line interface (CLI) for managing plugins via the Penguin RemoteCtrl Plugin Unix socket.
It uses Click for the CLI interface.

Example usage
-------------

.. code-block:: bash

    plugins load plugin_name [key=value ...]
    plugins enable plugin_name [key=value ...]
    plugins disable plugin_name [key=value ...]

Options
-------
- ``--sock``: Path to plugin socket (default: /workspace/results/latest/remotectrl.sock)
"""

import click
from rich import print
from pengutils.utils.util_events import send_command


def parse_extra_args(args_tuple):
    """
    Parses a tuple of arguments into a dictionary.
    Supports 'key=value' for key-value pairs.
    Supports 'flag' (no equals sign) as {flag: True}.
    Performs basic type inference for booleans and integers.
    """
    args_dict = {}
    for arg in args_tuple:
        if '=' in arg:
            key, value = arg.split('=', 1)
            # Try to infer type
            if value.lower() == 'true':
                value = True
            elif value.lower() == 'false':
                value = False
            elif value.isdigit():
                value = int(value)
            args_dict[key] = value
        else:
            # Handle flags as boolean True
            args_dict[arg] = True
    return args_dict


@click.group()
@click.option(
    "--sock",
    default="/workspace/results/latest/remotectrl.sock",
    help="Path to plugin socket (default: /workspace/results/latest/remotectrl.sock)",
)
@click.pass_context
def plugins(ctx, sock):
    """
    Manage plugins via the Penguin RemoteCtrl Plugin Unix socket.
    """
    ctx.ensure_object(dict)
    ctx.obj['sock'] = sock


def _send_plugin_cmd(ctx, cmd_type, plugin_name, args=None):
    sock = ctx.obj['sock']
    cmd = {"type": cmd_type, "name": plugin_name}
    if args:
        cmd['args'] = args

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
@click.argument("extra_args", nargs=-1)
@click.pass_context
def load(ctx, plugin_name, extra_args):
    """
    Load a plugin.

    EXTRA_ARGS: Optional arguments (key=value) to pass to the plugin configuration.
    """
    args_dict = parse_extra_args(extra_args)
    _send_plugin_cmd(ctx, "load_plugin", plugin_name, args=args_dict)


@plugins.command()
@click.argument("plugin_name")
@click.argument("extra_args", nargs=-1)
@click.pass_context
def enable(ctx, plugin_name, extra_args):
    """
    Enable a plugin (calls .enable()).

    EXTRA_ARGS: Optional arguments (key=value) passed to the enable method.
    """
    args_dict = parse_extra_args(extra_args)
    _send_plugin_cmd(ctx, "enable_plugin", plugin_name, args=args_dict)


@plugins.command()
@click.argument("plugin_name")
@click.argument("extra_args", nargs=-1)
@click.pass_context
def disable(ctx, plugin_name, extra_args):
    """
    Disable a plugin (calls .disable()).

    EXTRA_ARGS: Optional arguments (key=value) passed to the disable method.
    """
    args_dict = parse_extra_args(extra_args)
    _send_plugin_cmd(ctx, "disable_plugin", plugin_name, args=args_dict)


if __name__ == "__main__":
    plugins()
