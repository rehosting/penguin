"""
Main CLI Dispatcher
===================

This module provides a dynamic CLI that discovers and allows execution of other
registered console_scripts in the pengutils package.
"""

import click
from importlib.metadata import distribution


class PenguinCLI(click.MultiCommand):
    def list_commands(self, ctx):
        """Dynamically list commands registered in setup.cfg under console_scripts."""
        try:
            dist = distribution('pengutils')
        except Exception:
            # Fallback if package isn't installed (e.g. running raw script)
            return []

        commands = []
        # Filter for console_scripts belonging to this package
        for ep in dist.entry_points:
            # Ensure we look at the right group and exclude this meta-command itself
            # to prevent recursion ('peng peng')
            if ep.group == 'console_scripts' and ep.name != 'peng':
                commands.append(ep.name)

        return sorted(commands)

    def get_command(self, ctx, name):
        """Load and return the requested command object."""
        try:
            dist = distribution('pengutils')
        except Exception:
            return None

        for ep in dist.entry_points:
            if ep.group == 'console_scripts' and ep.name == name:
                return ep.load()

        return None


@click.command(cls=PenguinCLI, help="Pengutils meta-CLI to run other registered commands.")
def main():
    pass


if __name__ == "__main__":
    main()
