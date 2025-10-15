"""
Tasks Utility
=============

This module provides a command-line interface (CLI) for listing unique process names (tasks) from the events database.
It outputs the distinct process names, optionally to a file or to stdout, and is intended to be run as a script or imported as a module.
The CLI is built using `Click <https://click.palletsprojects.com/>`_.

Example usage
-------------

.. code-block:: bash

    tasks --results ./results/latest --output tasks.txt

Options
-------

- ``--results``: Path to results folder (default: ``./results/latest/``)
- ``--output``: Output file (default: ``/dev/stdout``)

Functions
---------

- ``query_tasks``: Main CLI command for listing unique process names.

"""

import click
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from rich import print as rprint
from events import Event
from os.path import join, exists
from events.utils.util_base import get_default_results_path


@click.command()
@click.option(
    "--results",
    default=get_default_results_path(),
    help="Path to results folder (default is ./results/)",
)
@click.option(
    "--output", default="/dev/stdout", help="Output to file instead of stdout"
)
def query_tasks(results, output):
    """
    Query and list unique process names (tasks) from the events database.

    :param results: Path to results folder.
    :type results: str
    :param output: Output file path (default: /dev/stdout).
    :type output: str
    """
    db_path = join(results, "plugins.db")
    if not exists(db_path):
        print(f"Failed to find db at {db_path}. Check your --results")
        return
    engine = create_engine(f"sqlite:///{db_path}")
    with open(output, "w") as f:
        with Session(engine) as sess:
            # only pretty print if we are printing to stdout
            if output == "/dev/stdout":
                printer = rprint
            else:
                printer = print

            query = sess.query(Event.procname).distinct().order_by(Event.id)
            for event in query.all():
                printer(event.procname, file=f)


if __name__ == "__main__":
    query_tasks()
