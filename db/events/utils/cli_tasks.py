"""
# Tasks Utility

This module provides a command-line interface (CLI) for listing unique process names (tasks) from the events database.
It outputs the distinct process names, optionally to a file or to stdout, and is intended to be run as a script or imported as a module.
The CLI is built using [Click](https://click.palletsprojects.com/).

## Example usage

```bash
tasks --results ./results/latest --output tasks.txt
```

## Options

- `--results`: Path to results folder (default: `./results/latest/`)
- `--output`: Output file (default: `/dev/stdout`)

## Functions

- `query_tasks`: Main CLI command for listing unique process names.

"""

import click
from sqlalchemy.orm import Session
from sqlalchemy import create_engine, func
from rich import print as rprint
from events import Event
from os.path import join, exists


@click.command()
@click.option(
    "--results",
    default="./results/latest",
    help="Path to results folder (default is ./results/latest/)",
)
@click.option(
    "--output", default="/dev/stdout", help="Output to file instead of stdout"
)
@click.option(
    "--index", "show_index", default=False, is_flag=True, help="Show indexes (first event id) in output"
)
def query_tasks(results, output, show_index):
    """
    ### Query and list unique process names (tasks) from the events database.

    **Args:**
    - `results` (`str`): Path to results folder.
    - `output` (`str`): Output file path (default: /dev/stdout).
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

            if show_index:
                query = (
                    sess.query(func.min(Event.id).label("min_id"), Event.procname)
                    .group_by(Event.procname)
                    .order_by(func.min(Event.id))
                )
                for row in query.all():
                    printer(f"{row.min_id} {row.procname}", file=f)
            else:
                query = sess.query(Event.procname).distinct().order_by(Event.id)
                for event in query.all():
                    printer(event.procname, file=f)


if __name__ == "__main__":
    query_tasks()
