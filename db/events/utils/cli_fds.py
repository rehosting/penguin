"""
# FDs Utility

This module provides a command-line interface (CLI) for querying file descriptor (FD) write events from a database.
It allows filtering by process name and file descriptor, supports outputting results to a file or stdout, and can
follow new events as they appear. The CLI is built using [Click](https://click.palletsprojects.com/) and is intended
to be run as a script or imported as a module.

## Example usage

```bash
fds --procname myproc --fd 3 --output results.txt
```

## Options

- `--results`: Path to results folder (default: `./results/latest`)
- `--procname`: Filter by process name (substring match)
- `--fd`: File descriptor number to filter
- `--output`: Output file (default: `/dev/stdout`)
- `--follow`: Show latest results as they appear

## Functions

- `query_fds`: Main CLI command for querying FD write events.

"""

from sqlalchemy import func, create_engine
import click
from events import Event, Write
from sqlalchemy.orm import Session
from rich import print
from time import sleep
from os.path import join, exists
from events.utils.util_base import get_default_results_path


@click.command()
@click.option(
    "--results",
    default=get_default_results_path(),
    help="Path to results folder (default is ./results)",
)
@click.option(
    "--procname", default=None, help="Process name to filter for (looks for substring)"
)
@click.option(
    "--follow", default=False, help="Show latest results as they appear", is_flag=True
)
@click.option(
    "--fd", default=None, help="file descriptor number to filter", is_flag=True
)
@click.option(
    "--output", default="/dev/stdout", help="Output to file instead of stdout"
)
def query_fds(results, procname, follow, fd, output):
    """
    ### Query file descriptor write events from the database with optional filters and output options.

    **Args:**
    - `results` (`str`): Path to results folder.
    - `procname` (`str` or `None`): Process name substring to filter for.
    - `follow` (`bool`): Whether to show latest results as they appear.
    - `fd` (`str` or `None`): File descriptor number to filter for.
    - `output` (`str`): Output file path (default: /dev/stdout).
    """
    db_path = join(results, "plugins.db")
    if not exists(db_path):
        print(f"Failed to find db at {db_path}. Check your --results")
        return
    engine = create_engine(f"sqlite:///{db_path}")
    with open(output, "w") as f:
        with Session(engine) as sess:
            highest_id = -1

            # in some cases we want to print the procname
            print_procname = True

            # in follow mode we print the last 4 events and then continue from there
            if follow:
                if id_num := sess.execute(func.max(Event.id)).first():
                    highest_id = id_num[0] - 4
            while True:
                query = sess.query(Write)
                if procname:
                    query = query.filter(Write.procname.contains(procname))
                    print_procname = False

                if highest_id != -1:
                    query = query.filter(Write.id > highest_id)

                if fd:
                    query = query.filter(Write.fd == fd)

                seen = set()
                for event in query.all():
                    if (event.procname, event.fd, event.fname) not in seen:
                        seen.add((event.procname, event.fd, event.fname))
                    highest_id = max(highest_id, event.id)

                for e in sorted(seen):
                    if print_procname:
                        print(f"({e[0]}) {e[1]} {e[2]}", file=f)
                    else:
                        print(f"{e[1]} {e[2]}", file=f)

                if not follow:
                    break
                else:
                    sleep(1)


if __name__ == "__main__":
    query_fds()
