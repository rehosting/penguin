"""
# Execs Utility

This module provides a command-line interface (CLI) for querying execution events from a database.
It allows filtering by process name, file descriptor, and file name, and supports outputting results
to a file or stdout. The CLI is built using [Click](https://click.palletsprojects.com/) and is intended
to be run as a script or imported as a module.

## Running Commands

Commands should be run from the root of your cleanguin workspace or any directory where the `results` folder is accessible.
You can specify a different results directory using the `--results` option if your data is stored elsewhere.

## Example usage

```bash
execs --procname myproc --fd 3 --filename log.txt --output results.txt
```

## Options

- `--results`: Path to results folder (default: `./results/latest/`)
- `--procname`: Filter by process name (substring match)
- `--fd`: Filter by file descriptor
- `--filename`: Filter by file name (substring match)
- `--output`: Output file (default: `/dev/stdout`)
- `--follow`: Show latest results as they appear

## Functions

- `exec_filter`: Helper to filter Exec queries.
- `query_execs`: Main CLI command.

"""

import click
from events import Exec
from events.utils.util_base import wrapper


def exec_filter(sess, procname, fd, filename):
    """
    ### Filter Exec query based on process name, file descriptor, and file name.

    **Args:**
    - `sess`: SQLAlchemy session object.
    - `procname` (`str` or `None`): Substring to match in process name.
    - `fd` (`str` or `None`): File descriptor to filter for.
    - `filename` (`str` or `None`): Substring to match in file name.

    **Returns:**
    - `sqlalchemy.orm.query.Query`: Filtered query object.
    """
    query = sess.query(Exec)
    if procname:
        query = query.filter(Exec.procname.contains(procname))
    if fd:
        query = query.filter(Exec.fd == fd)
    if filename:
        query = query.filter(Exec.fname.contains(filename))
    return query


@click.command()
@click.option(
    "--results",
    default="./results/latest",
    help="Path to results folder (default is ./results/latest/)",
)
@click.option(
    "--procname", default=None, help="Process name to filter for (looks for substring)"
)
@click.option(
    "--follow", default=False, help="Show latest results as they appear", is_flag=True
)
@click.option("--fd", default=None, help="Filter for file descriptor")
@click.option("--filename", default=None, help="Filter for file name")
@click.option(
    "--output", default="/dev/stdout", help="Output to file instead of stdout"
)
def query_execs(results, procname, follow, fd, filename, output):
    """
    ### Query execution events from the database with optional filters and output options.

    **Args:**
    - `results` (`str`): Path to results folder.
    - `procname` (`str` or `None`): Process name substring to filter for.
    - `follow` (`bool`): Whether to show latest results as they appear.
    - `fd` (`str` or `None`): File descriptor to filter for.
    - `filename` (`str` or `None`): File name substring to filter for.
    - `output` (`str`): Output file path (default: /dev/stdout).
    """
    print_procname = procname is None
    args = (procname, fd, filename)
    wrapper(results, output, print_procname, follow, exec_filter, args)


if __name__ == "__main__":
    query_execs()
