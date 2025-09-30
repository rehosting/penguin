"""
# Reads Utility

This module provides a command-line interface (CLI) for querying file read events from a database.
It allows filtering by process name, file descriptor, and file name, and supports outputting results
to a file or stdout. The CLI is built using [Click](https://click.palletsprojects.com/) and is intended
to be run as a script or imported as a module.

## Example usage

```bash
reads --procname myproc --fd 3 --filename input.txt --output results.txt
```

## Options

- `--results`: Path to results folder (default: `./results/latest/`)
- `--procname`: Filter by process name (substring match)
- `--fd`: Filter by file descriptor
- `--filename`: Filter by file name (substring match)
- `--output`: Output file (default: `/dev/stdout`)
- `--follow`: Show latest results as they appear

## Functions

- `read_filter`: Helper to filter Read queries.
- `query_reads`: Main CLI command.

"""

import click
from events import Read
from events.utils.util_base import wrapper, get_default_results_path


def read_filter(sess, procname, fd, filename):
    """
    ### Filter Read query based on process name, file descriptor, and file name.

    **Args:**
    - `sess`: SQLAlchemy session object.
    - `procname` (`str` or `None`): Substring to match in process name.
    - `fd` (`str` or `None`): File descriptor to filter for.
    - `filename` (`str` or `None`): Substring to match in file name.

    **Returns:**
    - `sqlalchemy.orm.query.Query`: Filtered query object.
    """
    query = sess.query(Read)
    if procname:
        query = query.filter(Read.procname.contains(procname))
    if fd:
        query = query.filter(Read.fd == fd)
    if filename:
        query = query.filter(Read.fname.contains(filename))
    return query


@click.command()
@click.option(
    "--results",
    default=get_default_results_path(),
    help="Path to results folder (default is ./results/)",
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
def query_reads(results, procname, follow, fd, filename, output):
    """
    ### Query file read events from the database with optional filters and output options.

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
    wrapper(results, output, print_procname, follow, read_filter, args)


if __name__ == "__main__":
    query_reads()
