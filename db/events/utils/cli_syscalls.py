"""
# Syscalls Utility

This module provides a command-line interface (CLI) for querying syscall events from a database.
It allows filtering by process name, syscall name, and error status, and supports outputting results
to a file or stdout. The CLI is built using [Click](https://click.palletsprojects.com/) and is intended
to be run as a script or imported as a module.

## Example usage

```bash
syscalls --procname myproc --syscall open --errors --output results.txt
```

## Options

- `--results`: Path to results folder (default: `./results/latest`)
- `--procname`: Filter by process name (substring match)
- `--syscall`: Syscall name to filter for (substring match, prepends `sys_` if missing)
- `--errors`: Show only syscalls that returned an error
- `--output`: Output file (default: `/dev/stdout`)
- `--follow`: Show latest results as they appear
- `--index`: Show indexes of the output

## Functions

- `syscall_filter`: Helper to filter Syscall queries.
- `query_syscalls`: Main CLI command.

"""

import click
from events import Syscall
from events.utils.util_base import wrapper


def syscall_filter(sess, procname, syscall, errors):
    """
    ### Filter Syscall query based on process name, syscall name, and error status.

    **Args:**
    - `sess`: SQLAlchemy session object.
    - `procname` (`str` or `None`): Substring to match in process name.
    - `syscall` (`str` or `None`): Substring to match in syscall name (prepends 'sys_' if missing).
    - `errors` (`bool`): If True, filter for syscalls that returned an error (retno < 0).

    **Returns:**
    - `sqlalchemy.orm.query.Query`: Filtered query object.
    """
    query = sess.query(Syscall)
    if procname:
        query = query.filter(Syscall.procname.contains(procname))
    if syscall:
        if not syscall.startswith("sys_"):
            syscall = "sys_" + syscall
        query = query.filter(Syscall.name.contains(syscall))
        # overrides all other run options
        pass
    if errors:
        query = query.filter(Syscall.retno < 0)
    return query


@click.command()
@click.option(
    "--results",
    default="./results/latest",
    help="Path to results folder (default is ./results/latest)",
)
@click.option(
    "--procname", default=None, help="Process name to filter for (looks for substring)"
)
@click.option(
    "--syscall", default=None, help="Syscall name to filter for (looks for substring)"
)
@click.option(
    "--errors",
    default=False,
    help="Just show syscalls that returned an error",
    is_flag=True,
)
@click.option(
    "--follow", default=False, help="Show latest results as they appear", is_flag=True
)
@click.option(
    "--output", default="/dev/stdout", help="Output to file instead of stdout"
)
@click.option(
    "--index", "show_index", default=False, is_flag=True, help="Show indexes (event ids) in output"
)
def query_syscalls(results, procname, syscall, errors, follow, output, show_index):
    """
    ### Query syscall events from the database with optional filters and output options.

    **Args:**
    - `results` (`str`): Path to results folder.
    - `procname` (`str` or `None`): Process name substring to filter for.
    - `syscall` (`str` or `None`): Syscall name substring to filter for.
    - `errors` (`bool`): Whether to show only syscalls that returned an error.
    - `follow` (`bool`): Whether to show latest results as they appear.
    - `output` (`str`): Output file path (default: /dev/stdout).
    """
    print_procname = procname is None
    args = (procname, syscall, errors)
    wrapper(results, output, print_procname, follow, show_index, syscall_filter, args)


if __name__ == "__main__":
    query_syscalls()
