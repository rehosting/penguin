"""
# Utility Base Functions

This module provides utility functions for wrapping and executing filtered queries on event databases.
It is designed to be used by CLI scripts for querying and outputting event data, supporting flexible
filtering and output options.

## Example usage

```python
from events.utils.util_base import wrapper

def my_filter(sess, arg1, arg2):
    # ...filter logic...
    return query

wrapper(results_path, output_path, print_procname, follow, my_filter, (arg1, arg2))
```

## Functions

- `wrapper`: Handles session setup, filtering, and output for event queries.

"""

from sqlalchemy.orm import Session
from sqlalchemy import func, create_engine
from rich import print as rprint
from rich.markup import escape
from time import sleep
from os.path import join, exists
from events import Event


def wrapper(results, output, print_procname, follow, show_index, filter_func, args):
    """
    ### Wrapper function to execute a filtered query and output results.

    **Args:**
    - `results` (`str`): Path to results folder.
    - `output` (`str`): Output file path (default: /dev/stdout).
    - `print_procname` (`bool`): Whether to print the process name in output.
    - `follow` (`bool`): Whether to show latest results as they appear.
    - `show_index` (`bool`): If True, prepend the Event.id (row index) to each line.
    - `filter_func` (`callable`): Function to filter the query. Should accept (sess, *args).
    - `args` (`tuple`): Arguments to pass to the filter function.

    **Returns:**
    - `None`
    """
    db_path = join(results, "plugins.db")
    if not exists(db_path):
        print(f"Failed to find db at {db_path}. Check your --results")
        return
    engine = create_engine(f"sqlite:///{db_path}")
    with open(output, "w") as f:
        with Session(engine) as sess:
            highest_id = -1

            # only pretty print if we are printing to stdout
            if output == "/dev/stdout":
                printer = lambda *args, **kwargs: rprint(*(escape(str(arg)) for arg in args), **kwargs)  # noqa: E731
            else:
                printer = print

            # in follow mode we print the last 4 events and then continue from there
            if follow:
                if id_num := sess.execute(func.max(Event.id)).first():
                    highest_id = id_num[0] - 4
            while True:
                query = filter_func(sess, *args)

                if highest_id != -1:
                    query = query.filter(Event.id > highest_id)

                for event in query.all():
                    prefix = f"{event.id} " if show_index else ""
                    if print_procname:
                        printer(f"{prefix}({event.procname}) {event}", file=f)
                    else:
                        printer(f"{prefix}{event}", file=f)
                    highest_id = max(highest_id, event.id)

                if not follow:
                    break
                else:
                    sleep(1)
