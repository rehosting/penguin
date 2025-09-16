"""
# Index Range Utility

Query events directly by their numeric (row) ids. You can:
- Start at a specific id and show a number of events forward (--start + --count)
- Or specify an inclusive id range (--start + --end)

## Example usage

Show 20 events starting at id 100 (default count):
index --start 100

Show 50 events starting at id 200:
index --start 200 --count 50

Show events from id 500 through 560 inclusive:
index --start 500 --end 560

Filter additionally by process name substring:
index --start 1000 --count 30 --procname python

Output to a file:
index --start 42 --count 5 --output selection.txt
"""

import click
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from sqlalchemy import and_
from rich import print as rprint
from rich.markup import escape
from os.path import join, exists
from events import Event


@click.command()
@click.option(
    "--results",
    default="./results/latest",
    help="Path to results folder (default is ./results/latest)",
)
@click.option(
    "--start",
    type=int,
    required=True,
    help="Starting event id (inclusive)",
)
@click.option(
    "--end",
    type=int,
    default=None,
    help="Ending event id (inclusive). If provided, --count is ignored.",
)
@click.option(
    "--count",
    type=int,
    default=20,
    help="Number of events to display starting at --start (ignored if --end supplied)",
)
@click.option(
    "--procname",
    default=None,
    help="Optional process name substring filter",
)
@click.option(
    "--output",
    default="/dev/stdout",
    help="Output file (default /dev/stdout)",
)
def query_index(results, start, end, count, procname, output):
    """
    Query events by id range.
    """
    if end is None:
        if count <= 0:
            print("--count must be > 0")
            return
        end = start + count - 1
    if end < start:
        print("--end must be >= --start")
        return

    db_path = join(results, "plugins.db")
    if not exists(db_path):
        print(f"Failed to find db at {db_path}. Check your --results")
        return

    engine = create_engine(f"sqlite:///{db_path}")
    with open(output, "w") as f:
        with Session(engine) as sess:
            if output == "/dev/stdout":
                printer = lambda s, **kw: rprint(escape(str(s)), **kw)  # noqa: E731
            else:
                printer = print

            query = sess.query(Event).filter(
                and_(Event.id >= start, Event.id <= end)
            )
            if procname:
                query = query.filter(Event.procname.contains(procname))
            query = query.order_by(Event.id.asc())

            found = False
            for ev in query.all():
                printer(f"{ev.id} ({ev.procname}) {ev}", file=f)
                found = True

            if not found:
                printer(f"No events found in range [{start}, {end}]", file=f)


if __name__ == "__main__":
    query_index()
