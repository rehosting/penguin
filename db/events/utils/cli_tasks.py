import click
from sqlalchemy.orm import Session
from sqlalchemy import create_engine
from rich import print as rprint
from events import Event
from os.path import join, exists


@click.command()
@click.option(
    "--results",
    default="./results/latest",
    help="Path to results folder (default is ./results/)",
)
@click.option(
    "--output", default="/dev/stdout", help="Output to file instead of stdout"
)
def query_tasks(results, output):
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
