import click
from events import Exec
from events.utils.util_base import wrapper


def exec_filter(sess, procname, fd, filename):
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
    default="results",
    help="Path to results folder (default is ./results/)",
)
@click.option(
    "--procname", default=None, help="Process name to filter for (looks for substring)"
)
@click.option(
    "--follow", default=False, help="Show latest results as they appear", is_flag=True
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
    print_procname = procname is None
    args = (procname, fd, filename)
    wrapper(results, output, print_procname, follow, exec_filter, args)


if __name__ == "__main__":
    query_execs()
