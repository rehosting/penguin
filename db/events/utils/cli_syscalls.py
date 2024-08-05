import click
from events import Syscall
from events.utils.util_base import wrapper


def syscall_filter(sess, procname, syscall, errors):
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
    default="results",
    help="Path to results folder (default is ./results/)",
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
def query_syscalls(results, procname, syscall, errors, follow, output):
    print_procname = procname is None
    args = (procname, syscall, errors)
    wrapper(results, output, print_procname, follow, syscall_filter, args)


if __name__ == "__main__":
    query_syscalls()
