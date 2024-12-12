import click
from sqlalchemy import or_
from events import Syscall
from events.utils.util_base import wrapper

def parse_comma_separated(ctx, param, value):
    result = []
    for val in value:
        for item in val.split(','):
            item = item.strip()
            if item:
                result.append(item)
    return tuple(result)

def syscall_filter(sess, include_procname, exclude_procname, include_syscall, exclude_syscall, arg_search, errors, pid):
    query = sess.query(Syscall)

    if include_procname:
        or_filter = [Syscall.procname.contains(p) for p in include_procname]
        query = query.filter(or_(*or_filter))

    # Exclude procnames
    for p in exclude_procname:
        query = query.filter(~Syscall.procname.contains(p))

    # Include syscalls
    if include_syscall:
        processed_syscalls = []
        for sc in include_syscall:
            if not sc.startswith("sys_"):
                sc = "sys_" + sc
            processed_syscalls.append(sc)
        or_filter = [Syscall.name.contains(sc) for sc in processed_syscalls]
        query = query.filter(or_(*or_filter))

    # Exclude syscalls
    for sc in exclude_syscall:
        if not sc.startswith("sys_"):
            sc = "sys_" + sc
        query = query.filter(~Syscall.name.contains(sc))

    # Argument search
    if arg_search:
        arg_fields = [f"arg{i}_repr" for i in range(6)]
        or_filter = []
        for field in arg_fields:
            or_filter.append(getattr(Syscall, field).contains(arg_search))
        query = query.filter(or_(*or_filter))

    # Errors only
    if errors:
        query = query.filter(Syscall.retno < 0)
    
    if pid is not None:
        query = query.filter(Syscall.pid == pid)

    return query


@click.command()
@click.option(
    "--results",
    default="./results/latest",
    help="Path to results folder (default is ./results/latest)",
)
@click.option(
    "--include-procname", multiple=True, callback=parse_comma_separated,
    help="Process name(s) to include. Can be repeated or comma separated."
)
@click.option(
    "--exclude-procname", multiple=True, callback=parse_comma_separated,
    help="Process name(s) to exclude. Can be repeated or comma separated."
)
@click.option(
    "--include-syscall", multiple=True, callback=parse_comma_separated,
    help="Syscall name(s) to include. Can be repeated or comma separated."
)
@click.option(
    "--exclude-syscall", multiple=True, callback=parse_comma_separated,
    help="Syscall name(s) to exclude. Can be repeated or comma separated."
)
@click.option(
    "--arg-search", default=None, help="Substring to search for in syscall arguments."
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
    "--print-procnames/--no-print-procnames", 
    default=True, 
    help="Toggle whether to print process names (default: True)."
)
@click.option(
    "--pid", default=None, type=int, help="Filter by PID"
)
@click.option(
    "--show-process-tree",
    is_flag=True,
    default=False,
    help="Reconstruct and show the process tree and IPC signals."
)
def query_syscalls(results, include_procname, exclude_procname, include_syscall, exclude_syscall, arg_search, errors, follow, output, print_procnames, pid, show_process_tree):
    args = (include_procname, exclude_procname, include_syscall, exclude_syscall, arg_search, errors, pid, show_process_tree)
    wrapper(results, output, print_procnames, follow, syscall_filter, args)


if __name__ == "__main__":
    query_syscalls()
