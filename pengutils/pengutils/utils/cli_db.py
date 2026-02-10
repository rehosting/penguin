"""
Database CLI
============

This script consolidates various database query utilities into a single command-line interface.
It allows querying execution events, file descriptor usage, file reads/writes, syscalls, and unique tasks (process names) from the Penguin RemoteCtrl Plugin database.

Example usage
-------------

.. code-block:: bash

    # Query tasks
    cli_db.py tasks --results ./results/latest

    # Query execs
    cli_db.py execs --procname myproc --fd 3

    # Query syscalls
    cli_db.py syscalls --errors

    # Query reads/writes
    cli_db.py reads --filename config.txt
    cli_db.py writes --fd 1

    # Query unique FDs
    cli_db.py fds --follow

Options
-------
Common options:
- ``--results``: Path to results folder (default: ``./results/latest/``)
- ``--output``: Output file (default: ``/dev/stdout``)

See individual commands for specific filters and options.
"""

import click
from sqlalchemy import create_engine, func
from sqlalchemy.orm import Session
from rich import print as rprint
from time import sleep
from os.path import join, exists

from pengutils.events import Event, Exec, Read, Syscall, Write
from pengutils.utils.util_base import wrapper, get_default_results_path

# --- Filter Helpers ---


def exec_filter(sess, procname, fd, filename):
    query = sess.query(Exec)
    if procname:
        query = query.filter(Exec.procname.contains(procname))
    if fd:
        query = query.filter(Exec.fd == fd)
    if filename:
        query = query.filter(Exec.fname.contains(filename))
    return query


def read_filter(sess, procname, fd, filename):
    query = sess.query(Read)
    if procname:
        query = query.filter(Read.procname.contains(procname))
    if fd:
        query = query.filter(Read.fd == fd)
    if filename:
        query = query.filter(Read.fname.contains(filename))
    return query


def write_filter(sess, procname, fd, filename):
    query = sess.query(Write)
    if procname:
        query = query.filter(Write.procname.contains(procname))
    if fd:
        query = query.filter(Write.fd == fd)
    if filename:
        query = query.filter(Write.fname.contains(filename))
    return query


def syscall_filter(sess, procname, syscall, errors):
    query = sess.query(Syscall)
    if procname:
        query = query.filter(Syscall.procname.contains(procname))
    if syscall:
        if not syscall.startswith("sys_"):
            syscall = "sys_" + syscall
        query = query.filter(Syscall.name.contains(syscall))
    if errors:
        query = query.filter(Syscall.retno < 0)
    return query

# --- CLI Group ---


@click.group(name="db")
def db_cli():
    """Database query commands."""
    pass

# --- Commands ---


@db_cli.command()
@click.option("--results", default=get_default_results_path(), help="Path to results folder")
@click.option("--procname", default=None, help="Process name to filter for (looks for substring)")
@click.option("--follow", default=False, help="Show latest results as they appear", is_flag=True)
@click.option("--fd", default=None, help="Filter for file descriptor")
@click.option("--filename", default=None, help="Filter for file name")
@click.option("--output", default="/dev/stdout", help="Output to file instead of stdout")
def execs(results, procname, follow, fd, filename, output):
    """Query execution events."""
    print_procname = procname is None
    args = (procname, fd, filename)
    wrapper(results, output, print_procname, follow, exec_filter, args)


@db_cli.command()
@click.option("--results", default=get_default_results_path(), help="Path to results folder")
@click.option("--procname", default=None, help="Process name to filter for (looks for substring)")
@click.option("--follow", default=False, help="Show latest results as they appear", is_flag=True)
@click.option("--fd", default=None, help="file descriptor number to filter")
@click.option("--output", default="/dev/stdout", help="Output to file instead of stdout")
def fds(results, procname, follow, fd, output):
    """Query file descriptor write events (unique combinations)."""
    db_path = join(results, "plugins.db")
    if not exists(db_path):
        rprint(
            f"[red]Failed to find db at {db_path}. Check your --results[/red]")
        return
    engine = create_engine(f"sqlite:///{db_path}")

    # Use built-in print for files to avoid ANSI codes, rprint for stdout
    printer = rprint if output == "/dev/stdout" else print

    with open(output, "w") as f:
        with Session(engine) as sess:
            highest_id = -1
            print_procname = True

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
                        printer(f"({e[0]}) {e[1]} {e[2]}", file=f)
                    else:
                        printer(f"{e[1]} {e[2]}", file=f)
                    # Flush to ensure output appears immediately when following
                    f.flush()

                if not follow:
                    break
                else:
                    sleep(1)


@db_cli.command()
@click.option("--results", default=get_default_results_path(), help="Path to results folder")
@click.option("--procname", default=None, help="Process name to filter for (looks for substring)")
@click.option("--follow", default=False, help="Show latest results as they appear", is_flag=True)
@click.option("--fd", default=None, help="Filter for file descriptor")
@click.option("--filename", default=None, help="Filter for file name")
@click.option("--output", default="/dev/stdout", help="Output to file instead of stdout")
def reads(results, procname, follow, fd, filename, output):
    """Query file read events."""
    print_procname = procname is None
    args = (procname, fd, filename)
    wrapper(results, output, print_procname, follow, read_filter, args)


@db_cli.command()
@click.option("--results", default=get_default_results_path(), help="Path to results folder")
@click.option("--procname", default=None, help="Process name to filter for (looks for substring)")
@click.option("--syscall", default=None, help="Syscall name to filter for (looks for substring)")
@click.option("--errors", default=False, help="Just show syscalls that returned an error", is_flag=True)
@click.option("--follow", default=False, help="Show latest results as they appear", is_flag=True)
@click.option("--output", default="/dev/stdout", help="Output to file instead of stdout")
def syscalls(results, procname, syscall, errors, follow, output):
    """Query syscall events."""
    print_procname = procname is None
    args = (procname, syscall, errors)
    wrapper(results, output, print_procname, follow, syscall_filter, args)


@db_cli.command()
@click.option("--results", default=get_default_results_path(), help="Path to results folder")
@click.option("--output", default="/dev/stdout", help="Output to file instead of stdout")
def tasks(results, output):
    """Query and list unique process names (tasks)."""
    db_path = join(results, "plugins.db")
    if not exists(db_path):
        rprint(
            f"[red]Failed to find db at {db_path}. Check your --results[/red]")
        return
    engine = create_engine(f"sqlite:///{db_path}")

    printer = rprint if output == "/dev/stdout" else print

    with open(output, "w") as f:
        with Session(engine) as sess:
            query = sess.query(Event.procname).distinct().order_by(Event.id)
            for event in query.all():
                printer(event.procname, file=f)


@db_cli.command()
@click.option("--results", default=get_default_results_path(), help="Path to results folder")
@click.option("--procname", default=None, help="Process name to filter for (looks for substring)")
@click.option("--follow", default=False, help="Show latest results as they appear", is_flag=True)
@click.option("--fd", default=None, help="Filter for file descriptor")
@click.option("--filename", default=None, help="Filter for file name")
@click.option("--output", default="/dev/stdout", help="Output to file instead of stdout")
def writes(results, procname, follow, fd, filename, output):
    """Query file write events."""
    print_procname = procname is None
    args = (procname, fd, filename)
    wrapper(results, output, print_procname, follow, write_filter, args)


if __name__ == "__main__":
    db_cli()
