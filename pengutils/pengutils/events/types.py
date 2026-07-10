"""
Event Types
===========

This module defines the main event types for the penguin event database, each as a subclass of `Event`.
These types represent different kinds of system events (read, write, syscall, exec) and are mapped to
corresponding tables in the database using SQLAlchemy ORM.

Example usage
-------------

.. code-block:: python

    from pengutils.events.types import Read, Write, Syscall, Exec

Classes
-------

- Read: Represents a file read event.
- Write: Represents a file write event.
- Syscall: Represents a syscall event with arguments and return value.
- Exec: Represents an exec event (process execution).

Each class provides a ``__str__`` method for human-readable representation.

Table Structure
---------------

Each event type is mapped to its own table and linked to the base ``event`` table via a foreign key.

"""

from .base import Event
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy import ForeignKey
from typing import Optional


class Read(Event):
    """
    Read Event
    ==========
    Represents a file read event.

    Attributes
    ----------
    id : int
        Primary key, foreign key to event.id.
    fd : int
        File descriptor read from.
    fname : str
        Name of the file read.
    buffer : Optional[bytes]
        Contents read from the file.
    """
    __tablename__ = "read"
    id: Mapped[int] = mapped_column(ForeignKey("event.id"), primary_key=True)
    fd: Mapped[int]
    fname: Mapped[str]
    buffer: Mapped[Optional[bytes]]

    __mapper_args__ = {
        "polymorphic_identity": "read",
    }

    def __str__(self):
        """
        Return a human-readable string representation of the read event.

        Returns
        -------
        str
            String representation.
        """
        buf = repr(self.buffer) if self.buffer is not None else ""
        return f'read({self.fd}, {self.fname}, "{buf}")'


class Write(Event):
    """
    Write Event
    ===========
    Represents a file write event.

    Attributes
    ----------
    id : int
        Primary key, foreign key to event.id.
    fd : int
        File descriptor written to.
    fname : Optional[str]
        Name of the file written.
    buffer : Optional[bytes]
        Contents written to the file.
    """
    __tablename__ = "write"
    id: Mapped[int] = mapped_column(ForeignKey("event.id"), primary_key=True)
    fd: Mapped[int]
    fname: Mapped[Optional[str]]
    buffer: Mapped[Optional[bytes]]

    __mapper_args__ = {
        "polymorphic_identity": "write",
    }

    def __str__(self):
        """
        Return a human-readable string representation of the write event.

        Returns
        -------
        str
            String representation.
        """
        buf = repr(self.buffer) if self.buffer is not None else ""
        return f'write({self.fd}, {self.fname}, "{buf}")'


class Syscall(Event):
    """
    Syscall Event
    =============
    Represents a syscall event, including arguments and return value.

    Attributes
    ----------
    id : int
        Primary key, foreign key to event.id.
    name : str
        Name of the syscall.
    retno : Optional[int]
        Return value of the syscall.
    retno_repr : Optional[str]
        String representation of the return value.
    arg0-arg5 : Optional[int]
        Argument values.
    arg0_repr-arg5_repr : Optional[str]
        String representations of arguments.
    """
    __tablename__ = "syscall"
    id: Mapped[int] = mapped_column(ForeignKey("event.id"), primary_key=True)
    name: Mapped[str]
    retno: Mapped[Optional[int]]
    retno_repr: Mapped[Optional[str]]
    arg0: Mapped[Optional[int]]
    arg0_repr: Mapped[Optional[str]]
    arg1: Mapped[Optional[int]]
    arg1_repr: Mapped[Optional[str]]
    arg2: Mapped[Optional[int]]
    arg2_repr: Mapped[Optional[str]]
    arg3: Mapped[Optional[int]]
    arg3_repr: Mapped[Optional[str]]
    arg4: Mapped[Optional[int]]
    arg4_repr: Mapped[Optional[str]]
    arg5: Mapped[Optional[int]]
    arg5_repr: Mapped[Optional[str]]

    __mapper_args__ = {
        "polymorphic_identity": "syscall",
    }

    def __str__(self):
        """
        Return a human-readable string representation of the syscall event.

        Returns
        -------
        str
            String representation.
        """
        args = []
        for i in range(6):
            arg, arg_repr = getattr(self, f"arg{i}"), getattr(self, f"arg{i}_repr")
            if arg is not None:
                args.append(f"{arg_repr}({arg:#x})")
        return f"{self.name}({', '.join(args)}) = {self.retno}({self.retno_repr})"


class Exec(Event):
    """
    Exec Event
    ==========
    Represents a process execution (exec) event.

    Attributes
    ----------
    id : int
        Primary key, foreign key to event.id.
    calltree : str
        Call tree information.
    argc : str
        Argument count.
    argv : str
        Argument values.
    envp : str
        Environment variables.
    euid : int
        Effective user ID.
    egid : int
        Effective group ID.
    """
    __tablename__ = "exec"
    id: Mapped[int] = mapped_column(ForeignKey("event.id"), primary_key=True)
    calltree: Mapped[str]
    argc: Mapped[str]
    argv: Mapped[str]
    envp: Mapped[str]
    euid: Mapped[int]
    egid: Mapped[int]

    __mapper_args__ = {
        "polymorphic_identity": "exec",
    }

    def __str__(self):
        """
        Return a human-readable string representation of the exec event.

        Returns
        -------
        str
            String representation.
        """
        return f'Exec: "{self.argv}" {self.calltree}'


class ProcStart(Event):
    """
    ProcStart Event
    ===============
    A process becoming visible (via exec) to the process-tree model. Lean and
    identity-focused -- argv/env live on :class:`Exec`; this carries only what
    the genealogy needs. Re-exec appends another row with the same
    ``(pid, create_time)``; consumers coalesce by that key.

    Attributes
    ----------
    pid : int
        Process id.
    ppid : int
        Parent process id (from ``osi_proc.ppid``).
    create_time : int
        Kernel task creation timestamp; stable across execve, so
        ``(pid, create_time)`` is a durable process identity across pid reuse.
    comm : str
        Kernel ``task->comm`` at exec time (the executed program's basename may
        differ; ``procname`` on the base row carries the fuller name).
    uid, gid, euid, egid : int
        Credentials at exec time.
    """
    __tablename__ = "proc_start"
    id: Mapped[int] = mapped_column(ForeignKey("event.id"), primary_key=True)
    pid: Mapped[int]
    ppid: Mapped[int]
    create_time: Mapped[int]
    comm: Mapped[str]
    uid: Mapped[int]
    gid: Mapped[int]
    euid: Mapped[int]
    egid: Mapped[int]

    __mapper_args__ = {
        "polymorphic_identity": "proc_start",
    }

    def __str__(self):
        return f"ProcStart: pid={self.pid} ppid={self.ppid} comm={self.comm}"


class ProcExit(Event):
    """
    ProcExit Event
    ==============
    A process/thread exit, recorded from the exit/exit_group syscall. Identity
    is denormalized from the syscall event (no memory read of the dying task).
    Pairs with :class:`ProcStart` by ``(pid, create_time)`` to close out a
    process in the derived tree.

    Attributes
    ----------
    pid : int
        Exiting process id.
    create_time : int
        Process identity key (see :class:`ProcStart`). May be 0 if an older
        driver did not denormalize it, in which case consumers fall back to the
        unique live ``(pid)``.
    code : int
        Exit status argument passed to exit / exit_group.
    reason : str
        ``"exit"`` or ``"exit_group"``.
    """
    __tablename__ = "proc_exit"
    id: Mapped[int] = mapped_column(ForeignKey("event.id"), primary_key=True)
    pid: Mapped[int]
    create_time: Mapped[int]
    code: Mapped[int]
    reason: Mapped[str]

    __mapper_args__ = {
        "polymorphic_identity": "proc_exit",
    }

    def __str__(self):
        return f"ProcExit: pid={self.pid} code={self.code} ({self.reason})"
