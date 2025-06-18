"""
# Event Types

This module defines the main event types for the cleanguin event database, each as a subclass of `Event`.
These types represent different kinds of system events (read, write, syscall, exec) and are mapped to
corresponding tables in the database using SQLAlchemy ORM.

## Example usage

```python
from events.types import Read, Write, Syscall, Exec
```

## Classes

- `Read`: Represents a file read event.
- `Write`: Represents a file write event.
- `Syscall`: Represents a syscall event with arguments and return value.
- `Exec`: Represents an exec event (process execution).

Each class provides a `__str__` method for human-readable representation.

## Table Structure

Each event type is mapped to its own table and linked to the base `event` table via a foreign key.

"""

from .base import Event
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy import ForeignKey
from typing import Optional


class Read(Event):
    """
    ### Represents a file read event.

    **Attributes:**
    - `id` (`int`): Primary key, foreign key to event.id.
    - `fd` (`int`): File descriptor read from.
    - `fname` (`str`): Name of the file read.
    - `buffer` (`Optional[str]`): Contents read from the file.
    """
    __tablename__ = "read"
    id: Mapped[int] = mapped_column(ForeignKey("event.id"), primary_key=True)
    fd: Mapped[int]
    fname: Mapped[str]
    buffer: Mapped[Optional[str]]

    __mapper_args__ = {
        "polymorphic_identity": "read",
    }

    def __str__(self):
        return f'read({self.fd}, {self.fname}, "{self.buffer.strip()}")'


class Write(Event):
    """
    ### Represents a file write event.

    **Attributes:**
    - `id` (`int`): Primary key, foreign key to event.id.
    - `fd` (`int`): File descriptor written to.
    - `fname` (`Optional[str]`): Name of the file written.
    - `buffer` (`Optional[str]`): Contents written to the file.
    """
    __tablename__ = "write"
    id: Mapped[int] = mapped_column(ForeignKey("event.id"), primary_key=True)
    fd: Mapped[int]
    fname: Mapped[Optional[str]]
    buffer: Mapped[Optional[str]]

    __mapper_args__ = {
        "polymorphic_identity": "write",
    }

    def __str__(self):
        return f'write({self.fd}, {self.fname}, "{self.buffer.strip()}")'


class Syscall(Event):
    """
    ### Represents a syscall event, including arguments and return value.

    **Attributes:**
    - `id` (`int`): Primary key, foreign key to event.id.
    - `name` (`str`): Name of the syscall.
    - `retno` (`Optional[int]`): Return value of the syscall.
    - `retno_repr` (`Optional[str]`): String representation of the return value.
    - `arg0-arg5` (`Optional[int]`): Argument values.
    - `arg0_repr-arg5_repr` (`Optional[str]`): String representations of arguments.
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
        args = []
        for i in range(6):
            arg, arg_repr = getattr(self, f"arg{i}"), getattr(self, f"arg{i}_repr")
            if arg is not None:
                args.append(f"{arg_repr}({arg:#x})")
        return f"{self.name}({', '.join(args)}) = {self.retno}({self.retno_repr})"


class Exec(Event):
    """
    ### Represents a process execution (exec) event.

    **Attributes:**
    - `id` (`int`): Primary key, foreign key to event.id.
    - `calltree` (`str`): Call tree information.
    - `argc` (`str`): Argument count.
    - `argv` (`str`): Argument values.
    - `envp` (`str`): Environment variables.
    - `euid` (`int`): Effective user ID.
    - `egid` (`int`): Effective group ID.
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
        return f'Exec: "{self.argv}" {self.calltree}'
