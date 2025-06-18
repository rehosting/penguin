"""
# Events Package

This package defines the core event data model and types for the cleanguin system. It provides SQLAlchemy ORM models
for all event types collected and stored in the cleanguin event database, as well as utilities for querying and
processing these events.

## Structure

- `base.py`: Contains the `Base` declarative class and the core `Event` model, which all event types inherit from.
- `types.py`: Defines specific event types such as `Read`, `Write`, `Syscall`, and `Exec`, each mapped to its own table.
- `utils/`: Contains utility modules and CLI tools for querying and filtering event data.

## Example programmatic usage

```python
from events import Event, Read, Write, Syscall, Exec

# Querying events (using SQLAlchemy session):
session.query(Read).filter(Read.procname == "myproc").all()
```

## Example CLI usage

```bash
execs --procname myproc --fd 3 --filename log.txt --output results.txt
reads --procname myproc --fd 4 --filename input.txt --output reads.txt
writes --procname myproc --fd 5 --filename output.txt --output writes.txt
syscalls --procname myproc --syscall open --errors --output syscalls.txt
fds --procname myproc --fd 3 --output fds.txt
tasks --results ./results/latest --output tasks.txt
```

## Available Types

- `Event`: Base class for all events.
- `Read`: File read events.
- `Write`: File write events.
- `Syscall`: System call events.
- `Exec`: Process execution events.

## Utilities

For CLI tools and helpers, see the `events.utils` subpackage.

"""

from .base import Base, Event
from .types import *
