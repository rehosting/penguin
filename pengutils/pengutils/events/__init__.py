"""
Pengutils Package
=================

Pengutils is a general-purpose utility and data modeling package for the Penguin system. It provides SQLAlchemy ORM models
for event data, as well as a growing set of utilities, helpers, and CLI tools for querying, filtering, and processing
Penguin database information.

Usage
-----

You can use pengutils:

1. **Inside the Penguin container**: All models and CLI tools are available by default.
2. **Outside the Penguin container**: Clone the repository and install from source to use the models and CLI tools independently:

   .. code-block:: bash

       git clone https://github.com/rehosting/penguin.git
       cd penguin/pengutils
       pip install .

Scope
-----

* Data models for core Penguin event types (e.g., Read, Write, Syscall, Exec).
* Utility functions for working with Penguin data.
* CLI tools for querying, filtering, and exporting results.
* Helpers for common database and analysis tasks.

Example programmatic usage
--------------------------

.. code-block:: python

    from pengutils.events import Event, Read, Write, Syscall, Exec

    # Querying events (using SQLAlchemy session):
    session.query(Read).filter(Read.procname == "myproc").all()

Example CLI usage
-----------------

.. code-block:: bash

    execs --procname myproc --fd 3 --filename log.txt --output results.txt
    reads --procname myproc --fd 4 --filename input.txt --output reads.txt
    writes --procname myproc --fd 5 --filename output.txt --output writes.txt
    syscalls --procname myproc --syscall open --errors --output syscalls.txt
    fds --procname myproc --fd 3 --output fds.txt
    tasks --results ./results/latest --output tasks.txt

Available Types
---------------

* ``Event``: Base class for all events.
* ``Read``: File read events.
* ``Write``: File write events.
* ``Syscall``: System call events.
* ``Exec``: Process execution events.

Utilities
---------

For CLI tools and helpers, see the ``pengutils.utils`` subpackage.

"""

from .base import Base, Event
from .types import *
