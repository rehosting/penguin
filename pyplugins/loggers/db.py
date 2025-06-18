"""
# DB Logger Plugin

This module implements a database-backed event logger plugin for the framework.
It uses SQLAlchemy to persist events to a SQLite database in a buffered, asynchronous manner.

## Features

- Buffers events in memory and flushes them to disk in batches for performance.
- Uses a background thread to periodically flush events or when the buffer is full.
- Thread-safe event queueing.
- Schema is auto-created on first flush.
- Configurable buffer size and output directory.

## Usage

```python
from pyplugins.loggers.db import DB

db_logger = DB()
db_logger.add_event(event)
db_logger.uninit()
```

## Arguments

- `outdir`: Output directory for the SQLite database file.
- `bufsize`: Buffer size before flushing to disk (default: 100000).
- `verbose`: Enable debug logging.

"""

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from os.path import join
from events import Base
from threading import Lock, Thread, Event
import time
from penguin import Plugin


class DB(Plugin):
    """
    Database-backed event logger plugin.

    Buffers events and writes them to a SQLite database asynchronously.
    """

    def __init__(self) -> None:
        """
        Initialize the DB logger plugin.

        - Sets up the output directory and database path.
        - Initializes the SQLAlchemy engine.
        - Starts the background flush worker thread.
        - Configures buffer size and logging verbosity.

        **Returns:** None
        """
        self.outdir = self.get_arg("outdir")
        self.db_path = join(self.outdir, "plugins.db")
        self.engine = create_engine(f"sqlite:///{self.db_path}")
        self.queued_events: list = []
        self.buffer_size: int = self.get_arg("bufsize") or 100000
        self.event_lock = Lock()
        self.flush_event = Event()
        self.stop_event = Event()
        self.initialized_db = False

        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        # Start the background flush thread
        Thread(target=self._flush_worker, daemon=True).start()

    def _flush_worker(self) -> None:
        """
        Background worker thread that periodically flushes events to the database.

        - Waits for either a flush signal or a timeout.
        - Flushes all queued events to the database.

        **Returns:** None
        """
        while not self.stop_event.is_set():
            # Wait for a flush signal or timeout
            self.flush_event.wait(timeout=5)
            self.flush_event.clear()

            with self.event_lock:
                events_to_flush = self.queued_events.copy()
                self.queued_events.clear()

            if events_to_flush:
                self._perform_flush(events_to_flush)

    def _perform_flush(self, events: list) -> None:
        """
        Flush a list of events to the database.

        - Initializes the database schema if needed.
        - Commits all events in a single transaction.

        **Parameters:**
        - `events` (`list`): List of event objects to flush.

        **Returns:** None
        """
        if events:
            self.logger.debug(f"Flushing {len(events)} events to DB")

            # Initialize schema if needed
            if not self.initialized_db:
                Base.metadata.create_all(self.engine)
                self.initialized_db = True

            # Write to database
            with Session(self.engine) as session:
                session.add_all(events)
                session.commit()

    def add_event(self, event) -> None:
        """
        Add an event to the buffer.

        - Sets `proc_id` to 0 if not present.
        - Triggers a flush if the buffer is full.

        **Parameters:**
        - `event`: The event object to add.

        **Returns:** None
        """
        if not event.proc_id:
            event.proc_id = 0

        with self.event_lock:
            self.queued_events.append(event)
            if len(self.queued_events) >= self.buffer_size:
                self.flush_event.set()

    def uninit(self) -> None:
        """
        Clean up the plugin and flush any remaining events.

        - Triggers a final flush.
        - Stops the background worker thread.
        - Disposes of the SQLAlchemy engine.

        **Returns:** None
        """
        # Trigger a final flush and stop the worker thread
        if self.queued_events:
            self.flush_event.set()

        self.stop_event.set()
        self.flush_event.set()  # Wake up the thread
        time.sleep(0.1)  # Give the thread time to process

        self.engine.dispose()
