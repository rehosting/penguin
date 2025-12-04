"""
DB Logger Plugin
================

This module implements a database-backed event logger plugin for the framework.
It uses SQLAlchemy to persist events to a SQLite database in a buffered, asynchronous manner.

Features
--------

- Buffers events in memory and flushes them to disk in batches for performance.
- Uses a background thread to periodically flush events or when the buffer is full.
- Thread-safe event queueing.
- Schema is auto-created on first flush.
- Configurable buffer size and output directory.

Usage
-----

.. code-block:: python

    from pyplugins.loggers.db import DB

    db_logger = DB()
    db_logger.add_event(event)
    db_logger.uninit()

Arguments
---------

- outdir: Output directory for the SQLite database file.
- bufsize: Buffer size before flushing to disk (default: 100000).
- verbose: Enable debug logging.

"""

from sqlalchemy import create_engine, insert
from os.path import join
from events import Base
from threading import Lock, Thread, Event
from penguin import Plugin
import time

class DB(Plugin):
    """
    Optimized Database-backed event logger.
    Uses SQLAlchemy Core for bulk inserts and minimizes locking contention.
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
        # increasing pool size for concurrent access if needed
        self.engine = create_engine(f"sqlite:///{self.db_path}", connect_args={'check_same_thread': False})
        self.queued_events: list = []
        self.buffer_size: int = int(self.get_arg("bufsize") or 100000)

        self.queue_lock = Lock()
        self.flush_event = Event()
        self.stop_event = Event()
        self.finished_worker = Event()
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
            # Wait for flush signal or periodic timeout (every 2 seconds)
            self.flush_event.wait(timeout=2)
            self.flush_event.clear()
            self._swap_and_flush()

        self._swap_and_flush()
        self.finished_worker.set()

    def _swap_and_flush(self):
        """Atomic swap of the queue to release the lock immediately."""
        to_flush = None
        with self.queue_lock:
            if self.queued_events:
                to_flush = self.queued_events
                self.queued_events = [] # allocate new list
        
        if to_flush:
            self._perform_flush(to_flush)

    def _perform_flush(self, events: list) -> None:
        if not self.initialized_db:
            Base.metadata.create_all(self.engine)
            self.initialized_db = True

        # Group events by table to perform bulk inserts
        # Structure: { TableClass: [dict1, dict2, ...] }
        batched = {}
        for table_cls, data in events:
            if table_cls not in batched:
                batched[table_cls] = []
            batched[table_cls].append(data)

        start_t = time.time()
        with self.engine.begin() as conn: # Transactional scope
            for table_cls, data_list in batched.items():
                # CORE INSERT: 10x faster than ORM add_all
                conn.execute(insert(table_cls), data_list)
        
        dur = time.time() - start_t
        self.logger.debug(f"Flushed {len(events)} events in {dur:.4f}s")

    def add_event(self, table_cls, data: dict) -> None:
        """
        Add an event to the buffer.
        Arguments:
            table_cls: The SQLAlchemy class (e.g., Syscall)
            data: A dictionary representing the row
        """
        if "proc_id" not in data or not data["proc_id"]:
            data["proc_id"] = 0

        with self.queue_lock:
            self.queued_events.append((table_cls, data))
            should_flush = len(self.queued_events) >= self.buffer_size
        
        if should_flush:
            self.flush_event.set()

    def uninit(self) -> None:
        """
        Clean up the plugin and flush any remaining events.

        - Triggers a final flush.
        - Stops the background worker thread.
        - Disposes of the SQLAlchemy engine.

        **Returns:** None
        """
        self.stop_event.set()
        self.flush_event.set()
        self.finished_worker.wait(timeout=10)
        self.engine.dispose()
