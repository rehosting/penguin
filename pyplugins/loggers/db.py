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
    db_logger.add_event(Syscall, row_dict)
    db_logger.uninit()

Arguments
---------

- outdir: Output directory for the SQLite database file.
- bufsize: Buffer size before flushing to disk (default: 100000).
- verbose: Enable debug logging.

"""

from sqlalchemy import create_engine, insert, inspect
from os.path import join
from events import Base
# Import the Base Event class for inheritance checks (aliased to avoid conflict with threading.Event)
from events.base import Event as BaseEvent
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

        # Cache for SQLAlchemy reflection results
        # Key: TableClass, Value: (poly_identity, poly_col_name, child_cols_set)
        self._reflection_cache = {}

        # Manual ID Counter for fresh DBs (Required for Dual Core Inserts)
        self.id_counter = 1

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
                self.queued_events = []  # allocate new list

        if to_flush:
            self._perform_flush(to_flush)

    def _get_table_info(self, table_cls):
        """Cached introspection of table metadata"""
        if table_cls in self._reflection_cache:
            return self._reflection_cache[table_cls]

        mapper = inspect(table_cls)
        poly_identity = mapper.polymorphic_identity

        base_mapper = inspect(BaseEvent)
        poly_col_name = base_mapper.polymorphic_on.name

        child_table_cols = {c.key for c in mapper.local_table.c}

        info = (poly_identity, poly_col_name, child_table_cols)
        self._reflection_cache[table_cls] = info
        return info

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

        # Open transaction
        with self.engine.begin() as conn:
            for table_cls, data_list in batched.items():

                # GENERIC OPTIMIZATION:
                # If the table inherits from Event (but is not Event itself),
                # we must perform a Split Insert (Event + Subclass).
                # This works for Syscall, Read, Write, Exec, etc.
                if issubclass(table_cls, BaseEvent) and table_cls is not BaseEvent:
                    poly_identity, poly_col_name, child_table_cols = self._get_table_info(table_cls)

                    batch_len = len(data_list)
                    start_id = self.id_counter
                    self.id_counter += batch_len

                    event_rows = []
                    child_rows = []

                    # Single-pass loop to split data efficiently
                    # zip(range) allows us to assign IDs without a separate counter increment
                    for current_id, row in zip(range(start_id, start_id + batch_len), data_list):

                        event_rows.append({
                            "id": current_id,
                            "proc_id": row.get('proc_id', 0),
                            "procname": row.get('procname', '[?]'),
                            poly_col_name: poly_identity
                        })

                        # 2. Add 'id' to the child row
                        row["id"] = current_id
                        child_rows.append(row)

                    # Execute Dual Inserts
                    # Insert into parent FIRST (for Foreign Key correctness)
                    conn.execute(insert(BaseEvent), event_rows)
                    # Insert into child SECOND
                    conn.execute(insert(table_cls), child_rows)

                else:
                    # Standard insert for flat tables
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
