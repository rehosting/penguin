from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from os.path import join
from pandare2 import PyPlugin
from events import Base
from threading import Lock, Thread, Event
import time
from penguin import getColoredLogger


class DB(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.db_path = join(self.outdir, "plugins.db")
        self.engine = create_engine(f"sqlite:///{self.db_path}")
        self.queued_events = []
        self.buffer_size = self.get_arg("bufsize") or 100000
        self.event_lock = Lock()
        self.flush_event = Event()
        self.stop_event = Event()
        self.logger = getColoredLogger("db")
        self.initialized_db = False
        
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
        
        # Start the background flush thread
        Thread(target=self._flush_worker, daemon=True).start()

    def _flush_worker(self):
        """Worker thread that periodically flushes events to the database."""
        while not self.stop_event.is_set():
            # Wait for a flush signal or timeout
            self.flush_event.wait(timeout=5)
            self.flush_event.clear()
            
            with self.event_lock:
                events_to_flush = self.queued_events.copy()
                self.queued_events.clear()
            
            if events_to_flush:
                self._perform_flush(events_to_flush)

    def _perform_flush(self, events):
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

    def add_event(self, event):
        if not event.proc_id:
            event.proc_id = 0

        with self.event_lock:
            self.queued_events.append(event)
            if len(self.queued_events) >= self.buffer_size:
                self.flush_event.set()

    def uninit(self):
        # Trigger a final flush and stop the worker thread
        if self.queued_events:
            self.flush_event.set()
        
        self.stop_event.set()
        self.flush_event.set()  # Wake up the thread
        time.sleep(0.1)  # Give the thread time to process
        
        self.engine.dispose()
