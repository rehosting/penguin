from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from os.path import join
from pandare2 import PyPlugin
from events import Base
from threading import Lock, Thread, Event
from penguin import getColoredLogger, plugins


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
        self.flush_thread = Thread(target=self._flush_worker, daemon=True)
        self.flush_thread.start()

        self.buffering = True  # Start in buffering mode
        self.pre_init_buffer = []
        # The early_monitoring flag determines whether to keep the pre-init buffered events
        config = self.get_arg("conf")
        self.early_monitoring = config["core"].get("early_monitoring", False)
        if self.early_monitoring:
            self.logger.info("Early monitoring enabled, buffering and will output pre-init events")
        plugins.subscribe(plugins.Events, "igloo_init_done", self.end_buffering)

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

        if self.buffering:
            self.pre_init_buffer.append(event)
            return

        with self.event_lock:
            self.queued_events.append(event)
            if len(self.queued_events) >= self.buffer_size:
                self.flush_event.set()

    def end_buffering(self, *args, **kwargs):
        self.buffering = False
        if self.early_monitoring:
            with self.event_lock:
                self.queued_events.extend(self.pre_init_buffer)
                if self.queued_events:
                    self.flush_event.set()
        self.pre_init_buffer.clear()

    def uninit(self):
        if self.buffering:
            self.end_buffering()
        # Trigger a final flush and stop the worker thread
        if self.queued_events:
            self.flush_event.set()

        self.stop_event.set()
        self.flush_event.set()  # Wake up the thread

        self.flush_thread.join(timeout=5)  # Wait up to 5 seconds for the thread to finish

        self.engine.dispose()
