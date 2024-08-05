from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from os.path import join
from pandare import PyPlugin
from events import Base


class DB(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.db_path = join(self.outdir, "plugins.db")
        self.engine = create_engine(f"sqlite:///{self.db_path}")
        self.queued_events = []
        # number of events to queue before flushing to db
        self.buffer_size = self.get_arg("bufsize") or 10000

    def _flush_queue(self):
        if not hasattr(self, "first"):
            self.first = True
            Base.metadata.create_all(self.engine)
        print(f"flushing queue with {len(self.queued_events)} events")
        with Session(self.engine) as session:
            session.add_all(self.queued_events)
            session.commit()
        self.queued_events.clear()

    @PyPlugin.ppp_export
    def add_event(self, event, proc_info=True):
        if proc_info and (event.procname is None or event.proc_id is None):
            panda = self.panda
            if "osi" in panda.plugins:
                cpu = panda.get_cpu()
                proc = panda.plugins["osi"].get_current_process(cpu)
                event.procname = (
                    panda.ffi.string(proc.name).decode("utf8", "ignore")
                    if proc.name != panda.ffi.NULL
                    else "[???]"
                )
                event.proc_id = proc.create_time
        self.queued_events.append(event)
        if len(self.queued_events) >= self.buffer_size:
            self._flush_queue()

    def close(self):
        if self.queued_events:
            self._flush_queue()
        self.engine.dispose()
