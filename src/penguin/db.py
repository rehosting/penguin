from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from os.path import join


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "event"
    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str]
    procname: Mapped[str]  # optional mapping to process involved
    proc_id: Mapped[int]

    __mapper_args__ = {
        "polymorphic_identity": "event",
        "polymorphic_on": "type",
    }


class DBConnector(object):
    def __new__(cls, outdir, panda):
        if not hasattr(cls, "instance"):
            cls.instance = super(DBConnector, cls).__new__(cls)
        return cls.instance

    def __init__(self, outdir, panda):
        # singleton model
        if hasattr(self, "engine"):
            return
        self.panda = panda
        self.outdir = outdir
        self.db_path = join(self.outdir, "plugins.db")
        self.engine = create_engine(f"sqlite:///{self.db_path}")
        self.queued_events = []
        # number of events to queue before flushing to db
        self.buffer_size = 1000

    def _flush_queue(self):
        if not hasattr(self, "first"):
            self.first = True
            Base.metadata.create_all(self.engine)
        print(f"flushing queue with {len(self.queued_events)} events")
        with Session(self.engine) as session:
            session.add_all(self.queued_events)
            session.commit()
        self.queued_events = []

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
        if len(self.queued_events) > self.buffer_size:
            self._flush_queue()

    def close(self):
        if self.queued_events:
            self._flush_queue()
        self.engine.dispose()
