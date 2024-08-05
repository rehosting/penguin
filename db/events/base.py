from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column


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
