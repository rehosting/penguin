"""
# Events Base Models

This module defines the SQLAlchemy base classes and the core `Event` model for the penguin event database.
All event types inherit from `Event`, which provides polymorphic mapping for different event subtypes.

## Example usage

```python
from events.base import Event, Base
```

## Classes

- `Base`: Declarative base for all ORM models.
- `Event`: Base class for all event records, supporting polymorphic identity.

## Table Structure

The `event` table contains:
- `id`: Primary key for the event.
- `type`: Polymorphic type identifier.
- `procname`: Name of the process involved in the event.
- `proc_id`: Process ID.

"""

from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column


class Base(DeclarativeBase):
    """
    ### Declarative base class for all ORM models.
    """
    pass


class Event(Base):
    """
    ### Base class for all event records in the database.

    **Attributes:**
    - `id` (`int`): Primary key for the event.
    - `type` (`str`): Polymorphic type identifier for the event.
    - `procname` (`str`): Name of the process involved in the event.
    - `proc_id` (`int`): Process ID associated with the event.

    SQLAlchemy polymorphic mapping is used to allow subclasses to represent different event types.
    """
    __tablename__ = "event"
    id: Mapped[int] = mapped_column(primary_key=True)
    type: Mapped[str]
    procname: Mapped[str]  # optional mapping to process involved
    proc_id: Mapped[int]

    __mapper_args__ = {
        "polymorphic_identity": "event",
        "polymorphic_on": "type",
    }
