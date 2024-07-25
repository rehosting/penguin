from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, Session
from typing import Optional

"""
This is our internal representation of a syscall event
"""


class Syscall(Event):
    __tablename__ = "syscall"
    id: Mapped[int] = mapped_column(ForeignKey("event.id"), primary_key=True)
    name: Mapped[str]
    retno: Mapped[Optional[int]]
    retno_repr: Mapped[Optional[str]]
    arg0: Mapped[Optional[int]]
    arg0_repr: Mapped[Optional[str]]
    arg1: Mapped[Optional[int]]
    arg1_repr: Mapped[Optional[str]]
    arg2: Mapped[Optional[int]]
    arg2_repr: Mapped[Optional[str]]
    arg3: Mapped[Optional[int]]
    arg3_repr: Mapped[Optional[str]]
    arg4: Mapped[Optional[int]]
    arg4_repr: Mapped[Optional[str]]
    arg5: Mapped[Optional[int]]
    arg5_repr: Mapped[Optional[str]]

    __mapper_args__ = {
        "polymorphic_identity": "syscall",
    }

    def __str__(self):
        args = []
        for i in range(6):
            arg, arg_repr = getattr(self, f"arg{i}"), getattr(self, f"arg{i}_repr")
            if arg is not None:
                args.append(f"{arg_repr}({arg:#x})")
        return f"{self.name}({', '.join(args)}) = {self.retno}({self.retno_repr})"
