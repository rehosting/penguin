from pandare import PyPlugin
from typing import Optional
from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy import ForeignKey
from typing import Optional
from penguin.db import Event

class Read(Event):
    __tablename__ = "read"
    id: Mapped[int] = mapped_column(
        ForeignKey("event.id"), primary_key=True)
    fd: Mapped[int]
    fname: Mapped[str]
    buffer: Mapped[Optional[str]]

    __mapper_args__ = {
        "polymorphic_identity": "read",
    }
    
    def __str__(self):
        return f'read({self.fd}, {self.fname}, "{self.buffer}")'


class Write(Event):
    __tablename__ = "write"
    id: Mapped[int] = mapped_column(
        ForeignKey("event.id"), primary_key=True)
    fd: Mapped[int]
    fname: Mapped[Optional[str]]
    buffer: Mapped[Optional[str]]

    __mapper_args__ = {
        "polymorphic_identity": "write",
    }

    def __str__(self):
        return f'write({self.fd}, {self.fname}, "{self.buffer}")'


class RWLog(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.DB = self.get_arg("db")
        panda.ppp("syscalls2", "on_sys_write_return")(self.write)
        panda.ppp("syscalls2", "on_sys_read_return")(self.read)

    def write(self, cpu, pc, fd, buf, count):
        try:
            s = self.panda.read_str(cpu, buf, count)
        except ValueError:
            s = "error"

        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        fname = self.panda.get_file_name(cpu, fd) or b"?"
        self.DB.add_event(Write(fd=signed_fd, 
                            fname=fname.decode('utf-8', errors='ignore'), buffer=s),
                          self.panda)

    def read(self, cpu, pc, fd, buf, count):
        try:
            s = self.panda.read_str(cpu, buf, count)
        except ValueError:
            s = "error"
        fname = self.panda.get_file_name(cpu, fd) or b"?"
        # Get name of FD, if it's valid
        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        self.DB.add_event(Read(fd=signed_fd,
                               fname=fname.decode('utf-8', errors='ignore'),
                               buffer=s))