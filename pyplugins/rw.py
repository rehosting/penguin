from pandare import PyPlugin
from events.types import Read, Write


class RWLog(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.DB = self.ppp.DB
        panda.ppp("syscalls2", "on_sys_write_return")(self.write)
        panda.ppp("syscalls2", "on_sys_read_return")(self.read)

    def write(self, cpu, pc, fd, buf, count):
        try:
            s = self.panda.read_str(cpu, buf, count)
        except ValueError:
            s = "error"

        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        fname = self.panda.get_file_name(cpu, fd) or b"?"
        self.DB.add_event(
            Write(
                fd=signed_fd,
                fname=fname.decode("latin-1", errors="ignore"),
                buffer=s,
            )
        )

    def read(self, cpu, pc, fd, buf, count):
        try:
            s = self.panda.read_str(cpu, buf, count)
        except ValueError:
            s = "error"
        fname = self.panda.get_file_name(cpu, fd) or b"?"
        # Get name of FD, if it's valid
        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        self.DB.add_event(
            Read(
                fd=signed_fd,
                fname=fname.decode("latin-1", errors="ignore"),
                buffer=s,
            )
        )
