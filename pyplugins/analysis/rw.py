from pandare2 import PyPlugin
from penguin import plugins
from events.types import Read, Write


class RWLog(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.DB = plugins.DB
        self.hyp = plugins.hypermem
        panda.hsyscall("on_sys_write_return")(self.hyp.wrap(self.write))
        panda.hsyscall("on_sys_read_return")(self.hyp.wrap(self.read))

    def write(self, cpu, proto, syscall, hook, fd, buf, count):
        s = yield from self.hyp.read_str(buf)

        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        fname = yield from self.hyp.get_fd_name(fd) or b"?"
        fname = self.panda.read_file_name(cpu, fd) or b"?"
        self.DB.add_event(
            Write(
                fd=signed_fd,
                fname=fname.decode("latin-1", errors="ignore"),
                buffer=s,
            )
        )

    def read(self, cpu, proto, syscall, hook, fd, buf, count):
        s = yield from self.hyp.read_str(buf)
        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        fname = yield from self.hyp.get_fd_name(fd) or b"?"
        # Get name of FD, if it's valid
        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        self.DB.add_event(
            Read(
                fd=signed_fd,
                fname=fname.decode("latin-1", errors="ignore"),
                buffer=s,
            )
        )
