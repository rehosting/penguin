from pandare2 import PyPlugin
from penguin import plugins
from events.types import Read, Write


class RWLog(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.DB = plugins.DB
        plugins.syscalls.syscall("on_sys_write_return")(self.write)
        plugins.syscalls.syscall("on_sys_read_return")(self.read)

    @plugins.portal.wrap
    def write(self, proto, syscall, fd, buf, count):
        s = yield from plugins.portal.read_str(buf)
        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        fname = yield from plugins.portal.get_fd_name(fd) or "?"
        args = yield from plugins.portal.get_args()
        if args:
            procname = args[0]
        else:
            procname = "[???]"
        self.DB.add_event(
            Write(
                procname=procname,
                fd=signed_fd,
                fname=fname,
                buffer=s,
            )
        )

    @plugins.portal.wrap
    def read(self, proto, syscall, fd, buf, count):
        s = yield from plugins.portal.read_str(buf)
        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        fname = yield from plugins.portal.get_fd_name(fd) or "?"
        # Get name of FD, if it's valid
        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        args = yield from plugins.portal.get_args()
        if args:
            procname = args[0]
        else:
            procname = "[???]"
        self.DB.add_event(
            Read(
                procname=procname,
                fd=signed_fd,
                fname=fname,
                buffer=s,
            )
        )
