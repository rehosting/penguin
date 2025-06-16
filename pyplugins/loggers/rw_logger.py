from penguin import plugins, Plugin
from events.types import Read, Write


class RWLog(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.DB = plugins.DB
        plugins.syscalls.syscall("on_sys_write_return")(self.write)
        plugins.syscalls.syscall("on_sys_read_return")(self.read)

    def write(self, cpu, proto, syscall, fd, buf, count):
        s = yield from plugins.mem.read_str(buf)
        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        fname = (yield from plugins.portal.get_fd_name(fd)) or "?"
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

    def read(self, cpu, proto, syscall, fd, buf, count):
        s = yield from plugins.mem.read_str(buf)
        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        fname = (yield from plugins.portal.get_fd_name(fd)) or "?"
        # Get name of FD, if it's valid
        signed_fd = int(self.panda.ffi.cast("target_long", fd))
        args = yield from plugins.osi.get_args()
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
