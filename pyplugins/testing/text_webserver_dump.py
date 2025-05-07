from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins
from os.path import join

class WebserverDump(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.webserver_dump")
        self.hyp = plugins.hypermem
        self.panda.hsyscall("on_sys_read_return", comm_filter="test_webserver")(self.hyp.wrap(self.recv_ret))

    def recv_ret(self, cpu, proto, syscall, hook, fd, buf, count):
        fd_name = yield from self.hyp.read_fd_name(fd) or "[???]"
        if "socket:" in fd_name:
            self.logger.info(f"FD: {fd_name}")
            data = yield from self.hyp.read_bytes(buf, count)
            self.logger.info(f"Data: {data}")

            if b"GET /dump" in data:
                self.logger.info("Doing dump in process")
                yield from self.hyp.do_dump()
