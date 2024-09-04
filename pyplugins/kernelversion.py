from pandare import PyPlugin

RETRY = 0xDEADBEEF


class KernelVersion(PyPlugin):
    def __init__(self, panda):
        self.panda = panda

        self.outdir = self.get_arg("outdir")
        self.sysname = self.get_arg("sysname")
        self.nodename = self.get_arg("nodename")
        self.release = self.get_arg("release")
        self.version = self.get_arg("kversion")
        self.machine = self.get_arg("machine")
        self.domainname = self.get_arg("domainname")

        self.ppp.Events.listen("igloo_uname", self.change_uname)

    def create_string(self):
        uname_str = ""

        uname_str += self.sysname + "," if self.sysname else "none,"
        uname_str += self.nodename + "," if self.nodename else "none,"
        uname_str += self.release + "," if self.release else "none,"
        uname_str += self.version + "," if self.version else "none,"
        uname_str += self.machine + "," if self.machine else "none,"
        uname_str += self.domainname + "," if self.domainname else "none,"

        return uname_str

    def change_uname(self, cpu, buf_ptr, filler):
        new_uname = self.create_string()
        try:
            self.panda.virtual_memory_write(
                cpu, buf_ptr, (new_uname.encode("utf-8") + b"\0")
            )
            self.panda.arch.set_retval(cpu, 0x1)
        except ValueError:
            self.panda.arch.set_retval(cpu, RETRY)
