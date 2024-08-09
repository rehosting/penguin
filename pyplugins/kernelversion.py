from pandare import PyPlugin
from os.path import join as pjoin

err_output = "kerver_err.txt"


class KernelVersion(PyPlugin):
    def __init__(self, panda):
        self.panda = panda

        self.outdir = self.get_arg("outdir")
        self.sysname = self.get_arg("sysname")
        self.nodename = self.get_arg("nodename")
        self.release = self.get_arg("release")
        self.version = self.get_arg("version")
        self.machine = self.get_arg("machine")
        self.domainname = self.get_arg("domainname")

        @self.panda.ppp("syscalls2", "on_sys_newuname_return")
        def post_uname(cpu, pc, buf_ptr):
            # Check if variable has been set in config and if so call virtual_memory_write
            if self.sysname:
                try:
                    self.panda.virtual_memory_write(
                        cpu, buf_ptr, (self.sysname.encode("utf-8") + b"\0")
                    )
                except ValueError as err:
                    self.write_error(err)
            if self.nodename:
                try:
                    self.panda.virtual_memory_write(
                        cpu, buf_ptr + 65 * 1, (self.nodename.encode("utf-8") + b"\0")
                    )
                except ValueError as err:
                    self.write_error(err)
            if self.release:
                try:
                    self.panda.virtual_memory_write(
                        cpu, buf_ptr + 65 * 2, (self.release.encode("utf-8") + b"\0")
                    )
                except ValueError as err:
                    self.write_error(err)
            if self.version:
                try:
                    self.panda.virtual_memory_write(
                        cpu, buf_ptr + 65 * 3, (self.version.encode("utf-8") + b"\0")
                    )
                except ValueError as err:
                    self.write_error(err)
            if self.machine:
                try:
                    self.panda.virtual_memory_write(
                        cpu, buf_ptr + 65 * 4, (self.machine.encode("utf-8") + b"\0")
                    )
                except ValueError as err:
                    self.write_error(err)
            if self.domainname:
                try:
                    self.panda.virtual_memory_write(
                        cpu, buf_ptr + 65 * 5, (self.domainname.encode("utf-8") + b"\0")
                    )
                except ValueError as err:
                    self.write_error(err)

    def write_error(self, error):
        with open(pjoin(self.outdir, err_output), "a") as file:
            file.write(f"An error occurred overwriting the utsname struct: {error}\n")
