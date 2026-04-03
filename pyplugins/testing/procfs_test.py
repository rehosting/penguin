from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import ProcFile
from hyperfile.models.read import ReadConstBuf
from hyperfile.models.write import WriteDiscard
from hyperfile.models.ioctl import IoctlZero


class SimpleProcfsFile(ReadConstBuf, WriteDiscard, IoctlZero, ProcFile):
    PATH = "s/i/m/p/l/e/simple_proc"

    def __init__(self):
        super().__init__(buffer=b"Hello from simple_proc!\n")

    def open(self, ptregs: PtRegsWrapper, inode: int, file: int):
        procname = yield from plugins.osi.get_proc_name()
        print(f"SimpleProcfsFile.open called in {procname}")
        ptregs.set_retval(0)

class CPUinfoFile(ReadConstBuf, ProcFile):
    PATH = "/proc/cpuinfo"
    def __init__(self):
        super().__init__(buffer=b"processor       : IGLOO\n")

class DynamicProcfsFile(ProcFile):
    PATH = "dynamic_proc"
    MODE = 0o666

    def __init__(self):
        self.value = 0

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        data = f"{self.value}\n".encode("utf-8")
        offset = yield from plugins.mem.read_int(loff)
        if size <= 0 or offset >= len(data):
            ptregs.set_retval(0)
            return
        chunk = min(size, len(data) - offset)
        yield from plugins.mem.write_bytes(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write_int(loff, offset + chunk)
        ptregs.set_retval(chunk)

    def write(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        raw = yield from plugins.mem.read_bytes(user_buf, size)
        try:
            self.value = int(raw.decode("utf-8").strip())
            ptregs.set_retval(size)
        except:
            ptregs.set_retval(-1)

class LargeProcFile(ReadConstBuf, ProcFile):
    PATH = "large_file"
    def __init__(self):
        super().__init__(buffer=b"A" * 8192)


class ProcTest(Plugin):
    def __init__(self):
        # 1. Standard Proc Registrations
        plugins.procfs.register_proc(SimpleProcfsFile())
        plugins.procfs.register_proc(CPUinfoFile())
        plugins.procfs.register_proc(DynamicProcfsFile())
        plugins.procfs.register_proc(LargeProcFile())


        # 3. Duplicate Check
        try:
            plugins.procfs.register_proc(SimpleProcfsFile())
            self.logger.error("Failed to catch duplicate proc registration!")
        except ValueError:
            self.logger.info("Successfully caught duplicate proc registration.")