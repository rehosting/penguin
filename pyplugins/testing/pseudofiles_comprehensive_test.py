from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import (
    ProcFile, DevFile, SysFile, SysctlFile, MtdDevice, AnonFile, SocketFile,
    FilePtr, CharPtr, SizeT, LoffTPtr, CtlTablePtr, CInt, SizeTPtr, LoffT, InodePtr, SocketPtr, SockAddrPtr, MsgHdrPtr
)
from hyperfile.models.read import ReadConstBuf
import os

# --- 1. ProcFile Test ---
class ComprehensiveProcFile(ReadConstBuf, ProcFile):
    PATH = "comprehensive_proc"
    def __init__(self):
        super().__init__(buffer=b"proc_works\n")

# --- 2. DevFile Test ---
class ComprehensiveDevFile(ReadConstBuf, DevFile):
    PATH = "/dev/comprehensive_dev"
    def __init__(self):
        super().__init__(buffer=b"dev_works\n")

# --- 3. SysFile Test ---
class ComprehensiveSysFile(SysFile):
    PATH = "/sys/kernel/comprehensive_sys"
    def show(self, ptregs: PtRegsWrapper, kobj: any, attr: any, buf: CharPtr):
        data = b"sys_works\n"
        yield from plugins.mem.write(buf, data)
        return len(data)

# --- 4. SysctlFile Test ---
class ComprehensiveSysctlFile(ReadConstBuf, SysctlFile):
    PATH = "kernel/comprehensive_sysctl"
    def __init__(self):
        super().__init__(buffer=b"sysctl_works\n")

# --- 5. MtdDevice Test ---
class ComprehensiveMtdDevice(MtdDevice):
    def __init__(self):
        super().__init__(name="comprehensive_mtd", size=1024*1024)
    def read(self, ptregs: PtRegsWrapper, offset: LoffT, length: SizeT, buf_ptr: CharPtr):
        data = b"mtd_works\n"
        # For MTD, we just return data at offset 0 for this test
        if int(offset) == 0:
            yield from plugins.mem.write(buf_ptr, data)
        return 0

class PseudofilesComprehensiveTest(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        
        # Register all models
        plugins.procfs.register_proc(ComprehensiveProcFile())
        plugins.devfs.register_devfs(ComprehensiveDevFile())
        plugins.sysfs.register_sysfs(ComprehensiveSysFile())
        plugins.sysctl.register_sysctl(ComprehensiveSysctlFile())
        plugins.mtd.register_mtd(ComprehensiveMtdDevice())
