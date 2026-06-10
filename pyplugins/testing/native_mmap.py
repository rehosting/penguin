from penguin import Plugin, plugins
from apis.syscalls import ValueFilter
from hyperfile.models.base import (
    AnonFile,
    CharPtr,
    DevFile,
    LoffT,
    MtdDevice,
    ProcFile,
    SizeT,
)
from hyperfile.models.read import ReadConstBuf
from hyperfile.models.write import WriteRecord


class NativeMmapDevFile(ReadConstBuf, WriteRecord, DevFile):
    PATH = "mmap_native"
    SUPPORT_MMAP = True

    def __init__(self):
        super().__init__(buffer=b"dev native mmap\n", size=4096)


class NativeMmapProcFile(ReadConstBuf, WriteRecord, ProcFile):
    PATH = "mmap_native"
    SUPPORT_MMAP = True

    def __init__(self):
        super().__init__(buffer=b"proc native mmap\n", size=4096)


class NativeMmapAnonFile(ReadConstBuf, WriteRecord, AnonFile):
    SUPPORT_MMAP = True

    def __init__(self):
        super().__init__(
            path="/tmp/mmap_native_anon",
            buffer=b"anon native mmap\n",
            size=4096,
        )


class NativeMmapMtdDevice(MtdDevice):
    NAME = "mmap_native_mtd"
    SIZE = 64 * 1024
    ERASE_SIZE = 4096
    WRITE_SIZE = 1
    OOB_SIZE = 0
    TYPE = "nor"

    def __init__(self):
        self.data = bytearray(b"\xff" * self.SIZE)
        initial = b"mtd native mmap\n"
        self.data[:len(initial)] = initial
        super().__init__()

    def read(self, ptregs, offset: LoffT, length: SizeT, buf_ptr: CharPtr):
        off = int(offset)
        size = int(length)
        if off >= self.SIZE:
            ptregs.retval = 0
            return 0
        chunk = min(size, self.SIZE - off)
        # issue831 EXPERIMENT: temporarily reverted to the PANDA write fast path
        # so this run reproduces the baseline fault alongside the isolated
        # mtd_only test. Restore prefer_portal=True after the experiment.
        yield from plugins.mem.write_bytes(
            buf_ptr,
            bytes(self.data[off:off + chunk]),
        )
        ptregs.retval = 0
        return 0

    def write(self, ptregs, offset: LoffT, length: SizeT, buf_ptr: CharPtr):
        off = int(offset)
        size = int(length)
        if off >= self.SIZE:
            ptregs.retval = -28
            return -28
        chunk = min(size, self.SIZE - off)
        raw = yield from plugins.mem.read(buf_ptr, chunk, fmt="bytes")
        self.data[off:off + chunk] = raw
        ptregs.retval = 0
        return 0

    def erase(self, ptregs, offset: LoffT, length: SizeT):
        off = int(offset)
        size = int(length)
        if off >= self.SIZE:
            ptregs.retval = -22
            return -22
        chunk = min(size, self.SIZE - off)
        self.data[off:off + chunk] = b"\xff" * chunk
        ptregs.retval = 0
        return 0


class NativeMmap(Plugin):
    def __init__(self):
        self.anon_file = NativeMmapAnonFile()

        plugins.devfs.register_devfs(NativeMmapDevFile())
        plugins.procfs.register_proc(NativeMmapProcFile())
        plugins.mtd.register_mtd(NativeMmapMtdDevice())

        syscalls = plugins.syscalls
        syscalls.syscall(
            "on_sys_open_enter",
            arg_filters=[ValueFilter.string_exact("/tmp/mmap_native_anon")]
        )(self.on_open_anon)
        syscalls.syscall(
            "on_sys_openat_enter",
            arg_filters=[
                None,
                ValueFilter.string_exact("/tmp/mmap_native_anon"),
            ],
        )(self.on_open_anon)

    def on_open_anon(self, regs, proto, syscall, *args):
        syscall.skip_syscall = True
        fd = yield from plugins.anonfs.register_anon_file(
            self.anon_file,
            name="[mmap_native_anon]",
        )
        syscall.retval = fd
