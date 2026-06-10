"""issue831 experiment: MTD OOP callback device in ISOLATION.

Registers a single object-oriented MTD device whose read callback delivers
data via the PANDA virtual-memory write fast path (plugins.mem.write_bytes,
NO prefer_portal) -- the suspected-faulty path -- with NO native-mmap /
qemu_mem machinery involved (no aperture, no dev/proc/anon SUPPORT_MMAP files,
no micropython mmap). Used to test whether the ppc64 read-back segfault is
traceable to the native-mmap code or to the MTD callback itself.
"""
from penguin import Plugin, plugins
from hyperfile.models.base import MtdDevice, LoffT, SizeT, CharPtr


class MtdOnlyDevice(MtdDevice):
    NAME = "mtd_only_repro"
    SIZE = 64 * 1024
    ERASE_SIZE = 4096
    WRITE_SIZE = 1
    OOB_SIZE = 0
    TYPE = "nor"

    def __init__(self):
        self.data = bytearray(b"\xff" * self.SIZE)
        initial = b"mtd only base\n"
        self.data[:len(initial)] = initial
        super().__init__()

    def read(self, ptregs, offset: LoffT, length: SizeT, buf_ptr: CharPtr):
        off = int(offset)
        size = int(length)
        if off >= self.SIZE:
            ptregs.retval = 0
            return 0
        chunk = min(size, self.SIZE - off)
        # PANDA virtual-memory write fast path (the suspected-faulty path).
        yield from plugins.mem.write_bytes(buf_ptr, bytes(self.data[off:off + chunk]))
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


class MtdOnlyRepro(Plugin):
    def __init__(self):
        plugins.mtd.register_mtd(MtdOnlyDevice())
