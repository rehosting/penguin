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
        # issue831 probe state
        self.outdir = None
        self._probe_reads = 0
        self._probe_logged = 0
        super().__init__()

    def _probe_log(self, line):
        self._probe_logged += 1
        if not self.outdir:
            return
        try:
            import os
            with open(os.path.join(self.outdir, "issue831_probe.txt"), "a") as f:
                f.write(line + "\n")
        except Exception:
            pass

    def read(self, ptregs, offset: LoffT, length: SizeT, buf_ptr: CharPtr):
        off = int(offset)
        size = int(length)
        if off >= self.SIZE:
            ptregs.retval = 0
            return 0
        chunk = min(size, self.SIZE - off)
        src = bytes(self.data[off:off + chunk])

        # issue831: deliver via the ORIGINAL PANDA virtual-memory fast path
        # (the suspected-faulty path) so the probe characterizes it.
        yield from plugins.mem.write_bytes(buf_ptr, src)

        # PROBE: read the same kernel VA back two ways and compare against what
        # we intended to write.
        #   panda_rb : PANDA cpu_memory_rw_debug read (same host translation)
        #   portal_rb: guest-executed portal read (the guest's REAL mapping)
        # If portal_rb != src (or != panda_rb), the PANDA write landed on a
        # different physical page than the guest sees -> wrong-PA confirmed.
        addr = buf_ptr.address if hasattr(buf_ptr, "address") else int(buf_ptr)
        self._probe_reads += 1
        idx = self._probe_reads
        try:
            panda_rb = yield from plugins.mem.read_bytes(buf_ptr, chunk)
            portal_rb = yield from plugins.mem.read_bytes(
                buf_ptr, chunk, prefer_portal=True)
        except Exception as e:
            self._probe_log(f"read#{idx} off={off} addr={addr:#x} chunk={chunk} EXC {e!r}")
            ptregs.retval = 0
            return 0

        flags = []
        if panda_rb != src:
            flags.append("panda!=src")
        if portal_rb != src:
            flags.append("portal!=src")
        if panda_rb != portal_rb:
            flags.append("panda!=portal")

        # Always log the first few reads (confirm probe active); after that log
        # only mismatches. Cap total lines.
        if (idx <= 8 or flags) and self._probe_logged < 300:
            def firstdiff(a, b):
                if a is None or b is None:
                    return -1
                for i in range(min(len(a), len(b))):
                    if a[i] != b[i]:
                        return i
                return len(a) if len(a) != len(b) else -1
            d_ps = firstdiff(panda_rb, src)
            d_qs = firstdiff(portal_rb, src)
            self._probe_log(
                f"read#{idx} off={off} addr={addr:#x} chunk={chunk} "
                f"flags={','.join(flags) or 'ok'} "
                f"src[:8]={src[:8].hex()} panda[:8]={(panda_rb or b'')[:8].hex()} "
                f"portal[:8]={(portal_rb or b'')[:8].hex()} "
                f"diff_panda_src@{d_ps} diff_portal_src@{d_qs}"
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
        mtd_dev = NativeMmapMtdDevice()
        mtd_dev.outdir = self.get_arg("outdir")  # issue831 probe output dir
        plugins.mtd.register_mtd(mtd_dev)

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
