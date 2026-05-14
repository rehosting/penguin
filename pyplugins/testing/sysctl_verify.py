from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import SysctlFile, CharPtr, LoffTPtr


class SysctlLenVerify(SysctlFile):
    PATH = "kernel/sysctl_len_verify"
    MODE = 0o666
    MAXLEN = 64
    INITIAL_VALUE = b"initial_content"

    def read(self, ptregs: PtRegsWrapper, file, user_buf: CharPtr, size: int, loff: LoffTPtr):
        # Read current offset
        offset = yield from plugins.mem.read(loff, fmt=int, size=8)
        data = b"verification_data"

        if offset >= len(data):
            return 0  # EOF

        # Calculate how much to read
        chunk = data[offset:offset+size]

        yield from plugins.mem.write(user_buf, chunk)
        yield from plugins.mem.write(loff, offset + len(chunk))

        print(f"DEBUG: SysctlRead returning {len(chunk)} bytes at offset {offset}")
        return len(chunk)

    def write(self, ptregs: PtRegsWrapper, file, user_buf: CharPtr, size: int, loff: LoffTPtr):
        data = yield from plugins.mem.read(user_buf, size, fmt="bytes")
        print(f"DEBUG: SysctlWrite received {size} bytes: {data}")

        # Optionally trigger a breakpoint on write

        # Standard behavior: update offset and return size
        offset = yield from plugins.mem.read(loff, fmt=int, size=8)
        yield from plugins.mem.write(loff, offset + size)

        return size


class SysctlVerify(Plugin):
    def __init__(self):
        plugins.sysctl.register_sysctl(SysctlLenVerify())
