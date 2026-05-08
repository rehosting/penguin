from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import SysctlFile, FilePtr, CharPtr, SizeTPtr, LoffTPtr, CtlTablePtr, CInt
from hyperfile.models.read import ReadConstBuf

# 1. Basic Static Read/Write


class StaticSysctlFile(SysctlFile):
    PATH = "kernel/custom_static"  # The C driver expects paths relative to /proc/sys/
    INITIAL_VALUE = b"hello_sysctl"
    MODE = 0o666  # Read/Write

# 2. Deep Directory Auto-Creation


class DeepSysctlFile(SysctlFile):
    PATH = "net/ipv4/conf/custom_net"
    INITIAL_VALUE = b"1"
    MODE = 0o644  # Read Only

# 3. Dynamic Python Interception via FFI


class DynamicSysctlFile(SysctlFile):
    PATH = "debug/dynamic_sysctl"
    INITIAL_VALUE = b"dynamic_init\n"
    MODE = 0o644

    def __init__(self):
        super().__init__()
        self.hit_count = 0

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, lenp_ptr: SizeTPtr, ppos_ptr: LoffTPtr):
        self.hit_count += 1

        offset = yield from plugins.mem.read(ppos_ptr, fmt=int)
        data = self.INITIAL_VALUE

        if offset >= len(data):
            yield from plugins.mem.write(lenp_ptr, 0)
            ptregs.retval = 0
            return 0

        chunk = data[offset:]
        yield from plugins.mem.write(user_buf, chunk)

        yield from plugins.mem.write(lenp_ptr, len(chunk))
        yield from plugins.mem.write(ppos_ptr, offset + len(chunk))

        ptregs.retval = len(chunk)
        return len(chunk)

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, lenp_ptr: SizeTPtr, ppos_ptr: LoffTPtr):
        offset = yield from plugins.mem.read(ppos_ptr, fmt=int)
        size = yield from plugins.mem.read(lenp_ptr, fmt=int)

        if size <= 0:
            yield from plugins.mem.write(lenp_ptr, 0)
            ptregs.retval = 0
            return 0

        data = yield from plugins.mem.read(user_buf, size, fmt="bytes")
        self.INITIAL_VALUE = data

        yield from plugins.mem.write(ppos_ptr, offset + size)
        yield from plugins.mem.write(lenp_ptr, size)
        ptregs.retval = 0
        return 0


class UsageCounterSysctl(SysctlFile):
    PATH = "kernel/usage_counter"
    MODE = 0o444

    def __init__(self):
        super().__init__()
        self.total_reads = 0

    def proc_handler(self, ptregs: PtRegsWrapper, ctl: CtlTablePtr, write: CInt, buffer: CharPtr, lenp: SizeTPtr, ppos: LoffTPtr):
        if int(write):
            ptregs.retval = -22  # -EINVAL
            return -22

        offset = yield from plugins.mem.read(ppos, fmt=int)

        # FIX: Only increment the counter on the FIRST read of a cat command
        if offset == 0:
            self.total_reads += 1

        data = f"AccessID: {self.total_reads}\n".encode("latin-1")

        if offset >= len(data):
            yield from plugins.mem.write(lenp, 0)
            ptregs.retval = 0
            return 0

        chunk = data[offset:]
        yield from plugins.mem.write(buffer, chunk)

        yield from plugins.mem.write(lenp, len(chunk))
        yield from plugins.mem.write(ppos, offset + len(chunk))

        ptregs.retval = 0
        return 0

# --- New Sysctl Subsystem Tests ---


class MergedSysctlFile(ReadConstBuf, SysctlFile):
    """Replaces the old MergedSysProcFile hack with proper shadowing."""
    PATH = "kernel/custom_merged"  # Relative to /proc/sys/

    def __init__(self):
        super().__init__(buffer=b"merged!\n")


class CollisionSysctlFile(ReadConstBuf, SysctlFile):
    """Tests the C driver's ability to handle root-level sysctls."""
    PATH = "collision_test"

    def __init__(self):
        super().__init__(buffer=b"collision_ok\n")


# 4. In-Place Kernel Interceptions

class DropCachesSysctl(SysctlFile):
    """Replaces the internal /proc/sys/vm/drop_caches handler"""
    PATH = "vm/drop_caches"
    MODE = 0o644  # Make it readable for testing the intercept string

    def proc_handler(self, ptregs: PtRegsWrapper, ctl: CtlTablePtr, write: CInt, buffer: CharPtr, lenp: SizeTPtr, ppos: LoffTPtr):
        if int(write):
            # Acknowledge the write to avoid shell errors
            size = yield from plugins.mem.read(lenp, fmt=int)
            yield from plugins.mem.write(ppos, size)
            ptregs.retval = 0
            return 0
        else:
            # Send custom data on read to prove the Python handler was executed
            offset = yield from plugins.mem.read(ppos, fmt=int)
            if offset == 0:
                data = b"drop_caches_intercepted\n"
                yield from plugins.mem.write(buffer, data)
                yield from plugins.mem.write(lenp, len(data))
                yield from plugins.mem.write(ppos, len(data))
            else:
                yield from plugins.mem.write(lenp, 0)

            ptregs.retval = 0
            return 0


class KernelHostnameSysctl(SysctlFile):
    """Replaces the internal /proc/sys/kernel/hostname handler"""
    PATH = "kernel/hostname"
    MODE = 0o644

    def proc_handler(self, ptregs: PtRegsWrapper, ctl: CtlTablePtr, write: CInt, buffer: CharPtr, lenp: SizeTPtr, ppos: LoffTPtr):
        if int(write):
            size = yield from plugins.mem.read(lenp, fmt=int)
            yield from plugins.mem.write(ppos, size)
            ptregs.retval = 0
            return 0
        else:
            offset = yield from plugins.mem.read(ppos, fmt=int)
            if offset == 0:
                data = b"hostname_intercepted\n"
                yield from plugins.mem.write(buffer, data)
                yield from plugins.mem.write(lenp, len(data))
                yield from plugins.mem.write(ppos, len(data))
            else:
                yield from plugins.mem.write(lenp, 0)

            ptregs.retval = 0
            return 0


class SysctlTest(Plugin):
    def __init__(self):
        # Register our test files
        plugins.sysctl.register_sysctl(StaticSysctlFile())
        plugins.sysctl.register_sysctl(DeepSysctlFile())

        # 2. Sysctl Subsystem Registrations
        plugins.sysctl.register_sysctl(MergedSysctlFile())
        plugins.sysctl.register_sysctl(CollisionSysctlFile())

        self.dynamic_file = DynamicSysctlFile()
        plugins.sysctl.register_sysctl(self.dynamic_file)
        plugins.sysctl.register_sysctl(UsageCounterSysctl())

        # 3. Registering Existing Kernel Sysctl Overrides
        plugins.sysctl.register_sysctl(DropCachesSysctl())
        plugins.sysctl.register_sysctl(KernelHostnameSysctl())
