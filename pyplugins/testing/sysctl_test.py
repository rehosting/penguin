# pyplugins/testing/sysctl_test.py
from penguin import Plugin, plugins
from hyperfile.models.base import SysctlFile
from hyperfile.models.read import ReadConstBuf

# 1. Basic Static Read/Write
class StaticSysctlFile(SysctlFile):
    PATH = "kernel/custom_static" # The C driver expects paths relative to /proc/sys/
    INITIAL_VALUE = b"hello_sysctl"
    MODE = 0o666 # Read/Write

# 2. Deep Directory Auto-Creation
class DeepSysctlFile(SysctlFile):
    PATH = "net/ipv4/conf/custom_net"
    INITIAL_VALUE = b"1"
    MODE = 0o644 # Read Only

# 3. Dynamic Python Interception via FFI
class DynamicSysctlFile(SysctlFile):
    PATH = "debug/dynamic_sysctl"
    INITIAL_VALUE = b"dynamic_init\n"
    MODE = 0o644

    def __init__(self):
        super().__init__()
        self.hit_count = 0

    def read(self, ptregs, file, user_buf, lenp_ptr, ppos_ptr):
        self.hit_count += 1
        
        # 1. Read current file offset from guest memory
        offset = yield from plugins.mem.read_int(ppos_ptr)
        data = self.INITIAL_VALUE
        
        if offset >= len(data):
            yield from plugins.mem.write_int(lenp_ptr, 0)
            return 0

        # 2. Write data to the guest's provided user buffer
        chunk = data[offset:]
        yield from plugins.mem.write_bytes(user_buf, chunk)
        
        # 3. Update the kernel's length and offset pointers
        yield from plugins.mem.write_int(lenp_ptr, len(chunk))
        yield from plugins.mem.write_int(ppos_ptr, offset + len(chunk))
        
        # Return positive bytes read (SysctlFile will map this to 0 for the kernel)
        return len(chunk)

class UsageCounterSysctl(SysctlFile):
    PATH = "kernel/usage_counter"
    MODE = 0o444

    def __init__(self):
        super().__init__()
        self.total_reads = 0

    def proc_handler(self, ptregs, ctl, write, buffer, lenp, ppos):
        if write:
            ptregs.set_retval(-22) # -EINVAL
            return -22

        # Read the current file offset from guest memory
        offset = yield from plugins.mem.read_int(ppos)

        # FIX: Only increment the counter on the FIRST read of a cat command
        if offset == 0:
            self.total_reads += 1
        
        # Prepare the data based on the counter state
        data = f"AccessID: {self.total_reads}\n".encode("latin-1")

        if offset >= len(data):
            yield from plugins.mem.write_int(lenp, 0)
            ptregs.set_retval(0)
            return 0

        chunk = data[offset:]
        yield from plugins.mem.write_bytes(buffer, chunk)

        yield from plugins.mem.write_int(lenp, len(chunk))
        yield from plugins.mem.write_int(ppos, offset + len(chunk))

        ptregs.set_retval(0)
        return 0

# --- New Sysctl Subsystem Tests ---

class MergedSysctlFile(ReadConstBuf, SysctlFile):
    """Replaces the old MergedSysProcFile hack with proper shadowing."""
    PATH = "kernel/custom_merged" # Relative to /proc/sys/
    def __init__(self):
        super().__init__(buffer=b"merged!\n")

class CollisionSysctlFile(ReadConstBuf, SysctlFile):
    """Tests the C driver's ability to handle root-level sysctls."""
    PATH = "collision_test"
    def __init__(self):
        super().__init__(buffer=b"collision_ok\n")


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