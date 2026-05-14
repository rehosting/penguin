from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import SysctlFile, CharPtr, SizeTPtr, LoffTPtr, SizeT, FilePtr
from dwarffi import Ptr

class SysctlLenVerify(SysctlFile):
    PATH = "kernel/sysctl_len_verify"
    MODE = 0o666
    MAXLEN = 64
    INITIAL_VALUE = b"initial_content"

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, offset_ptr: LoffTPtr):
        # Ensure offset_ptr is a Ptr to maintain type-safe updates
        assert isinstance(offset_ptr, Ptr), f"offset_ptr must be a Ptr, got {type(offset_ptr)}"

        # Read current offset using deref to keep loff_t context
        offset = yield from plugins.kffi.deref(offset_ptr)
        data = b"verification_data"
        
        if offset >= len(data):
            return 0 # EOF

        # Calculate how much to read
        chunk = data[offset:offset+int(size)]
        
        yield from plugins.mem.write(user_buf, chunk)
        # Using plugins.mem.write on a Ptr object is type-safe
        yield from plugins.mem.write(offset_ptr, offset + len(chunk))
        
        print(f"DEBUG: SysctlRead returning {len(chunk)} bytes at offset {offset}")
        return len(chunk)

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, offset_ptr: LoffTPtr):
        # Ensure offset_ptr is a Ptr
        assert isinstance(offset_ptr, Ptr), f"offset_ptr must be a Ptr, got {type(offset_ptr)}"

        data = yield from plugins.mem.read(user_buf, int(size), fmt="bytes")
        print(f"DEBUG: SysctlWrite received {size} bytes: {data}")
        
        # Standard behavior: update offset and return size
        offset = yield from plugins.kffi.deref(offset_ptr)
        yield from plugins.mem.write(offset_ptr, offset + len(data))
        
        return len(data)

class SysctlVerify(Plugin):
    def __init__(self):
        plugins.sysctl.register_sysctl(SysctlLenVerify())
