from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import DevFile, FilePtr, InodePtr, CharPtr, LoffTPtr, PollTablePtr, VmAreaPtr, FileLockPtr, SizeT, CInt, LoffT
from hyperfile.models.read import ReadConstBuf
from dwarffi import Ptr

class BaseTestDevFile(DevFile):
    def _verify_args(self, ptregs: PtRegsWrapper, **kwargs):
        for name, ptr in kwargs.items():
            # Block requests are processed asynchronously without a VFS file context
            if name == "file" and getattr(self, "IS_BLOCK", False):
                continue
                
            # Allow raw int 0 checks, or check the inner .address if it's a Ptr,
            # or dynamically cast a BoundTypeInstance primitive to an int
            addr_val = ptr.address if isinstance(ptr, Ptr) else int(ptr)
                
            if addr_val == 0:
                self.logger.error(f"Invalid NULL pointer received for {name}!")
                ptregs.retval = -22 # -EINVAL
                return False
        return True

class SimpleDevFile(ReadConstBuf, BaseTestDevFile):
    PATH = "simple"
    def __init__(self):
        super().__init__(buffer=b"Hello DevFS\n")
        
    def open(self, ptregs: PtRegsWrapper, inode: InodePtr, file: FilePtr):
        if self._verify_args(ptregs, inode=inode, file=file):
            ptregs.retval = 0

class DynamicDevFile(BaseTestDevFile):
    PATH = "dynamic"
    def __init__(self):
        self.value = 0
        super().__init__()

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff_ptr: LoffTPtr):
        if not self._verify_args(ptregs, file=file, user_buf=user_buf, loff_ptr=loff_ptr): return
        
        size_val = int(size)
        offset = yield from plugins.mem.read(loff_ptr, fmt=int, size=8)
        data = f"{self.value}\n".encode("utf-8")
        
        if size_val <= 0 or offset >= len(data):
            ptregs.retval = 0
            return 
            
        chunk = min(size_val, len(data) - offset)
        yield from plugins.mem.write(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write(loff_ptr, offset + chunk, size=8)
        ptregs.retval = chunk

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff_ptr: LoffTPtr):
        if not self._verify_args(ptregs, file=file, user_buf=user_buf, loff_ptr=loff_ptr): return
        
        size_val = int(size)
        # Bypass smart dispatcher by using string "bytes"
        raw = yield from plugins.mem.read(user_buf, size_val, fmt="bytes")
        try:
            self.value = int(raw.decode("utf-8").strip())
            ptregs.retval = size_val
        except ValueError:
            ptregs.retval = -22

class Lseek64DevFile(BaseTestDevFile):
    PATH = "lseek64"
    def __init__(self):
        self.last_seek = 0
        super().__init__()

    def lseek(self, ptregs: PtRegsWrapper, file: FilePtr, offset: LoffT, whence: CInt):
        if not self._verify_args(ptregs, file=file): return
        offset_val = int(offset)
        self.last_seek = offset_val
        ptregs.retval = offset_val 

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff_ptr: LoffTPtr):
        if not self._verify_args(ptregs, file=file, user_buf=user_buf, loff_ptr=loff_ptr): return
        
        size_val = int(size)
        offset = yield from plugins.mem.read(loff_ptr, fmt=int, size=8)
        data = f"{self.last_seek}\n".encode("utf-8")
        
        if size_val <= 0 or offset >= len(data):
            ptregs.retval = 0
            return 
            
        chunk = min(size_val, len(data) - offset)
        yield from plugins.mem.write(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write(loff_ptr, offset + chunk, size=8)
        ptregs.retval = chunk

class TrackingDevFile(BaseTestDevFile):
    PATH = "tracker"
    def __init__(self):
        self.opens = 0
        self.releases = 0
        super().__init__()

    def open(self, ptregs: PtRegsWrapper, inode: InodePtr, file: FilePtr):
        if self._verify_args(ptregs, inode=inode, file=file):
            self.opens += 1
            ptregs.retval = 0

    def release(self, ptregs: PtRegsWrapper, inode: InodePtr, file: FilePtr):
        if self._verify_args(ptregs, inode=inode, file=file):
            self.releases += 1
            ptregs.retval = 0

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff_ptr: LoffTPtr):
        if not self._verify_args(ptregs, file=file, user_buf=user_buf, loff_ptr=loff_ptr): return
        
        size_val = int(size)
        offset = yield from plugins.mem.read(loff_ptr, fmt=int, size=8)
        data = f"o:{self.opens} r:{self.releases}\n".encode("utf-8")
        
        if size_val <= 0 or offset >= len(data):
            ptregs.retval = 0
            return 
            
        chunk = min(size_val, len(data) - offset)
        yield from plugins.mem.write(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write(loff_ptr, offset + chunk, size=8)
        ptregs.retval = chunk

class AdvancedOpsDevFile(BaseTestDevFile):
    PATH = "advanced"
    
    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, offset_ptr: LoffTPtr):
        ptregs.retval = int(size)

    def fsync(self, ptregs: PtRegsWrapper, file: FilePtr, start: CInt, end: CInt, datasync: CInt):
        if not self._verify_args(ptregs, file=file): return
        ptregs.retval = 0
        
    def poll(self, ptregs: PtRegsWrapper, file: FilePtr, poll_table: PollTablePtr):
        if self._verify_args(ptregs, file=file): ptregs.retval = 0x41

    def lock(self, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, file_lock: FileLockPtr):
        if not self._verify_args(ptregs, file=file, file_lock=file_lock): return
        ptregs.retval = -22

    def mmap(self, ptregs: PtRegsWrapper, file: FilePtr, vm_area_struct: VmAreaPtr):
        if not self._verify_args(ptregs, file=file, vm_area_struct=vm_area_struct): return
        ptregs.retval = -19

    def get_unmapped_area(self, ptregs: PtRegsWrapper, file: FilePtr, addr: CInt, len_: SizeT, pgoff: CInt, flags: CInt):
        if not self._verify_args(ptregs, file=file): return
        ptregs.retval = int(addr)

class FixedDevFile(ReadConstBuf, BaseTestDevFile):
    PATH = "fixeddev"
    MAJOR = 242
    MINOR = 42
    def __init__(self):
        super().__init__(buffer=b"fixed\n")

class MmapSupportedDevFile(ReadConstBuf, BaseTestDevFile):
    PATH = "mmap_explicit"
    SUPPORT_MMAP = True
    def __init__(self):
        super().__init__(buffer=b"mmap_explicit\n")

class MmapCustomDevFile(ReadConstBuf, BaseTestDevFile):
    PATH = "mmap_custom"
    SUPPORT_MMAP = True
    def __init__(self):
        super().__init__(buffer=b"mmap_custom\n")
        
    def mmap(self, ptregs: PtRegsWrapper, file: FilePtr, vm_area_struct: VmAreaPtr):
        if not self._verify_args(ptregs, file=file, vm_area_struct=vm_area_struct): return
        ptregs.retval = -19 # -ENODEV

class VirtualBlockDevice(BaseTestDevFile):
    PATH = "vblock0"
    IS_BLOCK = True
    SIZE = 2 * 1024 * 1024  # 2 MB Disk
    LOGICAL_BLOCK_SIZE = 512

    def __init__(self):
        self.disk_data = bytearray(self.SIZE)
        super().__init__()

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff_ptr: LoffTPtr):
        if not self._verify_args(ptregs, file=file, user_buf=user_buf, loff_ptr=loff_ptr): return
        
        size_val = int(size)
        offset = yield from plugins.mem.read(loff_ptr, fmt=int, size=8)
        if offset >= self.SIZE or size_val <= 0:
            ptregs.retval = 0
            return 
            
        chunk = min(size_val, self.SIZE - offset)
        yield from plugins.mem.write(user_buf, bytes(self.disk_data[offset:offset+chunk]))
        yield from plugins.mem.write(loff_ptr, offset + chunk, size=8)
        ptregs.retval = chunk

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff_ptr: LoffTPtr):
        if not self._verify_args(ptregs, file=file, user_buf=user_buf, loff_ptr=loff_ptr): return
        
        size_val = int(size)
        offset = yield from plugins.mem.read(loff_ptr, fmt=int, size=8)
        if offset >= self.SIZE or size_val <= 0:
            ptregs.retval = -28 # ENOSPC
            return 
            
        chunk = min(size_val, self.SIZE - offset)
        # Bypass smart dispatcher by using string "bytes"
        raw = yield from plugins.mem.read(user_buf, chunk, fmt="bytes")
        self.disk_data[offset:offset+chunk] = raw
        
        yield from plugins.mem.write(loff_ptr, offset + chunk, size=8)
        ptregs.retval = chunk


class DevfsTest(Plugin):
    def __init__(self):
        plugins.devfs.register_devfs(SimpleDevFile())
        plugins.devfs.register_devfs(DynamicDevFile())
        plugins.devfs.register_devfs(Lseek64DevFile())
        plugins.devfs.register_devfs(TrackingDevFile())
        plugins.devfs.register_devfs(AdvancedOpsDevFile())
        plugins.devfs.register_devfs(FixedDevFile())
        
        # Instantiate cleanly to avoid kwarg inheritance collisions
        dev_nested = SimpleDevFile()
        plugins.devfs.register_devfs(dev_nested, path="/dev/nested/simple")
        
        plugins.devfs.register_devfs(MmapSupportedDevFile())
        plugins.devfs.register_devfs(MmapCustomDevFile())
        
        # Fallback test: enable mmap dynamically
        dev_fb = SimpleDevFile()
        dev_fb.SIZE = 4096
        plugins.devfs.register_devfs(dev_fb, path="/dev/mmap_fallback")
        
        plugins.devfs.register_devfs(VirtualBlockDevice())