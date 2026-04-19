from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import DevFile
from hyperfile.models.read import ReadConstBuf

class BaseTestDevFile(DevFile):
    def _verify_args(self, ptregs: PtRegsWrapper, **kwargs):
        for name, ptr in kwargs.items():
            # Block requests are processed asynchronously without a VFS file context
            if name == "file" and getattr(self, "IS_BLOCK", False):
                continue
                
            if ptr == 0:
                self.logger.error(f"Invalid NULL pointer received for {name}!")
                ptregs.set_retval(-22) # -EINVAL
                return False
        return True

class SimpleDevFile(ReadConstBuf, BaseTestDevFile):
    PATH = "simple"
    def __init__(self):
        super().__init__(buffer=b"Hello DevFS\n")
        
    def open(self, ptregs: PtRegsWrapper, inode: int, file: int):
        if self._verify_args(ptregs, inode=inode, file=file):
            ptregs.set_retval(0)

class DynamicDevFile(BaseTestDevFile):
    PATH = "dynamic"
    def __init__(self):
        self.value = 0
        super().__init__()

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff_ptr: int):
        if not self._verify_args(ptregs, file=file, user_buf=user_buf, loff_ptr=loff_ptr): return
        
        offset = yield from plugins.mem.read_int(loff_ptr)
        data = f"{self.value}\n".encode("utf-8")
        
        if size <= 0 or offset >= len(data):
            return ptregs.set_retval(0)
            
        chunk = min(size, len(data) - offset)
        yield from plugins.mem.write_bytes(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write_int(loff_ptr, offset + chunk)
        ptregs.set_retval(chunk)

    def write(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff_ptr: int):
        if not self._verify_args(ptregs, file=file, user_buf=user_buf, loff_ptr=loff_ptr): return
        raw = yield from plugins.mem.read_bytes(user_buf, size)
        try:
            self.value = int(raw.decode("utf-8").strip())
            ptregs.set_retval(size)
        except ValueError:
            ptregs.set_retval(-22)

class Lseek64DevFile(BaseTestDevFile):
    PATH = "lseek64"
    def __init__(self):
        self.last_seek = 0
        super().__init__()

    def lseek(self, ptregs: PtRegsWrapper, file: int, offset: int, whence: int):
        if not self._verify_args(ptregs, file=file): return
        self.last_seek = offset
        ptregs.set_retval(offset) 

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff_ptr: int):
        if not self._verify_args(ptregs, file=file, user_buf=user_buf, loff_ptr=loff_ptr): return
        offset = yield from plugins.mem.read_int(loff_ptr)
        data = f"{self.last_seek}\n".encode("utf-8")
        
        if size <= 0 or offset >= len(data):
            return ptregs.set_retval(0)
            
        chunk = min(size, len(data) - offset)
        yield from plugins.mem.write_bytes(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write_int(loff_ptr, offset + chunk)
        ptregs.set_retval(chunk)

class TrackingDevFile(BaseTestDevFile):
    PATH = "tracker"
    def __init__(self):
        self.opens = 0
        self.releases = 0
        super().__init__()

    def open(self, ptregs: PtRegsWrapper, inode: int, file: int):
        if self._verify_args(ptregs, inode=inode, file=file):
            self.opens += 1
            ptregs.set_retval(0)

    def release(self, ptregs: PtRegsWrapper, inode: int, file: int):
        if self._verify_args(ptregs, inode=inode, file=file):
            self.releases += 1
            ptregs.set_retval(0)

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff_ptr: int):
        if not self._verify_args(ptregs, file=file, user_buf=user_buf, loff_ptr=loff_ptr): return
        offset = yield from plugins.mem.read_int(loff_ptr)
        data = f"o:{self.opens} r:{self.releases}\n".encode("utf-8")
        
        if size <= 0 or offset >= len(data):
            return ptregs.set_retval(0)
            
        chunk = min(size, len(data) - offset)
        yield from plugins.mem.write_bytes(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write_int(loff_ptr, offset + chunk)
        ptregs.set_retval(chunk)

class AdvancedOpsDevFile(BaseTestDevFile):
    PATH = "advanced"
    
    def write(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, offset_ptr: int):
        ptregs.set_retval(size)

    def fsync(self, ptregs: PtRegsWrapper, file: int, start: int, end: int, datasync: int):
        if not self._verify_args(ptregs, file=file): return
        ptregs.set_retval(0)
        
    def poll(self, ptregs: PtRegsWrapper, file: int, poll_table: int):
        if self._verify_args(ptregs, file=file): ptregs.set_retval(0x41)

    def lock(self, ptregs: PtRegsWrapper, file: int, cmd: int, file_lock: int):
        if not self._verify_args(ptregs, file=file, file_lock=file_lock): return
        ptregs.set_retval(-22)

    def mmap(self, ptregs: PtRegsWrapper, file: int, vm_area_struct: int):
        if not self._verify_args(ptregs, file=file, vm_area_struct=vm_area_struct): return
        ptregs.set_retval(-19)

    def get_unmapped_area(self, ptregs: PtRegsWrapper, file: int, addr: int, len_: int, pgoff: int, flags: int):
        if not self._verify_args(ptregs, file=file): return
        ptregs.set_retval(addr)

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
        
    def mmap(self, ptregs: PtRegsWrapper, file: int, vm_area_struct: int):
        if not self._verify_args(ptregs, file=file, vm_area_struct=vm_area_struct): return
        ptregs.set_retval(-19) # -ENODEV

class VirtualBlockDevice(BaseTestDevFile):
    PATH = "vblock0"
    IS_BLOCK = True
    SIZE = 2 * 1024 * 1024  # 2 MB Disk
    LOGICAL_BLOCK_SIZE = 512

    def __init__(self):
        self.disk_data = bytearray(self.SIZE)
        super().__init__()

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff_ptr: int):
        if not self._verify_args(ptregs, file=file, user_buf=user_buf, loff_ptr=loff_ptr): return
        
        offset = yield from plugins.mem.read_int(loff_ptr)
        if offset >= self.SIZE or size <= 0:
            return ptregs.set_retval(0)
            
        chunk = min(size, self.SIZE - offset)
        yield from plugins.mem.write_bytes(user_buf, bytes(self.disk_data[offset:offset+chunk]))
        yield from plugins.mem.write_int(loff_ptr, offset + chunk)
        ptregs.set_retval(chunk)

    def write(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff_ptr: int):
        if not self._verify_args(ptregs, file=file, user_buf=user_buf, loff_ptr=loff_ptr): return
        
        offset = yield from plugins.mem.read_int(loff_ptr)
        if offset >= self.SIZE or size <= 0:
            return ptregs.set_retval(-28) # ENOSPC
            
        chunk = min(size, self.SIZE - offset)
        raw = yield from plugins.mem.read_bytes(user_buf, chunk)
        self.disk_data[offset:offset+chunk] = raw
        
        yield from plugins.mem.write_int(loff_ptr, offset + chunk)
        ptregs.set_retval(chunk)


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