from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import ProcFile, FilePtr, InodePtr, CharPtr, LoffTPtr, PollTablePtr, VmAreaPtr, SizeT, CInt, LoffT
from hyperfile.models.read import ReadConstBuf
from hyperfile.models.write import WriteDiscard
from hyperfile.models.ioctl import IoctlZero
from typing import Union
from dwarffi import Ptr


class SimpleProcfsFile(ReadConstBuf, WriteDiscard, IoctlZero, ProcFile):
    PATH = "s/i/m/p/l/e/simple_proc"

    def __init__(self, **kwargs):
        if "buffer" not in kwargs:
            kwargs["buffer"] = b"Hello from simple_proc!\n"
        super().__init__(**kwargs)

    def open(self, ptregs: PtRegsWrapper, inode: InodePtr, file: FilePtr):
        procname = yield from plugins.osi.get_proc_name()
        self.logger.info(f"SimpleProcfsFile.open called in {procname}")
        ptregs.retval = 0

class CPUinfoFile(ReadConstBuf, ProcFile):
    PATH = "cpuinfo"
    def __init__(self, **kwargs):
        if "buffer" not in kwargs:
            kwargs["buffer"] = b"processor        : IGLOO\n"
        super().__init__(**kwargs)

class DynamicProcfsFile(ProcFile):
    PATH = "dynamic_proc"
    MODE = 0o666

    def __init__(self, **kwargs):
        self.value = 0
        super().__init__(**kwargs)

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        size_val = int(size)
        data = f"{self.value}\n".encode("utf-8")
        
        # Use fmt=int, size=8 to read the 64-bit loff_t offset
        offset = yield from plugins.mem.read(loff, fmt=int, size=8)
        
        if size_val <= 0 or offset >= len(data):
            ptregs.retval = 0
            return
            
        chunk = min(size_val, len(data) - offset)
        yield from plugins.mem.write(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write(loff, offset + chunk, size=8)
        ptregs.retval = chunk

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        size_val = int(size)
        # Explicitly request raw bytes to bypass CharPtr's automatic string conversion
        raw = yield from plugins.mem.read(user_buf, size_val, fmt="bytes")
        try:
            self.value = int(raw.decode("utf-8").strip())
            ptregs.retval = size_val
        except (ValueError, UnicodeDecodeError):
            ptregs.retval = -1

class LargeProcFile(ReadConstBuf, ProcFile):
    PATH = "large_file"
    def __init__(self, **kwargs):
        if "buffer" not in kwargs:
            kwargs["buffer"] = b"A" * 8192
        super().__init__(**kwargs)

class WriteOnlyProcFile(ProcFile):
    PATH = "write_only_proc"
    MODE = 0o222 # Write-only permissions

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        ptregs.retval = -9 # EBADF

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        ptregs.retval = int(size)

class FailingOpenProcFile(ProcFile):
    PATH = "fail_open_proc"
    MODE = 0o444

    def open(self, ptregs: PtRegsWrapper, inode: InodePtr, file: FilePtr):
        ptregs.retval = -13 # EACCES

class IoctlCustomProcFile(ReadConstBuf, ProcFile):
    PATH = "custom_ioctl_proc"
    MODE = 0o666

    def __init__(self, **kwargs):
        if "buffer" not in kwargs:
            kwargs["buffer"] = b"Send me ioctls!\n"
        super().__init__(**kwargs)

    def ioctl(self, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, arg: CInt):
        if int(cmd) == 0xDEADBEEF:
            ptregs.retval = 42
        else:
            ptregs.retval = -25 # ENOTTY

class SeekableRWProcFile(ProcFile):
    PATH = "seekable_rw"
    MODE = 0o666
    
    # Explicitly authorize memory mapping for this test device
    SUPPORT_MMAP = True
    SIZE = 4096

    def __init__(self, **kwargs):
        # Initialize a 4KB mutable buffer
        self.data = bytearray(b"Initial Data" + b"\x00" * 4084)
        super().__init__(**kwargs)

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        size_val = int(size)
        offset = yield from plugins.mem.read(loff, fmt=int, size=8)
        
        if offset >= len(self.data) or size_val <= 0:
            ptregs.retval = 0
            return
            
        chunk = min(size_val, len(self.data) - offset)
        yield from plugins.mem.write(user_buf, bytes(self.data[offset:offset+chunk]))
        yield from plugins.mem.write(loff, offset + chunk, size=8)
        self.logger.debug(f"Read from seekable_rw at offset {offset}")
        ptregs.retval = chunk

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        size_val = int(size)
        offset = yield from plugins.mem.read(loff, fmt=int, size=8)
        
        if offset >= len(self.data) or size_val <= 0:
            ptregs.retval = -28 # ENOSPC
            return
            
        chunk = min(size_val, len(self.data) - offset)
        raw = yield from plugins.mem.read(user_buf, chunk, fmt="bytes")
        
        # Mutate the underlying buffer
        self.logger.debug(f"Writing to seekable_rw at offset {offset} with data: {raw[:chunk]}")
        self.data[offset:offset+chunk] = raw
        
        yield from plugins.mem.write_long(loff, offset + chunk)
        ptregs.set_retval(chunk)

    def lseek(self, ptregs: PtRegsWrapper, file: FilePtr, offset: LoffT, whence: CInt):
        offset_val = int(offset)
        whence_val = int(whence)
        
        self.logger.debug(f"lseek called with offset={offset_val}, whence={whence_val}")
        if whence_val == 0: # SEEK_SET
            if offset_val < 0 or offset_val > len(self.data):
                ptregs.retval = -22 # EINVAL
            else:
                # Update file->f_pos using kffi field writing
                yield from plugins.kffi.write_field(file, "struct file", "f_pos", offset_val)
                ptregs.retval = offset_val
        else:
            ptregs.retval = -22

class ReleaseTrackingProcFile(ProcFile):
    PATH = "release_tracker"
    MODE = 0o444

    def __init__(self, **kwargs):
        self.active_opens = 0
        self.total_opens = 0
        self.total_releases = 0
        super().__init__(**kwargs)

    def open(self, ptregs: PtRegsWrapper, inode: InodePtr, file: FilePtr):
        self.active_opens += 1
        self.total_opens += 1
        self.logger.info(f"release_tracker opened. Active: {self.active_opens}")
        ptregs.retval = 0

    def release(self, ptregs: PtRegsWrapper, inode: InodePtr, file: FilePtr):
        self.active_opens -= 1
        self.total_releases += 1
        self.logger.info(f"release_tracker released. Active: {self.active_opens}")
        ptregs.retval = 0

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        size_val = int(size)
        data = f"active:{self.active_opens},opens:{self.total_opens},releases:{self.total_releases}\n".encode("utf-8")
        offset = yield from plugins.mem.read(loff, fmt=int, size=8)
        
        if size_val <= 0 or offset >= len(data):
            ptregs.retval = 0
            return
        chunk = min(size_val, len(data) - offset)
        yield from plugins.mem.write(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write(loff, offset + chunk, size=8)
        ptregs.retval = chunk


class PollableProcFile(ProcFile):
    PATH = "pollable_proc"
    MODE = 0o444

    def poll(self, ptregs: PtRegsWrapper, file: FilePtr, poll_table: PollTablePtr):
        self.logger.info("pollable_proc polled!")
        # 1 = POLLIN (There is data to read)
        # 64 = POLLRDNORM (Normal data may be read without blocking)
        # Standard mask for readable file: POLLIN | POLLRDNORM (0x41)
        ptregs.retval = 0x41

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        size_val = int(size)
        data = b"Data is ready!\n"
        offset = yield from plugins.mem.read(loff, fmt=int, size=8)
        
        if size_val <= 0 or offset >= len(data):
            ptregs.retval = 0
            return
            
        chunk = min(size_val, len(data) - offset)
        yield from plugins.mem.write(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write(loff, offset + chunk, size=8)
        ptregs.retval = chunk

# --- NEW MMAP ENFORCEMENT TEST DEVICES ---

class MmapSupportedProcFile(ReadConstBuf, ProcFile):
    PATH = "mmap_explicit"
    SUPPORT_MMAP = True
    
    def __init__(self, **kwargs):
        if "buffer" not in kwargs:
            kwargs["buffer"] = b"mmap_explicit\n"
        super().__init__(**kwargs)

class MmapCustomProcFile(ReadConstBuf, ProcFile):
    PATH = "mmap_custom"
    SUPPORT_MMAP = True
    
    def __init__(self, **kwargs):
        if "buffer" not in kwargs:
            kwargs["buffer"] = b"mmap_custom\n"
        super().__init__(**kwargs)
        
    def mmap(self, ptregs: PtRegsWrapper, file: FilePtr, vm_area_struct: VmAreaPtr):
        ptregs.retval = -19 # -ENODEV


class ProcTest(Plugin):
    def __init__(self):
        # 1. Standard Proc Registrations
        plugins.procfs.register_proc(SimpleProcfsFile())
        plugins.procfs.register_proc(CPUinfoFile())
        plugins.procfs.register_proc(DynamicProcfsFile())
        plugins.procfs.register_proc(LargeProcFile())

        # 2. Edge Case Proc Registrations
        plugins.procfs.register_proc(WriteOnlyProcFile())
        plugins.procfs.register_proc(FailingOpenProcFile())
        plugins.procfs.register_proc(IoctlCustomProcFile())
        plugins.procfs.register_proc(SeekableRWProcFile())

        # 3. Duplicate Check
        try:
            plugins.procfs.register_proc(SimpleProcfsFile())
            self.logger.error("Failed to catch duplicate proc registration!")
        except ValueError:
            self.logger.info("Successfully caught duplicate proc registration.")

        # 4. Advanced Operations Registrations
        plugins.procfs.register_proc(ReleaseTrackingProcFile())
        plugins.procfs.register_proc(PollableProcFile())

        # 5. MMAP Registrations
        plugins.procfs.register_proc(MmapSupportedProcFile())
        plugins.procfs.register_proc(MmapCustomProcFile())
        
        # Fallback test: enable mmap just by passing size dynamically
        plugins.procfs.register_proc(
            SimpleProcfsFile(path="mmap_fallback", size=4096)
        )