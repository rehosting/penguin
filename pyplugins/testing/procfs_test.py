from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import ProcFile
from hyperfile.models.read import ReadConstBuf
from hyperfile.models.write import WriteDiscard
from hyperfile.models.ioctl import IoctlZero


class SimpleProcfsFile(ReadConstBuf, WriteDiscard, IoctlZero, ProcFile):
    PATH = "s/i/m/p/l/e/simple_proc"

    def __init__(self):
        super().__init__(buffer=b"Hello from simple_proc!\n")

    def open(self, ptregs: PtRegsWrapper, inode: int, file: int):
        procname = yield from plugins.osi.get_proc_name()
        print(f"SimpleProcfsFile.open called in {procname}")
        ptregs.set_retval(0)

class CPUinfoFile(ReadConstBuf, ProcFile):
    PATH = "/proc/cpuinfo"
    def __init__(self):
        super().__init__(buffer=b"processor       : IGLOO\n")

class DynamicProcfsFile(ProcFile):
    PATH = "dynamic_proc"
    MODE = 0o666

    def __init__(self):
        self.value = 0

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        data = f"{self.value}\n".encode("utf-8")
        offset = yield from plugins.mem.read_int(loff)
        if size <= 0 or offset >= len(data):
            ptregs.set_retval(0)
            return
        chunk = min(size, len(data) - offset)
        yield from plugins.mem.write_bytes(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write_int(loff, offset + chunk)
        ptregs.set_retval(chunk)

    def write(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        raw = yield from plugins.mem.read_bytes(user_buf, size)
        try:
            self.value = int(raw.decode("utf-8").strip())
            ptregs.set_retval(size)
        except:
            ptregs.set_retval(-1)

class LargeProcFile(ReadConstBuf, ProcFile):
    PATH = "large_file"
    def __init__(self):
        super().__init__(buffer=b"A" * 8192)

class WriteOnlyProcFile(ProcFile):
    PATH = "write_only_proc"
    MODE = 0o222 # Write-only permissions

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        # Should ideally be caught by VFS before this, but good defensive programming
        ptregs.set_retval(-9) # EBADF

    def write(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        ptregs.set_retval(size) # Pretend we successfully consumed the data

class FailingOpenProcFile(ProcFile):
    PATH = "fail_open_proc"
    MODE = 0o444

    def open(self, ptregs: PtRegsWrapper, inode: int, file: int):
        # Simulate a file that dynamically refuses to be opened (e.g., EACCES)
        ptregs.set_retval(-13) 

class IoctlCustomProcFile(ReadConstBuf, ProcFile):
    PATH = "custom_ioctl_proc"
    MODE = 0o666

    def __init__(self):
        super().__init__(buffer=b"Send me ioctls!\n")

    def ioctl(self, ptregs: PtRegsWrapper, file: int, cmd: int, arg: int):
        # Custom IOCTL handling: respond to a specific magic command
        if cmd == 0xDEADBEEF:
            ptregs.set_retval(42)
        else:
            ptregs.set_retval(-25) # ENOTTY (Inappropriate ioctl for device)

class SeekableRWProcFile(ProcFile):
    PATH = "seekable_rw"
    MODE = 0o666

    def __init__(self):
        # Initialize a 4KB mutable buffer
        self.data = bytearray(b"Initial Data" + b"\x00" * 4084)

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        offset = yield from plugins.mem.read_int(loff)
        if offset >= len(self.data) or size <= 0:
            ptregs.set_retval(0)
            return
        chunk = min(size, len(self.data) - offset)
        yield from plugins.mem.write_bytes(user_buf, bytes(self.data[offset:offset+chunk]))
        yield from plugins.mem.write_int(loff, offset + chunk)
        self.logger.debug(f"Read from seekable_rw at offset {offset} with data: {self.data[offset:offset+chunk]}")
        ptregs.set_retval(chunk)

    def write(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        offset = yield from plugins.mem.read_int(loff)
        if offset >= len(self.data) or size <= 0:
            ptregs.set_retval(-28) # ENOSPC
            return
        chunk = min(size, len(self.data) - offset)
        raw = yield from plugins.mem.read_bytes(user_buf, chunk)
        
        # Mutate the underlying buffer
        self.logger.debug(f"Writing to seekable_rw at offset {offset} with data: {raw[:chunk]}")
        self.data[offset:offset+chunk] = raw
        
        yield from plugins.mem.write_int(loff, offset + chunk)
        ptregs.set_retval(chunk)

    def lseek(self, ptregs: PtRegsWrapper, file: int, offset: int, whence: int):
        self.logger.debug(f"lseek called with offset={offset}, whence={whence}")
        if whence == 0:
            if offset < 0 or offset > len(self.data):
                ptregs.set_retval(-22) # EINVAL
            else:
                # Dynamically write the offset using dwarffi's architecture awareness
                yield from plugins.kffi.write_field(file, "struct file", "f_pos", offset)
                
                # Return the new offset as required by the llseek signature
                ptregs.set_retval(offset)
        else:
            ptregs.set_retval(-22)

class ReleaseTrackingProcFile(ProcFile):
    PATH = "release_tracker"
    MODE = 0o444

    def __init__(self):
        self.active_opens = 0
        self.total_opens = 0
        self.total_releases = 0

    def open(self, ptregs: PtRegsWrapper, inode: int, file: int):
        self.active_opens += 1
        self.total_opens += 1
        self.logger.info(f"release_tracker opened. Active: {self.active_opens}")
        ptregs.set_retval(0)

    def release(self, ptregs: PtRegsWrapper, inode: int, file: int):
        self.active_opens -= 1
        self.total_releases += 1
        self.logger.info(f"release_tracker released. Active: {self.active_opens}")
        ptregs.set_retval(0)

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        data = f"active:{self.active_opens},opens:{self.total_opens},releases:{self.total_releases}\n".encode("utf-8")
        offset = yield from plugins.mem.read_int(loff)
        if size <= 0 or offset >= len(data):
            ptregs.set_retval(0)
            return
        chunk = min(size, len(data) - offset)
        yield from plugins.mem.write_bytes(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write_int(loff, offset + chunk)
        ptregs.set_retval(chunk)


class PollableProcFile(ProcFile):
    PATH = "pollable_proc"
    MODE = 0o444

    def poll(self, ptregs: PtRegsWrapper, file: int, poll_table: int):
        self.logger.info("pollable_proc polled!")
        # 1 = POLLIN (There is data to read)
        # 64 = POLLRDNORM (Normal data may be read without blocking)
        # Standard Linux bitmask for a readable file is typically POLLIN | POLLRDNORM (0x41)
        ptregs.set_retval(0x41)

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        data = b"Data is ready!\n"
        offset = yield from plugins.mem.read_int(loff)
        if size <= 0 or offset >= len(data):
            ptregs.set_retval(0)
            return
        chunk = min(size, len(data) - offset)
        yield from plugins.mem.write_bytes(user_buf, data[offset:offset + chunk])
        yield from plugins.mem.write_int(loff, offset + chunk)
        ptregs.set_retval(chunk)


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