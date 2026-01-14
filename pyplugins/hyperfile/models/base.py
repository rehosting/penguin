from wrappers.ptregs_wrap import PtRegsWrapper
from penguin import getColoredLogger


class BaseFile:
    """
    The root base class for all file types. 
    Acts as the 'Argument Sink' to prevent object.__init__ failures.
    """
    PATH = None
    FS = "unknown"

    def __init__(self, *, path: str = None, fs: str = None, **kwargs):
        """
        Consumes 'path' and 'fs' arguments.
        Swallows any remaining kwargs so object.__init__ doesn't crash.
        """
        if path is not None:
            self.PATH = path
        if fs is not None:
            self.FS = fs
        
        # We do not pass kwargs to super() because object() takes no args.
        super().__init__()
    
    @property
    def full_path(self) -> str:
        if self.PATH is None:
            return "unknown_path"
        pth = self.PATH.lstrip("/")
        if self.FS == "procfs":
            if pth.startswith("/proc/"):
                pth = pth[len("/proc/"):]
            return f"/proc/{pth}"
        elif self.FS == "devfs":
            if pth.startswith("/dev/"):
                pth = pth[len("/dev/"):]
            return f"/dev/{pth}"
        elif self.FS == "sysfs":
            if pth.startswith("/sys/"):
                pth = pth[len("/sys/"):]
            return f"/sys/{pth}"
        else:
            return self.PATH

    @property
    def logger(self):
        if hasattr(self, "_logger"):
            return self._logger
        self._logger = getColoredLogger(f"hyperfs.{self.FS}.{self.full_path}")
        return self._logger


class VFSFile(BaseFile):
    """
    Base class defining the VFS interface.
    """
    def open(self, ptregs: PtRegsWrapper, inode: int, file: int) -> None:
        pass

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, offset_ptr: int) -> None:
        pass

    def read_iter(self, ptregs: PtRegsWrapper, kiocb: int, iov_iter: int) -> None:
        pass

    def write(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, offset_ptr: int) -> None:
        pass

    def lseek(self, ptregs: PtRegsWrapper, file: int, offset: int, whence: int) -> None:
        pass

    def release(self, ptregs: PtRegsWrapper, inode: int, file: int) -> None:
        pass

    def poll(self, ptregs: PtRegsWrapper, file: int, poll_table_struct: int) -> None:
        pass

    def ioctl(self, ptregs: PtRegsWrapper, file: int, cmd: int, arg: int) -> None:
        pass

    def compat_ioctl(self, ptregs: PtRegsWrapper, file: int, cmd: int, arg: int) -> None:
        pass

    def mmap(self, ptregs: PtRegsWrapper, file: int, vm_area_struct: int) -> None:
        pass

    def get_unmapped_area(self, ptregs: PtRegsWrapper, file: int, addr: int, len_: int, pgoff: int, flags: int) -> None:
        pass


class ProcFile(VFSFile):
    FS = "procfs"


class DevFile(VFSFile):
    FS = "devfs"
    MAJOR = -1   # -1 for dynamic
    MINOR = 0

    def __init__(self, *, major: int = None, minor: int = None, **kwargs):
        if major is not None:
            self.MAJOR = major
        if minor is not None:
            self.MINOR = minor
        super().__init__(**kwargs)

    def flush(self, ptregs: PtRegsWrapper, file: int, owner: int) -> None:
        pass

    def fsync(self, ptregs: PtRegsWrapper, file: int, start: int, end: int, datasync: int) -> None:
        pass

    def fasync(self, ptregs: PtRegsWrapper, fd: int, file: int, on: int) -> None:
        pass

    def lock(self, ptregs: PtRegsWrapper, file: int, cmd: int, file_lock: int) -> None:
        pass


class SysFile(BaseFile):
    """
    SysFS nodes usually use show/store rather than raw read/write.
    """
    FS = "sysfs"

    def show(self, ptregs: PtRegsWrapper, kobj, attr, buf) -> None:
        pass

    def store(self, ptregs: PtRegsWrapper, kobj, attr, buf, count) -> None:
        pass


class SysfsBridge:
    """
    Bridging class that maps SysFS show/store to VFS read/write 
    so we can use standard Read/Write mixins.
    """
    def show(self, ptregs, kobj, attr, buf):
        # Create a fake 'user_buf' pointer (actually the kernel buf)
        # and call the mixin's read method.
        # Note: Sysfs show ignores offset/size usually, just dumping the whole thing.
        # We might need to adapt arguments based on your specific read implementation.
        yield from self.read(ptregs, file=0, user_buf=buf, size=4096, loff=0)

    def store(self, ptregs, kobj, attr, buf, count):
        yield from self.write(ptregs, file=0, user_buf=buf, size=count, loff=0)