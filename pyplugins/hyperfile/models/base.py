from wrappers.ptregs_wrap import PtRegsWrapper
from penguin import getColoredLogger, plugins


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
    Bridging class that handles SysFS show/store natively.
    Bypasses VFS read/write mixins to safely read/write directly 
    to the kernel PAGE_SIZE buffer.
    """
    _data = None
    filename = None
    write_filepath = None

    def __init__(self, *, data=None, filename=None, write_filepath=None, **kwargs):
        if data is not None:
            self._data = data
        if filename is not None:
            self.filename = filename
        if write_filepath is not None:
            self.write_filepath = write_filepath
        
        # Pass remaining kwargs up the MRO (eventually hitting BaseFile's sink)
        super().__init__(**kwargs)

    def show(self, ptregs: PtRegsWrapper, kobj: int, attr: int, buf: int):
        data = None
        
        # Priority 1: In-memory data
        if self._data is not None:
            data = self._data
            
        # Priority 2: Read from host file
        elif self.filename is not None:
            try:
                with open(self.filename, 'rb') as f:
                    data = f.read()
            except Exception as e:
                self.logger.error(f"Failed to read backing file {self.filename}: {e}")
                return -1  # Return negative error code (e.g., -EIO)

        # Write data to the kernel buffer
        if data is not None:
            if isinstance(data, str):
                data = data.encode('utf-8')
            
            # Sysfs show buffers are strictly limited to PAGE_SIZE (typically 4096)
            write_size = min(len(data), 4096)
            yield from plugins.mem.write_bytes(buf, data[:write_size])
            return write_size  # show() must return the number of bytes printed
            
        return 0

    def store(self, ptregs: PtRegsWrapper, kobj: int, attr: int, buf: int, count: int):
        if count <= 0:
            return 0
            
        # Read the data the guest wrote to the kernel buffer
        data = yield from plugins.mem.read_bytes(buf, count)
        
        # Priority 1: Write out to a host file
        if self.write_filepath is not None:
            try:
                with open(self.write_filepath, 'ab') as f:
                    f.write(data)
            except Exception as e:
                self.logger.error(f"Failed to write to backing file {self.write_filepath}: {e}")
                return -1
        # Priority 2: No backing file, just log it and consume
        else:
            self.logger.info(f"Discarding sysfs store payload: {data}")
            
        return count  # store() must return the number of bytes consumed