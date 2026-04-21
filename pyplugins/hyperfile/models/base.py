from wrappers.ptregs_wrap import PtRegsWrapper
from typing import Union, Annotated
from penguin import getColoredLogger, plugins
from dwarffi import Ptr
from dwarffi.instances import BoundTypeInstance
import inspect

# --- DWARFFI Kernel Pointer Aliases ---
FilePtr = Annotated[Ptr, "struct file *"]
InodePtr = Annotated[Ptr, "struct inode *"]
KiocbPtr = Annotated[Ptr, "struct kiocb *"]
IovIterPtr = Annotated[Ptr, "struct iov_iter *"]
LoffTPtr = Annotated[Ptr, "loff_t *"]
CharPtr = Annotated[Ptr, "char *"]
PollTablePtr = Annotated[Ptr, "struct poll_table_struct *"]
VmAreaPtr = Annotated[Ptr, "struct vm_area_struct *"]
FileLockPtr = Annotated[Ptr, "struct file_lock *"]

# SysFS & Sysctl Specific Pointers
SizeTPtr = Annotated[Ptr, "size_t *"]
KobjPtr = Annotated[Ptr, "struct kobject *"]
AttrPtr = Annotated[Ptr, "struct attribute *"]
CtlTablePtr = Annotated[Ptr, "struct ctl_table *"]

# --- DWARFFI Value Aliases ---
CInt = Union[int, BoundTypeInstance]
SizeT = Annotated[CInt, "size_t"]
LoffT = Annotated[CInt, "loff_t"]


class BaseFile:
    """
    The root base class for all file types.
    Acts as the 'Argument Sink' to prevent object.__init__ failures.
    """
    PATH = None
    FS = "unknown"
    SIZE = 0
    SUPPORT_MMAP = False  # Explicitly declare mmap capability

    def __init__(self, *, path: str = None, fs: str = None, size: int = None, mode: int = None, support_mmap: bool = None, **kwargs):
        """
        Consumes 'path', 'fs', 'size', 'mode', and 'support_mmap' arguments.
        """
        if path is not None:
            self.PATH = path
        if fs is not None:
            self.FS = fs

        if size is not None:
            self.SIZE = size

        if support_mmap is not None:
            self.SUPPORT_MMAP = support_mmap

        # Use provided mode, or automatically derive it
        if mode is not None:
            self.MODE = mode
        else:
            self.MODE = self._derive_mode()

        super().__init__()

    def _derive_mode(self) -> int:
        """Derive appropriate file permissions based on implemented methods."""
        has_read = self._is_overridden('read') or self._is_overridden(
            'show') or self._is_overridden('read_iter')
        has_write = self._is_overridden(
            'write') or self._is_overridden('store')

        if has_read and has_write:
            return 0o666  # Read/Write
        elif has_write:
            return 0o222  # Write-only
        else:
            return 0o444  # Read-only (Default)

    def _is_overridden(self, method_name: str) -> bool:
        """Check if a method was overridden by the user's subclass."""
        if not hasattr(self, method_name):
            return False

        # Traverse the Method Resolution Order (MRO) to see where the method is defined
        for cls in type(self).__mro__:
            if method_name in cls.__dict__:
                # If the method belongs to one of our framework base classes, it's not custom
                if cls.__name__ in ('BaseFile', 'VFSFile', 'ProcFile', 'DevFile', 'SysFile', 'SysfsBridge', 'SysctlFile'):
                    return False
                # If it belongs to a subclass, the user implemented it!
                return True
        return False

    @property
    def full_path(self) -> str:
        if self.PATH is None:
            return "unknown_path"
        pth = self.PATH
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
        self._logger = getColoredLogger(f"hyperfs.{self.full_path}")
        return self._logger


class VFSFile(BaseFile):
    """
    Base class defining the VFS interface, strictly typed with dwarffi Ptrs and BoundTypeInstances.
    """

    def open(self, ptregs: PtRegsWrapper, inode: InodePtr, file: FilePtr) -> None:
        pass

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, offset_ptr: LoffTPtr) -> None:
        pass

    def read_iter(self, ptregs: PtRegsWrapper, kiocb: KiocbPtr, iov_iter: IovIterPtr) -> None:
        pass

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, offset_ptr: LoffTPtr) -> None:
        pass

    def lseek(self, ptregs: PtRegsWrapper, file: FilePtr, offset: LoffT, whence: CInt) -> None:
        pass

    def release(self, ptregs: PtRegsWrapper, inode: InodePtr, file: FilePtr) -> None:
        pass

    def poll(self, ptregs: PtRegsWrapper, file: FilePtr, poll_table_struct: PollTablePtr) -> None:
        pass

    def ioctl(self, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, arg: CInt) -> None:
        pass

    def compat_ioctl(self, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, arg: CInt) -> None:
        pass

    def mmap(self, ptregs: PtRegsWrapper, file: FilePtr, vm_area_struct: VmAreaPtr) -> None:
        pass

    def get_unmapped_area(self, ptregs: PtRegsWrapper, file: FilePtr, addr: CInt, len_: SizeT, pgoff: CInt, flags: CInt) -> None:
        pass


class ProcFile(VFSFile):
    FS = "procfs"


class DevFile(VFSFile):
    FS = "devfs"
    MAJOR = -1   # -1 for dynamic
    MINOR = 0
    IS_BLOCK = False

    def __init__(self, *, major: int = None, minor: int = None, is_block: bool = None, logical_block_size: int = None, **kwargs):
        if major is not None:
            self.MAJOR = major
        if minor is not None:
            self.MINOR = minor

        # Only overwrite the class attributes if explicitly provided
        if is_block is not None:
            self.IS_BLOCK = is_block
        if logical_block_size is not None:
            self.LOGICAL_BLOCK_SIZE = logical_block_size

        super().__init__(**kwargs)

    def flush(self, ptregs: PtRegsWrapper, file: FilePtr, owner: CInt) -> None:
        pass

    def fsync(self, ptregs: PtRegsWrapper, file: FilePtr, start: CInt, end: CInt, datasync: CInt) -> None:
        pass

    def fasync(self, ptregs: PtRegsWrapper, fd: CInt, file: FilePtr, on: CInt) -> None:
        pass

    def lock(self, ptregs: PtRegsWrapper, file: FilePtr, cmd: CInt, file_lock: FileLockPtr) -> None:
        pass


class SysFile(BaseFile):
    """
    SysFS nodes usually use show/store rather than raw read/write.
    """
    FS = "sysfs"

    def show(self, ptregs: PtRegsWrapper, kobj: KobjPtr, attr: AttrPtr, buf: CharPtr) -> None:
        pass

    def store(self, ptregs: PtRegsWrapper, kobj: KobjPtr, attr: AttrPtr, buf: CharPtr, count: SizeT) -> None:
        pass


class SysfsBridge(SysFile):
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

    def show(self, ptregs: PtRegsWrapper, kobj: KobjPtr, attr: AttrPtr, buf: CharPtr):
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
                self.logger.error(
                    f"Failed to read backing file {self.filename}: {e}")
                return -1  # Return negative error code (e.g., -EIO)

        # Write data to the kernel buffer
        if data is not None:
            if isinstance(data, str):
                data = data.encode('utf-8')

            # Sysfs show buffers are strictly limited to PAGE_SIZE (typically 4096)
            write_size = min(len(data), 4096)
            yield from plugins.mem.write(buf, data[:write_size])
            return write_size  # show() must return the number of bytes printed

        return 0

    def store(self, ptregs: PtRegsWrapper, kobj: KobjPtr, attr: AttrPtr, buf: CharPtr, count: SizeT):
        count_val = int(count)
        if count_val <= 0:
            return 0

        # Read the data the guest wrote to the kernel buffer
        # Using fmt=bytes to explicitly request raw bytes instead of attempting string interpretation
        data = yield from plugins.mem.read(buf, size=count_val, fmt="bytes")

        # Priority 1: Write out to a host file
        if self.write_filepath is not None:
            try:
                with open(self.write_filepath, 'ab') as f:
                    f.write(data)
            except Exception as e:
                self.logger.error(
                    f"Failed to write to backing file {self.write_filepath}: {e}")
                return -1
        # Priority 2: No backing file, just log it and consume
        else:
            self.logger.info(f"Discarding sysfs store payload: {data}")

        return count_val  # store() must return the number of bytes consumed


class SysctlFile(BaseFile):
    FS = "sysctl"
    PATH: str = ""
    MODE: int = 0o644
    MAXLEN: int = 256
    INITIAL_VALUE: Union[str, bytes] = ""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.PATH = kwargs.get("path", getattr(self, "PATH", ""))
        self.MODE = kwargs.get("mode", getattr(self, "MODE", 0o644))
        self.MAXLEN = kwargs.get("maxlen", getattr(self, "MAXLEN", 256))
        self.INITIAL_VALUE = kwargs.get(
            "INITIAL_VALUE", getattr(self, "INITIAL_VALUE", b""))

    def read(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        """No-op generator."""
        if False:
            yield
        return 0

    def write(self, ptregs: PtRegsWrapper, file: FilePtr, user_buf: CharPtr, size: SizeT, loff: LoffTPtr):
        """No-op generator."""
        if False:
            yield
        return 0

    def proc_handler(self, ptregs: PtRegsWrapper, ctl: CtlTablePtr, write: CInt, buffer: CharPtr, lenp: SizeTPtr, ppos: LoffTPtr):
        """
        Unified sysctl entry point.
        Extracts arguments from ptregs and routes to read() or write().
        """
        if int(write):
            res = self.write(ptregs, None, buffer, lenp, ppos)
        else:
            res = self.read(ptregs, None, buffer, lenp, ppos)

        # 2. Conditionally yield if the method was a generator (e.g. uses memory plugins)
        if inspect.isgenerator(res):
            ret = yield from res
        else:
            ret = res

        # 3. Ensure a safe numeric return for the KFFI callback
        ret_val = ret if ret is not None else 0
        ptregs.retval = ret_val if ret_val < 0 else 0
        return ret_val


class MtdDevice(BaseFile):
    """
    Object-Oriented representation of an MTD (Memory Technology Device).
    Can be dynamically registered via plugins.mtd.register_mtd(dev)
    """
    FS = "mtd"
    NAME: str = "mtd_custom"
    SIZE: int = 0
    ERASE_SIZE: int = 131072
    WRITE_SIZE: int = 2048
    OOB_SIZE: int = 64
    TYPE: str = "nand"  # 'nand' or 'nor'

    def __init__(self, **kwargs):
        self.NAME = kwargs.get("name", getattr(self, "NAME", "mtd_custom"))
        self.SIZE = kwargs.get("size", getattr(self, "SIZE", 0))
        self.ERASE_SIZE = kwargs.get(
            "erase_size", getattr(self, "ERASE_SIZE", 131072))
        self.WRITE_SIZE = kwargs.get(
            "write_size", getattr(self, "WRITE_SIZE", 2048))
        self.OOB_SIZE = kwargs.get("oob_size", getattr(self, "OOB_SIZE", 64))
        self.TYPE = kwargs.get("type", getattr(self, "TYPE", "nand"))
        super().__init__(**kwargs)

    def read(self, ptregs: PtRegsWrapper, offset: LoffT, length: SizeT, buf_ptr: CharPtr):
        """
        Reads `length` bytes from the flash starting at `offset` into `buf_ptr`.
        Should return 0 on success, or a negative error code (e.g. -EIO).
        """
        if False:
            yield
        return 0

    def write(self, ptregs: PtRegsWrapper, offset: LoffT, length: SizeT, buf_ptr: CharPtr):
        """
        Writes `length` bytes from `buf_ptr` into the flash starting at `offset`.
        Should return 0 on success, or a negative error code.
        """
        if False:
            yield
        return 0

    def erase(self, ptregs: PtRegsWrapper, offset: LoffT, length: SizeT):
        """
        Erases `length` bytes of the flash starting at `offset`.
        Should return 0 on success, or a negative error code.
        """
        if False:
            yield
        return 0
