from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import DevFile
from hyperfile.models.read import ReadBufWrapper

class SimpleDevfsDevice(DevFile, ReadBufWrapper):
    PATH = "simpledev"
    MAJOR = -1  # Dynamic allocation
    MINOR = 0

    def __init__(self):
        self.value = 0
        self.open_count = 0
        self.release_count = 0

    def open(self, ptregs: PtRegsWrapper, inode: int, file: int):
        self.open_count += 1
        ptregs.set_retval(0)

    def release(self, ptregs: PtRegsWrapper, inode: int, file: int):
        self.release_count += 1
        ptregs.set_retval(0)

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        """
        Returns the string representation of the stored integer value.
        ReadBufWrapper handles the `loff` (lseek) offset natively.
        """
        data = str(self.value).encode("utf-8") + b"\n"
        yield from self._impl_read(ptregs, file, user_buf, size, loff, data)

    def write(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, offset_ptr: int):
        """
        Accepts an integer string and stores it. Rejects bad data with -1 (-EPERM).
        """
        if size <= 0:
            ptregs.set_retval(0)
            return
        raw = yield from plugins.mem.read_bytes(user_buf, size)
        try:
            val = int(raw.decode("utf-8").strip())
            self.value = val
            ptregs.set_retval(size)
        except ValueError:
            # Inject a failure that the guest user-space will see
            ptregs.set_retval(-1)

    def ioctl(self, ptregs: PtRegsWrapper, file: int, cmd: int, arg: int):
        """
        Example IOCTL handling.
        """
        if cmd == 0x1337:
            self.value += 100
            ptregs.set_retval(0)
        else:
            ptregs.set_retval(-25) # -ENOTTY (Inappropriate ioctl for device)


class FixedDevfsDevice(DevFile, ReadBufWrapper):
    """
    Tests forcing a specific Major and Minor number for the device node.
    """
    PATH = "fixeddev"
    MAJOR = 242
    MINOR = 42

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        yield from self._impl_read(ptregs, file, user_buf, size, loff, b"fixed_node\n")


class DevfsTest(Plugin):
    def __init__(self):
        # 1. Standard dynamic device
        plugins.devfs.register_devfs(SimpleDevfsDevice())
        
        # 2. Overridden absolute path
        plugins.devfs.register_devfs(SimpleDevfsDevice(), path="/dev/bcde")
        
        # 3. Deeply nested device (tests automatic parent directory creation)
        plugins.devfs.register_devfs(SimpleDevfsDevice(), path="/dev/deep/nested/device")
        
        # 4. Fixed Major/Minor device
        plugins.devfs.register_devfs(FixedDevfsDevice())