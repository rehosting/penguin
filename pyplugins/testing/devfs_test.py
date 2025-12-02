from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import DevFile
from hyperfile.models.read import ReadBufWrapper

class SimpleDevfsDevice(DevFile, ReadBufWrapper):
    PATH = "simpledev"
    MAJOR = -1  # dynamic
    MINOR = 0

    def __init__(self):
        self.value = 0

    def open(self, ptregs: PtRegsWrapper, inode: int, file: int):
        print("SimpleDevfsDevice.open called")
        ptregs.set_retval(0)

    def read(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, loff: int):
        """
        Returns the string representation of the stored integer value.
        """
        data = str(self.value).encode("utf-8")
        yield from self._impl_read(ptregs, file, user_buf, size, loff, data)

    def write(self, ptregs: PtRegsWrapper, file: int, user_buf: int, size: int, offset_ptr: int):
        """
        Accepts an integer string and stores it.
        """
        if size <= 0:
            ptregs.set_retval(0)
            return
        raw = yield from plugins.mem.read_bytes(user_buf, size)
        try:
            val = int(raw.decode("utf-8").strip())
            self.value = val
            ptregs.set_retval(size)
        except Exception:
            ptregs.set_retval(-1)

class DevfsTest(Plugin):
    def __init__(self):
        plugins.devfs.register_devfs(SimpleDevfsDevice())
        plugins.devfs.register_devfs(SimpleDevfsDevice(), path="/dev/bcde")
