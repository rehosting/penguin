from penguin import Plugin
from hyperfile.models.base import DevFile

class NativeMmap(Plugin):
    def __init__(self):
        self.logger.info("Initializing NativeMmap plugin")
        # We'll register our device here
        from penguin import plugins
        dev = MmapDev()
        try:
            plugins.devfs.register_devfs(dev, path="/dev/mmap_native")
        except ValueError:
            pass # Already registered

class MmapDev(DevFile):
    def __init__(self):
        super().__init__(size=0x1000)
        self.storage = {}

    def qemu_mmap_read(self, addr, size):
        val = self.storage.get(addr, 0)
        self.logger.info(f"QEMU MMAP READ: addr=0x{addr:x} val=0x{val:x}")
        return val

    def qemu_mmap_write(self, addr, data, size):
        self.logger.info(f"QEMU MMAP WRITE: addr=0x{addr:x} val=0x{data:x}")
        self.storage[addr] = data
