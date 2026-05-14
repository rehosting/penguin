from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import SysFile, KobjPtr, AttrPtr, CharPtr, SizeT
from dwarffi import Ptr, BoundTypeInstance


class SimpleSysfsFile(SysFile):
    PATH = "/sys/kernel/simple_sysfs/value"  # No /sys prefix

    def __init__(self):
        self.value = 0

    def show(self, ptregs: PtRegsWrapper, kobj: KobjPtr, attr: AttrPtr, buf: CharPtr):
        """
        Write the current value as a string to buf.
        """
        assert isinstance(kobj, Ptr), "kobj must be a Ptr"
        assert isinstance(attr, Ptr), "attr must be a Ptr"
        assert isinstance(buf, Ptr), "buf must be a Ptr"

        data = f"{self.value}\n".encode("utf-8")
        yield from plugins.mem.write_bytes(buf, data)
        ptregs.set_retval(len(data))

    def store(self, ptregs: PtRegsWrapper, kobj: KobjPtr, attr: AttrPtr, buf: CharPtr, count: SizeT):
        """
        Read an integer from buf and store it.
        """
        assert isinstance(kobj, Ptr), "kobj must be a Ptr"
        assert isinstance(attr, Ptr), "attr must be a Ptr"
        assert isinstance(buf, Ptr), "buf must be a Ptr"
        assert isinstance(count, (int, BoundTypeInstance)), "count must be int or BoundTypeInstance"

        if int(count) <= 0:
            ptregs.set_retval(0)
            return
        raw = yield from plugins.mem.read_bytes(buf, int(count))
        try:
            val = int(raw.decode("utf-8").strip())
            self.value = val
            ptregs.set_retval(int(count))
        except Exception:
            ptregs.set_retval(-1)


class RandomSysfsFile(SysFile):
    PATH = "/sys/kernel/simple_sysfs/random"  # No /sys prefix

    def show(self, ptregs: PtRegsWrapper, kobj: KobjPtr, attr: AttrPtr, buf: CharPtr):
        """
        Write the current value as a string to buf.
        """
        assert isinstance(kobj, Ptr), "kobj must be a Ptr"
        assert isinstance(attr, Ptr), "attr must be a Ptr"
        assert isinstance(buf, Ptr), "buf must be a Ptr"

        import random
        data = f"{random.randint(0, 0xffffffff)}\n".encode("utf-8")
        yield from plugins.mem.write_bytes(buf, data)
        ptregs.set_retval(len(data))

    def store(self, ptregs: PtRegsWrapper, kobj: KobjPtr, attr: AttrPtr, buf: CharPtr, count: SizeT):
        assert isinstance(kobj, Ptr), "kobj must be a Ptr"
        assert isinstance(attr, Ptr), "attr must be a Ptr"
        assert isinstance(buf, Ptr), "buf must be a Ptr"
        assert isinstance(count, (int, BoundTypeInstance)), "count must be int or BoundTypeInstance"
        ptregs.set_retval(int(count))


class PowerStateSyfsFile(SysFile):
    PATH = "/sys/power/state"  # No /sys prefix

    def show(self, ptregs: PtRegsWrapper, kobj: KobjPtr, attr: AttrPtr, buf: CharPtr):
        """
        Write the current power state as a string to buf.
        """
        assert isinstance(kobj, Ptr), "kobj must be a Ptr"
        assert isinstance(attr, Ptr), "attr must be a Ptr"
        assert isinstance(buf, Ptr), "buf must be a Ptr"

        data = "mem\n"
        data_bytes = data.encode("utf-8")
        yield from plugins.mem.write_bytes(buf, data_bytes)
        ptregs.set_retval(len(data_bytes))

    def store(self, ptregs: PtRegsWrapper, kobj: KobjPtr, attr: AttrPtr, buf: CharPtr, count: SizeT):
        """
        Accepts any write, discards data, and returns the number of bytes written.
        """
        assert isinstance(kobj, Ptr), "kobj must be a Ptr"
        assert isinstance(attr, Ptr), "attr must be a Ptr"
        assert isinstance(buf, Ptr), "buf must be a Ptr"
        assert isinstance(count, (int, BoundTypeInstance)), "count must be int or BoundTypeInstance"
        ptregs.set_retval(int(count))


class BaseStateSyfsFile(SysFile):
    PATH = "/sys/s/t/a/state"  # No /sys prefix

    def show(self, ptregs: PtRegsWrapper, kobj: KobjPtr, attr: AttrPtr, buf: CharPtr):
        """
        Write the current power state as a string to buf.
        """
        assert isinstance(kobj, Ptr), "kobj must be a Ptr"
        assert isinstance(attr, Ptr), "attr must be a Ptr"
        assert isinstance(buf, Ptr), "buf must be a Ptr"

        data = "mem\n"
        data_bytes = data.encode("utf-8")
        yield from plugins.mem.write_bytes(buf, data_bytes)
        ptregs.set_retval(len(data_bytes))

    def store(self, ptregs: PtRegsWrapper, kobj: KobjPtr, attr: AttrPtr, buf: CharPtr, count: SizeT):
        """
        Accepts any write, discards data, and returns the number of bytes written.
        """
        assert isinstance(kobj, Ptr), "kobj must be a Ptr"
        assert isinstance(attr, Ptr), "attr must be a Ptr"
        assert isinstance(buf, Ptr), "buf must be a Ptr"
        assert isinstance(count, (int, BoundTypeInstance)), "count must be int or BoundTypeInstance"
        ptregs.set_retval(int(count))


class SysfsTest(Plugin):
    def __init__(self):
        plugins.sysfs.register_sysfs(SimpleSysfsFile())
        plugins.sysfs.register_sysfs(RandomSysfsFile())
        plugins.sysfs.register_sysfs(PowerStateSyfsFile())
        plugins.sysfs.register_sysfs(BaseStateSyfsFile())
