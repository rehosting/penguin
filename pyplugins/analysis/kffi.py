from pandare2 import PyPlugin
from penguin import plugins, getColoredLogger
from analysis.kernel_types import load_isf_json, Ptr
from os.path import join, realpath, isfile
from hyper.portal_wrappers import Wrapper
import functools


class KFFI(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        conf = self.get_arg("conf")
        kernel = conf["core"]["kernel"]
        arch = conf["core"]["arch"]
        self.isf = realpath(join(kernel, f"../cosi.{arch}.json.xz"))
        self.logger = getColoredLogger("plugins.kffi")
        if not isfile(self.isf):
            self.logger.error(f"ISF file not found: {self.isf}")
            raise FileNotFoundError(f"ISF file not found: {self.isf}")

        self.logger.debug(f"Loading ISF file: {self.isf}")
        self.ffi = load_isf_json(self.isf)

    def _get_type(self, type_):
        t = self.ffi.get_user_type(type_)
        if not t:
            t = self.ffi.get_base_type(type_)
            if not t:
                t = self.ffi.get_enum(type_)
                if not t:
                    self.logger.error(f"Type {type_} not found in ISF")
                    return None
        return t

    def new(self, type_):
        t = self._get_type(type_)
        if not t:
            return None
        size = t.size
        buf = b"\x00" * size
        return self.ffi.create_instance(t, buf)

    def from_buffer(self, type_, buf, instance_offset_in_buffer=0):
        t = self._get_type(type_)
        return self.ffi.create_instance(t, buf, instance_offset_in_buffer)

    def read_type_panda(self, cpu, addr, type_):
        t = self._get_type(type_)
        if not t:
            return None
        buf = self.panda.virtual_memory_read(cpu, addr, t.size)
        if not buf:
            self.logger.error(f"Failed to read bytes from {addr:#x}")
            return None
        return self.ffi.create_instance(t, buf)

    def read_type(self, addr, type_):
        t = self._get_type(type_)
        if not t:
            return None
        portal = plugins.portal
        buf = yield from portal.read_bytes(addr, t.size)
        if not buf:
            self.logger.error(f"Failed to read bytes from {addr:#x}")
            return None
        return self.ffi.create_instance(t, buf)

    def deref(self, ptr: Ptr):
        if ptr.address == 0:
            self.logger.error(f"Pointer address is 0: {ptr}")
            return None
        val = yield from self.read_type(ptr.address, ptr._subtype_info.get("name"))
        return val

    def get_enum_dict(self, enum_name):
        enum = self.ffi.get_enum(enum_name)
        if not enum:
            self.logger.error(f"Enum {enum_name} not found in ISF")
            return {}
        return Wrapper(enum.constants)

    @functools.lru_cache
    def get_struct_size(self, struct_name):
        struct = self.ffi.get_user_type(struct_name)
        if struct:
            return struct.size

    def sizeof(self, struct_name):
        return self.get_struct_size(struct_name)
