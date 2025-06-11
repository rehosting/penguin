from penguin import plugins, getColoredLogger, Plugin
from analysis.kernel_types import load_isf_json, Ptr
from os.path import join, realpath, isfile
from wrappers.generic import Wrapper
import functools
from typing import Union


class KFFI(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        conf = self.get_arg("conf")
        kernel = conf["core"]["kernel"]
        arch = conf["core"]["arch"]
        if arch == "intel64":
            arch = "x86_64"
        elif arch == "aarch64":
            arch = "arm64"
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

    def get_function_address(self, function):
        sym = self.ffi.get_symbol(function)
        if sym:
            return sym.address

    def _prepare_ffi_call(self, func_ptr, args):
        """
        Prepare FFI call structure for kernel execution.

        Args:
            func_ptr: Address of the kernel function to call
            args: List of arguments to pass to the function (max 8)

        Returns:
            Serialized portal_ffi_call structure as bytes
        """
        self.logger.debug(
            f"Preparing FFI call: func_ptr={func_ptr:#x}, args={args}")

        # Validate arguments
        if len(args) > 8:
            raise ValueError(
                f"Too many arguments for FFI call: {len(args)} > 8")

        # Create FFI call structure
        ffi_call = self.new("portal_ffi_call")
        ffi_call.func_ptr = func_ptr
        ffi_call.num_args = len(args)

        # Set arguments
        for i, arg in enumerate(args):
            ffi_call.args[i] = arg

        # Return serialized structure
        return ffi_call.to_bytes()

    def call_kernel_function(self, func: Union[int, str], *args):
        """
        Call a kernel function dynamically with the given arguments.

        This uses the FFI mechanism to directly call kernel functions.
        CAUTION: This is extremely powerful and can easily crash the kernel
        if used incorrectly. Only call functions that are safe to call
        from arbitrary contexts.

        Args:
            func_ptr: Address of the kernel function to call
            *args: Arguments to pass to the function (max 8)

        Returns:
            Return value from the kernel function
        """
        if isinstance(func, str):
            func_ptr = self.get_function_address(func)
            if func_ptr is None:
                self.logger.error(f"Function not found: {func}")
                return None
        elif isinstance(func, int):
            func_ptr = func
        else:
            raise ValueError(f"Invalid function pointer type: {type(func)}")

        self.logger.debug(
            f"call_kernel_function: func_ptr={func_ptr:#x}, args={args}")

        buf = self._prepare_ffi_call(func_ptr, args)

        # Call the function
        response = yield ("ffi_exec", buf)

        if not response:
            self.logger.error(f"FFI call failed: func_ptr={func_ptr:#x}")
            return None

        # Parse the response
        result_struct = self.from_buffer("portal_ffi_call", response)
        result = result_struct.result

        self.logger.debug(f"FFI call returned: {result:#x}")
        return result

    def kmalloc(self, size):
        """
        Allocate memory in the kernel using kmalloc.

        Args:
            size: Size of memory to allocate
        """
        val = yield from self.call_kernel_function("igloo_kzalloc", size)
        return val

    def kfree(self, addr):
        """
        Free memory in the kernel using kfree.

        Args:
            addr: Address of memory to free
        """
        yield from self.call_kernel_function("igloo_kfree", addr)
