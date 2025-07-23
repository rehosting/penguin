"""
# KFFI API Plugin

This module provides the KFFI (Kernel Foreign Function Interface) plugin for the penguin framework.
It enables calling kernel-space functions and interacting with kernel memory from user-space plugins.
The KFFI plugin abstracts low-level kernel function invocation, argument marshalling, and result handling,
allowing other plugins to perform advanced kernel introspection and manipulation.

## Features

- Call arbitrary kernel functions with specified arguments.
- Read and write kernel memory.
- Marshal arguments and results between user-space and kernel-space.
- Supports type-safe function signatures and return values.

## Example Usage

```python
from penguin import plugins

# Call a kernel function (e.g., do_sys_open) with arguments
result = yield from plugins.kffi.call_function("do_sys_open", ["/etc/passwd", 0, 0])

# Read kernel memory at a specific address
data = yield from plugins.kffi.read_kernel_memory(0xffff888000000000, 64)

# Write to kernel memory
yield from plugins.kffi.write_kernel_memory(0xffff888000000000, b"\x90\x90\x90\x90")
```
"""

from penguin import plugins, getColoredLogger, Plugin
from wrappers.ctypes_wrap import Ptr, VtypeJsonGroup
from os.path import join, realpath, isfile
from wrappers.generic import Wrapper
import functools
from typing import Any, Optional, Union, Generator


class KFFI(Plugin):
    """
    # KFFI Plugin

    Provides methods for calling kernel functions and interacting with kernel memory.

    ## Methods

    - `call_function`: Call a kernel function with arguments.
    - `read_kernel_memory`: Read bytes from kernel memory.
    - `write_kernel_memory`: Write bytes to kernel memory.
    """

    def __init__(self) -> None:
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
        self.igloo_ko_isf  = realpath(join(kernel, f"../igloo.ko.{arch}.json.xz"))
        self.ffi = VtypeJsonGroup([self.igloo_ko_isf, self.isf])
    
    def _fixup_igloo_module_baseaddr(self, addr):
        self.ffi.vtypejsons[self.igloo_ko_isf].shift_symbol_addresses(addr)

    def _get_type(self, type_: str) -> Any:
        """
        ### Get type information from ISF

        **Args:**
        - `type_` (`str`): Name of the type to look up.

        **Returns:**
        - Type object or None if not found.
        """
        t = self.ffi.get_user_type(type_)
        if not t:
            t = self.ffi.get_base_type(type_)
            if not t:
                t = self.ffi.get_enum(type_)
                if not t:
                    self.logger.error(f"Type {type_} not found in ISF")
                    return None
        return t

    def new(self, type_: str) -> Any:
        """
        ### Create a new instance of a type

        **Args:**
        - `type_` (`str`): Name of the type.

        **Returns:**
        - Instance of the type, or None if type not found.
        """
        t = self._get_type(type_)
        if not t:
            return None
        size = t.size
        buf = b"\x00" * size
        return self.ffi.create_instance(t, buf)

    def from_buffer(self, type_: str, buf: bytes,
                    instance_offset_in_buffer: int = 0) -> Any:
        """
        ### Create an instance of a type from a buffer

        **Args:**
        - `type_` (`str`): Name of the type.
        - `buf` (`bytes`): Buffer containing the data.
        - `instance_offset_in_buffer` (`int`, optional): Offset in buffer (default: 0).

        **Returns:**
        - Instance of the type.
        """
        t = self._get_type(type_)
        return self.ffi.create_instance(t, buf, instance_offset_in_buffer)

    def read_type_panda(self, cpu: Any, addr: int, type_: str) -> Any:
        """
        ### Read a type from kernel memory using PANDA

        **Args:**
        - `cpu` (`Any`): CPU context.
        - `addr` (`int`): Address to read from.
        - `type_` (`str`): Name of the type.

        **Returns:**
        - Instance of the type, or None if read fails.
        """
        t = self._get_type(type_)
        if not t:
            return None
        buf = self.panda.virtual_memory_read(cpu, addr, t.size)
        if not buf:
            self.logger.error(f"Failed to read bytes from {addr:#x}")
            return None
        return self.ffi.create_instance(t, buf)

    def read_type(self, addr: int, type_: str) -> Generator[Any, Any, Any]:
        """
        ### Read a type from kernel memory

        **Args:**
        - `addr` (`int`): Address to read from.
        - `type_` (`str`): Name of the type.

        **Returns:**
        - Instance of the type, or None if read fails.
        """
        t = self._get_type(type_)
        if not t:
            return None
        buf = yield from plugins.mem.read_bytes(addr, t.size)
        if not buf:
            self.logger.error(f"Failed to read bytes from {addr:#x}")
            return None
        return self.ffi.create_instance(t, buf)

    def deref(self, ptr: Ptr) -> Generator[Any, Any, Any]:
        """
        ### Dereference a pointer to a type

        **Args:**
        - `ptr` (`Ptr`): Pointer object.

        **Returns:**
        - Value pointed to, or None if pointer is null.
        """
        if ptr.address == 0:
            self.logger.error(f"Pointer address is 0: {ptr}")
            return None
        val = yield from self.read_type(ptr.address, ptr._subtype_info.get("name"))
        return val

    def get_enum_dict(self, enum_name: str) -> Wrapper:
        """
        ### Get dictionary of enum constants

        **Args:**
        - `enum_name` (`str`): Name of the enum.

        **Returns:**
        - `Wrapper`: Wrapper containing enum constants.
        """
        enum = self.ffi.get_enum(enum_name)
        if not enum:
            self.logger.error(f"Enum {enum_name} not found in ISF")
            return {}
        return Wrapper(enum.constants)

    @functools.lru_cache
    def get_struct_size(self, struct_name: str) -> Optional[int]:
        """
        ### Get the size of a struct

        **Args:**
        - `struct_name` (`str`): Name of the struct.

        **Returns:**
        - `int` or `None`: Size of the struct, or None if not found.
        """
        struct = self.ffi.get_user_type(struct_name)
        if struct:
            return struct.size

    def sizeof(self, struct_name: str) -> Optional[int]:
        """
        ### Alias for get_struct_size

        **Args:**
        - `struct_name` (`str`): Name of the struct.

        **Returns:**
        - `int` or `None`: Size of the struct, or None if not found.
        """
        return self.get_struct_size(struct_name)

    def get_function_address(self, function: str) -> Optional[int]:
        """
        ### Get the address of a kernel function

        **Args:**
        - `function` (`str`): Name of the function.

        **Returns:**
        - `int` or `None`: Address of the function, or None if not found.
        """
        sym = self.ffi.get_symbol(function)
        if sym:
            return sym.address

    def _prepare_ffi_call(self, func_ptr: int, args: list) -> bytes:
        """
        ### Prepare FFI call structure for kernel execution

        **Args:**
        - `func_ptr` (`int`): Address of the kernel function to call.
        - `args` (`list`): List of arguments to pass to the function (max 8).

        **Returns:**
        - `bytes`: Serialized portal_ffi_call structure.
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

    def call_kernel_function(
            self, func: Union[int, str], *args: Any) -> Generator[Any, Any, Any]:
        """
        ### Call a kernel function dynamically with the given arguments

        This uses the FFI mechanism to directly call kernel functions.
        CAUTION: This is extremely powerful and can easily crash the kernel
        if used incorrectly. Only call functions that are safe to call
        from arbitrary contexts.

        **Args:**
        - `func` (`int` or `str`): Function address or name.
        - `*args` (`Any`): Arguments to pass to the function (max 8).

        **Returns:**
        - Return value from the kernel function, or None if call fails.
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

        # importing here to avoid circular import issues
        from hyper.portal import PortalCmd

        # Call the function
        response = yield PortalCmd("ffi_exec", size=len(buf), data=buf)

        if not response:
            self.logger.error(f"FFI call failed: func_ptr={func_ptr:#x}")
            return None

        # Parse the response
        result_struct = self.from_buffer("portal_ffi_call", response)
        result = result_struct.result

        self.logger.debug(f"FFI call returned: {result:#x}")
        return result

    def kmalloc(self, size: int) -> Generator[Any, Any, Any]:
        """
        ### Allocate memory in the kernel using kmalloc

        **Args:**
        - `size` (`int`): Size of memory to allocate.

        **Returns:**
        - Address of allocated memory, or None if allocation fails.
        """
        val = yield from self.call_kernel_function("igloo_kzalloc", size)
        return val

    def kfree(self, addr: int) -> Generator[Any, Any, Any]:
        """
        ### Free memory in the kernel using kfree

        **Args:**
        - `addr` (`int`): Address of memory to free.

        **Returns:**
        - `None`
        """
        yield from self.call_kernel_function("igloo_kfree", addr)
