"""
KFFI API Plugin
================

This module provides the KFFI (Kernel Foreign Function Interface) plugin for the
Penguin framework. It enables calling kernel-space functions and interacting with
kernel memory from user-space plugins. The KFFI plugin abstracts low-level kernel
function invocation, argument marshalling, and result handling, allowing other
plugins to perform advanced kernel introspection and manipulation.

Features
--------

* Call arbitrary kernel functions with specified arguments.
* Read and write kernel memory.
* Marshal arguments and results between user-space and kernel-space.
* Supports type-safe function signatures and return values.

Example usage
-------------

.. code-block:: python

    from penguin import plugins

    # Call a kernel function (e.g., do_sys_open) with arguments
    result = yield from plugins.kffi.call_function("do_sys_open", "/etc/passwd", 0, 0)

    # Read kernel memory at a specific address
    data = yield from plugins.kffi.read_kernel_memory(0xffff888000000000, 64)

    # Write to kernel memory
    yield from plugins.kffi.write_kernel_memory(0xffff888000000000, b"\x90\x90\x90\x90")
"""

from penguin import plugins, getColoredLogger, Plugin
from wrappers.ctypes_wrap import Ptr, VtypeJsonGroup, BoundTypeInstance, BoundArrayView
from os.path import join, realpath, isfile
from wrappers.generic import Wrapper
import functools
import inspect
from typing import Any, Optional, Union, Generator, Tuple, Iterator
from wrappers.ptregs_wrap import get_pt_regs_wrapper


class KFFI(Plugin):
    """
    KFFI Plugin
    -----------

    Provides methods for calling kernel functions and interacting with kernel memory.

    Methods
    ~~~~~~~

    - ``call_function``: Call a kernel function with arguments.
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
        self.igloo_ko_isf = realpath(join(kernel, f"../igloo.ko.{arch}.json.xz"))
        self.ffi = VtypeJsonGroup([self.igloo_ko_isf, self.isf])
        self._tramp_callbacks = {}
        self._tramp_addresses = {}
        self.tramp_init = False

    def __init_tramp_functionality(self):
        if self.tramp_init:
            return
        self.tramp_init = True
        # Register trampoline hit hypercall handler
        from hyper.consts import igloo_hypercall_constants as iconsts
        self.portal = plugins.portal
        self._on_tramp_hit_hypercall =  \
                self.panda.hypercall(iconsts.IGLOO_HYP_TRAMP_HIT)(
                self.portal.wrap(self._on_tramp_hit_hypercall))

        # Register with portal's interrupt handler system
        self.portal.register_interrupt_handler(
            "kffi", self._tramp_interrupt_handler)

    def new(self, type_: str) -> Any:
        """
        Create a new instance of a type.

        Args:
            type_ (str): Name of the type.

        Returns:
            Any: Instance of the type, or None if type not found.
        """
        t = self.ffi.get_type(type_)
        if not t:
            return None
        size = t.size
        buf = b"\x00" * size
        return self.ffi.create_instance(t, buf)

    def from_buffer(self, type_: str, buf: bytes,
                    instance_offset_in_buffer: int = 0) -> Any:
        """
        Create an instance of a type from a buffer.

        Args:
            type_ (str): Name of the type.
            buf (bytes): Buffer containing the data.
            instance_offset_in_buffer (int): Offset in buffer (default: 0).

        Returns:
            Any: Instance of the type.
        """
        t = self.ffi.get_type(type_)
        return self.ffi.create_instance(t, buf, instance_offset_in_buffer)

    def read_type_panda(self, cpu: Any, addr: int, type_: str) -> Any:
        """
        Read a type from kernel memory using PANDA.

        Args:
            cpu (Any): CPU context.
            addr (int): Address to read from.
            type_ (str): Name of the type.

        Returns:
            Any: Instance of the type, or None if read fails.
        """
        t = self.ffi.get_type(type_)
        if not t:
            return None
        buf = self.panda.virtual_memory_read(cpu, addr, t.size)
        if not buf:
            self.logger.error(f"Failed to read bytes from {addr:#x}")
            return None
        return self.ffi.create_instance(t, buf)

    def read_type(self, addr: int, type_: str) -> Generator[Any, Any, Any]:
        """
        Read a type from kernel memory.

        Args:
            addr (int): Address to read from.
            type_ (str): Name of the type.

        Returns:
            Any: Instance of the type, or None if read fails.
        """
        t = self.ffi.get_type(type_)
        if not t:
            return None
        buf = yield from plugins.mem.read_bytes(addr, t.size)
        if not buf:
            self.logger.error(f"Failed to read bytes from {addr:#x}")
            return None
        return self.ffi.create_instance(t, buf)

    def deref(self, ptr: Ptr) -> Generator[Any, Any, Any]:
        """
        Dereference a pointer to a type.

        Args:
            ptr (Ptr): Pointer object.

        Returns:
            Any: Value pointed to, or None if pointer is null.
        """
        if ptr.address == 0:
            self.logger.error(f"Pointer address is 0: {ptr}")
            return None
        val = yield from self.read_type(ptr.address, ptr._subtype_info.get("name"))
        return val

    def get_enum_dict(self, enum_name: str) -> Wrapper:
        """
        Get dictionary of enum constants.

        Args:
            enum_name (str): Name of the enum.

        Returns:
            Wrapper: Wrapper containing enum constants.
        """
        enum = self.ffi.get_enum(enum_name)
        if not enum:
            self.logger.error(f"Enum {enum_name} not found in ISF")
            return {}
        return Wrapper(enum.constants)

    @functools.lru_cache
    def get_struct_size(self, struct_name: str) -> Optional[int]:
        """
        Get the size of a struct.

        Args:
            struct_name (str): Name of the struct.

        Returns:
            Optional[int]: Size of the struct, or None if not found.
        """
        struct = self.ffi.get_user_type(struct_name)
        if struct:
            return struct.size

    def sizeof(self, struct_name: str) -> Optional[int]:
        """
        Alias for get_struct_size.

        Args:
            struct_name (str): Name of the struct.

        Returns:
            Optional[int]: Size of the struct, or None if not found.
        """
        return self.get_struct_size(struct_name)

    def get_function_address(self, function: str) -> Optional[int]:
        """
        Get the address of a kernel function.

        Args:
            function (str): Name of the function.

        Returns:
            Optional[int]: Address of the function, or None if not found.
        """
        sym = self.ffi.get_symbol(function)
        if sym:
            return sym.address

    def _fixup_igloo_module_baseaddr(self, addr):
        self.ffi.vtypejsons[self.igloo_ko_isf].shift_symbol_addresses(addr)

    def _prepare_ffi_call(self, func_ptr: int, args: list, func_name: str = None) -> Generator[Tuple[bytes, Optional[int], Optional[dict]], Any, Any]:
        """
        Prepare FFI call structure for kernel execution, using function signature if available.

        Args:
            func_ptr (int): Address of the kernel function to call.
            args (list): List of arguments to pass to the function (max 8).
            func_name (str, optional): Name of the function (for signature lookup).

        Returns:
            Tuple[bytes, Optional[int], Optional[dict]]: Serialized ``portal_ffi_call`` structure,
            kernel memory address if allocated, and function signature ``type_info`` if available.
        """
        self.logger.debug(
            f"Preparing FFI call: func_ptr={func_ptr:#x}, args={args}, func_name={func_name}")

        # Lookup function signature if possible
        func_typeinfo = None
        if func_name:
            sym = self.ffi.get_symbol(func_name)
            if sym and sym.type_info and sym.type_info.get("kind") == "function":
                func_typeinfo = sym.type_info
        # Validate arguments
        if len(args) > 8:
            raise ValueError(
                f"Too many arguments for FFI call: {len(args)} > 8")
        # Use signature to cast/corral arguments
        marshalled_args = []
        if func_typeinfo and "parameters" in func_typeinfo:
            params = func_typeinfo["parameters"]
            for i, arg in enumerate(args):
                if i < len(params):
                    param_type = params[i]["type"]
                    kind = param_type.get("kind")
                    # Unsigned base type: convert negative ints
                    if kind == "base":
                        base_type = self.ffi.get_base_type(param_type.get("name"))
                        if base_type and base_type.signed is False and isinstance(arg, int) and arg < 0:
                            arg = arg % (1 << (base_type.size * 8))
                    # Pointer: allow int or Ptr
                    elif kind == "pointer":
                        if isinstance(arg, Ptr):
                            arg = arg.address
                        elif not isinstance(arg, int):
                            raise TypeError(f"Argument {i} expected pointer/int, got {type(arg)}")
                    # String: allow str/bytes
                    elif kind == "base" and param_type.get("name") in ("char", "unsigned char"):
                        if isinstance(arg, str):
                            arg = arg.encode() + b"\x00"
                        elif isinstance(arg, bytes):
                            arg = arg if arg.endswith(b"\x00") else arg + b"\x00"
                    # TODO: struct/array/enum
                marshalled_args.append(arg)
        else:
            marshalled_args = list(args)
        arg_bytes = []
        arg_ptr_indices = []
        total_bytes = 0
        boundtype_ptrs = {}
        for i, arg in enumerate(marshalled_args):
            if isinstance(arg, (int, float)) or hasattr(arg, '_value'):
                arg_bytes.append(None)
            elif isinstance(arg, str):
                b = arg.encode() + b"\x00"
                arg_bytes.append(b)
                arg_ptr_indices.append((i, total_bytes, len(b)))
                total_bytes += len(b)
            elif isinstance(arg, bytes):
                b = arg if arg.endswith(b"\x00") else arg + b"\x00"
                arg_bytes.append(b)
                arg_ptr_indices.append((i, total_bytes, len(b)))
                total_bytes += len(b)
            elif type(arg).__name__ == 'BoundTypeInstance':
                if not hasattr(arg, 'address'):
                    to_write = arg.to_bytes()
                    raw_addr = yield from self.kmalloc(len(to_write) + 64)
                    if not raw_addr:
                        raise RuntimeError("Failed to allocate kernel memory for BoundTypeInstance")
                    aligned_addr = (raw_addr + 63) & ~63
                    yield from plugins.mem.write_bytes(aligned_addr, to_write)
                    boundtype_ptrs[i] = aligned_addr
            elif hasattr(arg, 'to_bytes') and hasattr(arg, 'size'):
                b = arg.to_bytes()
                arg_bytes.append(b)
                arg_ptr_indices.append((i, total_bytes, len(b)))
                total_bytes += len(b)
            else:
                raise TypeError(f"Unsupported argument type for FFI: {type(arg)}")
        kmem_addr = None
        if total_bytes > 0:
            kmem_addr = yield from self.kmalloc(total_bytes)
            if not kmem_addr:
                raise RuntimeError("Failed to allocate kernel memory for FFI args")
            for i, off, sz in arg_ptr_indices:
                b = arg_bytes[i]
                if b is not None and sz > 0:
                    yield from plugins.mem.write_bytes(kmem_addr + off, b)
        ffi_call = self.new("portal_ffi_call")
        ffi_call.func_ptr = func_ptr
        ffi_call.num_args = len(marshalled_args)
        for i, arg in enumerate(marshalled_args):
            if isinstance(arg, (int, float)) or hasattr(arg, '_value'):
                ffi_call.args[i] = int(arg) if not isinstance(arg, float) else arg
            elif isinstance(arg, (str, bytes)) or (hasattr(arg, 'to_bytes') and hasattr(arg, 'size')):
                for idx, off, sz in arg_ptr_indices:
                    if idx == i:
                        ffi_call.args[i] = kmem_addr + off
                        break
            elif type(arg).__name__ == 'BoundTypeInstance':
                if hasattr(arg, 'address'):
                    ffi_call.args[i] = arg.address
                else:
                    ffi_call.args[i] = boundtype_ptrs[i]
            else:
                raise TypeError(f"Unsupported argument type for FFI: {type(arg)}")
        return ffi_call.to_bytes(), kmem_addr, func_typeinfo

    def call_kernel_function(
            self, func: Union[int, str], *args: Any) -> Generator[Any, Any, Any]:
        """
        Call a kernel function dynamically with the given arguments.

        This uses the FFI mechanism to directly call kernel functions.
        CAUTION: This is extremely powerful and can easily crash the kernel
        if used incorrectly. Only call functions that are safe to call from
        arbitrary contexts.

        Args:
            func (int or str): Function address or name.
            *args (Any): Arguments to pass to the function (max 8).

        Returns:
            Any: Return value from the kernel function, or None if call fails.

        Note:
            This leaks memory. We should have a better policy on that.
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

        func_name = func if isinstance(func, str) else None
        buf, optsbuf, func_typeinfo = yield from self._prepare_ffi_call(func_ptr, args, func_name)

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
        # Marshal return value if function signature is available
        if func_typeinfo and "return_type" in func_typeinfo:
            ret_type = func_typeinfo["return_type"]
            kind = ret_type.get("kind")
            name = ret_type.get("name")
            if kind == "base":
                base_type = self.ffi.get_base_type(name)
                if base_type:
                    # Unsigned fixup
                    if base_type.signed is False and result < 0:
                        result = result % (1 << (base_type.size * 8))
                    # Convert to correct Python type
                    if base_type.kind == "int" or base_type.kind == "pointer":
                        result = int(result)
                    elif base_type.kind == "float":
                        result = float(result)
                    elif base_type.kind == "bool":
                        result = bool(result)
            elif kind == "enum":
                enum_type = self.ffi.get_enum(name)
                if enum_type:
                    result = enum_type and enum_type.base and self.ffi.get_base_type(enum_type.base)
                    if enum_type:
                        result = self.ffi.create_instance(enum_type, result.to_bytes(enum_type.size, 'little'))._value
            elif kind == "pointer":
                # Return a Ptr object
                ptr_type = ret_type.get("subtype")
                result = Ptr(result, ptr_type, self.ffi)
            elif kind in ("struct", "union"):
                # Read struct/union from kernel memory at returned address
                struct_type = name
                if result != 0:
                    val = yield from self.read_type(result, struct_type)
                    result = val
                else:
                    result = None
        return result

    def call(self, func: Union[int, str], *args: Any) -> Generator[Any, Any, Any]:
        val = yield from self.call_kernel_function(func, *args)
        return val

    def kmalloc(self, size: int) -> Generator[Any, Any, Any]:
        """
        Allocate memory in the kernel using ``kmalloc``.

        Args:
            size (int): Size of memory to allocate.

        Returns:
            Any: Address of allocated memory, or None if allocation fails.
        """
        val = yield from self.call_kernel_function("igloo_kzalloc", size)
        return val

    def kfree(self, addr: int) -> Generator[Any, Any, Any]:
        """
        Free memory in the kernel using ``kfree``.

        Args:
            addr (int): Address of memory to free.

        Returns:
            None
        """
        yield from self.call_kernel_function("igloo_kfree", addr)

    def kallsyms_lookup(self, symbol: str) -> Generator[Any, Any, Any]:
        """
        Look up a kernel symbol address using the ``kallsyms_lookup`` portal operation (simplified).

        Args:
            symbol (str): Name of the symbol to look up.

        Returns:
            Any: Address of the symbol as int, or None if not found.
        """
        if not symbol or not isinstance(symbol, str):
            self.logger.error("Symbol name must be a non-empty string")
            return None
        # Send symbol name as null-terminated bytes
        symbol_bytes = symbol.encode() + b"\x00"
        from hyper.portal import PortalCmd
        addr = yield PortalCmd("kallsyms_lookup", size=len(symbol_bytes), data=symbol_bytes)
        if not addr:
            self.logger.error(f"kallsyms_lookup: symbol not found: {symbol}")
            return None
        self.logger.debug(f"kallsyms_lookup: {symbol} -> {addr:#x}")
        return addr

    def generate_trampoline(self) -> Generator[Any, Any, Any]:
        """
        Request a trampoline from the kernel via portal.

        Returns:
            dict: Keys include ``tramp_id``, ``tramp_addr``, and ``status``.
        """
        from hyper.portal import PortalCmd
        self.__init_tramp_functionality()
        # Send empty buffer for trampoline generation
        response = yield PortalCmd("tramp_generate", size=0, data=b"")
        if not response:
            self.logger.error("Trampoline generation failed: no response")
            return None
        tramp_struct = self.from_buffer("portal_tramp_generate", response)
        return {
            "tramp_id": tramp_struct.tramp_id,
            "tramp_addr": tramp_struct.tramp_addr,
            "status": tramp_struct.status,
        }

    def callback(self, func) -> Generator[Any, Any, Any]:
        """
        Register a trampoline callback and return an integer guest virtual address.

        Immediately generates the trampoline, sets up the interrupt handler, and returns an integer address.
        """
        if func in self._tramp_addresses:
            return self._tramp_addresses[func]
        tramp_info = yield from self.generate_trampoline()
        tramp_id = tramp_info.get("tramp_id")
        tramp_addr = tramp_info.get("tramp_addr")
        num_args = len(inspect.signature(func).parameters)
        self._tramp_callbacks[tramp_id] = (func, num_args)
        self._tramp_callbacks[func] = tramp_id
        self._tramp_addresses[tramp_id] = tramp_addr
        self._tramp_addresses[func] = tramp_addr
        return tramp_addr

    def get_callback_id(self, f: Union[int, Any]) -> Optional[int]:
        """
        Get the trampoline ID for a registered callback function or trampoline address.

        Args:
            f (int | Any): Callback function or trampoline address.

        Returns:
            Optional[int]: Trampoline ID, or None if not found.
        """
        return self._tramp_callbacks.get(f, None)

    def _tramp_interrupt_handler(self):
        """
        Interrupt handler to register trampoline callbacks.
        """
        if not hasattr(self, '_pending_tramp_callbacks') or not self._pending_tramp_callbacks:
            return False
        while self._pending_tramp_callbacks:
            func = self._pending_tramp_callbacks.pop(0)
            tramp_info = yield from self.generate_trampoline()
            tramp_id = tramp_info.get("tramp_id")
            tramp_addr = tramp_info.get("tramp_addr")
            tramp_status = tramp_info.get("status")
            if tramp_id is not None and tramp_addr is not None:
                num_args = len(inspect.signature(func).parameters)
                self._tramp_callbacks[tramp_id] = (func, num_args)
                self.logger.debug(f"Registered trampoline callback {func.__name__} with id={tramp_id} addr={tramp_addr}")
                # Set Callback info if exists
                if hasattr(self, '_tramp_proxy_map') and func in self._tramp_proxy_map:
                    cb = self._tramp_proxy_map[func]
                    cb.address = tramp_addr
                    cb.id = tramp_id
                    cb.status = tramp_status
                    cb.ready = True
            else:
                self.logger.error(f"Failed to register trampoline callback for {func.__name__}")
        return False

    def _on_tramp_hit_hypercall(self, cpu):
        """
        Handles trampoline hit hypercall and invokes the registered callback with pt_regs.
        """
        tramp_id = self.panda.arch.get_arg(cpu, 1, convention="syscall")
        pt_regs_addr = self.panda.arch.get_arg(cpu, 2, convention="syscall")
        if not hasattr(self, '_tramp_callbacks') or tramp_id not in self._tramp_callbacks:
            self.logger.error(f"Trampoline hit for unknown id: {tramp_id}")
            return
        entry = self._tramp_callbacks[tramp_id]
        callback, num_args = entry

        self.logger.debug(f"Invoking trampoline callback for id={tramp_id}: {getattr(callback, '__name__', repr(callback))}")
        pt_regs_raw = yield from self.read_type(pt_regs_addr, "pt_regs")
        pt_regs = get_pt_regs_wrapper(self.panda, pt_regs_raw)
        original_bytes = pt_regs.to_bytes()[:]
        # Get args from pt_regs
        if num_args > 1:
            # Get args from pt_regs
            args = yield from pt_regs.get_args_portal(num_args - 1, convention="userland")
        else:
            args = []
        # Call callback with pt_regs and args
        result = callback(pt_regs, *args)
        if isinstance(result, Iterator):
            result = yield from result
        # If callback returns int, set as return value
        if isinstance(result, int):
            pt_regs.set_retval(result)
        new = pt_regs.to_bytes()
        if original_bytes != new:
            yield from plugins.mem.write_bytes(pt_regs_addr, new)
    
    def write_struct(self, addr: Union[int, Ptr], instance: BoundTypeInstance):
        if isinstance(addr, Ptr):
            addr = addr.address
        
        data = instance.to_bytes()
        yield from plugins.mem.write_bytes(addr, data)

    def string(self, instance: Union[BoundArrayView, BoundTypeInstance, bytes, bytearray]) -> str:
        """
        Extract a string from the buffer at the instance's offset.
        Always returns a best-effort string, never raises.
        """
        try:
            # Raw bytes or bytearray
            if isinstance(instance, (bytes, bytearray)):
                return instance.decode('latin-1', errors='replace').split('\x00', 1)[0]
            # BoundArrayView: get bytes from array elements
            if type(instance).__name__ == "BoundArrayView":
                arr_bytes = bytearray()
                try:
                    for i in range(len(instance)):
                        val = instance[i]
                        if hasattr(val, '_value'):
                            arr_bytes.append(int(val._value))
                        elif isinstance(val, int):
                            arr_bytes.append(val)
                        else:
                            break
                        if arr_bytes[-1] == 0:
                            break
                except Exception:
                    pass
                return arr_bytes.decode('latin-1', errors='replace').split('\x00', 1)[0]
            # BoundTypeInstance: get bytes from buffer at offset, up to size
            if type(instance).__name__ == "BoundTypeInstance":
                buf = getattr(instance, "_instance_buffer", None)
                offset = getattr(instance, "_instance_offset", 0)
                size = getattr(instance._instance_type_def, "size", None)
                if buf is not None and size is not None:
                    raw = buf[offset:offset+size]
                    return raw.decode('latin-1', errors='replace').split('\x00', 1)[0]
                # fallback: try to_bytes
                try:
                    raw = instance.to_bytes()
                    return raw.decode('latin-1', errors='replace').split('\x00', 1)[0]
                except Exception:
                    pass
            # fallback: str()
            return str(instance)
        except Exception:
            return ""
