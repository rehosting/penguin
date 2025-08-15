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
result = yield from plugins.kffi.call_function("do_sys_open", "/etc/passwd", 0, 0)

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
from typing import Any, Optional, Union, Generator, Tuple, Iterator
from wrappers.ptregs_wrap import get_pt_regs_wrapper


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
        self.igloo_ko_isf = realpath(join(kernel, f"../igloo.ko.{arch}.json.xz"))
        self.ffi = VtypeJsonGroup([self.igloo_ko_isf, self.isf])

    def __init_tramp_functionality(self):
        if hasattr(self, 'tramp_init') and self.tramp_init:
            return
        self.tramp_init = True
        # Register trampoline hit hypercall handler
        IGLOO_HYP_TRAMP_HIT = 0x7903  # Update with correct value if needed
        self.portal = plugins.portal
        self._on_tramp_hit_hypercall = self.portal.wrap(self._on_tramp_hit_hypercall)
        self.panda.hypercall(IGLOO_HYP_TRAMP_HIT)(self._on_tramp_hit_hypercall)

        # Register with portal's interrupt handler system
        self.portal.register_interrupt_handler(
            "kffi", self._tramp_interrupt_handler)

    def _fixup_igloo_module_baseaddr(self, addr):
        self.ffi.vtypejsons[self.igloo_ko_isf].shift_symbol_addresses(addr)

    def new(self, type_: str) -> Any:
        """
        ### Create a new instance of a type

        **Args:**
        - `type_` (`str`): Name of the type.

        **Returns:**
        - Instance of the type, or None if type not found.
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
        ### Create an instance of a type from a buffer

        **Args:**
        - `type_` (`str`): Name of the type.
        - `buf` (`bytes`): Buffer containing the data.
        - `instance_offset_in_buffer` (`int`, optional): Offset in buffer (default: 0).

        **Returns:**
        - Instance of the type.
        """
        t = self.ffi.get_type(type_)
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
        ### Read a type from kernel memory

        **Args:**
        - `addr` (`int`): Address to read from.
        - `type_` (`str`): Name of the type.

        **Returns:**
        - Instance of the type, or None if read fails.
        """
        t = self.ffi.get_type(type_)
        if not t:
            return None
        buf = yield from plugins.mem.read_bytes(addr, t.size)
        if not buf:
            self.logger.error(f"Failed to read bytes from {addr:#x}")
            return None
        return self.ffi.create_instance(t, buf)
    
    def write_type(self, addr: int, instance: Any) -> Generator[Any, Any, None]:
        """
        ### Write a type instance to kernel memory
        **Args:**
        - `addr` (`int`): Address to write to.
        - `instance` (`Any`): Instance of the type to write.

        **Returns:**
        - `None`
        """
        if not hasattr(instance, 'to_bytes'):
            self.logger.error(f"Instance {instance} does not have to_bytes method")
            return
        buf = instance.to_bytes()
        if not buf:
            self.logger.error(f"Failed to convert instance {instance} to bytes")
            return
        yield from plugins.mem.write_bytes(addr, buf)

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

    def _prepare_ffi_call(self, func_ptr: int, args: list, func_name: str = None) -> Tuple[bytes, Optional[int], Optional[dict]]:
        """
        ### Prepare FFI call structure for kernel execution, using function signature if available

        **Args:**
        - `func_ptr` (`int`): Address of the kernel function to call.
        - `args` (`list`): List of arguments to pass to the function (max 8).
        - `func_name` (`str`, optional): Name of the function (for signature lookup).

        **Returns:**
        - `bytes`: Serialized portal_ffi_call structure.
        - `int` or None: Kernel memory address if allocated.
        - `dict` or None: Function signature type_info if available.
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

        TODO: This leaks memory. We should have a better policy on that.
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
        ### Allocate memory in the kernel using kmalloc

        **Args:**
        - `size` (`int`): Size of memory to allocate.

        **Returns:**
        - Address of allocated memory, or None if allocation fails.
        """
        val = yield from self.call_kernel_function("igloo_kzalloc", size)
        return val
    
    def copy_obj(self, obj) -> Generator[Any, Any, Any]:
        to_write = obj.to_bytes()
        val = yield from self.kmalloc(len(to_write))
        yield from plugins.mem.write_bytes(val, to_write)
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

    def kallsyms_lookup(self, symbol: str) -> Generator[Any, Any, Any]:
        """
        ### Look up a kernel symbol address using the kallsyms_lookup portal operation (simplified)

        **Args:**
        - `symbol` (`str`): Name of the symbol to look up.

        **Returns:**
        - Address of the symbol as int, or None if not found.
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

    def generate_trampoline(self, count: int = 1) -> Generator[Any, Any, Any]:
        """
        ### Request trampolines from the kernel via portal

        **Args:**
        - `count` (`int`, optional): Number of trampolines to generate (default: 1).

        **Returns:**
        - dict with keys: tramp_id, tramp_addr, status, count, addresses (if count > 1)
        """
        from hyper.portal import PortalCmd
        self.__init_tramp_functionality()
        # Create the trampoline generation request structure
        tramp_req = self.new("portal_tramp_generate")
        tramp_req.count = count
        tramp_req.tramp_id = 0
        tramp_req.tramp_addr = 0
        tramp_req.status = 0
        
        # Calculate size needed for request + address array
        struct_size = len(tramp_req.to_bytes())
        total_size = struct_size + (count * 8)  # 8 bytes per address (unsigned long)
        
        # Create buffer with structure + space for addresses
        request_data = tramp_req.to_bytes() + b'\x00' * (count * 8)
        
        response = yield PortalCmd("tramp_generate", size=total_size, data=request_data)
        if not response:
            self.logger.error("Trampoline generation failed: no response")
            return None
            
        tramp_struct = self.from_buffer("portal_tramp_generate", response)
        result = {
            "tramp_id": tramp_struct.tramp_id,
            "tramp_addr": tramp_struct.tramp_addr,
            "status": tramp_struct.status,
            "count": tramp_struct.count,
        }
        
        # If multiple trampolines were requested, extract the address array
        if count > 1 and tramp_struct.count > 1:
            addresses = []
            addr_data = response[struct_size:]
            for i in range(tramp_struct.count):
                addr_bytes = addr_data[i*8:(i+1)*8]
                if len(addr_bytes) == 8:
                    addr = int.from_bytes(addr_bytes, byteorder='little')
                    addresses.append(addr)
            result["addresses"] = addresses
            
        return result

    def callback(self, func) -> Generator[Any, Any, Any]:
        """
        ### Register a trampoline callback and return the trampoline address

        Immediately generates the trampoline, sets up the interrupt handler, and returns the trampoline address.
        
        **Args:**
        - `func`: The callback function to register
        
        **Returns:**
        - `int`: The trampoline address
        """
        tramp_info = yield from self.generate_trampoline()
        if tramp_info is None or tramp_info.get("status") != 0:
            self.logger.error(f"Failed to generate trampoline for {func.__name__}")
            return None
            
        tramp_id = tramp_info.get("tramp_id")
        tramp_addr = tramp_info.get("tramp_addr")
        self._tramp_callbacks = getattr(self, '_tramp_callbacks', {})
        self._tramp_callbacks[tramp_id] = func
        return tramp_addr

    def callbacks(self, funcs: list) -> Generator[Any, Any, Any]:
        """
        ### Register multiple trampoline callbacks and return their addresses

        Generates multiple trampolines in one call for efficiency.
        
        **Args:**
        - `funcs` (`list`): List of callback functions to register
        
        **Returns:**
        - `list`: List of trampoline addresses corresponding to the input functions
        """
        if not funcs:
            return []
            
        count = len(funcs)
        tramp_info = yield from self.generate_trampoline(count)
        
        if tramp_info is None or tramp_info.get("status") != 0:
            self.logger.error(f"Failed to generate {count} trampolines")
            return [None] * count
            
        self._tramp_callbacks = getattr(self, '_tramp_callbacks', {})
        addresses = []
        
        if count == 1:
            # Single trampoline case
            tramp_id = tramp_info.get("tramp_id")
            tramp_addr = tramp_info.get("tramp_addr")
            self._tramp_callbacks[tramp_id] = funcs[0]
            addresses.append(tramp_addr)
        else:
            # Multiple trampolines case
            tramp_addrs = tramp_info.get("addresses", [])
            base_id = tramp_info.get("tramp_id")
            
            for i, func in enumerate(funcs):
                if i < len(tramp_addrs):
                    tramp_id = base_id + i
                    tramp_addr = tramp_addrs[i]
                    self._tramp_callbacks[tramp_id] = func
                    addresses.append(tramp_addr)
                else:
                    addresses.append(None)
                    
        return addresses
    
    def cb(self, func) -> 'KFFI.Callback':
        """
        ### Alias for callback method

        This is a convenience method to register a trampoline callback.
        """
        return self.callback(func)

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
                self._tramp_callbacks[tramp_id] = func
                self.logger.info(f"Registered trampoline callback {func.__name__} with id={tramp_id} addr={tramp_addr}")
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
        callback = self._tramp_callbacks[tramp_id]
        self.logger.info(f"Invoking trampoline callback for id={tramp_id}: {callback.__name__}")
        try:
            import inspect
            if not hasattr(self, '_callback_signatures'):
                self._callback_signatures = {}
            if callback in self._callback_signatures:
                sig = self._callback_signatures[callback]
            else:
                sig = inspect.signature(callback)
                self._callback_signatures[callback] = sig
            pt_regs_raw = yield from self.read_type(pt_regs_addr, "pt_regs")
            pt_regs = get_pt_regs_wrapper(self.panda, pt_regs_raw)
            original_bytes = pt_regs.to_bytes()[:]
            num_args = len(sig.parameters)
            # Get syscall args from pt_regs
            if num_args > 1:
                syscall_args = yield from pt_regs.get_args_portal(num_args - 1, convention="syscall")
            else:
                syscall_args = []
            result = callback(pt_regs, *syscall_args)
            if isinstance(result, Iterator):
                result = yield from result
            if isinstance(result, int):
                pt_regs.set_retval(result)
            new = pt_regs.to_bytes()
            if original_bytes != new:
                yield from plugins.mem.write_bytes(pt_regs_addr, new)
        except Exception as e:
            self.logger.error(f"Error in trampoline callback {callback.__name__}: {e}")
