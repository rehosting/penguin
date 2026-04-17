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
* Compile and inject dynamic C-structs/typedefs on the fly using DWARFFI.

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

    # Load a custom struct layout into the emulator's architecture
    plugins.kffi.cdef("struct my_payload { int a; char b[10]; };")
"""

import inspect
import hashlib
import os
from os.path import isfile, join, realpath
from pathlib import Path
from typing import Any, Generator, Iterator, Optional, Tuple, Union, Dict

from dwarffi.instances import BoundTypeInstance, Ptr, EnumInstance
from dwarffi.dffi import DFFI
import struct

from wrappers.generic import Wrapper
from wrappers.ptregs_wrap import get_pt_regs_wrapper

from penguin import Plugin, getColoredLogger, plugins
from penguin.abi_info import ARCH_ABI_INFO


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
        self.ffi = DFFI([self.igloo_ko_isf, self.isf])
        self._tramp_callbacks = {}
        self._tramp_addresses = {}
        self.tramp_init = False
        self._is_32bit = self.panda.bits == 32

    def __init_tramp_functionality(self):
        if self.tramp_init:
            return
        self.tramp_init = True
        # Register trampoline hit hypercall handler
        from hyper.consts import igloo_hypercall_constants as iconsts
        self.portal = plugins.portal
        self._on_tramp_hit_hypercall = self.portal.wrap(self._on_tramp_hit_hypercall)
        self.panda.hypercall(iconsts.IGLOO_HYP_TRAMP_HIT)(self._on_tramp_hit_hypercall)

        # Register with portal's interrupt handler system
        self.portal.register_interrupt_handler(
            "kffi", self._tramp_interrupt_handler)

    def cdef(self, source: str) -> None:
        """
        Compile C definitions on the fly and load them into DWARFFI.
        Automatically handles architecture-specific compiler flags, musl headers,
        and caches the ISF output to speed up subsequent runs.

        Args:
            source (str): The C code containing structs/enums/typedefs to compile.
        """
        conf = self.get_arg("conf")
        proj_dir = self.get_arg("proj_dir")

        arch = conf["core"]["arch"]
        arch_info = ARCH_ABI_INFO[arch]
        abi = arch_info.get("default_abi", list(arch_info.get("abis", {}).keys())[0])
        abi_info = arch_info["abis"][abi]

        # Determine caching directory
        if proj_dir:
            cache_dir = Path(proj_dir).resolve() / "qcows" / "cache"
        else:
            cache_dir = Path(os.path.dirname(os.path.abspath(__file__))).resolve() / "qcows" / "cache"

        os.makedirs(cache_dir, exist_ok=True)

        # Hash input for caching
        hash_input = f"{arch}_{abi}_{source}".encode()
        cache_key = hashlib.sha256(hash_input).hexdigest()
        cache_path = cache_dir / f"kffi_cdef_{arch}_{abi}_{cache_key}.json.xz"

        # Check cache
        if cache_path.exists():
            self.logger.debug(f"Loading cached DWARFFI ISF from {cache_path}")
            self.ffi.load_isf(str(cache_path))
            return

        # Build strict cross-compilation flags based on ABI config
        headers_dir = f"/igloo_static/musl-headers/{abi_info['musl_arch_name']}/include"
        target = abi_info.get("target_triple", None) or arch_info["target_triple"]

        compiler_flags = [
            "-O3", "-g", "-gdwarf-4", "-fno-eliminate-unused-debug-types", "-c",
            "-target", target,
            "-isystem", headers_dir,
            "-nostdinc",
        ]

        for key, value in abi_info.get("m_flags", {}).items():
            compiler_flags.append(f"-m{key.replace('_', '-')}={value}")

        compiler_flags.extend(abi_info.get("extra_flags", []))

        self.logger.info(
            f"Compiling cdef for {arch} {abi}. Caching to {cache_path.name}")

        # Delegate to DFFI to invoke clang -> dwarf2json -> load -> cache
        try:
            self.ffi.cdef(
                source=source,
                compiler="clang-20",
                compiler_flags=compiler_flags,
                save_isf_to=str(cache_path)
            )
        except Exception as e:
            self.logger.error(f"Failed to compile and load cdef: {e}")
            raise

    def new(self, type_: str, init: Any = None) -> Any:
        """
        Create a new instance of a type.

        Args:
            type_ (str): Name of the type.
            init (Any): Initial value for the instance (optional).

        Returns:
            Any: Instance of the type, or None if type not found.
        """
        try:
            return self.ffi.new(type_, init)
        except (KeyError, ValueError):
            return None

    def from_buffer(self, type_: str, buf: bytes, instance_offset_in_buffer: int = 0) -> Any:
        """
        Create an instance of a type from a buffer.

        Args:
            type_ (str): Name of the type.
            buf (bytes): Buffer containing the data.
            instance_offset_in_buffer (int): Offset in buffer (default: 0).

        Returns:
            Any: Instance of the type.
        """
        """Create an instance of a type from a buffer."""
        # Ensure we pass a bytearray to dwarffi
        return self.ffi.from_buffer(type_, bytearray(buf), offset=instance_offset_in_buffer)

    def get_field_casted(self, struct: Any, field: str) -> Any:
        """
        Get a field from a struct, casted to its declared CFFI type.

        Args:
            struct (Any): Struct instance.
            field (str): Field name.
        Returns:
            Any: Field value, or None if error occurs.
        """
        try:
            return self.ffi.cast(struct._instance_type_def.fields[field].type_info["name"], getattr(struct, field))
        except Exception as e:
            self.logger.error(f"Error casting field {field} of struct {struct}: {e}")
            return None

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
        size = self.ffi.sizeof(type_)
        if not size:
            return None
        buf = plugins.mem.read_bytes_panda(cpu, addr, size)
        if not buf:
            self.logger.error(f"Failed to read bytes from {addr:#x}")
            return None
        return self.ffi.from_buffer(type_, bytearray(buf), address=addr)

    def read_type(self, addr: int, type_: str) -> Generator[Any, Any, Any]:
        """
        Read a type from kernel memory.

        Args:
            addr (int): Address to read from.
            type_ (str): Name of the type.

        Returns:
            Any: Instance of the type, or None if read fails.
        """
        size = self.ffi.sizeof(type_)
        if not size:
            return None
        if isinstance(addr, Ptr):
            addr = addr.address
        buf = yield from plugins.mem.read_bytes(addr, size)
        if not buf:
            self.logger.error(f"Failed to read bytes from {addr:#x}")
            return None
        instance = self.ffi.from_buffer(type_, buf, address=addr)
        return instance

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
        val = yield from self.read_type(ptr.address, ptr.points_to_type_name)
        return val

    def ref(self, thing: Any) -> Optional[int]:
        """
        Gets the address of an ffi type'd object (usually a struct)

        Args:
            thing (Any): Object.

        Returns:
            int: The address, or None if no address attribute.
        """
        return self.ffi.addressof(thing)

    def get_enum_dict(self, enum_name: str) -> Wrapper:
        """
        Get dictionary of enum constants.

        Args:
            enum_name (str): Name of the enum.

        Returns:
            Wrapper: Wrapper containing enum constants.
        """
        enum = self.ffi.get_type(enum_name)
        if not enum or not hasattr(enum, "constants"):
            self.logger.error(f"Enum {enum_name} not found in ISF")
            return {}
        return Wrapper(enum.constants)

    def get_struct_size(self, struct_name: str) -> Optional[int]:
        """
        Get the size of a struct.

        Args:
            struct_name (str): Name of the struct.

        Returns:
            Optional[int]: Size of the struct, or None if not found.
        """
        try:
            return self.ffi.sizeof(struct_name)
        except (KeyError, ValueError):
            return None

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
        sym = self.ffi.get_symbol(function, path=self.igloo_ko_isf)
        if sym and hasattr(sym, "address") and sym.address not in [None, 0]:
            return sym.address
        sym = self.ffi.get_symbol(function, path=self.isf)
        if sym and hasattr(sym, "address") and sym.address not in [None, 0]:
            return sym.address
        return None

    def _fixup_igloo_module_baseaddr(self, addr):
        self.ffi.vtypejsons[self.igloo_ko_isf].shift_symbol_addresses(addr)

    def _prepare_ffi_call(self, func_ptr: int, args: list, func_name: str = None) -> Generator[Tuple[bytes, Optional[int], Optional[dict], bool], Any, Any]:
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

        # Helper to extract the raw dictionary from dwarffi objects
        def get_t_dict(p):
            if hasattr(p, "type_info"): return p.type_info
            if isinstance(p, dict): return p.get("type", p)
            return p

        # Helper to recursively identify 64-bit types
        def is_type_64bit(t_info):
            t_info = get_t_dict(t_info)
            if not isinstance(t_info, dict): return False
            if t_info.get("kind") == "pointer": return False
            if t_info.get("size") == 8: return True
            
            name = t_info.get("name", "")
            if name:
                nl = name.lower()
                if any(x in nl for x in ["long long", "int64", "u64", "uint64"]): 
                    return True
                try:
                    t_def = self.ffi.get_type(name)
                    if t_def and getattr(t_def, "size", 0) == 8: 
                        return True
                except Exception: 
                    pass
            return False

        # 1. Lookup function signature prioritizing the new dwarffi get_function mapping
        func_info = None
        if func_name:
            func_obj = self.ffi.get_function(func_name)
            if func_obj:
                func_info = {
                    "return_type": get_t_dict(getattr(func_obj, "return_type", None)),
                    "parameters": [get_t_dict(p) for p in getattr(func_obj, "parameters", [])]
                }
            else:
                sym = self.ffi.get_symbol(func_name)
                if sym and hasattr(sym, "type_info") and isinstance(sym.type_info, dict):
                    if sym.type_info.get("kind") == "function":
                        func_info = {
                            "return_type": get_t_dict(sym.type_info.get("return_type")),
                            "parameters": [get_t_dict(p) for p in sym.type_info.get("parameters", [])]
                        }
                
        if len(args) > 8:
            raise ValueError(f"Too many arguments for FFI call: {len(args)} > 8")
            
        # UNIVERSAL UNWRAP: Automatically extract the integer address from any Ptr objects
        args = [arg.address if isinstance(arg, Ptr) else arg for arg in args]
        
        marshalled_args = []
        if func_info and "parameters" in func_info:
            params = func_info["parameters"]
            for i, arg in enumerate(args):
                if i < len(params):
                    param_type = params[i]
                    if isinstance(param_type, dict):
                        kind = param_type.get("kind")
                        if kind == "pointer":
                            if not isinstance(arg, (int, str, bytes, BoundTypeInstance)) and not hasattr(arg, '__bytes__'): 
                                raise TypeError(f"Argument {i} expected pointer/int/str/bytes/struct, got {type(arg)}")
                        elif kind == "base" and param_type.get("name") in ("char", "unsigned char"):
                            if isinstance(arg, str): arg = arg.encode() + b"\x00"
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
            elif isinstance(arg, BoundTypeInstance):
                base_addr = getattr(arg, "_base_address", None)
                if base_addr is None:
                    to_write = bytes(arg)
                    raw_addr = yield from self.kmalloc(len(to_write) + 64)
                    if not raw_addr:
                        raise RuntimeError("Failed to allocate kernel memory for BoundTypeInstance")
                    aligned_addr = (raw_addr + 63) & ~63
                    yield from plugins.mem.write_bytes(aligned_addr, to_write)
                    boundtype_ptrs[i] = aligned_addr
                else:
                    boundtype_ptrs[i] = self.ffi.addressof(arg).address
            elif hasattr(arg, '__bytes__'):
                b = bytes(arg)
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
        
        sig_mask = (len(marshalled_args) << 8)
        
        is_64bit_return = getattr(self.panda, "bits", 64) == 64
        if not is_64bit_return and func_info and "return_type" in func_info:
            is_64bit_return = is_type_64bit(func_info["return_type"])

        for i, arg in enumerate(marshalled_args):
            is_64bit = False
            
            if func_info and "parameters" in func_info and i < len(func_info["parameters"]):
                is_64bit = is_type_64bit(func_info["parameters"][i])

            # Python-side fallback: Force 64-bit if value requires it
            if not is_64bit and isinstance(arg, int) and (arg > 0xFFFFFFFF or arg < -0x80000000):
                is_64bit = True

            if is_64bit:
                sig_mask |= (1 << i)

            if isinstance(arg, float):
                ffi_call.args[i] = struct.unpack('<Q', struct.pack('<d', arg))[0] & 0xFFFFFFFFFFFFFFFF
            elif isinstance(arg, BoundTypeInstance):
                # FIX: Check for BoundTypeInstance BEFORE checking for __bytes__
                ffi_call.args[i] = boundtype_ptrs[i] & 0xFFFFFFFFFFFFFFFF
            elif isinstance(arg, int) or hasattr(arg, '_value'):
                ffi_call.args[i] = int(arg) & 0xFFFFFFFFFFFFFFFF
            elif isinstance(arg, (str, bytes)) or hasattr(arg, '__bytes__'):
                for idx, off, sz in arg_ptr_indices:
                    if idx == i:
                        ffi_call.args[i] = (kmem_addr + off) & 0xFFFFFFFFFFFFFFFF
                        break
            else:
                raise TypeError(f"Unsupported argument type for FFI assignment: {type(arg)}")

        ffi_call.sig_mask = sig_mask

        return bytes(ffi_call), kmem_addr, func_info, is_64bit_return


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
        buf, optsbuf, func_info, is_64bit_return = yield from self._prepare_ffi_call(func_ptr, args, func_name)

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
        if self._is_32bit and not is_64bit_return:
            result = result & 0xFFFFFFFF
            
        if func_info and "return_type" in func_info:
            ret_type = func_info["return_type"]
            if isinstance(ret_type, dict):
                kind = ret_type.get("kind")
                name = ret_type.get("name")
                if kind == "base":
                    base_type = self.ffi.get_type(name)
                    if base_type:
                        # Unsigned fixup
                        if base_type.signed is False and result < 0:
                            result = result % (1 << (base_type.size * 8))
                        # Convert to correct Python type
                        if base_type.kind in ("int", "pointer"):
                            result = int(result)
                        elif base_type.kind == "float":
                            result = float(result)
                        elif base_type.kind == "bool":
                            result = bool(result)
                elif kind == "enum":
                    try:
                        enum_def = self.ffi.get_enum(name)
                        if enum_def:
                            result = EnumInstance(enum_def, result)._value
                    except Exception as e:
                        self.logger.warning(f"Failed to cast return value to enum {name}: {e}")
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

    def kmalloc(self, size: Union[int, Ptr]) -> Generator[Any, Any, Any]:
        """
        Allocate memory in the kernel using ``kmalloc``.

        Args:
            size (Union[int, Ptr]): Size of memory to allocate.

        Returns:
            Any: Address of allocated memory, or None if allocation fails.
        """
        val = yield from self.call_kernel_function("igloo_kzalloc", size)
        
        # Unwrap the pointer object so math (kmem_addr + offset) works correctly
        if isinstance(val, Ptr):
            return val.address
            
        return val

    def kfree(self, addr: Union[int, Ptr]) -> Generator[Any, Any, Any]:
        """
        Free memory in the kernel using ``kfree``.

        Args:
            addr (Union[int, Ptr]): Address of memory to free.

        Returns:
            None
        """
        # Unwrap the pointer object so math (kmem_addr + offset) works correctly
        if isinstance(addr, Ptr):
            addr = addr.address
            
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

    def callback(self, func, func_type: Optional[Dict] = None) -> Generator[Any, Any, Any]:
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
        
        # Save the func_type into our callbacks lookup table
        self._tramp_callbacks[tramp_id] = (func, num_args, func_type)
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
        pending_tramp_callbacks = self._pending_tramp_callbacks[:]
        self._pending_tramp_callbacks = []
        while pending_tramp_callbacks:
            item = pending_tramp_callbacks.pop(0)
            
            # Safely unpack in case older plugins append just the function
            if isinstance(item, tuple) and len(item) == 2:
                func, func_type = item
            else:
                func = item
                func_type = None
                
            tramp_info = yield from self.generate_trampoline()
            tramp_id = tramp_info.get("tramp_id")
            tramp_addr = tramp_info.get("tramp_addr")
            tramp_status = tramp_info.get("status")
            if tramp_id is not None and tramp_addr is not None:
                num_args = len(inspect.signature(func).parameters)
                self._tramp_callbacks[tramp_id] = (func, num_args, func_type)
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
        if len(entry) == 3:
            callback, num_args, func_type = entry
        else:
            callback, num_args = entry
            func_type = None

        self.logger.debug(f"Invoking trampoline callback for id={tramp_id}: {getattr(callback, '__name__', repr(callback))}")
        try:
            pt_regs_raw = yield from self.read_type(pt_regs_addr, "pt_regs")
            
            # INJECT Context Dictionary Here
            pt_regs = get_pt_regs_wrapper(
                self.panda, 
                pt_regs_raw, 
                extra_context={"func_type": func_type}
            )
            
            original_bytes = pt_regs.to_bytes()[:]
            # Get args from pt_regs
            if num_args > 1:
                # No longer need to explicitly pass func_type since it's in the extra_context
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

        except Exception as e:
            self.logger.error(f"Error in trampoline callback {callback.__name__}: {e}")

    def write_field(self, addr: int, type_: str, field: str, val: Any) -> Generator[Any, Any, None]:
        """
        Write a single field of a struct in kernel memory.
        Automatically handles offsets, endianness, and bitfield masking.
        """
        struct_def = self.ffi.get_type(type_)
        if not struct_def or not hasattr(struct_def, 'fields') or field not in struct_def.fields:
            raise ValueError(f"Invalid field '{field}' for type '{type_}'")
            
        field_info = struct_def.fields[field]
        offset = field_info.offset
        size = field_info.size
        
        # Read the current memory for this field's width to safely handle bitfields
        existing_bytes = yield from plugins.mem.read_bytes(addr + offset, size)
        if not existing_bytes:
            raise RuntimeError(f"Failed to read memory at {addr + offset:#x}")
            
        # Embed it into a dummy bytearray buffer of the full struct size
        dummy_buf = bytearray(self.ffi.sizeof(type_))
        dummy_buf[offset:offset+size] = existing_bytes
        
        # Parse it with dwarffi and modify the field (this triggers the packing logic)
        dummy = self.ffi.from_buffer(type_, dummy_buf)
        setattr(dummy, field, val)
        
        # Extract the newly packed bytes and write them back to memory
        new_bytes = dummy_buf[offset:offset+size]
        if existing_bytes != new_bytes:
            yield from plugins.mem.write_bytes(addr + offset, new_bytes)

    def read_field(self, addr: int, type_: str, field: str) -> Generator[Any, Any, Any]:
        """
        Read a single field of a struct from kernel memory.
        """
        struct_def = self.ffi.get_type(type_)
        if not struct_def or not hasattr(struct_def, 'fields') or field not in struct_def.fields:
            raise ValueError(f"Invalid field '{field}' for type '{type_}'")
            
        field_info = struct_def.fields[field]
        offset = field_info.offset
        size = field_info.size
        
        raw_bytes = yield from plugins.mem.read_bytes(addr + offset, size)
        if not raw_bytes:
            raise RuntimeError(f"Failed to read memory at {addr + offset:#x}")
            
        dummy_buf = bytearray(self.ffi.sizeof(type_))
        dummy_buf[offset:offset+size] = raw_bytes
        
        dummy = self.ffi.from_buffer(type_, dummy_buf, address=addr)
        return getattr(dummy, field)