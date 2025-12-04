"""
ptregs_wrap.py - Architecture-agnostic wrappers for Linux pt_regs structures
===========================================================================

This module provides Pythonic, type-annotated wrappers for Linux kernel pt_regs structures across multiple CPU architectures. It enables convenient, architecture-independent access to process register state, such as that captured at system call entry/exit, exceptions, or context switches. The wrappers abstract away the raw struct layout and provide a unified interface for reading/writing registers, extracting syscall arguments, and handling calling conventions.

Overview
--------

The module defines a base PtRegsWrapper class and a set of subclasses for each supported architecture (x86, x86_64, ARM, AArch64, MIPS, PowerPC, LoongArch64, RISC-V, etc). Each subclass knows how to access registers and arguments according to its architecture's ABI and pt_regs layout. The wrappers can be used with PANDA or other emulation/analysis frameworks that expose pt_regs-like objects.

The module also provides a get_pt_regs_wrapper() factory function to select the correct wrapper for a given architecture.

Typical Usage
-------------

Suppose you have a PANDA plugin or other tool that provides a pt_regs struct (e.g., at a syscall, exception, or context switch):

.. code-block:: python

    from wrappers.ptregs_wrap import get_pt_regs_wrapper
    # Assume 'regs' is a pt_regs struct and 'panda' is a PANDA object
    wrapper = get_pt_regs_wrapper(panda, regs, arch_name=panda.arch_name)

    # Access registers in an architecture-agnostic way
    pc = wrapper.get_pc()
    sp = wrapper.get_sp()
    retval = wrapper.get_retval()

    # Get syscall arguments (handles calling convention automatically)
    arg0 = wrapper.get_syscall_arg(0)
    arg1 = wrapper.get_syscall_arg(1)
    # Or get userland function arguments
    user_arg0 = wrapper.get_userland_arg(0)

    # Dump all registers as a dictionary
    reg_dict = wrapper.dump()

    # Coroutine-style argument access (portal):
    # get_args_portal and get_arg_portal are generator-based and can yield if a memory read is required (e.g., stack argument).
    # Use 'yield from' to drive these coroutines in a portal/coroutine context.
    args = yield from wrapper.get_args_portal(3)

The wrappers also support advanced features such as handling 32-bit compatibility mode on x86_64/AArch64, stack argument extraction, and portal-style coroutine memory reads. The get_args_portal and get_arg_portal methods are generator-based and will yield if a memory read is required (such as when reading stack arguments may fail and need to be retried or handled asynchronously).

Classes
-------

- PtRegsWrapper: Base class for all pt_regs wrappers, provides generic register access and argument extraction.
- X86PtRegsWrapper, X86_64PtRegsWrapper, ArmPtRegsWrapper, ...: Architecture-specific subclasses.
- PandaMemReadFail: Exception for failed memory reads (for portal/coroutine use).

Functions
---------

- get_pt_regs_wrapper(panda: Optional[Any], regs: Any, arch_name: Optional[str] = None) -> PtRegsWrapper: Factory to select the correct wrapper for a given architecture.

These wrappers are useful for dynamic analysis, syscall tracing, emulation, and any tool that needs to reason about process register state in a cross-architecture way.
"""

from wrappers.generic import Wrapper
import struct
from penguin import plugins
from typing import Any, Dict, List, Optional, Union, Generator


class PandaMemReadFail(Exception):
    """
    Exception for failed memory reads, used for portal/coroutine use-cases.

    Attributes:
        addr (int): The address that failed to read.
        size (int): The size of the attempted read.
    """

    def __init__(self, addr: int, size: int) -> None:
        super().__init__(f"Failed to read {size} bytes from address {addr}")
        self.addr: int = addr
        self.size: int = size

# --- Helper Factories for Fast Accessors ---
# These helper functions create optimized lambda closures to avoid string parsing
# and attribute lookup overhead at runtime.


def _make_attr_getter(attr):
    return lambda obj: getattr(obj, attr)


def _make_attr_setter(attr):
    return lambda obj, val: setattr(obj, attr, val)


def _make_array_getter(attr, idx):
    return lambda obj: getattr(obj, attr)[idx]


def _make_array_setter(attr, idx):
    return lambda obj, val: getattr(obj, attr).__setitem__(idx, val)


class PtRegsWrapper(Wrapper):
    """
    Base class for pt_regs wrappers across different architectures.

    Args:
        obj: The pt_regs structure to wrap.
        panda: Optional PANDA object for memory reading.
    """
    # Optimization: Use slots for fast attribute access
    __slots__ = ('_panda', '_obj')

    # Class-level cache for accessors. Subclasses must populate this.
    # Format: { "reg_name": (getter_func, setter_func) }
    _ACCESSORS: Dict[str, Any] = {}

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        # Bypass Wrapper.__init__ overhead if it just sets _obj
        object.__setattr__(self, '_obj', obj)
        object.__setattr__(self, '_extra_attrs', {})
        object.__setattr__(self, '_is_dict', False)  # pt_regs is never a dict
        self._panda = panda

    def get_register(self, reg_name: str) -> Optional[int]:
        """Get register value by name (Optimized)."""
        # Fast path: Dictionary lookup + Direct Call
        entry = self._ACCESSORS.get(reg_name)
        if entry:
            return entry[0](self._obj)
        return None

    def set_register(self, reg_name: str, value: int) -> bool:
        """Set register value by name (Optimized)."""
        entry = self._ACCESSORS.get(reg_name)
        if entry:
            entry[1](self._obj, value)
            return True
        return False

    def to_bytes(self):
        """Pass-through to underlying bound object for serialization."""
        return self._obj.to_bytes()

    # --- Standard Accessors (Proxied via get_register for simplicity) ---

    def get_pc(self) -> Optional[int]:
        """Get program counter."""
        return self.get_register("pc")

    def set_pc(self, value: int) -> None:
        """Set program counter."""
        self.set_register("pc", value)

    def get_sp(self) -> Optional[int]:
        """Get stack pointer."""
        return self.get_register("sp")

    def get_return_value(self) -> Optional[int]:
        """Get return value (typically in a0/r0/rax)."""
        return self.get_register("retval")

    def get_retval(self) -> Optional[int]:
        """Get return value (alias for get_return_value)."""
        return self.get_return_value()

    def set_retval(self, value: int) -> None:
        """Set the return value (typically in a0/r0/rax)."""
        self.set_register("retval", value)

    def dump(self) -> Dict[str, Optional[int]]:
        """Dump all registers to a dictionary."""
        result = {}
        for reg_name, (getter, _) in self._ACCESSORS.items():
            result[reg_name] = getter(self._obj)
        return result

    def get_args(self, count: int, convention: Optional[str] = None) -> List[Optional[int]]:
        """
        Get a list of function arguments according to the calling convention.

        Args:
            count: Number of arguments to retrieve.
            convention: Calling convention ('syscall' or 'userland').

        Returns:
            List of argument values (may include None if unavailable).
        """
        return [self.get_arg(i, convention) for i in range(count)]

    def get_arg(self, num: int, convention: Optional[str] = None) -> Optional[int]:
        """
        Get function argument based on calling convention.

        Args:
            num: Argument number (0-based)
            convention: Calling convention ('syscall' or 'userland')

        Returns:
            The value of the requested argument
        """
        # Default implementation delegates to architecture-specific functions
        try:
            if convention == "syscall":
                return self.get_syscall_arg(num)
            else:
                return self.get_userland_arg(num)
        except PandaMemReadFail:
            return None

    def get_args_portal(self, count: int, convention: Optional[str] = None) -> Generator[Optional[int], Any, List[Optional[int]]]:
        """
        Coroutine/generator version of get_args for portal/coroutine use.

        Args:
            count: Number of arguments to retrieve.
            convention: Calling convention ('syscall' or 'userland').

        Returns:
            List of argument values (may include None if unavailable).
        """
        arr = []
        for i in range(count):
            arr.append((yield from self.get_arg_portal(i, convention)))
        return arr

    def get_arg_portal(self, num: int, convention: Optional[str] = None) -> Generator[Optional[int], Any, Optional[int]]:
        """
        Coroutine/generator version of get_arg for portal/coroutine use.

        Args:
            num: Argument number (0-based)
            convention: Calling convention ('syscall' or 'userland')

        Returns:
            The value of the requested argument (or None if unavailable).
        """
        try:
            if convention == "syscall":
                return self.get_syscall_arg(num)
            else:
                return self.get_userland_arg(num)
        except PandaMemReadFail as e:
            if e.size == 4:
                val = yield from plugins.mem.read_int(e.addr)
            else:
                val = yield from plugins.mem.read_long(e.addr)
            return val

    def _read_memory(self, addr: int, size: int, fmt: str = 'int') -> Union[int, bytes, str]:
        """
        Read memory from guest using PANDA's virtual_memory_read (Optimized).

        Args:
            addr: Address to read from.
            size: Size to read (1, 2, 4, 8).
            fmt: Format to return ('int', 'ptr', 'bytes', 'str').

        Returns:
            The memory value in the requested format.

        Raises:
            ValueError: If PANDA reference or CPU is unavailable.
            PandaMemReadFail: If memory read fails.
        """
        if not self._panda:
            raise ValueError("Cannot read memory: no PANDA reference available")

        cpu = plugins.cas.get_cpu()
        if not cpu:
            raise ValueError("Cannot read memory: failed to get CPU")

        try:
            data = plugins.mem.read_bytes_panda(cpu, addr, size)
            if fmt == 'bytes':
                return data
            elif fmt == 'str':
                return data.decode('latin-1', errors='replace')

            # Use the correct endianness format based on the architecture
            endian_fmt = '>' if hasattr(self._panda, 'endianness') and self._panda.endianness == 'big' else '<'

            if fmt == 'int' or fmt == 'ptr':
                # Fast path struct unpacking
                if size == 4:
                    return struct.unpack(endian_fmt + 'I', data)[0]
                elif size == 8:
                    return struct.unpack(endian_fmt + 'Q', data)[0]
                elif size == 1:
                    return struct.unpack(endian_fmt + 'B', data)[0]
                elif size == 2:
                    return struct.unpack(endian_fmt + 'H', data)[0]
            return struct.unpack(endian_fmt + ('I' if size == 4 else 'Q'), data)[0]
        except ValueError:  # This is what PANDA's virtual_memory_read raises on failure
            raise PandaMemReadFail(addr, size)

    def read_stack_arg(self, arg_num: int, word_size: Optional[int] = None) -> Optional[int]:
        """
        Read a function argument from the stack.

        Args:
            arg_num: Argument number (0-based).
            word_size: Word size override (default: based on architecture).

        Returns:
            The argument value read from the stack.
        """
        if not self._panda:
            raise ValueError(
                "Cannot read stack args: no PANDA reference available")

        # Default word size based on architecture
        if word_size is None:
            word_size = 4 if self._panda.bits == 32 else 8

        # Get stack pointer
        sp = self.get_sp()
        if sp is None:
            return None

        # For most architectures, args start after saved return address
        # So typically: sp + word_size + (arg_num * word_size)
        addr = sp + word_size + (arg_num * word_size)

        # Read the value
        return self._read_memory(addr, word_size, 'ptr')

    def get_syscall_arg(self, num: int) -> Optional[int]:
        """Get syscall argument. Subclasses must implement."""
        return None

    def get_userland_arg(self, num: int) -> Optional[int]:
        """Get userland argument. Subclasses must implement."""
        return None

    def get_syscall_number(self) -> Optional[int]:
        """Get syscall number. Subclasses must implement."""
        return None


class X86PtRegsWrapper(PtRegsWrapper):
    """Wrapper for x86 (32-bit) pt_regs"""

    _ACCESSORS = {
        "eax": (_make_attr_getter("ax"), _make_attr_setter("ax")),
        "ebx": (_make_attr_getter("bx"), _make_attr_setter("bx")),
        "ecx": (_make_attr_getter("cx"), _make_attr_setter("cx")),
        "edx": (_make_attr_getter("dx"), _make_attr_setter("dx")),
        "esi": (_make_attr_getter("si"), _make_attr_setter("si")),
        "edi": (_make_attr_getter("di"), _make_attr_setter("di")),
        "ebp": (_make_attr_getter("bp"), _make_attr_setter("bp")),
        "esp": (_make_attr_getter("sp"), _make_attr_setter("sp")),
        "eip": (_make_attr_getter("ip"), _make_attr_setter("ip")),
        "orig_eax": (_make_attr_getter("orig_ax"), _make_attr_setter("orig_ax")),
        "eflags": (_make_attr_getter("flags"), _make_attr_setter("flags")),
        "cs": (_make_attr_getter("cs"), _make_attr_setter("cs")),
        "ds": (_make_attr_getter("ds"), _make_attr_setter("ds")),
        "ss": (_make_attr_getter("ss"), _make_attr_setter("ss")),
        "es": (_make_attr_getter("fs"), _make_attr_setter("fs")),  # Note fs map
        "gs": (_make_attr_getter("gs"), _make_attr_setter("gs")),
        # Aliases
        "pc": (_make_attr_getter("ip"), _make_attr_setter("ip")),
        "sp": (_make_attr_getter("sp"), _make_attr_setter("sp")),
        "retval": (_make_attr_getter("ax"), _make_attr_setter("ax")),
    }

    def get_syscall_arg(self, num: int) -> Optional[int]:
        """Get x86 syscall argument"""
        if num == 0:
            return self.get_register("ebx")
        if num == 1:
            return self.get_register("ecx")
        if num == 2:
            return self.get_register("edx")
        if num == 3:
            return self.get_register("esi")
        if num == 4:
            return self.get_register("edi")
        if num == 5:
            return self.get_register("ebp")
        return None

    def get_userland_arg(self, num: int) -> Optional[int]:
        """Get x86 userland argument from stack"""
        # For x86, arguments are on the stack at esp+4, esp+8, etc.
        sp = self.get_sp()
        if sp is not None:
            # For x86, first arg is at sp+4 (after return address)
            addr = sp + 4 + (num * 4)
            return self._read_memory(addr, 4, 'ptr')
        return None

    def get_syscall_number(self) -> Optional[int]:
        """Get syscall number from EAX register"""
        return self.get_register("orig_eax")


class X86_64PtRegsWrapper(PtRegsWrapper):
    """Wrapper for x86_64 pt_regs"""
    # Pre-compute accessors for 64-bit regs
    _ACCESSORS = {
        name: (_make_attr_getter(name), _make_attr_setter(name))
        for name in ["r15", "r14", "r13", "r12", "r11", "r10", "r9", "r8", "cs", "ss"]
    }
    # Map struct names to canonical names
    _MAPPINGS = {
        "rbp": "bp", "rbx": "bx", "rax": "ax", "rcx": "cx", "rdx": "dx",
        "rsi": "si", "rdi": "di", "orig_rax": "orig_ax", "rip": "ip",
        "eflags": "flags", "rsp": "sp"
    }
    for k, v in _MAPPINGS.items():
        _ACCESSORS[k] = (_make_attr_getter(v), _make_attr_setter(v))

    # Aliases
    _ACCESSORS["pc"] = _ACCESSORS["rip"]
    _ACCESSORS["sp"] = _ACCESSORS["rsp"]
    _ACCESSORS["retval"] = _ACCESSORS["rax"]

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        super().__init__(obj, panda=panda)
        # Create a delegate for x86 (32-bit) mode access (but don't initialize it yet)
        self._x86_delegate = None
        # Flag to prevent recursion in _is_compatibility_mode
        self._checking_mode = False

    def _get_x86_delegate(self) -> 'X86PtRegsWrapper':
        """
        Get or create an X86PtRegsWrapper delegate for 32-bit compatibility mode access.
        """
        if self._x86_delegate is None:
            self._x86_delegate = X86PtRegsWrapper(self._obj, panda=self._panda)
        return self._x86_delegate

    def _is_compatibility_mode(self) -> bool:
        """
        Check if the CPU is running in 32-bit compatibility mode
        based on the code segment (CS) register value.

        In 64-bit mode, CS is typically 0x33 for user-space and 0x10 for kernel-space.
        In 32-bit compatibility mode, it's typically 0x23 for user-space.
        This check is a heuristic based on these common values.
        """
        # Prevent recursion
        if self._checking_mode:
            return False

        self._checking_mode = True
        try:
            # Check if the cs field is actually available in the structure
            if hasattr(self._obj, "cs"):
                # Heuristic: 64-bit user mode CS is 0x33. 64-bit kernel is 0x10.
                # If it's not one of these, we assume it's compatibility mode (e.g., 0x23).
                return self._obj.cs not in [0x33, 0x10]

            # Fallback to using flags register if cs isn't directly accessible
            elif hasattr(self._obj, "flags"):
                # Check for VM86 mode flag in EFLAGS
                return (self._obj.flags & (1 << 17)) != 0

            # Default: assume not in compatibility mode if we can't determine
            return False
        finally:
            self._checking_mode = False

    def get_register(self, reg_name: str) -> Optional[int]:
        # Handle compatibility mode dispatch logic
        if not self._checking_mode and self._is_compatibility_mode():
            if reg_name in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]:
                return self._get_x86_delegate().get_register(reg_name)

        # 32-bit partial access optimization
        if reg_name.startswith("e") and len(reg_name) == 3:
            r64_name = "r" + reg_name[1:]
            entry = self._ACCESSORS.get(r64_name)
            if entry:
                return entry[0](self._obj) & 0xFFFFFFFF

        return super().get_register(reg_name)

    def set_register(self, reg_name: str, value: int) -> bool:
        # For compatibility mode, consider delegating to x86 wrapper
        if self._is_compatibility_mode() and reg_name in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]:
            return self._get_x86_delegate().set_register(reg_name, value)

        # Handle basic 32-bit registers for non-compatibility mode
        if reg_name.startswith("e") and len(reg_name) == 3:
            # For setting e-registers in 64-bit mode, we need to preserve upper 32 bits
            r64_name = "r" + reg_name[1:]
            entry = self._ACCESSORS.get(r64_name)
            if entry:
                current = entry[0](self._obj) & 0xFFFFFFFF00000000
                # Get current 64-bit value, clear lower 32 bits, add new 32-bit value
                new_value = current | (value & 0xFFFFFFFF)
                entry[1](self._obj, new_value)
                return True

        return super().set_register(reg_name, value)

    def get_syscall_arg(self, num: int) -> Optional[int]:
        """Get x86_64 syscall argument, considering compatibility mode"""
        if self._is_compatibility_mode():
            return self._get_x86_delegate().get_syscall_arg(num)

        # rdi, rsi, rdx, r10, r8, r9
        if num == 0:
            return self.get_register("rdi")
        if num == 1:
            return self.get_register("rsi")
        if num == 2:
            return self.get_register("rdx")
        if num == 3:
            return self.get_register("r10")
        if num == 4:
            return self.get_register("r8")
        if num == 5:
            return self.get_register("r9")
        return None

    def get_userland_arg(self, num: int) -> Optional[int]:
        """Get x86_64 userland argument, considering compatibility mode"""
        if self._is_compatibility_mode():
            # In 32-bit compatibility mode, use x86 userland convention (stack-based)
            return self._get_x86_delegate().get_userland_arg(num)

        # Default x86_64 userland convention
        # rdi, rsi, rdx, rcx, r8, r9
        if num == 0:
            return self.get_register("rdi")
        if num == 1:
            return self.get_register("rsi")
        if num == 2:
            return self.get_register("rdx")
        if num == 3:
            return self.get_register("rcx")
        if num == 4:
            return self.get_register("r8")
        if num == 5:
            return self.get_register("r9")
        # For arguments beyond the registers, read from the stack
        # In x86_64, the standard calling convention places additional args on the stack
        sp = self.get_sp()
        if sp is None:
            return None
        # Stack args start at offset 8 (after 6 regs * 8 bytes? No, SysV is 6 regs, then stack)
        stack_idx = num - 6
        addr = sp + 8 + (stack_idx * 8)
        return self._read_memory(addr, 8, 'ptr')

    def get_syscall_number(self) -> Optional[int]:
        """
        Get syscall number, considering compatibility mode.
        In x86_64, the syscall number is in orig_rax.
        In compatibility mode, use x86 implementation.
        """
        if self._is_compatibility_mode():
            return self._get_x86_delegate().get_syscall_number()
        return self.get_register("orig_rax")


class ArmPtRegsWrapper(PtRegsWrapper):
    """Wrapper for ARM pt_regs"""

    # Pre-calculate accessors for uregs array
    _ACCESSORS = {
        f"r{i}": (_make_array_getter("uregs", i), _make_array_setter("uregs", i))
        for i in range(13)
    }
    _ACCESSORS.update({
        "sp": (_make_array_getter("uregs", 13), _make_array_setter("uregs", 13)),
        "lr": (_make_array_getter("uregs", 14), _make_array_setter("uregs", 14)),
        "pc": (_make_array_getter("uregs", 15), _make_array_setter("uregs", 15)),
        "cpsr": (_make_array_getter("uregs", 16), _make_array_setter("uregs", 16)),
        "orig_r0": (_make_array_getter("uregs", 17), _make_array_setter("uregs", 17)),
    })
    _ACCESSORS["retval"] = _ACCESSORS["r0"]

    def get_syscall_arg(self, num: int) -> Optional[int]:
        """Get ARM syscall argument"""
        if 0 <= num < 7:  # r0-r6
            return self.get_register(f"r{num}")
        return None

    def get_userland_arg(self, num: int) -> Optional[int]:
        """Get ARM userland argument"""
        if 0 <= num < 4:  # r0-r3 for first 4 args
            return self.get_register(f"r{num}")
        # Additional arguments would be on the stack
        # On ARM, the stack pointer (sp) points to the stack frame,
        # and arguments 5+ are at [sp, #0], [sp, #4], etc.
        sp = self.get_sp()
        # Calculate the correct stack offset for argument num
        # For ARM, arguments start at sp+0 for the 5th argument
        addr = sp + ((num - 4) * 4)
        return self._read_memory(addr, 4, 'ptr')

    def get_syscall_number(self) -> Optional[int]:
        """Get syscall number from r7 register"""
        return self.get_register("r7")


class AArch64PtRegsWrapper(PtRegsWrapper):
    """Wrapper for AArch64 pt_regs"""

    # Helper for nested access: obj.unnamed_field_0.unnamed_field_0
    # We can pre-calculate the getter to jump straight to the inner struct

    _ACCESSORS = {}

    @staticmethod
    def _get_inner(obj):
        return obj.unnamed_field_0.unnamed_field_0

    # Build accessors
    for i in range(31):
        _ACCESSORS[f"x{i}"] = (
            lambda obj, i=i: AArch64PtRegsWrapper._get_inner(obj).regs[i],
            lambda obj, val, i=i: AArch64PtRegsWrapper._get_inner(obj).regs.__setitem__(i, val)
        )

    _ACCESSORS["sp"] = (lambda obj: AArch64PtRegsWrapper._get_inner(obj).sp,
                        lambda obj, val: setattr(AArch64PtRegsWrapper._get_inner(obj), 'sp', val))
    _ACCESSORS["pc"] = (lambda obj: AArch64PtRegsWrapper._get_inner(obj).pc,
                        lambda obj, val: setattr(AArch64PtRegsWrapper._get_inner(obj), 'pc', val))
    _ACCESSORS["pstate"] = (lambda obj: AArch64PtRegsWrapper._get_inner(obj).pstate,
                            lambda obj, val: setattr(AArch64PtRegsWrapper._get_inner(obj), 'pstate', val))

    # Direct fields
    _ACCESSORS["syscallno"] = (_make_attr_getter("syscallno"), _make_attr_setter("syscallno"))
    _ACCESSORS["orig_x0"] = (_make_attr_getter("orig_x0"), _make_attr_setter("orig_x0"))

    # Aliases
    _ACCESSORS["retval"] = _ACCESSORS["x0"]
    _ACCESSORS["fp"] = _ACCESSORS["x29"]
    _ACCESSORS["lr"] = _ACCESSORS["x30"]

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        super().__init__(obj, panda)
        self._arm_delegate = None
        self._checking_mode = False

    def _is_aarch32_mode(self) -> bool:
        """
        Check if the CPU is running in AArch32 (compatibility) mode
        based on the PSTATE register.

        PSTATE.nRW bit (bit 4) indicates the execution state:
        - When 0, AArch64 state
        - When 1, AArch32 state
        """
        # Prevent recursion
        if self._checking_mode:
            return False

        self._checking_mode = True
        try:
            # Check pstate nRW bit (bit 4). 1 = 32-bit.
            pstate = self._get_inner(self._obj).pstate
            return (pstate & 0x10) != 0
        except (AttributeError, TypeError):
            return False
        finally:
            self._checking_mode = False

    def _get_arm_delegate(self) -> ArmPtRegsWrapper:
        """
        Get or create an ARM registers delegate for AArch32 mode access
        """
        if self._arm_delegate is None:
            # Create delegate with our original object but use ARM wrapper
            self._arm_delegate = ArmPtRegsWrapper(self._obj, panda=self._panda)
        return self._arm_delegate

    def get_register(self, reg_name: str) -> Optional[int]:
        """
        Get register value by name, handling AArch32 compatibility mode if needed
        """
        # Check if we're in AArch32 mode and the register is an ARM register
        # Only do the mode check if we're not already checking the mode
        if not self._checking_mode and reg_name.startswith("r"):
            if self._is_aarch32_mode():
                return self._get_arm_delegate().get_register(reg_name)

        # For AArch64 registers, proceed with standard access
        return super().get_register(reg_name)

    def set_register(self, reg_name: str, value: int) -> bool:
        """
        Set register value by name, handling AArch32 compatibility mode if needed
        """
        # Check if we're in AArch32 mode and the register is an ARM register
        if self._is_aarch32_mode() and reg_name.startswith("r"):
            return self._get_arm_delegate().set_register(reg_name, value)

        # For AArch64 registers, proceed with standard access
        return super().set_register(reg_name, value)

    def get_syscall_arg(self, num: int) -> Optional[int]:
        """Get AArch64 syscall argument, considering compatibility mode"""
        if self._is_aarch32_mode():
            # In AArch32 mode, use ARM syscall convention
            return self._get_arm_delegate().get_syscall_arg(num)

        # Default AArch64 syscall convention
        if 0 <= num < 8:  # x0-x7 for syscall args
            return self.get_register(f"x{num}")
        return None

    def get_userland_arg(self, num: int) -> Optional[int]:
        """Get AArch64 userland argument, considering compatibility mode"""
        if self._is_aarch32_mode():
            # In AArch32 mode, use ARM userland convention
            return self._get_arm_delegate().get_userland_arg(num)

        # Default AArch64 userland convention
        if 0 <= num < 8:  # x0-x7 for first 8 args
            return self.get_register(f"x{num}")

        # Additional arguments would be on the stack
        # In AArch64, arguments beyond registers are at sp, sp+8, sp+16, etc.
        # No need to skip return address as it's in LR (x30)
        sp = self.get_sp()
        if sp is None:
            return None
        # Stack arguments start at sp, and each is 8 bytes (64 bits)
        addr = sp + ((num - 8) * 8)
        return self._read_memory(addr, 8, 'ptr')

    def get_syscall_number(self) -> Optional[int]:
        """
        Get syscall number, considering compatibility mode.
        In AArch64, the syscall number is in syscallno.
        In AArch32 mode, use ARM implementation.
        """
        if self._is_aarch32_mode():
            return self._get_arm_delegate().get_syscall_number()
        return self.get_register("syscallno")


class MipsPtRegsWrapper(PtRegsWrapper):
    """Wrapper for MIPS pt_regs"""

    # Pre-calculate MIPS regs array
    _ACCESSORS = {
        f"r{i}": (_make_array_getter("regs", i), _make_array_setter("regs", i))
        for i in range(32)
    }
    # Add named MIPS registers (a0, v0, sp, etc)
    _MIPS_MAP = {
        "zero": 0, "at": 1, "v0": 2, "v1": 3, "a0": 4, "a1": 5, "a2": 6, "a3": 7,
        "t0": 8, "t1": 9, "t2": 10, "t3": 11, "t4": 12, "t5": 13, "t6": 14, "t7": 15,
        "s0": 16, "s1": 17, "s2": 18, "s3": 19, "s4": 20, "s5": 21, "s6": 22, "s7": 23,
        "t8": 24, "t9": 25, "k0": 26, "k1": 27, "gp": 28, "sp": 29, "fp": 30, "ra": 31
    }
    for name, idx in _MIPS_MAP.items():
        _ACCESSORS[name] = _ACCESSORS[f"r{idx}"]

    # Special fields
    _ACCESSORS.update({
        "cp0_status": (_make_attr_getter("cp0_status"), _make_attr_setter("cp0_status")),
        "hi": (_make_attr_getter("hi"), _make_attr_setter("hi")),
        "lo": (_make_attr_getter("lo"), _make_attr_setter("lo")),
        "cp0_epc": (_make_attr_getter("cp0_epc"), _make_attr_setter("cp0_epc")),
        # Aliases
        "pc": (_make_attr_getter("cp0_epc"), _make_attr_setter("cp0_epc")),
        "retval": (_make_array_getter("regs", 2), _make_array_setter("regs", 2))  # v0
    })

    def get_syscall_arg(self, num: int) -> Optional[int]:
        """Get MIPS syscall argument"""
        if 0 <= num < 4:  # a0-a3 (r4-r7)
            return self.get_register(f"a{num}")
        # Arguments 4 and 5 are at a4 and a5 (r8 and r9 in o32 ABI)
        if num == 4:
            return self.get_register("r8")
        if num == 5:
            return self.get_register("r9")
        return None

    def get_userland_arg(self, num: int) -> Optional[int]:
        """Get MIPS userland argument"""
        if 0 <= num < 4:  # a0-a3 for first 4 args
            return self.get_register(f"a{num}")
        # Additional arguments on the stack at $sp+16, +20, etc.
        sp = self.get_sp()
        if sp is not None:
            addr = sp + 16 + ((num - 4) * 4)  # MIPS stack args start at sp+16
            return self._read_memory(addr, 4, 'ptr')
        return None

    def get_syscall_number(self) -> Optional[int]:
        """Get syscall number from v0 register"""
        return self.get_register("v0")


class Mips64PtRegsWrapper(MipsPtRegsWrapper):
    """Wrapper for MIPS64 pt_regs"""

    # Copy accessors from base and update for MIPS64 args aliases
    _ACCESSORS = MipsPtRegsWrapper._ACCESSORS.copy()
    _ACCESSORS.update({
        "a4": MipsPtRegsWrapper._ACCESSORS["r8"],
        "a5": MipsPtRegsWrapper._ACCESSORS["r9"],
        "a6": MipsPtRegsWrapper._ACCESSORS["r10"],
        "a7": MipsPtRegsWrapper._ACCESSORS["r11"],
    })

    def get_syscall_arg(self, num: int) -> Optional[int]:
        """Get MIPS64 syscall argument"""
        if 0 <= num < 8:  # a0-a7 (r4-r11)
            return self.get_register(f"a{num}")
        return None

    def get_userland_arg(self, num: int) -> Optional[int]:
        """Get MIPS64 userland argument"""
        if 0 <= num < 8:  # a0-a7 for first 8 args
            return self.get_register(f"a{num}")

        # Additional arguments would be on the stack
        # In MIPS64 N64 ABI, stack arguments start at sp+0 (rather than sp+16 as in MIPS32)
        # Each stack argument is 8 bytes (64 bits)
        sp = self.get_sp()
        if sp is None:
            return None

        # Stack arguments start at sp, and each is 8 bytes (64 bits)
        stack_idx = num - 8  # Adjust for the 8 registers already used
        addr = sp + (stack_idx * 8)  # No extra offset needed

        return self._read_memory(addr, 8, 'ptr')


class PowerPCPtRegsWrapper(PtRegsWrapper):
    """Wrapper for PowerPC pt_regs"""

    # Helper to traverse PANDA's nested union structure for PPC
    # obj.unnamed_field_0.unnamed_field_0.gpr[i]
    @staticmethod
    def _get_inner(obj):
        # Optimistic access: assumes standard PANDA nesting
        return obj.unnamed_field_0.unnamed_field_0

    _ACCESSORS = {}

    # 1. GPRs (r0-r31)
    for i in range(32):
        _ACCESSORS[f"r{i}"] = (
            lambda obj, i=i: PowerPCPtRegsWrapper._get_inner(obj).gpr[i],
            lambda obj, val, i=i: PowerPCPtRegsWrapper._get_inner(obj).gpr.__setitem__(i, val)
        )

    # 2. Special Registers (Direct fields in inner struct)
    for reg in ["nip", "msr", "orig_gpr3", "ctr", "link", "xer", "ccr", "softe", "trap", "dar", "dsisr", "result"]:
        _ACCESSORS[reg] = (
            lambda obj, r=reg: getattr(PowerPCPtRegsWrapper._get_inner(obj), r),
            lambda obj, val, r=reg: setattr(PowerPCPtRegsWrapper._get_inner(obj), r, val)
        )

    # 3. Aliases
    _ACCESSORS["pc"] = _ACCESSORS["nip"]
    _ACCESSORS["lr"] = _ACCESSORS["link"]
    _ACCESSORS["orig_r3"] = _ACCESSORS["orig_gpr3"]
    # r1 is stack pointer
    _ACCESSORS["sp"] = _ACCESSORS["r1"]
    # r3 holds return value
    _ACCESSORS["retval"] = _ACCESSORS["r3"]

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        super().__init__(obj, panda)
        # Check if we need to adjust the object for non-nested structures (rare case)
        if not hasattr(obj, "unnamed_field_0"):
            # If struct is flat, we patch _get_inner to return obj identity
            # (Note: This monkeypatch is per-instance if we attach it to self,
            # but accessors are class-level. Standard PANDA is nested.
            # We assume nested for the optimized path).
            pass

    def get_syscall_arg(self, num: int) -> Optional[int]:
        """Get PowerPC syscall argument"""
        if 0 <= num < 6:
            # r3-r8 for syscall args
            return self.get_register(f"r{3+num}")
        return None

    def get_userland_arg(self, num: int) -> Optional[int]:
        """Get PowerPC userland argument"""
        if 0 <= num < 8:
            # r3-r10 for userland args (arguments 0 through 7)
            return self.get_register(f"r{3+num}")

        # Additional arguments would be on the stack (arguments 8 onwards)
        sp = self.get_sp()
        if sp is None:
            return None

        # Determine stack layout based on architecture
        base_offset = 0
        word_size = 0
        if self._panda.bits == 32:
            # 32-bit PowerPC - args start at SP+8
            base_offset = 8
            word_size = 4
        else:  # 64-bit
            # 64-bit PowerPC - Linux ABI (ELF V2)
            base_offset = 96
            word_size = 8

        # Calculate stack address
        # Adjust for the 8 registers already used (args 0-7)
        stack_idx = num - 8
        addr = sp + base_offset + (stack_idx * word_size)

        return self._read_memory(addr, word_size, 'ptr')

    def get_syscall_number(self) -> Optional[int]:
        """Get syscall number from r0 register"""
        return self.get_register("r0")


class PowerPC64PtRegsWrapper(PowerPCPtRegsWrapper):
    """Wrapper for PowerPC64 pt_regs"""
    pass


class LoongArch64PtRegsWrapper(PtRegsWrapper):
    """Wrapper for LoongArch64 pt_regs"""

    _ACCESSORS = {
        f"r{i}": (_make_array_getter("regs", i), _make_array_setter("regs", i))
        for i in range(32)
    }

    # Direct fields
    for field in ["orig_a0", "csr_era", "csr_badvaddr", "csr_crmd", "csr_prmd", "csr_euen", "csr_ecfg", "csr_estat"]:
        _ACCESSORS[field] = (_make_attr_getter(field), _make_attr_setter(field))

    # Aliases
    _LOONG_MAP = {
        "zero": 0, "ra": 1, "tp": 2, "sp": 3, "a0": 4, "a1": 5, "a2": 6, "a3": 7,
        "a4": 8, "a5": 9, "a6": 10, "a7": 11, "t0": 12, "t1": 13, "t2": 14, "t3": 15,
        "t4": 16, "t5": 17, "t6": 18, "t7": 19, "t8": 20, "u0": 21, "fp": 22,
        "s0": 23, "s1": 24, "s2": 25, "s3": 26, "s4": 27, "s5": 28, "s6": 29, "s7": 30, "s8": 31
    }
    for name, idx in _LOONG_MAP.items():
        _ACCESSORS[name] = _ACCESSORS[f"r{idx}"]

    _ACCESSORS["pc"] = _ACCESSORS["csr_era"]
    _ACCESSORS["retval"] = _ACCESSORS["a0"]

    def get_syscall_arg(self, num: int) -> Optional[int]:
        """Get LoongArch64 syscall argument"""
        if 0 <= num < 8:
            # a0-a7 for syscall args
            return self.get_register(f"a{num}")
        return None

    def get_userland_arg(self, num: int) -> Optional[int]:
        """Get LoongArch64 userland argument"""
        if 0 <= num < 8:
            # a0-a7 for userland args
            return self.get_register(f"a{num}")

        # Additional arguments would be on the stack
        # In LoongArch64, arguments beyond registers are at sp, sp+8, sp+16, etc.
        # No need to skip return address as it's in r1 (ra)
        sp = self.get_sp()
        if sp is None:
            return None

        # Stack arguments start at sp, and each is 8 bytes (64 bits)
        stack_idx = num - 8  # Adjust for the 8 registers already used
        addr = sp + (stack_idx * 8)  # No extra offset needed

        return self._read_memory(addr, 8, 'ptr')

    def get_syscall_number(self) -> Optional[int]:
        """Get syscall number from a7 register"""
        return self.get_register("a7")


class Riscv32PtRegsWrapper(PtRegsWrapper):
    """Wrapper for RISC-V 32-bit pt_regs"""

    # RISC-V uses direct named fields in the struct
    _RISCV_FIELDS = [
        "epc", "ra", "sp", "gp", "tp", "t0", "t1", "t2", "s0", "s1", "a0", "a1",
        "a2", "a3", "a4", "a5", "a6", "a7", "s2", "s3", "s4", "s5", "s6", "s7",
        "s8", "s9", "s10", "s11", "t3", "t4", "t5", "t6", "status", "badaddr",
        "cause", "orig_a0"
    ]

    _ACCESSORS = {
        name: (_make_attr_getter(name), _make_attr_setter(name))
        for name in _RISCV_FIELDS
    }

    # Aliases map x-registers to ABI names
    _RISCV_X_MAP = {
        "x1": "ra", "x2": "sp", "x3": "gp", "x4": "tp", "x5": "t0", "x6": "t1", "x7": "t2",
        "x8": "s0", "x9": "s1", "x10": "a0", "x11": "a1", "x12": "a2", "x13": "a3", "x14": "a4",
        "x15": "a5", "x16": "a6", "x17": "a7", "x18": "s2", "x19": "s3", "x20": "s4", "x21": "s5",
        "x22": "s6", "x23": "s7", "x24": "s8", "x25": "s9", "x26": "s10", "x27": "s11",
        "x28": "t3", "x29": "t4", "x30": "t5", "x31": "t6"
    }
    for x_reg, abi_name in _RISCV_X_MAP.items():
        _ACCESSORS[x_reg] = _ACCESSORS[abi_name]

    # Special logic for Zero
    _ACCESSORS["x0"] = (lambda obj: 0, lambda obj, val: None)
    _ACCESSORS["zero"] = _ACCESSORS["x0"]

    # Common Aliases
    _ACCESSORS["pc"] = _ACCESSORS["epc"]
    _ACCESSORS["fp"] = _ACCESSORS["s0"]
    _ACCESSORS["retval"] = _ACCESSORS["a0"]

    def get_syscall_arg(self, num: int) -> Optional[int]:
        """Get RISC-V 32-bit syscall argument"""
        if 0 <= num < 8:  # a0-a7 for syscall args
            return self.get_register(f"a{num}")
        return None

    def get_userland_arg(self, num: int) -> Optional[int]:
        """Get RISC-V 32-bit userland argument"""
        if 0 <= num < 8:  # a0-a7 for first 8 args
            return self.get_register(f"a{num}")

        # Additional arguments would be on the stack
        # In RISC-V, arguments beyond registers are placed directly at sp, sp+4, sp+8, etc.
        # No need to skip any return address as it's in the ra register
        sp = self.get_sp()
        if sp is None:
            return None

        # Stack arguments start at sp, and each is 4 bytes (32 bits)
        stack_idx = num - 8  # Adjust for the 8 registers already used
        addr = sp + (stack_idx * 4)  # No extra offset needed

        return self._read_memory(addr, 4, 'ptr')

    def get_syscall_number(self) -> Optional[int]:
        """Get syscall number from a7 register"""
        return self.get_register("a7")


class Riscv64PtRegsWrapper(Riscv32PtRegsWrapper):
    """Wrapper for RISC-V 64-bit pt_regs - same structure as 32-bit but with 64-bit registers"""
    # Inherits accessors from Riscv32 (names are the same)

    def get_userland_arg(self, num: int) -> Optional[int]:
        """Get RISC-V 64-bit userland argument"""
        if 0 <= num < 8:  # a0-a7 for first 8 args
            return self.get_register(f"a{num}")

        # Additional arguments would be on the stack
        # In RISC-V, arguments beyond registers are placed directly at sp, sp+8, sp+16, etc.
        # No need to skip any return address as it's in the ra register
        sp = self.get_sp()
        if sp is None:
            return None

        # 64-bit stack width
        addr = sp + ((num - 8) * 8)
        return self._read_memory(addr, 8, 'ptr')


# --- Caching Factory ---

_WRAPPER_CACHE = {
    "i386": X86PtRegsWrapper,
    "x86_64": X86_64PtRegsWrapper,
    "arm": ArmPtRegsWrapper,
    "aarch64": AArch64PtRegsWrapper,
    "mips": MipsPtRegsWrapper,
    "mipsel": MipsPtRegsWrapper,
    "mips64": Mips64PtRegsWrapper,
    "mips64el": Mips64PtRegsWrapper,
    "ppc": PowerPCPtRegsWrapper,
    "ppc64": PowerPC64PtRegsWrapper,
    "loongarch64": LoongArch64PtRegsWrapper,
    "riscv32": Riscv32PtRegsWrapper,
    "riscv64": Riscv64PtRegsWrapper,
}


def get_pt_regs_wrapper(
    panda: Optional[Any],
    regs: Any,
    arch_name: Optional[str] = None
) -> PtRegsWrapper:
    """
    Factory function to create the appropriate pt_regs wrapper based on architecture.

    Args:
        panda: PANDA object (may be used to determine architecture if arch_name not provided)
        regs: The pt_regs structure to wrap
        arch_name: Architecture name (optional, will be determined from PANDA if not provided)

    Returns:
        An appropriate PtRegsWrapper subclass instance.
    """
    if arch_name is None:
        if panda:
            arch_name = panda.arch_name
        else:
            arch_name = "x86_64"

    # Fast lookup from cache
    klass = _WRAPPER_CACHE.get(arch_name.lower())
    if klass:
        return klass(regs, panda)

    return PtRegsWrapper(regs, panda)
