"""
# ptregs_wrap.py - Architecture-agnostic wrappers for Linux pt_regs structures

This module provides Pythonic, type-annotated wrappers for Linux kernel pt_regs structures across multiple CPU architectures. It enables convenient, architecture-independent access to process register state, such as that captured at system call entry/exit, exceptions, or context switches. The wrappers abstract away the raw struct layout and provide a unified interface for reading/writing registers, extracting syscall arguments, and handling calling conventions.

## Overview

The module defines a base `PtRegsWrapper` class and a set of subclasses for each supported architecture (`x86`, `x86_64`, `ARM`, `AArch64`, `MIPS`, `PowerPC`, `LoongArch64`, `RISC-V`, etc). Each subclass knows how to access registers and arguments according to its architecture's ABI and pt_regs layout. The wrappers can be used with PANDA or other emulation/analysis frameworks that expose pt_regs-like objects.

The module also provides a `get_pt_regs_wrapper()` factory function to select the correct wrapper for a given architecture.

## Typical Usage

Suppose you have a PANDA plugin or other tool that provides a pt_regs struct (e.g., at a syscall, exception, or context switch):

```python
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
```

The wrappers also support advanced features such as handling 32-bit compatibility mode on x86_64/AArch64, stack argument extraction, and portal-style coroutine memory reads. The `get_args_portal` and `get_arg_portal` methods are generator-based and will yield if a memory read is required (such as when reading stack arguments that may fail and need to be retried or handled asynchronously).

## Classes

- `PtRegsWrapper`: Base class for all pt_regs wrappers, provides generic register access and argument extraction.
- `X86PtRegsWrapper`, `X86_64PtRegsWrapper`, `ArmPtRegsWrapper`, ...: Architecture-specific subclasses.
- `PandaMemReadFail`: Exception for failed memory reads (for portal/coroutine use).

## Functions

- `get_pt_regs_wrapper(panda: Optional[Any], regs: Any, arch_name: Optional[str] = None) -> PtRegsWrapper`: Factory to select the correct wrapper for a given architecture.

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


class PtRegsWrapper(Wrapper):
    """
    Base class for pt_regs wrappers across different architectures.

    Args:
        obj: The pt_regs structure to wrap.
        panda: Optional PANDA object for memory reading.
    """

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        super().__init__(obj)
        self._register_map: Dict[str, Union[str, tuple]] = {}  # Will be populated by subclasses
        self._panda: Optional[Any] = panda      # Reference to PANDA object for memory reading

    def get_register(self, reg_name: str) -> Optional[int]:
        """Get register value by name."""
        if reg_name in self._register_map:
            access_info = self._register_map[reg_name]
            return self._access_register(access_info)
        return None

    def set_register(self, reg_name: str, value: int) -> bool:
        """Set register value by name."""
        if reg_name in self._register_map:
            access_info = self._register_map[reg_name]
            self._write_register(access_info, value)
            return True
        return False

    def _access_register(self, access_info: Union[str, tuple]) -> Optional[int]:
        """Access register based on access info."""
        if isinstance(access_info, str):
            # Direct attribute access
            return getattr(self._obj, access_info)
        elif isinstance(access_info, tuple):
            # Complex access (array, masked, etc.)
            access_type, *params = access_info
            if access_type == 'array':
                array_name, index = params
                return getattr(self._obj, array_name)[index]
            elif access_type == 'masked':
                reg_name, mask, shift = params
                value = getattr(self._obj, reg_name)
                return (value >> shift) & mask
            elif access_type == 'computed':
                compute_func = params[0]
                return compute_func(self._obj)
        return None

    def _write_register(self, access_info: Union[str, tuple], value: int) -> None:
        """Write register based on access info."""
        if isinstance(access_info, str):
            # Direct attribute write
            setattr(self._obj, access_info, value)
        elif isinstance(access_info, tuple):
            # Complex access (array, masked, etc.)
            access_type, *params = access_info
            if access_type == 'array':
                array_name, index = params
                getattr(self._obj, array_name)[index] = value
            elif access_type == 'masked':
                reg_name, mask, shift = params
                current = getattr(self._obj, reg_name)
                cleared = current & ~(mask << shift)
                new_value = cleared | ((value & mask) << shift)
                setattr(self._obj, reg_name, new_value)
            elif access_type == 'computed':
                _, write_func = params
                write_func(self._obj, value)

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
        # Subclasses should override this if convention is different
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
        for reg_name in self._register_map.keys():
            result[reg_name] = self.get_register(reg_name)
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
        Read memory from guest using PANDA's virtual_memory_read.

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
            raise ValueError(
                "Cannot read memory: no PANDA reference available")

        cpu = self._panda.get_cpu()
        if not cpu:
            raise ValueError("Cannot read memory: failed to get CPU")

        try:
            data = self._panda.virtual_memory_read(cpu, addr, size)
            if fmt == 'bytes':
                return data
            elif fmt == 'str':
                return data.decode('latin-1', errors='replace')

            # Use the correct endianness format based on the architecture
            endian_fmt = '>' if hasattr(
                self._panda, 'endianness') and self._panda.endianness == 'big' else '<'

            if fmt == 'int':
                if size == 1:
                    return struct.unpack(endian_fmt + 'B', data)[0]
                elif size == 2:
                    return struct.unpack(endian_fmt + 'H', data)[0]
                elif size == 4:
                    return struct.unpack(endian_fmt + 'I', data)[0]
                elif size == 8:
                    return struct.unpack(endian_fmt + 'Q', data)[0]
            elif fmt == 'ptr':
                if self._panda.bits == 32:
                    return struct.unpack(endian_fmt + 'I', data)[0]
                else:  # 64-bit
                    return struct.unpack(endian_fmt + 'Q', data)[0]
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

    def get_syscall_number(self) -> Optional[int]:
        """
        Get the syscall number from the registers.
        Each architecture implements this differently.

        Returns:
            int: The syscall number or None if not available
        """
        # Default implementation - should be overridden by subclasses
        return None


class X86PtRegsWrapper(PtRegsWrapper):
    """Wrapper for x86 (32-bit) pt_regs"""

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        super().__init__(obj, panda=panda)
        # Map register names to access info
        self._register_map = {
            "eax": "ax",
            "ebx": "bx",
            "ecx": "cx",
            "edx": "dx",
            "esi": "si",
            "edi": "di",
            "ebp": "bp",
            "esp": "sp",
            "eip": "ip",
            "orig_eax": "orig_ax",
            "eflags": "flags",
            "cs": "cs",
            "ds": "ds",
            "ss": "ss",
            "es": "fs",
            "gs": "gs",
            # Alias common names
            "pc": "ip",
            "sp": "sp",
            "retval": "ax",
        }

    def get_syscall_arg(self, num: int) -> Optional[int]:
        """Get x86 syscall argument"""
        syscall_args = ["ebx", "ecx", "edx", "esi", "edi", "ebp"]
        if 0 <= num < len(syscall_args):
            return self.get_register(syscall_args[num])
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

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        super().__init__(obj, panda=panda)
        # Map register names to access info based on the actual x86_64 pt_regs structure
        # The x86_64 pt_regs has individual register fields, not an array
        self._register_map = {
            # Direct register mappings from the pt_regs structure
            "r15": "r15",
            "r14": "r14",
            "r13": "r13",
            "r12": "r12",
            "rbp": "bp",  # bp in struct
            "rbx": "bx",  # bx in struct
            "r11": "r11",
            "r10": "r10",
            "r9": "r9",
            "r8": "r8",
            "rax": "ax",  # ax in struct
            "rcx": "cx",  # cx in struct
            "rdx": "dx",  # dx in struct
            "rsi": "si",  # si in struct
            "rdi": "di",  # di in struct
            "orig_rax": "orig_ax",  # orig_ax in struct
            "rip": "ip",  # ip in struct
            "cs": "cs",
            "eflags": "flags",  # flags in struct
            "rsp": "sp",  # sp in struct
            "ss": "ss",

            # Alias common names
            "pc": "ip",
            "sp": "sp",
            "retval": "ax",  # ax holds the return value
        }

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
                cs = self._obj.cs
                # Heuristic: 64-bit user mode CS is 0x33. 64-bit kernel is 0x10.
                # If it's not one of these, we assume it's compatibility mode (e.g., 0x23).
                return cs not in [0x33, 0x10]

            # Fallback to using flags register if cs isn't directly accessible
            elif hasattr(self._obj, "flags"):
                flags = self._obj.flags
                # Check for VM86 mode flag in EFLAGS
                return (flags & (1 << 17)) != 0

            # Default: assume not in compatibility mode if we can't determine
            return False
        finally:
            self._checking_mode = False

    def get_register(self, reg_name: str) -> Optional[int]:
        # Prevent recursion when checking for compatibility mode
        if self._checking_mode and reg_name == "cs":
            # Direct access without compatibility check
            if reg_name in self._register_map:
                access_info = self._register_map[reg_name]
                return self._access_register(access_info)
            return None

        # For compatibility mode, consider delegating to x86 wrapper
        if not self._checking_mode and self._is_compatibility_mode() and reg_name in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]:
            return self._get_x86_delegate().get_register(reg_name)

        # Handle basic 32-bit registers for non-compatibility mode
        if reg_name.startswith("e") and reg_name[1:] in ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"]:
            # Handle 32-bit registers (eax, ebx, etc)
            r64_name = "r" + reg_name[1:]
            return super().get_register(r64_name) & 0xFFFFFFFF

        return super().get_register(reg_name)

    def set_register(self, reg_name: str, value: int) -> bool:
        # For compatibility mode, consider delegating to x86 wrapper
        if self._is_compatibility_mode() and reg_name in ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]:
            return self._get_x86_delegate().set_register(reg_name, value)

        # Handle basic 32-bit registers for non-compatibility mode
        if reg_name.startswith("e") and reg_name[1:] in ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"]:
            # For setting e-registers in 64-bit mode, we need to preserve upper 32 bits
            r64_name = "r" + reg_name[1:]
            # Get current 64-bit value, clear lower 32 bits, add new 32-bit value
            current = super().get_register(r64_name) & 0xFFFFFFFF00000000
            new_value = current | (value & 0xFFFFFFFF)
            return super().set_register(r64_name, new_value)

        return super().set_register(reg_name, value)

    def get_syscall_arg(self, num: int) -> Optional[int]:
        """Get x86_64 syscall argument, considering compatibility mode"""
        if self._is_compatibility_mode():
            # In 32-bit compatibility mode, use x86 syscall convention
            return self._get_x86_delegate().get_syscall_arg(num)

        # Default x86_64 syscall convention
        syscall_args = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
        if 0 <= num < len(syscall_args):
            return self.get_register(syscall_args[num])
        return None

    def get_userland_arg(self, num: int) -> Optional[int]:
        """Get x86_64 userland argument, considering compatibility mode"""
        if self._is_compatibility_mode():
            # In 32-bit compatibility mode, use x86 userland convention (stack-based)
            return self._get_x86_delegate().get_userland_arg(num)

        # Default x86_64 userland convention
        userland_args = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
        if 0 <= num < len(userland_args):
            return self.get_register(userland_args[num])

        # For arguments beyond the registers, read from the stack
        # In x86_64, the standard calling convention places additional args on the stack
        sp = self.get_sp()
        if sp is None:
            return None

        # Stack arguments start at position 0 relative to the stack pointer
        # Each subsequent argument is 8 bytes (64 bits) further
        stack_idx = num - len(userland_args)
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

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        super().__init__(obj, panda=panda)
        # ARM registers in uregs[18]
        # Order: r0-r15, cpsr, orig_r0
        self._register_map = {
            "r0": ("array", "uregs", 0),
            "r1": ("array", "uregs", 1),
            "r2": ("array", "uregs", 2),
            "r3": ("array", "uregs", 3),
            "r4": ("array", "uregs", 4),
            "r5": ("array", "uregs", 5),
            "r6": ("array", "uregs", 6),
            "r7": ("array", "uregs", 7),
            "r8": ("array", "uregs", 8),
            "r9": ("array", "uregs", 9),
            "r10": ("array", "uregs", 10),
            "r11": ("array", "uregs", 11),
            "r12": ("array", "uregs", 12),
            "sp": ("array", "uregs", 13),
            "lr": ("array", "uregs", 14),
            "pc": ("array", "uregs", 15),
            "cpsr": ("array", "uregs", 16),
            "orig_r0": ("array", "uregs", 17),
            # Aliases
            "retval": ("array", "uregs", 0),
        }

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

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        super().__init__(obj, panda=panda)
        # Map register names to access info
        self._register_map = {
            # Access through the nested union and struct
            # regs array for general registers x0-x30
            **{f"x{i}": ("computed", lambda obj, i=i: obj.unnamed_field_0.unnamed_field_0.regs[i]) for i in range(31)},
            # Special registers
            "sp": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.sp),
            "pc": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.pc),
            "pstate": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.pstate),
            # Other fields directly in pt_regs
            "syscallno": "syscallno",
            "orig_x0": "orig_x0",
            # Aliases
            # x0 holds the return value
            "retval": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.regs[0]),
            # Common aliases for named registers
            # x29
            "fp": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.regs[29]),
            # x30
            "lr": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.regs[30]),
        }

        # Create a delegate for ARM mode access (but don't initialize it yet)
        self._arm_delegate = None
        # Add a flag to prevent recursion
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
            # Try to access pstate via the nested structure
            try:
                pstate = self._obj.unnamed_field_0.unnamed_field_0.pstate
                # Bit 4 (0x10) is the nRW bit that indicates execution state
                return (pstate & 0x10) != 0
            except (AttributeError, TypeError):
                # If we can't access pstate through the expected path, default to AArch64 mode
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
        stack_idx = num - 8  # Adjust for the 8 registers already used
        addr = sp + (stack_idx * 8)  # No extra offset needed

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

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        super().__init__(obj, panda=panda)
        # Map register names to access info (MIPS registers are in regs[32] array)
        self._register_map = {
            # General registers
            **{f"r{i}": ("array", "regs", i) for i in range(32)},
            # Special registers
            "cp0_status": "cp0_status",
            "hi": "hi",
            "lo": "lo",
            "cp0_badvaddr": "cp0_badvaddr",
            "cp0_cause": "cp0_cause",
            "cp0_epc": "cp0_epc",
            # Aliases for common named registers
            "zero": ("array", "regs", 0),
            "at": ("array", "regs", 1),
            "v0": ("array", "regs", 2),
            "v1": ("array", "regs", 3),
            "a0": ("array", "regs", 4),
            "a1": ("array", "regs", 5),
            "a2": ("array", "regs", 6),
            "a3": ("array", "regs", 7),
            "t0": ("array", "regs", 8),
            "t1": ("array", "regs", 9),
            "t2": ("array", "regs", 10),
            "t3": ("array", "regs", 11),
            "t4": ("array", "regs", 12),
            "t5": ("array", "regs", 13),
            "t6": ("array", "regs", 14),
            "t7": ("array", "regs", 15),
            "s0": ("array", "regs", 16),
            "s1": ("array", "regs", 17),
            "s2": ("array", "regs", 18),
            "s3": ("array", "regs", 19),
            "s4": ("array", "regs", 20),
            "s5": ("array", "regs", 21),
            "s6": ("array", "regs", 22),
            "s7": ("array", "regs", 23),
            "t8": ("array", "regs", 24),
            "t9": ("array", "regs", 25),
            "k0": ("array", "regs", 26),
            "k1": ("array", "regs", 27),
            "gp": ("array", "regs", 28),
            "sp": ("array", "regs", 29),
            "fp": ("array", "regs", 30),
            "ra": ("array", "regs", 31),
            # Important aliases
            "pc": "cp0_epc",
            "retval": ("array", "regs", 2),  # v0
        }

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
    """Wrapper for MIPS64 pt_regs - same structure but different register meanings"""

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        super().__init__(obj, panda=panda)
        # Add MIPS64-specific register aliases (a4-a7 for arguments)
        self._register_map.update({
            "a4": ("array", "regs", 8),
            "a5": ("array", "regs", 9),
            "a6": ("array", "regs", 10),
            "a7": ("array", "regs", 11),
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

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        super().__init__(obj, panda=panda)
        # PowerPC has numbered registers in the gpr array, nested two levels deep in unions/structs
        self._register_map = {
            # General purpose registers are in the gpr array inside two levels of anonymous struct/union
            **{f"r{i}": ("computed", lambda obj, i=i: obj.unnamed_field_0.unnamed_field_0.gpr[i]) for i in range(32)},
            # Special registers are direct fields in the anonymous struct
            "nip": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.nip),
            "msr": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.msr),
            "orig_r3": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.orig_gpr3),
            "ctr": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.ctr),
            "lr": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.link),
            "xer": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.xer),
            "ccr": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.ccr),
            "softe": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.softe),
            "trap": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.trap),
            "dar": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.dar),
            "dsisr": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.dsisr),
            "result": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.result),
            # Aliases
            # r1 is stack pointer
            "sp": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.gpr[1]),
            "pc": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.nip),
            # r3 holds return values
            "retval": ("computed", lambda obj: obj.unnamed_field_0.unnamed_field_0.gpr[3]),
        }

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
    """Wrapper for PowerPC64 pt_regs - same structure as PowerPC"""
    pass


class LoongArch64PtRegsWrapper(PtRegsWrapper):
    """Wrapper for LoongArch64 pt_regs"""

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        super().__init__(obj, panda=panda)
        # LoongArch64 has r0-r31 in regs[32]
        self._register_map = {
            **{f"r{i}": ("array", "regs", i) for i in range(32)},
            "orig_a0": "orig_a0",
            "csr_era": "csr_era",
            "csr_badvaddr": "csr_badvaddr",
            "csr_crmd": "csr_crmd",
            "csr_prmd": "csr_prmd",
            "csr_euen": "csr_euen",
            "csr_ecfg": "csr_ecfg",
            "csr_estat": "csr_estat",
            # Register aliases
            "zero": ("array", "regs", 0),
            "ra": ("array", "regs", 1),
            "tp": ("array", "regs", 2),
            "sp": ("array", "regs", 3),
            "a0": ("array", "regs", 4),
            "a1": ("array", "regs", 5),
            "a2": ("array", "regs", 6),
            "a3": ("array", "regs", 7),
            "a4": ("array", "regs", 8),
            "a5": ("array", "regs", 9),
            "a6": ("array", "regs", 10),
            "a7": ("array", "regs", 11),
            "t0": ("array", "regs", 12),
            "t1": ("array", "regs", 13),
            "t2": ("array", "regs", 14),
            "t3": ("array", "regs", 15),
            "t4": ("array", "regs", 16),
            "t5": ("array", "regs", 17),
            "t6": ("array", "regs", 18),
            "t7": ("array", "regs", 19),
            "t8": ("array", "regs", 20),
            "u0": ("array", "regs", 21),
            "fp": ("array", "regs", 22),
            "s0": ("array", "regs", 23),
            "s1": ("array", "regs", 24),
            "s2": ("array", "regs", 25),
            "s3": ("array", "regs", 26),
            "s4": ("array", "regs", 27),
            "s5": ("array", "regs", 28),
            "s6": ("array", "regs", 29),
            "s7": ("array", "regs", 30),
            "s8": ("array", "regs", 31),
            # Important aliases
            "pc": "csr_era",
            "retval": ("array", "regs", 4),  # a0
        }

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

    def __init__(self, obj: Any, panda: Optional[Any] = None) -> None:
        super().__init__(obj, panda=panda)
        # RISC-V pt_regs has individual fields for each register rather than an array
        self._register_map = {
            # Direct register mappings from the pt_regs structure
            "epc": "epc",          # Program Counter
            "ra": "ra",            # Return Address (x1)
            "sp": "sp",            # Stack Pointer (x2)
            "gp": "gp",            # Global Pointer (x3)
            "tp": "tp",            # Thread Pointer (x4)
            "t0": "t0",            # Temporary registers (x5-x7)
            "t1": "t1",
            "t2": "t2",
            "s0": "s0",            # Saved register (x8) / Frame Pointer
            "s1": "s1",            # Saved register (x9)
            "a0": "a0",            # Argument/Return registers (x10-x17)
            "a1": "a1",
            "a2": "a2",
            "a3": "a3",
            "a4": "a4",
            "a5": "a5",
            "a6": "a6",
            "a7": "a7",
            "s2": "s2",            # Saved registers (x18-x27)
            "s3": "s3",
            "s4": "s4",
            "s5": "s5",
            "s6": "s6",
            "s7": "s7",
            "s8": "s8",
            "s9": "s9",
            "s10": "s10",
            "s11": "s11",
            "t3": "t3",            # Temporary registers (x28-x31)
            "t4": "t4",
            "t5": "t5",
            "t6": "t6",
            "status": "status",    # CSR: status
            "badaddr": "badaddr",  # CSR: bad address
            "cause": "cause",      # CSR: trap cause
            "orig_a0": "orig_a0",  # a0 saved at syscall entry

            # Aliases for x-registers by ABI name
            "x1": "ra",
            "x2": "sp",
            "x3": "gp",
            "x4": "tp",
            "x5": "t0",
            "x6": "t1",
            "x7": "t2",
            "x8": "s0",
            "x9": "s1",
            "x10": "a0",
            "x11": "a1",
            "x12": "a2",
            "x13": "a3",
            "x14": "a4",
            "x15": "a5",
            "x16": "a6",
            "x17": "a7",
            "x18": "s2",
            "x19": "s3",
            "x20": "s4",
            "x21": "s5",
            "x22": "s6",
            "x23": "s7",
            "x24": "s8",
            "x25": "s9",
            "x26": "s10",
            "x27": "s11",
            "x28": "t3",
            "x29": "t4",
            "x30": "t5",
            "x31": "t6",

            # Alias for x0 (always zero)
            "x0": ("computed", lambda obj: 0),
            "zero": ("computed", lambda obj: 0),

            # Common aliases
            "pc": "epc",
            "fp": "s0",  # Frame pointer is s0/x8 in RISC-V
            "retval": "a0",  # a0/x10 holds return value
        }

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

        # Stack arguments start at sp, and each is 8 bytes (64 bits)
        stack_idx = num - 8  # Adjust for the 8 registers already used
        addr = sp + (stack_idx * 8)  # No extra offset needed

        return self._read_memory(addr, 8, 'ptr')


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
        # Determine architecture from CPU object if possible
        if panda:
            arch_name = panda.arch_name
        else:
            # Default to x86_64 if can't determine from CPU object
            arch_name = "x86_64"

    arch_map = {
        "i386": X86PtRegsWrapper,
        "x86_64": X86_64PtRegsWrapper,
        "arm": ArmPtRegsWrapper,
        "aarch64": AArch64PtRegsWrapper,
        "mips": MipsPtRegsWrapper,
        "mipsel": MipsPtRegsWrapper,  # Same structure, just different endianness
        "mips64": Mips64PtRegsWrapper,
        "mips64el": Mips64PtRegsWrapper,  # Same structure, just different endianness
        "ppc": PowerPCPtRegsWrapper,
        "ppc64": PowerPC64PtRegsWrapper,
        "loongarch64": LoongArch64PtRegsWrapper,
        "riscv32": Riscv32PtRegsWrapper,
        "riscv64": Riscv64PtRegsWrapper,
    }

    wrapper_class = arch_map.get(arch_name.lower(), PtRegsWrapper)
    return wrapper_class(regs, panda=panda)
