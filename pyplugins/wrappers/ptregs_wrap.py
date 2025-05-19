from wrappers.generic import Wrapper
import struct
from penguin import plugins


class PandaMemReadFail(Exception):
    """
    This class allows us to throw an error and pick up memory reads for
    portal use-case without having to make all the code yield
    """

    def __init__(self, addr, size):
        super().__init__(f"Failed to read {size} bytes from address {addr}")
        self.addr = addr
        self.size = size


class PtRegsWrapper(Wrapper):
    """Base class for pt_regs wrappers across different architectures"""

    def __init__(self, obj, panda=None):
        super().__init__(obj)
        self._register_map = {}  # Will be populated by subclasses
        self._panda = panda      # Reference to PANDA object for memory reading

    def get_register(self, reg_name):
        """Get register value by name"""
        if reg_name in self._register_map:
            access_info = self._register_map[reg_name]
            return self._access_register(access_info)
        return None

    def set_register(self, reg_name, value):
        """Set register value by name"""
        if reg_name in self._register_map:
            access_info = self._register_map[reg_name]
            self._write_register(access_info, value)
            return True
        return False

    def _access_register(self, access_info):
        """Access register based on access info"""
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

    def _write_register(self, access_info, value):
        """Write register based on access info"""
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

    def get_pc(self):
        """Get program counter"""
        return self.get_register("pc")

    def set_pc(self, value):
        """Set program counter"""
        self.set_register("pc", value)

    def get_sp(self):
        """Get stack pointer"""
        return self.get_register("sp")

    def get_return_value(self):
        """Get return value (typically in a0/r0/rax)"""
        # Subclasses should override this if convention is different
        return self.get_register("retval")

    def get_retval(self):
        """Get return value (alias for get_return_value)"""
        return self.get_return_value()

    def dump(self):
        """Dump all registers to a dictionary"""
        result = {}
        for reg_name in self._register_map.keys():
            result[reg_name] = self.get_register(reg_name)
        return result

    def get_args(self, count, convention=None):
        return [self.get_arg(i, convention) for i in range(count)]

    def get_arg(self, num, convention=None):
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

    def get_args_portal(self, count, convention=None):
        arr = []
        for i in range(count):
            arr.append((yield from self.get_arg_portal(i, convention)))
        return arr

    def get_arg_portal(self, num, convention=None):
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
        except PandaMemReadFail as e:
            if e.size == 4:
                val = yield from plugins.portal.read_int(e.addr)
            else:
                val = yield from plugins.portal.read_long(e.addr)
            return val

    def get_syscall_arg(self, num):
        """Get syscall argument (architecture-specific)"""
        raise NotImplementedError(
            f"get_syscall_arg not implemented for {self.__class__.__name__}")

    def get_userland_arg(self, num):
        """Get userland function argument (architecture-specific)"""
        raise NotImplementedError(
            f"get_userland_arg not implemented for {self.__class__.__name__}")

    def read_memory(self, addr, size, fmt='int'):
        """
        Read memory from guest using PANDA's virtual_memory_read.

        Args:
            addr: Address to read from
            size: Size to read (1, 2, 4, 8)
            fmt: Format to return ('int', 'ptr', 'bytes', 'str')

        Returns:
            The memory value in the requested format
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
            elif fmt == 'int':
                if size == 1:
                    return struct.unpack('<B', data)[0]
                elif size == 2:
                    return struct.unpack('<H', data)[0]
                elif size == 4:
                    return struct.unpack('<I', data)[0]
                elif size == 8:
                    return struct.unpack('<Q', data)[0]
            elif fmt == 'ptr':
                if self._panda.bits == 32:
                    return struct.unpack('<I', data)[0]
                else:
                    return struct.unpack('<Q', data)[0]
        except ValueError:
            raise PandaMemReadFail(addr, size)

    def read_stack_arg(self, arg_num, word_size=None):
        """
        Read a function argument from the stack

        Args:
            arg_num: Argument number (0-based)
            word_size: Word size override (default: based on architecture)

        Returns:
            The argument value read from the stack
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
        return self.read_memory(addr, word_size, 'ptr')

    def get_syscall_number(self):
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

    def __init__(self, obj, panda=None):
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
            "es": "es",
            "fs": "fs",
            "gs": "gs",
            # Alias common names
            "pc": "ip",
            "sp": "sp",
            "retval": "ax",
        }

    def get_syscall_arg(self, num):
        """Get x86 syscall argument"""
        syscall_args = ["ebx", "ecx", "edx", "esi", "edi", "ebp"]
        if 0 <= num < len(syscall_args):
            return self.get_register(syscall_args[num])
        return None

    def get_userland_arg(self, num):
        """Get x86 userland argument from stack"""
        # For x86, arguments are on the stack at esp+4, esp+8, etc.
        sp = self.get_sp()
        if sp is not None:
            # For x86, first arg is at sp+4 (after return address)
            addr = sp + 4 + (num * 4)
            return self.read_memory(addr, 4, 'ptr')
        return None

    def get_syscall_number(self):
        """Get syscall number from EAX register"""
        return self.get_register("orig_eax")


class X86_64PtRegsWrapper(PtRegsWrapper):
    """Wrapper for x86_64 pt_regs"""

    def __init__(self, obj, panda=None):
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

    def _is_compatibility_mode(self):
        """
        Check if the CPU is running in 32-bit compatibility mode
        based on the code segment (CS) register value.

        In 64-bit mode, CS is typically 0x33, while in 32-bit mode it's 0x23.
        The second-lowest bit (bit 1) of CS indicates the privilege level:
        - When 0, kernel mode
        - When 1, user mode
        The third-lowest bit (bit 2) indicates the execution mode:
        - When 0, compatibility mode (16/32-bit)
        - When 1, 64-bit long mode
        """
        # Prevent recursion
        if self._checking_mode:
            return False
            
        self._checking_mode = True
        try:
            # Check if the cs field is actually available in the structure
            # Access it directly as a field - not via masked access
            if hasattr(self._obj, "cs"):
                cs = self._obj.cs
                return (cs & 0x4) == 0  # If bit 2 is 0, we're in compatibility mode
            
            # Fallback to using flags register if cs isn't directly accessible
            elif hasattr(self._obj, "flags"):
                flags = self._obj.flags
                return (flags & (1 << 17)) != 0  # VM8086 mode check
            
            # Default: assume not in compatibility mode if we can't determine
            return False
        finally:
            self._checking_mode = False

    def get_register(self, reg_name):
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

    def set_register(self, reg_name, value):
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

    def get_syscall_arg(self, num):
        """Get x86_64 syscall argument, considering compatibility mode"""
        if self._is_compatibility_mode():
            # In 32-bit compatibility mode, use x86 syscall convention
            return self._get_x86_delegate().get_syscall_arg(num)

        # Default x86_64 syscall convention
        syscall_args = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
        if 0 <= num < len(syscall_args):
            return self.get_register(syscall_args[num])
        return None

    def get_userland_arg(self, num):
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
        
        return self.read_memory(addr, 8, 'ptr')

    def get_syscall_number(self):
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

    def __init__(self, obj, panda=None):
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

    def get_syscall_arg(self, num):
        """Get ARM syscall argument"""
        if 0 <= num < 7:  # r0-r6
            return self.get_register(f"r{num}")
        return None

    def get_userland_arg(self, num):
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
        return self.read_memory(addr, 4, 'ptr')

    def get_syscall_number(self):
        """Get syscall number from r7 register"""
        return self.get_register("r7")


class AArch64PtRegsWrapper(PtRegsWrapper):
    """Wrapper for AArch64 pt_regs"""

    def __init__(self, obj, panda=None):
        super().__init__(obj, panda=panda)
        # Map register names to access info
        self._register_map = {
            # General registers
            **{f"x{i}": ("array", "regs", i) for i in range(31)},
            "sp": "sp",
            "pc": "pc",
            "pstate": "pstate",
            "syscallno": "syscallno",
            "orig_x0": "orig_x0",
            # Aliases
            "retval": ("array", "regs", 0),
            # Common aliases for named registers
            "fp": ("array", "regs", 29),  # x29
            "lr": ("array", "regs", 30),  # x30
        }

        # Create a delegate for ARM mode access (but don't initialize it yet)
        self._arm_delegate = None

    def _is_aarch32_mode(self):
        """
        Check if the CPU is running in AArch32 (compatibility) mode
        based on the PSTATE register.

        PSTATE.nRW bit (bit 4) indicates the execution state:
        - When 0, AArch64 state
        - When 1, AArch32 state
        """
        pstate = self.get_register("pstate")
        # Bit 4 (0x10) is the nRW bit that indicates execution state
        return (pstate & 0x10) != 0

    def _get_arm_delegate(self):
        """
        Get or create an ARM registers delegate for AArch32 mode access
        """
        if self._arm_delegate is None:
            # Create delegate with our original object but use ARM wrapper
            # This is a simplified mapping as the real mapping would be more complex
            self._arm_delegate = ArmPtRegsWrapper(self._obj, panda=self._panda)
        return self._arm_delegate

    def get_register(self, reg_name):
        """
        Get register value by name, handling AArch32 compatibility mode if needed
        """
        # Check if we're in AArch32 mode and the register is an ARM register
        if self._is_aarch32_mode() and reg_name.startswith("r"):
            return self._get_arm_delegate().get_register(reg_name)

        # For AArch64 registers, proceed with standard access
        return super().get_register(reg_name)

    def set_register(self, reg_name, value):
        """
        Set register value by name, handling AArch32 compatibility mode if needed
        """
        # Check if we're in AArch32 mode and the register is an ARM register
        if self._is_aarch32_mode() and reg_name.startswith("r"):
            return self._get_arm_delegate().set_register(reg_name, value)

        # For AArch64 registers, proceed with standard access
        return super().set_register(reg_name, value)

    def get_syscall_arg(self, num):
        """Get AArch64 syscall argument, considering compatibility mode"""
        if self._is_aarch32_mode():
            # In AArch32 mode, use ARM syscall convention
            return self._get_arm_delegate().get_syscall_arg(num)

        # Default AArch64 syscall convention
        if 0 <= num < 8:  # x0-x7 for syscall args
            return self.get_register(f"x{num}")
        return None

    def get_userland_arg(self, num):
        """Get AArch64 userland argument, considering compatibility mode"""
        if self._is_aarch32_mode():
            # In AArch32 mode, use ARM userland convention
            return self._get_arm_delegate().get_userland_arg(num)

        # Default AArch64 userland convention
        if 0 <= num < 8:  # x0-x7 for first 8 args
            return self.get_register(f"x{num}")
        # Additional arguments would be on the stack
        return self.read_stack_arg(num - 8, word_size=8)

    def get_syscall_number(self):
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

    def __init__(self, obj, panda=None):
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

    def get_syscall_arg(self, num):
        """Get MIPS syscall argument"""
        if 0 <= num < 4:  # a0-a3 (r4-r7)
            return self.get_register(f"a{num}")
        # Arguments 4 and 5 are at a4 and a5 (r8 and r9 in o32 ABI)
        if num == 4:
            return self.get_register("r8")
        if num == 5:
            return self.get_register("r9")
        return None

    def get_userland_arg(self, num):
        """Get MIPS userland argument"""
        if 0 <= num < 4:  # a0-a3 for first 4 args
            return self.get_register(f"a{num}")
        # Additional arguments on the stack at $sp+16, +20, etc.
        sp = self.get_sp()
        if sp is not None:
            addr = sp + 16 + ((num - 4) * 4)  # MIPS stack args start at sp+16
            return self.read_memory(addr, 4, 'ptr')
        return None

    def get_syscall_number(self):
        """Get syscall number from v0 register"""
        return self.get_register("v0")


class Mips64PtRegsWrapper(MipsPtRegsWrapper):
    """Wrapper for MIPS64 pt_regs - same structure but different register meanings"""

    def __init__(self, obj, panda=None):
        super().__init__(obj, panda=panda)
        # Add MIPS64-specific register aliases (a4-a7 for arguments)
        self._register_map.update({
            "a4": ("array", "regs", 8),
            "a5": ("array", "regs", 9),
            "a6": ("array", "regs", 10),
            "a7": ("array", "regs", 11),
        })

    def get_syscall_arg(self, num):
        """Get MIPS64 syscall argument"""
        if 0 <= num < 8:  # a0-a7 (r4-r11)
            return self.get_register(f"a{num}")
        return None

    def get_userland_arg(self, num):
        """Get MIPS64 userland argument"""
        if 0 <= num < 8:  # a0-a7 for first 8 args
            return self.get_register(f"a{num}")
        # Additional arguments would be on the stack
        return self.read_stack_arg(num - 8, word_size=8)


class PowerPCPtRegsWrapper(PtRegsWrapper):
    """Wrapper for PowerPC pt_regs"""

    def __init__(self, obj, panda=None):
        super().__init__(obj, panda=panda)
        # PowerPC has numbered registers r0-r31
        self._register_map = {
            **{f"r{i}": ("array", "regs", i) for i in range(32)},
            "nip": ("computed", lambda obj: obj.nip),
            "msr": ("computed", lambda obj: obj.msr),
            "orig_r3": ("computed", lambda obj: obj.orig_gpr3),
            "ctr": ("computed", lambda obj: obj.ctr),
            "lr": ("computed", lambda obj: obj.link),
            "xer": ("computed", lambda obj: obj.xer),
            "ccr": ("computed", lambda obj: obj.ccr),
            "softe": ("computed", lambda obj: obj.softe),
            "trap": ("computed", lambda obj: obj.trap),
            "dar": ("computed", lambda obj: obj.dar),
            "dsisr": ("computed", lambda obj: obj.dsisr),
            "result": ("computed", lambda obj: obj.result),
            # Aliases
            "sp": ("array", "regs", 1),  # r1 is stack pointer
            "pc": "nip",
            "retval": ("array", "regs", 3),  # r3 holds return values
        }

    def get_syscall_arg(self, num):
        """Get PowerPC syscall argument"""
        if 0 <= num < 6:
            # r3-r8 for syscall args
            return self.get_register(f"r{3+num}")
        return None

    def get_userland_arg(self, num):
        """Get PowerPC userland argument"""
        if 0 <= num < 8:
            # r3-r10 for userland args
            return self.get_register(f"r{3+num}")
        # Additional arguments would be on the stack
        return self.read_stack_arg(num - 8, word_size=8)

    def get_syscall_number(self):
        """Get syscall number from r0 register"""
        return self.get_register("r0")


class PowerPC64PtRegsWrapper(PowerPCPtRegsWrapper):
    """Wrapper for PowerPC64 pt_regs - same structure as PowerPC"""
    pass


class LoongArch64PtRegsWrapper(PtRegsWrapper):
    """Wrapper for LoongArch64 pt_regs"""

    def __init__(self, obj, panda=None):
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

    def get_syscall_arg(self, num):
        """Get LoongArch64 syscall argument"""
        if 0 <= num < 8:
            # a0-a7 for syscall args
            return self.get_register(f"a{num}")
        return None

    def get_userland_arg(self, num):
        """Get LoongArch64 userland argument"""
        if 0 <= num < 8:
            # a0-a7 for userland args
            return self.get_register(f"a{num}")
        # Additional arguments would be on the stack
        return self.read_stack_arg(num - 8, word_size=8)

    def get_syscall_number(self):
        """Get syscall number from a7 register"""
        return self.get_register("a7")


class Riscv32PtRegsWrapper(PtRegsWrapper):
    """Wrapper for RISC-V 32-bit pt_regs"""

    def __init__(self, obj, panda=None):
        super().__init__(obj, panda=panda)
        # RISC-V has x0-x31 registers
        self._register_map = {
            **{f"x{i}": ("array", "regs", i) for i in range(32)},
            "pc": ("computed", lambda obj: obj.epc),
            "status": ("computed", lambda obj: obj.status),
            "badaddr": ("computed", lambda obj: obj.badaddr),
            "orig_a0": ("computed", lambda obj: obj.orig_a0),
            # Register aliases
            "zero": ("array", "regs", 0),
            "ra": ("array", "regs", 1),
            "sp": ("array", "regs", 2),
            "gp": ("array", "regs", 3),
            "tp": ("array", "regs", 4),
            "t0": ("array", "regs", 5),
            "t1": ("array", "regs", 6),
            "t2": ("array", "regs", 7),
            "s0": ("array", "regs", 8),
            "fp": ("array", "regs", 8),  # Alias for s0
            "s1": ("array", "regs", 9),
            "a0": ("array", "regs", 10),
            "a1": ("array", "regs", 11),
            "a2": ("array", "regs", 12),
            "a3": ("array", "regs", 13),
            "a4": ("array", "regs", 14),
            "a5": ("array", "regs", 15),
            "a6": ("array", "regs", 16),
            "a7": ("array", "regs", 17),
            "s2": ("array", "regs", 18),
            "s3": ("array", "regs", 19),
            "s4": ("array", "regs", 20),
            "s5": ("array", "regs", 21),
            "s6": ("array", "regs", 22),
            "s7": ("array", "regs", 23),
            "s8": ("array", "regs", 24),
            "s9": ("array", "regs", 25),
            "s10": ("array", "regs", 26),
            "s11": ("array", "regs", 27),
            "t3": ("array", "regs", 28),
            "t4": ("array", "regs", 29),
            "t5": ("array", "regs", 30),
            "t6": ("array", "regs", 31),
            # Aliases
            "retval": ("array", "regs", 10),  # a0
        }

    def get_syscall_arg(self, num):
        """Get RISC-V 32-bit syscall argument"""
        if 0 <= num < 8:
            # a0-a7 for syscall args
            return self.get_register(f"a{num}")
        return None

    def get_userland_arg(self, num):
        """Get RISC-V 32-bit userland argument"""
        if 0 <= num < 8:
            # a0-a7 for function args
            return self.get_register(f"a{num}")
        # Additional arguments would be on the stack
        return self.read_stack_arg(num - 8, word_size=4)

    def get_syscall_number(self):
        """Get syscall number from a7 register"""
        return self.get_register("a7")


class Riscv64PtRegsWrapper(Riscv32PtRegsWrapper):
    """Wrapper for RISC-V 64-bit pt_regs - same structure as 32-bit"""
    pass


def get_pt_regs_wrapper(panda, regs, arch_name=None):
    """
    Factory function to create the appropriate pt_regs wrapper based on architecture.

    Args:
        cpu: CPU object (may be used to determine architecture if arch_name not provided)
        regs: The pt_regs structure to wrap
        arch_name: Architecture name (optional, will be determined from CPU if not provided)

    Returns:
        An appropriate PtRegsWrapper subclass instance
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
