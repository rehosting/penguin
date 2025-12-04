"""
CAS (CPU Architecture State) Plugin
===================================

This plugin provides a high-performance, architecture-agnostic proxy for the panda.arch interface.
It replaces the default architecture plugin with a version that uses aggressive caching and precomputed
lookup tables for register and argument access. The goal is to accelerate all hot-path operations
(register/argument get/set, PC/retval access, etc.) by avoiding repeated string parsing, reflection,
and slow attribute lookups.

Purpose
-------

- Provides a drop-in replacement for panda.arch with much higher performance.
- Uses precomputed tables and caching for register and argument access.
- Implements all methods from panda.arch except for dump_stack and telescope-related methods,
  which are intentionally omitted for efficiency and separation of concerns.

Usage
-----

This plugin is loaded automatically as part of the penguin plugin system. Other plugins and core
infrastructure use it transparently in place of panda.arch.

Design
------

- On initialization, the plugin introspects the slow panda.arch and builds fast lookup tables.
- All hot-path methods (get_reg, set_reg, get_arg, set_arg, get_pc, set_pc, get_retval, set_retval)
  are hoisted to the plugin instance for maximum speed.
- Architecture-specific subclasses implement the details of register access for each supported CPU.

Example
-------

.. code-block:: python

    from penguin import plugins

    # Access registers and arguments efficiently
    eax = plugins.cas.get_reg(cpu, "EAX")
    plugins.cas.set_reg(cpu, "EAX", 0x1234)
    arg0 = plugins.cas.get_arg(cpu, 0)
    plugins.cas.set_retval(cpu, 0)

    # PC and SP access
    pc = plugins.cas.get_pc(cpu)
    plugins.cas.set_pc(cpu, new_pc)

Notes
-----

- All methods from panda.arch are implemented except for dump_stack and telescope-related methods.
- This plugin is intended for use in performance-critical code paths.

"""

# This module provides a high-performance proxy/wrapper for panda.arch,
# replacing the default architecture plugin with a version that uses
# aggressive caching and precomputed lookup tables for register and argument
# access. It is designed to accelerate all hot-path operations (register/argument
# get/set, PC/retval access, etc.) by avoiding repeated string parsing, reflection,
# and slow attribute lookups. All methods from panda.arch are implemented here
# except for dump_stack and telescope-related methods, which are intentionally
# omitted for efficiency and separation of concerns.

from penguin import Plugin

class CPUArchState(Plugin):
    """
    Optimized Architecture Plugin.
    Proxy that replaces panda.arch with high-performance cached lookups.

    This plugin provides a high-performance, drop-in replacement for panda.arch,
    using aggressive caching and precomputed lookup tables for register and argument
    access. All methods from panda.arch are implemented here except for dump_stack
    and telescope-related methods, which are intentionally omitted for efficiency.
    """
    
    def __init__(self, panda):
        self.panda = panda
        self.impl = self._select_implementation()
        
        # 1. Reflection: Learn layout from the slow panda.arch
        self.impl.ingest_panda_arch(self.panda.arch)
        
        # 2. Hoisting: Bind methods to self to avoid 'self.impl' dot-lookup in hot path
        self.get_reg = self.impl.get_reg
        self.set_reg = self.impl.set_reg
        self.get_arg = self.impl.get_arg
        self.set_arg = self.impl.set_arg
        self.get_pc = self.impl.get_pc
        self.set_pc = self.impl.set_pc
        self.get_retval = self.impl.get_retval
        self.set_retval = self.impl.set_retval
        # 3. Optimized get_cpu strategy
        self._init_get_cpu_strategy()

    def _init_get_cpu_strategy(self):
        """
        Determines the fastest safe way to retrieve the current CPU object.
        """
        smp = 1
        try:
            # Safely navigate config to find SMP count
            conf = self.get_arg("conf")
            if conf and "core" in conf:
                smp = int(conf["core"].get("smp", 1))
        except Exception:
            # If config lookup fails, assume safe default (1) or fallback to dynamic
            pass

        if smp == 1:
            # --- OPTIMIZATION: Single Core ---
            # In single-core mode, 'first_cpu' is the ONLY cpu. 
            # We cache the Python object once to avoid all CFFI overhead.
            self._cached_single_cpu = None
            
            def get_cpu_fast():
                if self._cached_single_cpu is None:
                    self._cached_single_cpu = self.panda.libpanda.get_cpu()
                return self._cached_single_cpu
            
            self.get_cpu = get_cpu_fast
            self.logger.debug("CAS: Enabled Single-CPU fast-path optimization")
        else:
            # --- SMP Mode ---
            # We must call C to check TLS (Thread Local Storage) every time.
            self.get_cpu = self.impl.get_cpu
            self.logger.debug(f"CAS: SMP={smp}, using dynamic CPU lookup")

    def _select_implementation(self):
        name = self.panda.arch_name
        # Return specific implementation or base if none exists
        if name == "i386":             return X86Impl(self.panda)
        elif name == "x86_64":         return X86_64Impl(self.panda)
        elif name == "arm":            return ArmImpl(self.panda)
        elif name == "aarch64":        return Aarch64Impl(self.panda)
        elif name.startswith("mips"):  return MipsImpl(self.panda)
        elif name.startswith("ppc"):   return PowerPCImpl(self.panda)
        elif name.startswith("riscv"): return RiscvImpl(self.panda)
        elif name == "loongarch64":    return LoongarchImpl(self.panda)
        else:
            self.logger.warning(f"Optimization not available for {name}, using generic fallback")
            return _BaseArchImpl(self.panda, 32, 'little')

class _BaseArchImpl:
    """Base implementation with caching logic."""
    def __init__(self, panda, bits, endianness):
        self.panda = panda
        self.bits = bits
        self.byte_order = endianness
        self.reg_size = bits // 8
        
        # CACHE: cpu_addr (int) -> CPUArchState (cdata)
        self._env_cache = {} 
        
        # CACHE: "REGNAME" -> int (index) OR lambda
        self._reg_accessors = {} 
        self._reg_setters = {}
        
        # CACHE: "convention" -> list of (int_index | tuple_stack_offset)
        self._arg_locators = {}
        
        self.sp_reg_idx = None 
        self.retval_reg_idx = None

    def ingest_panda_arch(self, source_arch):
        """Build optimized tables from standard panda.arch definitions."""
        # 1. Map Registers
        for name, idx in source_arch.registers.items():
            u_name = name.upper()
            # Only add if subclass hasn't already defined a specialized accessor (like SP)
            if u_name not in self._reg_accessors:
                self._reg_accessors[u_name] = idx
                self._reg_setters[u_name] = idx

        # 2. Map Special Regs
        self.sp_reg_idx = source_arch.reg_sp
        
        if source_arch.reg_retval:
            default_ret = source_arch.reg_retval.get('default')
            if default_ret:
                # Resolve the string name to an index NOW
                self.retval_reg_idx = self._reg_accessors.get(default_ret.upper())

        # 3. Map Arguments (The massive speedup for get_arg)
        if source_arch.call_conventions:
            self._register_arg_locators(source_arch.call_conventions)

    def _register_arg_locators(self, convention_map):
        for conv, args in convention_map.items():
            locators = []
            for arg in args:
                if arg.startswith("stack_"):
                    # Pre-calculate stack offset bytes
                    stack_idx = int(arg.split("_")[1])
                    offset = (stack_idx + 1) * self.reg_size 
                    locators.append(('stack', offset))
                else:
                    reg = arg.upper()
                    # Resolve to INT INDEX if possible
                    if reg in self._reg_accessors and isinstance(self._reg_accessors[reg], int):
                        locators.append(self._reg_accessors[reg])
                    else:
                        # Fallback to string (slower, but necessary for complex regs)
                        locators.append(reg)
            self._arg_locators[conv] = locators

    def _get_env(self, cpu):
        """
        Fastest way to get env. 
        Casts pointer address to int and looks up in python dict.
        """
        cpu_addr = int(self.panda.ffi.cast("uintptr_t", cpu))
        if cpu_addr in self._env_cache:
            return self._env_cache[cpu_addr]
        
        # Slow path (hit once per VCPU)
        env = self.panda.libpanda.panda_cpu_env(cpu)
        self._env_cache[cpu_addr] = env
        return env

    def get_reg(self, cpu, reg):
        # FAST PATH: Integer Index
        if isinstance(reg, int):
            return self._get_reg_by_index(self._get_env(cpu), reg)
        
        # STRING PATH: Dict Lookup
        reg_upper = reg.upper()
        accessor = self._reg_accessors.get(reg_upper)
        
        if isinstance(accessor, int):
            return self._get_reg_by_index(self._get_env(cpu), accessor)
        elif callable(accessor):
            return accessor(self._get_env(cpu))
        else:
            raise ValueError(f"Unknown register: {reg}")

    def set_reg(self, cpu, reg, val):
        if isinstance(reg, int):
            self._set_reg_by_index(self._get_env(cpu), reg, val)
            return

        reg_upper = reg.upper()
        setter = self._reg_setters.get(reg_upper)
        
        if isinstance(setter, int):
            self._set_reg_by_index(self._get_env(cpu), setter, val)
        elif callable(setter):
            setter(self._get_env(cpu), val)
        else:
            raise ValueError(f"Unknown register: {reg}")

    def get_arg(self, cpu, idx, convention='default'):
        # ULTRA FAST PATH
        # No string parsing, no "stack_" splitting, no calling conventions logic.
        # Just array lookups.
        try:
            loc = self._arg_locators[convention][idx]
        except (KeyError, IndexError):
            # Fallback to default if convention specific lookup failed
            if convention != 'default' and 'default' in self._arg_locators:
                 return self.get_arg(cpu, idx, 'default')
            raise ValueError(f"Arg {idx} not found for {convention}")

        if isinstance(loc, int):
            # Direct register index read
            return self._get_reg_by_index(self._get_env(cpu), loc)
        elif isinstance(loc, tuple) and loc[0] == 'stack':
            # Pre-calculated stack offset read
            offset = loc[1]
            env = self._get_env(cpu)
            
            # Get SP (Optimized)
            if isinstance(self.sp_reg_idx, int):
                sp_val = self._get_reg_by_index(env, self.sp_reg_idx)
            else:
                # SP is complex (e.g. AArch64 property), use slow path
                sp_val = self.get_reg(cpu, "SP")
                
            return self.panda.virtual_memory_read(cpu, sp_val + offset, self.reg_size, fmt='int')
        else:
            # Complex register name fallback
            return self.get_reg(cpu, loc)

    # Standard Helpers
    def set_arg(self, cpu, idx, val, convention='default'):
        # Logic mirrors get_arg but for writing
        try:
            loc = self._arg_locators[convention][idx]
        except (KeyError, IndexError):
             if convention != 'default' and 'default' in self._arg_locators:
                 return self.set_arg(cpu, idx, val, 'default')
             raise

        if isinstance(loc, int):
            self._set_reg_by_index(self._get_env(cpu), loc, val)
        elif isinstance(loc, tuple) and loc[0] == 'stack':
            offset = loc[1]
            env = self._get_env(cpu)
            if isinstance(self.sp_reg_idx, int):
                sp_val = self._get_reg_by_index(env, self.sp_reg_idx)
            else:
                sp_val = self.get_reg(cpu, "SP")
            val_bytes = val.to_bytes(self.reg_size, self.byte_order)
            self.panda.virtual_memory_write(cpu, sp_val + offset, val_bytes)
        else:
            self.set_reg(cpu, loc, val)

    def get_retval(self, cpu, convention='default'):
        # If we successfully resolved the retval register index at init
        if isinstance(self.retval_reg_idx, int):
            return self._get_reg_by_index(self._get_env(cpu), self.retval_reg_idx)
        # Fallback to slow lookup if retval reg is complex
        return self.get_reg(cpu, self.panda.arch.reg_retval[convention])

    def set_retval(self, cpu, val, convention='default', failure=False):
        """
        Sets the return value register.
        Supports the 'failure' flag for architectures that use a secondary register 
        (like MIPS A3) to indicate success/failure.
        """
        # Optimized path if we resolved the register index
        if isinstance(self.retval_reg_idx, int):
            self._set_reg_by_index(self._get_env(cpu), self.retval_reg_idx, val)
            return

        # Slow path fallback
        reg_name = self.panda.arch.reg_retval.get(convention, self.panda.arch.reg_retval['default'])
        self.set_reg(cpu, reg_name, val)

    # Abstract methods
    def _get_reg_by_index(self, env, idx): raise NotImplementedError
    def _set_reg_by_index(self, env, idx, val): raise NotImplementedError
    def get_pc(self, cpu): raise NotImplementedError
    def set_pc(self, cpu, val): raise NotImplementedError


# -----------------------------------------------------------------------------
# Implementations
# These are small shim classes that only define HOW to access the struct
# -----------------------------------------------------------------------------

class ArmImpl(_BaseArchImpl):
    def __init__(self, panda):
        super().__init__(panda, 32, 'little')
        # registers are populated by ingest_panda_arch
        
    def _get_reg_by_index(self, env, idx):
        return env.regs[idx]

    def _set_reg_by_index(self, env, idx, val):
        env.regs[idx] = val

    def get_pc(self, cpu):
        return self._get_env(cpu).regs[15]

    def set_pc(self, cpu, val):
        self._get_env(cpu).regs[15] = val

class Aarch64Impl(_BaseArchImpl):
    def __init__(self, panda):
        super().__init__(panda, 64, 'little')
        # SP in AArch64 often requires specific property access in PyPANDA/QEMU 
        # overriding the index-based lookups
        self._reg_accessors["SP"] = lambda env: env.sp 
        self._reg_setters["SP"] = lambda env, val: setattr(env, 'sp', val)

    def _get_reg_by_index(self, env, idx):
        return env.xregs[idx]

    def _set_reg_by_index(self, env, idx, val):
        env.xregs[idx] = val

    def get_pc(self, cpu):
        return self._get_env(cpu).pc

    def set_pc(self, cpu, val):
        self._get_env(cpu).pc = val

class X86_64Impl(_BaseArchImpl):
    def __init__(self, panda):
        super().__init__(panda, 64, 'little')
        
    def ingest_panda_arch(self, source_arch):
        super().ingest_panda_arch(source_arch)
        # Add 32-bit alias optimizations (EAX masking on RAX)
        for name, idx in source_arch.registers.items():
            if name.startswith('R') and not name[1].isdigit():
                e_name = 'E' + name[1:]
                # Add efficient masking lambda
                self._reg_accessors[e_name] = lambda env, i=idx: env.regs[i] & 0xFFFFFFFF
                self._reg_setters[e_name] = lambda env, val, i=idx: \
                    setattr(env.regs, i, (env.regs[i] & ~0xFFFFFFFF) | (val & 0xFFFFFFFF))

    def _get_reg_by_index(self, env, idx):
        return env.regs[idx]

    def _set_reg_by_index(self, env, idx, val):
        env.regs[idx] = val

    def get_pc(self, cpu):
        return self._get_env(cpu).eip

    def set_pc(self, cpu, val):
        self._get_env(cpu).eip = val
        
    def get_retval(self, cpu, convention='default'):
        # FreeBSD ABI Check
        env = self._get_env(cpu)
        val = env.regs[0] # RAX
        if convention == 'syscall' and self.panda.get_os_family() == 'OS_FREEBSD':
             if self.panda.libpanda.cpu_cc_compute_all(env, 1) & 1:
                 return -val
        return val

class X86Impl(_BaseArchImpl):
    def __init__(self, panda):
        super().__init__(panda, 32, 'little')

    def _get_reg_by_index(self, env, idx):
        return env.regs[idx]

    def _set_reg_by_index(self, env, idx, val):
        env.regs[idx] = val

    def get_pc(self, cpu):
        return self._get_env(cpu).eip

    def set_pc(self, cpu, val):
        self._get_env(cpu).eip = val

class MipsImpl(_BaseArchImpl):
    def __init__(self, panda, is_64=False):
        super().__init__(panda, 64 if is_64 else 32, 
                         'big' if 'el' not in panda.arch_name else 'little')
        self.a3_idx = 7 # Common index for A3

    def ingest_panda_arch(self, source_arch):
        super().ingest_panda_arch(source_arch)
        # Cache A3 index for retval error checking
        if 'A3' in self._reg_accessors:
            self.a3_idx = self._reg_accessors['A3']

    def _get_reg_by_index(self, env, idx):
        return env.active_tc.gpr[idx]

    def _set_reg_by_index(self, env, idx, val):
        env.active_tc.gpr[idx] = val

    def get_pc(self, cpu):
        return self._get_env(cpu).active_tc.PC

    def set_pc(self, cpu, val):
        self._get_env(cpu).active_tc.PC = val
        
    def get_retval(self, cpu, convention='default'):
        # MIPS Syscall error logic
        env = self._get_env(cpu)
        # V0 is usually index 2
        val = env.active_tc.gpr[2] 
        if convention == 'syscall':
            # Check A3
            if env.active_tc.gpr[self.a3_idx] == 1:
                return -val
        return val

    def set_retval(self, cpu, val, convention='default', failure=False):
        """
        MIPS override: Handles the A3 error register for syscalls.
        """
        env = self._get_env(cpu)
        
        if convention == 'syscall':
            # Set A3 (error flag) based on failure
            env.active_tc.gpr[self.a3_idx] = 1 if failure else 0
            
            # If failing, ensure the return value is positive (errno), 
            # as the kernel returns -ERRNO but sets A3=1 and V0=ERRNO
            if failure and val < 0:
                val = -val

        # Set V0 (Return Value)
        # We use index 2 directly as V0 is standard on MIPS32/64
        env.active_tc.gpr[2] = val

class PowerPCImpl(_BaseArchImpl):
    def __init__(self, panda, is_64=False):
        super().__init__(panda, 64 if is_64 else 32, 'big')
        # Non-GPR registers
        self._reg_accessors['LR'] = lambda env: env.lr
        self._reg_setters['LR'] = lambda env, val: setattr(env, 'lr', val)
        self._reg_accessors['CTR'] = lambda env: env.ctr
        self._reg_setters['CTR'] = lambda env, val: setattr(env, 'ctr', val)

    def _get_reg_by_index(self, env, idx):
        return env.gpr[idx]

    def _set_reg_by_index(self, env, idx, val):
        env.gpr[idx] = val

    def get_pc(self, cpu):
        return self._get_env(cpu).nip

    def set_pc(self, cpu, val):
        self._get_env(cpu).nip = val

class RiscvImpl(_BaseArchImpl):
    def __init__(self, panda, is_64=True):
        super().__init__(panda, 64 if is_64 else 32, 'little')

    def _get_reg_by_index(self, env, idx):
        return env.gpr[idx]

    def _set_reg_by_index(self, env, idx, val):
        env.gpr[idx] = val

    def get_pc(self, cpu):
        return self._get_env(cpu).pc

    def set_pc(self, cpu, val):
        self._get_env(cpu).pc = val

class LoongarchImpl(_BaseArchImpl):
    def __init__(self, panda):
        super().__init__(panda, 64, 'little')

    def _get_reg_by_index(self, env, idx):
        return env.gpr[idx]

    def _set_reg_by_index(self, env, idx, val):
        env.gpr[idx] = val

    def get_pc(self, cpu):
        return self._get_env(cpu).pc

    def set_pc(self, cpu, val):
        self._get_env(cpu).pc = val