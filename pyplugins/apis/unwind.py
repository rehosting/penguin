"""
Unwind Plugin (unwind.py)
=========================

Advanced stack unwinding using DWARF CFI and Heuristics with Capstone-powered
instruction validation for multi-architecture support.

Dependencies:
- capstone (pip install capstone)
- penguin.plugins.*
"""

import bisect
from typing import Optional, List, Dict, Any, Generator, Tuple

# External Libs
try:
    from capstone import *
    from capstone.arm import *
    from capstone.arm64 import *
    from capstone.mips import *
    from capstone.ppc import *
    from capstone.x86 import *
    from capstone.riscv import *
    HAVE_CAPSTONE = True
except ImportError:
    HAVE_CAPSTONE = False

from elftools.elf.elffile import ELFFile
from elftools.dwarf.callframe import FDE
from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper

class ArchInfo:
    def __init__(self, name, ptr_size, endian, dwarf_map, cs_arch, cs_mode, call_offset):
        self.name = name
        self.ptr_size = ptr_size
        self.endian = endian
        self.dwarf_map = dwarf_map
        self.cs_arch = cs_arch
        self.cs_mode = cs_mode
        self.call_offset = call_offset  # Distance from Return Address to Call Instr


# DWARF Register Mappings (Standard ABI)
# Note: "pc_reg" is often virtual or LR depending on arch
X86_64_MAP = {"sp_reg": 7, "ra_reg": 16, "fp_reg": 6}
ARM_MAP = {"sp_reg": 13, "ra_reg": 14, "fp_reg": 11}  # R13=SP, R14=LR, R11=FP
ARM64_MAP = {"sp_reg": 31, "ra_reg": 30, "fp_reg": 29}  # X29=FP, X30=LR
MIPS_MAP = {"sp_reg": 29, "ra_reg": 31, "fp_reg": 30}  # $29=SP, $31=RA, $30=FP
# R1=SP, LR=65 (DWARF), R31=Frame
PPC_MAP = {"sp_reg": 1, "ra_reg": 65, "fp_reg": 31}
RISCV_MAP = {"sp_reg": 2, "ra_reg": 1, "fp_reg": 8}    # x2=SP, x1=RA, x8=FP/s0

# Architecture Definitions
# Call Offset:
#   x86: 5 (usually)
#   MIPS: 8 (Delay slot!)
#   RISCV/ARM/PPC: 4
CONFIGS = {
    # Intel
    "intel64":      ArchInfo("x86_64", 8, "little", X86_64_MAP, CS_ARCH_X86, CS_MODE_64, 5),

    # ARM
    "armel":        ArchInfo("arm",    4, "little", ARM_MAP,    CS_ARCH_ARM, CS_MODE_ARM, 4),
    "aarch64":      ArchInfo("arm64",  8, "little", ARM64_MAP,  CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, 4),

    # MIPS (Note: MIPS uses delay slots, so RA is Instr+8)
    "mipsel":       ArchInfo("mips",   4, "little", MIPS_MAP,   CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN, 8),
    "mipseb":       ArchInfo("mips",   4, "big",    MIPS_MAP,   CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN,    8),
    "mips64el":     ArchInfo("mips64", 8, "little", MIPS_MAP,   CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN, 8),
    "mips64eb":     ArchInfo("mips64", 8, "big",    MIPS_MAP,   CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN,    8),

    # PowerPC
    "powerpc":      ArchInfo("ppc",    4, "big",    PPC_MAP,    CS_ARCH_PPC, CS_MODE_32 + CS_MODE_BIG_ENDIAN, 4),
    "powerpc64":    ArchInfo("ppc64",  8, "big",    PPC_MAP,    CS_ARCH_PPC, CS_MODE_64 + CS_MODE_BIG_ENDIAN, 4),
    "powerpc64le":  ArchInfo("ppc64",  8, "little", PPC_MAP,    CS_ARCH_PPC, CS_MODE_64 + CS_MODE_LITTLE_ENDIAN, 4),

    # RISC-V
    "riscv64":      ArchInfo("riscv",  8, "little", RISCV_MAP,  CS_ARCH_RISCV, CS_MODE_RISCV64, 4),

    # LoongArch (Requires very new Capstone, generic fallback if missing)
    "loongarch64":  ArchInfo("loongarch", 8, "little", {"sp_reg": 3, "ra_reg": 1, "fp_reg": 22}, None, None, 4),
}


class StackUnwinder(Plugin):
    def __init__(self):
        self._elf_cache = {}
        self._arch_info = None
        self._reverse_sym_cache = {}
        self._is_pie_cache = {}
        self._md = None  # Capstone instance
        self.logger.setLevel("DEBUG")

        if not HAVE_CAPSTONE:
            self.logger.warning(
                "Capstone not found. Heuristic unwinding will be severely limited.")

    def _init_capstone(self, arch: ArchInfo):
        """Initialize Capstone disassembler for the target architecture."""
        if not HAVE_CAPSTONE or not arch.cs_arch:
            return
        if self._md:
            return

        try:
            self._md = Cs(arch.cs_arch, arch.cs_mode)
            # Enable detailed instruction info (operands)
            self._md.detail = True
        except Exception as e:
            self.logger.error(f"Failed to init Capstone for {arch.name}: {e}")
            self._md = None

    def _get_arch_info(self) -> ArchInfo:
        if self._arch_info:
            return self._arch_info
        conf = self.get_arg("conf")
        if not conf:
            return CONFIGS["intel64"]

        # Normalize config string
        arch_str = conf.get("core", {}).get("arch")
        if arch_str not in CONFIGS:
            self.logger.warning(
                f"Unknown arch '{arch_str}', defaulting to intel64")
            return CONFIGS["intel64"]

        info = CONFIGS[arch_str]
        self._init_capstone(info)
        return info

    def _validate_call_capstone(self, addr: int, data: bytes, func_start: Optional[int]) -> Tuple[bool, bool]:
        """
        Uses Capstone to validate if bytes at `addr` are a Call/Branch-Link instruction.
        Returns: (Is_Call_Instruction, Linkage_Confirmed)
        """
        if not self._md:
            return True, None  # Permissive fallback if no capstone

        try:
            # Disassemble one instruction
            insns = list(self._md.disasm(data, addr))
            if not insns:
                return False, False
            insn = insns[0]

            # 1. Group Check: Is it a Call?
            # CS_GRP_CALL covers x86 CALL, ARM BL, MIPS JAL/JALR, etc.
            if not (insn.group(CS_GRP_CALL) or insn.group(CS_GRP_BRANCH_RELATIVE)):
                # Edge case: RISC-V JAL is often just a jump, but acts as call if rd=ra
                # Simpler to be slightly permissive on pure branches if they link registers
                return False, False

            # 2. Linkage Check (Ghost Frame Filter)
            if func_start is None:
                return True, None  # Cannot verify linkage without symbol info

            # Check if operands point to func_start
            # This is complex across archs, simplified here:
            for op in insn.operands:
                if op.type == CS_OP_IMM:
                    target = op.imm
                    # Handle relative vs absolute logic implicitly via Capstone
                    if target == func_start:
                        return True, True
                    # Heuristic: If it calls a DIFFERENT function, it's a Ghost Frame
                    if abs(target - addr) > 0x100000:  # Far jump logic
                        return True, False

            # If indirect call (register), we can't verify linkage statically
            return True, None

        except Exception as e:
            # self.logger.debug(f"Capstone error at {addr:#x}: {e}")
            return False, False

    def _get_elf_for_mapping(self, path: str) -> Optional[ELFFile]:
        if path in self._elf_cache:
            return self._elf_cache[path]
        try:
            f = plugins.static_fs.open(path)
            if not f:
                return None
            elf = ELFFile(f)
            self._elf_cache[path] = elf
            try:
                self._is_pie_cache[path] = (elf.header.e_type == 'ET_DYN')
            except Exception:
                self._is_pie_cache[path] = True
            return elf
        except Exception:
            return None

    def _prepare_reverse_lookup(self, path: str):
        if path in self._reverse_sym_cache:
            return
        offsets = []
        try:
            sym_db = plugins.symbols._load_symbols_db()
            if sym_db and path in sym_db:
                offsets = sorted(
                    [(off, name) for name, off in sym_db[path].items() if isinstance(off, int)])
        except AttributeError:
            pass
        if not offsets:
            try:
                plugins.symbols.lookup(path, "__force_load__")
                sym_db = plugins.symbols._load_symbols_db()
                if sym_db and path in sym_db:
                    offsets = sorted(
                        [(off, name) for name, off in sym_db[path].items() if isinstance(off, int)])
            except Exception:
                pass
        self._reverse_sym_cache[path] = offsets

    def _resolve_symbol(self, path: str, address: int) -> Tuple[str, int]:
        self._prepare_reverse_lookup(path)
        sorted_syms = self._reverse_sym_cache.get(path, [])
        if not sorted_syms:
            return "unknown", 0
        idx = bisect.bisect_right(sorted_syms, (address, ""))
        if idx == 0:
            return "unknown", 0
        sym_addr, sym_name = sorted_syms[idx - 1]
        diff = address - sym_addr
        if diff > 0x10000:
            return "unknown", 0
        return sym_name, diff

    def _normalize_mappings(self, raw_mappings: Any) -> Tuple[List[Any], Dict[str, int]]:
        self.logger.debug(f"Normalizing {len(raw_mappings)} mappings...")
        sorted_maps = sorted(list(raw_mappings), key=lambda x: x.base)
        normalized = []
        lib_bases = {}
        last_named_map = None
        for m in sorted_maps:
            name = m.name
            if (not name or name == "[anonymous]" or name == "/dev/zero") and last_named_map:
                if m.base - (last_named_map.base + last_named_map.size) < 0x2000:
                    self.logger.debug(
                        f"  Stitching {m.base:#x} to {last_named_map.name}")
                    m.name = last_named_map.name
                    name = m.name
            if name and not name.startswith("[") and name != "/dev/zero":
                last_named_map = m
                if name not in lib_bases:
                    lib_bases[name] = m.base
                else:
                    lib_bases[name] = min(lib_bases[name], m.base)
            normalized.append(m)
        return normalized, lib_bases

    def unwind(self, regs: PtRegsWrapper) -> Generator[Any, None, List[Dict[str, Any]]]:
        self.logger.info("--- Starting Multi-Arch Unwind ---")
        frames = []
        arch = self._get_arch_info()
        dwarf_map = arch.dwarf_map

        current_ip = regs.get_pc()
        current_sp = regs.get_sp()

        # Init Regs for DWARF
        current_regs = {}
        if dwarf_map:
            current_regs[dwarf_map["sp_reg"]] = current_sp
            # Attempt to populate generic regs (r0-r31)
            for i in range(32):
                rname = f"r{i}"
                val = regs.get_register(rname)
                if val is not None:
                    current_regs[i] = val

        raw_mappings = yield from plugins.osi.get_mappings()
        sorted_maps, lib_bases = self._normalize_mappings(raw_mappings)

        visited_sps = {current_sp}

        for depth in range(64):
            # 1. Symbol Resolution
            sym_name = "unknown"
            sym_diff = 0
            module_name = "unknown"
            map_offset = 0

            # Find mapping
            mapping = None
            for m in sorted_maps:
                if m.base <= current_ip < m.base + m.size:
                    mapping = m
                    break

            if mapping:
                module_name = mapping.name
                map_offset = current_ip - mapping.base
                if module_name and not module_name.startswith("["):
                    # PIE logic
                    is_pie = self._is_pie_cache.get(module_name, True)
                    lookup = current_ip
                    if is_pie:
                        if module_name in lib_bases:
                            lookup = current_ip - lib_bases[module_name]
                        else:
                            lookup = current_ip - mapping.base

                    sym_name, sym_diff = self._resolve_symbol(
                        module_name, lookup)

            repr_str = f"{current_ip:#x}"
            if sym_name != "unknown":
                repr_str = f"{module_name}!{sym_name}+{sym_diff:#x}"

            frames.append({
                "depth": depth, "ip": current_ip, "sp": current_sp,
                "module": module_name, "symbol": sym_name, "repr": repr_str,
                "offset": map_offset,
            })

            # 2. Next State Determination
            next_state = None
            method = "failed"

            # A. DWARF CFI
            if dwarf_map:
                try:
                    next_state = yield from self._unwind_frame_dwarf(current_ip, current_regs, mapping, arch)
                    if next_state:
                        method = "dwarf"
                except Exception:
                    pass

            # B. Heuristic (Stack Scan)
            if not next_state:
                # FIX: Calculate function start for ghost frame filtering
                func_start_addr = (
                    current_ip - sym_diff) if sym_name != "unknown" else None

                # FIX: Pass func_start_addr to the heuristic
                next_state = yield from self._unwind_frame_heuristic(current_sp, current_ip, sorted_maps, arch, func_start_addr)

                if next_state:
                    method = "heuristic"

            if not next_state:
                self.logger.debug(
                    f"  Unwind stopped at depth {depth}: No method succeeded.")
                break

            current_ip, new_regs = next_state

            # Update SP
            if dwarf_map:
                current_sp = new_regs.get(dwarf_map["sp_reg"], current_sp)
            else:
                # For heuristic, we must trust the SP returned (which is usually the RA location + ptr size)
                # If heuristic didn't return a reg map, we have to infer SP.
                # In the _unwind_frame_heuristic I provided, it returns new_regs with SP, so we are good.
                if arch.dwarf_map and arch.dwarf_map["sp_reg"] in new_regs:
                    current_sp = new_regs[arch.dwarf_map["sp_reg"]]

            current_regs = new_regs
            frames[-1]["method"] = method

            if current_sp in visited_sps:
                self.logger.warning(f"  Loop detected at SP {current_sp:#x}")
                break
            visited_sps.add(current_sp)
            if current_ip == 0:
                break

        return frames

    def _unwind_frame_dwarf(self, pc, regs, mapping, arch):
        if not mapping or not mapping.name or mapping.name.startswith("["):
            return None
        elf = self._get_elf_for_mapping(mapping.name)
        if not elf or not elf.has_dwarf_info():
            return None
        rel_pc = pc - mapping.base + mapping.offset
        dwarf = elf.get_dwarf_info()
        if not dwarf.has_CFI():
            return None

        fde = None
        for entry in dwarf.CFI_entries():
            if isinstance(entry, FDE) and entry.header.initial_location <= rel_pc < entry.header.initial_location + entry.header.address_range:
                fde = entry
                break
        if not fde:
            return None

        decoded = fde.get_decoded()
        rule_row = next((r for r in reversed(decoded) if r.pc <= rel_pc), None)
        if not rule_row:
            return None

        cfa = regs.get(rule_row.cfa.reg, 0) + rule_row.cfa.offset
        new_regs = regs.copy()
        new_regs[arch.dwarf_map["sp_reg"]] = cfa

        ret_addr = 0
        ra_reg = arch.dwarf_map["ra_reg"]
        ra_rule = rule_row.regs.get(ra_reg)

        if not ra_rule:
            ret_addr = regs.get(ra_reg, 0)
        elif ra_rule[0] == 'OFFSET':
            data = yield from plugins.mem.read_bytes(cfa + ra_rule[1], arch.ptr_size)
            if data:
                ret_addr = int.from_bytes(data, byteorder=arch.endian)

        if ret_addr == 0:
            return None
        return ret_addr, new_regs

    def _unwind_frame_fp(self, fp, mappings, arch):
        try:
            w1 = yield from plugins.mem.read_bytes(fp, arch.ptr_size)
            w2 = yield from plugins.mem.read_bytes(fp + arch.ptr_size, arch.ptr_size)
            if not w1 or not w2:
                return None

            val1 = int.from_bytes(w1, byteorder=arch.endian)
            val2 = int.from_bytes(w2, byteorder=arch.endian)

            ra, next_fp = 0, 0

            def is_code(addr):
                for m in mappings:
                    if m.base <= addr < m.base + m.size:
                        return m.exec
                return False

            if is_code(val2):
                ra, next_fp = val2, val1
            elif is_code(val1):
                ra, next_fp = val1, val2
            else:
                return None

            if next_fp <= fp:
                return None

            new_regs = {
                arch.dwarf_map["sp_reg"]: fp + (arch.ptr_size * 2),
                arch.dwarf_map["fp_reg"]: next_fp
            }
            return ra, new_regs
        except Exception:
            return None

    def _resolve_symbol(self, path: str, address: int) -> Tuple[str, int]:
        """
        Returns (symbol_name, offset_from_start).
        """
        self._prepare_reverse_lookup(path)
        sorted_syms = self._reverse_sym_cache.get(path, [])
        if not sorted_syms:
            return "unknown", 0
        idx = bisect.bisect_right(sorted_syms, (address, ""))
        if idx == 0:
            return "unknown", 0
        sym_addr, sym_name = sorted_syms[idx - 1]
        diff = address - sym_addr
        # Sanity check: reasonable function size (e.g., 64KB)
        if diff > 0x10000:
            return "unknown", 0
        return sym_name, diff

    def _verify_linkage(self, arch, call_site_addr, call_instr, current_func_start):
        """
        Verifies if the CALL instruction at call_site_addr actually targets
        the function we are currently in (current_func_start).
        Returns: True (Valid), False (Invalid), None (Cannot Determine/Indirect)
        """
        if not current_func_start:
            return None  # We don't know where we are, so we can't filter.

        if arch.name.startswith("mips"):
            # Decode MIPS JAL (0000 11xx ...) -> Opcode 0x03
            opcode = (call_instr >> 26) & 0x3F
            if opcode == 0x03:
                # Target Calculation: (PC & 0xF0000000) | (target << 2)
                # PC used is the address of the Delay Slot (call_site + 4)
                target_idx = call_instr & 0x03FFFFFF
                delay_slot = call_site_addr + 4
                target_addr = (delay_slot & 0xF0000000) | (target_idx << 2)

                # Strict check: The call MUST target the start of the current function
                if target_addr != current_func_start:
                    return False
                return True

            # Helper: Handle JALR (Op 0x00, Funct 0x09) -> Indirect
            # We cannot statically verify indirect calls. We must be permissive.
            funct = call_instr & 0x3F
            if opcode == 0x00 and funct == 0x09:
                return None

        elif arch.name == "x86_64":
            # Basic relative CALL (E8 xx xx xx xx) check
            if (call_instr & 0xFF) == 0xE8:
                rel_offset = (call_instr >> 8) & 0xFFFFFFFF
                # Sign extend 32-bit offset
                if rel_offset & 0x80000000:
                    rel_offset -= 0x100000000

                # Target = Next IP + Offset
                next_ip = call_site_addr + 5
                target_addr = next_ip + rel_offset

                if target_addr != current_func_start:
                    return False
                return True

        # Default to permissive if we can't decode the arch specific call
        return None

    def _unwind_frame_heuristic(self, sp, current_ip, mappings, arch, current_func_start):
        try:
            # Read stack window (Scan 1KB)
            stack_data = yield from plugins.mem.read_bytes(sp, 1024)
        except Exception:
            return None
        if not stack_data:
            return None

        ptr_size = arch.ptr_size
        endian = arch.endian

        # Pre-calculate call offset logic
        call_offset = arch.call_offset

        # 1. Scan Stack for Pointers
        for i in range(0, len(stack_data), ptr_size):
            chunk = stack_data[i:i+ptr_size]
            possible_ra = int.from_bytes(chunk, byteorder=endian)

            # Filter 1: Basic constraints
            if possible_ra < 0x1000 or (possible_ra & 1):
                continue
            if possible_ra == current_ip:
                continue

            # Filter 2: Executable Memory Check
            target_map = next((m for m in mappings if m.base <=
                              possible_ra < m.base + m.size), None)
            if not target_map or not target_map.exec:
                continue

            # Filter 3: Call Site Validation (The Core Logic)
            call_site_addr = possible_ra - call_offset

            # Determine read size (x86 instructions vary, others fixed 4)
            read_len = 16 if "x86" in arch.name else 4

            instr_bytes = yield from plugins.mem.read_bytes(call_site_addr, read_len)
            if not instr_bytes:
                continue

            # Use Capstone to validate
            is_call, linkage = self._validate_call_capstone(
                call_site_addr, instr_bytes, current_func_start)

            if not is_call:
                continue

            if linkage is False:
                # Capstone determined this call targets a different function than the one we are in.
                # This is likely a stale pointer on the stack (Ghost Frame).
                self.logger.debug(
                    f"  [Heuristic] Rejecting {possible_ra:#x} - Linkage Mismatch")
                continue

            # Success
            new_sp = sp + i + ptr_size
            new_regs = {arch.dwarf_map["sp_reg"]: new_sp} if arch.dwarf_map else {}
            return possible_ra, new_regs

        return None
