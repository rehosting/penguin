"""
Unwind Plugin (unwind.py)
=========================

Advanced stack unwinding using DWARF CFI and Heuristics with Capstone-powered
instruction validation for multi-architecture support.

Dependencies:
- capstone (pip install capstone)
- penguin.plugins.*
- wrappers.ptregs_wrap
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


# DWARF Register Mappings (Standard ABI) for creating new states
# We still need these to interpret DWARF rules, but not for initial state.
X86_64_MAP = {"sp_reg": 7, "ra_reg": 16, "fp_reg": 6}
ARM_MAP = {"sp_reg": 13, "ra_reg": 14, "fp_reg": 11}  # R13=SP, R14=LR, R11=FP
ARM64_MAP = {"sp_reg": 31, "ra_reg": 30, "fp_reg": 29}  # X29=FP, X30=LR
MIPS_MAP = {"sp_reg": 29, "ra_reg": 31, "fp_reg": 30}  # $29=SP, $31=RA, $30=FP
PPC_MAP = {"sp_reg": 1, "ra_reg": 65, "fp_reg": 31}
# x2=SP, x1=RA, x8=FP/s0
RISCV_MAP = {"sp_reg": 2, "ra_reg": 1, "fp_reg": 8}

CONFIGS = {
    "intel64":      ArchInfo("x86_64", 8, "little", X86_64_MAP, CS_ARCH_X86, CS_MODE_64, 5),
    "armel":        ArchInfo("arm",    4, "little", ARM_MAP,    CS_ARCH_ARM, CS_MODE_ARM, 4),
    "aarch64":      ArchInfo("arm64",  8, "little", ARM64_MAP,  CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN, 4),
    "mipsel":       ArchInfo("mips",   4, "little", MIPS_MAP,   CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_LITTLE_ENDIAN, 8),
    "mipseb":       ArchInfo("mips",   4, "big",    MIPS_MAP,   CS_ARCH_MIPS, CS_MODE_MIPS32 + CS_MODE_BIG_ENDIAN,    8),
    "mips64el":     ArchInfo("mips64", 8, "little", MIPS_MAP,   CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_LITTLE_ENDIAN, 8),
    "mips64eb":     ArchInfo("mips64", 8, "big",    MIPS_MAP,   CS_ARCH_MIPS, CS_MODE_MIPS64 + CS_MODE_BIG_ENDIAN,    8),
    "powerpc":      ArchInfo("ppc",    4, "big",    PPC_MAP,    CS_ARCH_PPC, CS_MODE_32 + CS_MODE_BIG_ENDIAN, 4),
    "powerpc64":    ArchInfo("ppc64",  8, "big",    PPC_MAP,    CS_ARCH_PPC, CS_MODE_64 + CS_MODE_BIG_ENDIAN, 4),
    "powerpc64le":  ArchInfo("ppc64",  8, "little", PPC_MAP,    CS_ARCH_PPC, CS_MODE_64 + CS_MODE_LITTLE_ENDIAN, 4),
    "riscv64":      ArchInfo("riscv",  8, "little", RISCV_MAP,  CS_ARCH_RISCV, CS_MODE_RISCV64, 4),
    "loongarch64":  ArchInfo("loongarch", 8, "little", {"sp_reg": 3, "ra_reg": 1, "fp_reg": 22}, None, None, 4),
}


class StackUnwinder(Plugin):
    def __init__(self):
        self._elf_cache = {}
        self._fde_cache = {}
        self._arch_info = None
        self._reverse_sym_cache = {}
        self._is_pie_cache = {}
        self._md = None
        self.logger.setLevel("DEBUG")

        if not HAVE_CAPSTONE:
            self.logger.warning(
                "Capstone not found. Heuristic unwinding will be severely limited.")

    def _init_capstone(self, arch: ArchInfo):
        if not HAVE_CAPSTONE or not arch.cs_arch:
            return
        if self._md:
            return
        try:
            self._md = Cs(arch.cs_arch, arch.cs_mode)
            self._md.detail = True
        except Exception as e:
            self.logger.error(f"Failed to init Capstone for {arch.name}: {e}")
            self._md = None

    def _get_arch_info(self) -> ArchInfo:
        if self._arch_info:
            return self._arch_info
        conf = self.get_arg("conf")
        arch_str = conf.get("core", {}).get("arch") if conf else "intel64"
        if arch_str not in CONFIGS:
            arch_str = "intel64"
        info = CONFIGS[arch_str]
        self._init_capstone(info)
        return info

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

        # Initial State from Wrapper
        current_ip = regs.get_pc()
        current_sp = regs.get_sp()

        # Best effort FP retrieval using generic aliases in wrapper
        current_fp = None
        # Try generic aliases first (fp, rbp, s0, etc handled by wrapper)
        if "fp" in regs.REG_NAMES:
            current_fp = regs.get_register("fp")
        elif "ebp" in regs.REG_NAMES:
            current_fp = regs.get_register("ebp")
        elif "s0" in regs.REG_NAMES:
            current_fp = regs.get_register("s0")  # RISC-V FP
        elif "r11" in regs.REG_NAMES and "arm" in arch.name:
            current_fp = regs.get_register("r11")  # ARM FP

        # DWARF State tracking (Dictionary of register indices)
        # We only populate this fully if we are doing DWARF unwinding
        current_dwarf_regs = {}
        if dwarf_map:
            current_dwarf_regs[dwarf_map["sp_reg"]] = current_sp
            # Populate generics
            for i in range(32):
                val = regs.get_register(f"r{i}")
                if val is not None:
                    current_dwarf_regs[i] = val

        raw_mappings = yield from plugins.osi.get_mappings()
        sorted_maps, lib_bases = self._normalize_mappings(raw_mappings)

        visited_sps = {current_sp}

        for depth in range(64):
            # --- Symbol Resolution ---
            sym_name = "unknown"
            sym_diff = 0
            module_name = "unknown"
            map_offset = 0

            mapping = next((m for m in sorted_maps if m.base <=
                           current_ip < m.base + m.size), None)
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

            # --- Next State Determination ---
            # Tuple (next_ip, next_sp, next_fp, next_dwarf_regs)
            next_state = None
            method = "failed"

            # 1. DWARF CFI
            if dwarf_map:
                try:
                    # Pass the dict, get back (ret_addr, new_reg_dict)
                    dwarf_res = yield from self._unwind_frame_dwarf(current_ip, current_dwarf_regs, mapping, arch)
                    if dwarf_res:
                        d_ret, d_regs = dwarf_res
                        d_sp = d_regs.get(dwarf_map["sp_reg"], current_sp)
                        d_fp = d_regs.get(dwarf_map["fp_reg"], current_fp)
                        next_state = (d_ret, d_sp, d_fp, d_regs)
                        method = "dwarf"
                except Exception:
                    pass

            # 2. Frame Pointer
            if not next_state and current_fp and current_fp > 0:
                if abs(current_fp - current_sp) < 0x100000:
                    fp_res = yield from self._unwind_frame_fp(current_fp, sorted_maps, arch)
                    if fp_res:
                        f_ret, f_sp, f_fp = fp_res
                        # Clear dwarf regs, we lost context
                        next_state = (f_ret, f_sp, f_fp, {})
                        method = "frame_pointer"

            # 3. Heuristic
            if not next_state:
                func_start_addr = (
                    current_ip - sym_diff) if sym_name != "unknown" else None
                h_res = yield from self._unwind_frame_heuristic(current_sp, current_ip, sorted_maps, arch, func_start_addr)
                if h_res:
                    h_ret, h_sp = h_res
                    # Heuristic doesn't recover FP or full regs
                    next_state = (h_ret, h_sp, current_fp, {})
                    method = "heuristic"

            if not next_state:
                break

            current_ip, current_sp, current_fp, current_dwarf_regs = next_state
            frames[-1]["method"] = method

            if current_sp in visited_sps:
                self.logger.warning(f"  Loop detected at SP {current_sp:#x}")
                break
            visited_sps.add(current_sp)
            if current_ip == 0:
                break

        return frames

    def _unwind_frame_dwarf(self, pc, regs_dict, mapping, arch):
        if not mapping or not mapping.name or mapping.name.startswith("["):
            return None
        elf = self._get_elf_for_mapping(mapping.name)
        if not elf or not elf.has_dwarf_info():
            return None
        rel_pc = pc - mapping.base + mapping.offset

        # Optimized lookup (cache)
        cache_key = f"{mapping.name}_{rel_pc}"
        fde = self._fde_cache.get(cache_key)
        if not fde:
            dwarf = elf.get_dwarf_info()
            if not dwarf.has_CFI():
                return None
            # Still linear, but result is cached.
            # Ideally use an IntervalTree here for O(log n)
            for entry in dwarf.CFI_entries():
                if isinstance(entry, FDE) and entry.header.initial_location <= rel_pc < entry.header.initial_location + entry.header.address_range:
                    fde = entry
                    break
            if fde:
                self._fde_cache[cache_key] = fde

        if not fde:
            return None

        decoded = fde.get_decoded()
        rule_row = next((r for r in reversed(decoded) if r.pc <= rel_pc), None)
        if not rule_row:
            return None

        # Calculate CFA
        cfa = regs_dict.get(rule_row.cfa.reg, 0) + rule_row.cfa.offset
        new_regs = regs_dict.copy()
        new_regs[arch.dwarf_map["sp_reg"]] = cfa

        # Calculate Return Address
        ret_addr = 0
        ra_reg = arch.dwarf_map["ra_reg"]
        ra_rule = rule_row.regs.get(ra_reg)

        if not ra_rule:
            ret_addr = regs_dict.get(ra_reg, 0)
        elif ra_rule[0] == 'OFFSET':
            data = yield from plugins.mem.read_bytes(cfa + ra_rule[1], arch.ptr_size)
            if data:
                ret_addr = int.from_bytes(data, byteorder=arch.endian)

        if ret_addr == 0:
            return None
        return ret_addr, new_regs

    def _unwind_frame_fp(self, fp, mappings, arch):
        """
        Standard RBP/FP chain walking.
        Returns: (ret_addr, new_sp, new_fp)
        """
        # Read [FP] -> Old FP, [FP+Size] -> Ret Addr
        try:
            w1 = yield from plugins.mem.read_bytes(fp, arch.ptr_size)
            w2 = yield from plugins.mem.read_bytes(fp + arch.ptr_size, arch.ptr_size)
            if not w1 or not w2:
                return None

            next_fp = int.from_bytes(w1, byteorder=arch.endian)
            ra = int.from_bytes(w2, byteorder=arch.endian)

            # Sanity checks
            def is_code(addr):
                for m in mappings:
                    if m.base <= addr < m.base + m.size:
                        return m.exec
                return False

            if not is_code(ra):
                return None
            if next_fp <= fp:
                return None  # Stack must grow up

            # SP for next frame is usually just above where RA was saved
            new_sp = fp + (arch.ptr_size * 2)
            return ra, new_sp, next_fp
        except Exception:
            return None

    def _validate_call_capstone(self, addr: int, data: bytes, func_start: Optional[int]) -> Tuple[bool, bool]:
        """
        Returns: (Is_Call, Linkage_Confirmed)
        """
        if not self._md:
            return True, None
        try:
            insns = list(self._md.disasm(data, addr))
            if not insns:
                return False, False
            insn = insns[0]

            if not (insn.group(CS_GRP_CALL) or insn.group(CS_GRP_BRANCH_RELATIVE)):
                return False, False

            if func_start is None:
                return True, None

            for op in insn.operands:
                if op.type == CS_OP_IMM:
                    target = op.imm
                    if target == func_start:
                        return True, True
                    if abs(target - addr) > 0x100000:
                        return True, False

            return True, None
        except Exception:
            return False, False

    def _unwind_frame_heuristic(self, sp, current_ip, mappings, arch, current_func_start):
        stack_data = yield from plugins.mem.read_bytes(sp, 1024)
        if not stack_data:
            return None

        ptr_size = arch.ptr_size
        endian = arch.endian

        # We step through the stack looking for pointers
        for i in range(0, len(stack_data), ptr_size):
            chunk = stack_data[i:i+ptr_size]
            possible_ra = int.from_bytes(chunk, byteorder=endian)

            # Filter 1: Basic constraints
            if possible_ra < 0x1000 or (possible_ra & 1):
                continue
            if possible_ra == current_ip:
                continue

            # Filter 2: Executable Memory
            target_map = next((m for m in mappings if m.base <=
                              possible_ra < m.base + m.size), None)
            if not target_map or not target_map.exec:
                continue

            # Filter 3: Call Site Validation
            is_valid_call = False

            # X86 Backwards scan
            if "x86" in arch.name:
                scan_start = possible_ra - 16
                instr_bytes = yield from plugins.mem.read_bytes(scan_start, 16)
                if instr_bytes:
                    for offset in range(14, 0, -1):
                        candidate_data = instr_bytes[offset:]
                        if not candidate_data:
                            continue
                        try:
                            insn = next(self._md.disasm(
                                candidate_data, scan_start + offset))
                            if (scan_start + offset + insn.size) == possible_ra:
                                if insn.group(CS_GRP_CALL):
                                    is_valid_call = True
                                    break
                        except StopIteration:
                            pass

            # RISC Fixed offset
            else:
                call_offset = arch.call_offset
                call_site_addr = possible_ra - call_offset
                instr_bytes = yield from plugins.mem.read_bytes(call_site_addr, 4)
                if instr_bytes:
                    is_call, linkage = self._validate_call_capstone(
                        call_site_addr, instr_bytes, current_func_start)
                    # If we explicitly failed linkage (ghost frame), skip
                    if linkage is False:
                        continue
                    is_valid_call = is_call

            if is_valid_call:
                new_sp = sp + i + ptr_size
                return possible_ra, new_sp

        return None
