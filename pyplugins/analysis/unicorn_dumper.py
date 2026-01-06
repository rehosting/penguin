"""
unicorndumper.py - Unicorn Context Dumper for Penguin
=====================================================

This plugin replicates the functionality of 'unicorn_dumper_gdb.py' for the Penguin
environment. It dumps the current state (registers, memory mappings, and memory content)
of a process to a directory, formatted for use with the AFL++ 'unicorn_loader.py'.

Features:
- Compatible with AFL++ unicorn_loader.py.
- Architecture-aware register mapping.
- Surgical uprobe repair: Uses the Uprobes plugin registry to identify and patch
  software breakpoints in the dump with original instruction bytes from StaticFS.
- Granular caching of patched bytes to minimize IO.
"""

import os
import json
import zlib
import hashlib
import time
import datetime
from typing import Any, Dict, List, Optional, Generator, Tuple

from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper


class UnicornDumper(Plugin):
    """
    UnicornDumper Plugin
    ====================
    Dumps process context (registers, memory) for Unicorn emulation.
    Compatible with AFL++ unicorn_loader.py.
    """

    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        # Cache key: (file_path, file_offset) -> original_bytes
        self._patch_cache: Dict[Tuple[str, int], bytes] = {}

    def _map_arch(self) -> str:
        """
        Map Penguin/PANDA architecture names to Unicorn-compatible architecture strings
        expected by unicorn_loader.py.
        """
        arch = self.panda.arch_name
        endian = getattr(self.panda, 'endianness', 'little')  # 'little' or 'big'
        
        if arch == "x86_64":
            return "x64"
        elif arch == "i386":
            return "x86"
        elif arch == "aarch64":
            return "arm64be" if endian == "big" else "arm64le"
        elif arch == "arm":
            # TODO: Add logic to detect THUMB mode if possible (cpsr & 0x20)
            return "armbe" if endian == "big" else "armle"
        elif arch == "mips":
            return "mips" # Big endian 32-bit
        elif arch == "mipsel":
            return "mipsel" # Little endian 32-bit
        elif arch == "mips64":
            return "mips64" # Big endian 64-bit
        elif arch == "mips64el":
            return "mips64el" # Little endian 64-bit
        elif arch == "ppc64":
            return "ppc64"
        elif arch == "riscv64":
            return "riscv64"
        
        # Fallback
        return arch

    def _dump_arch_info(self) -> Dict[str, str]:
        """Create the architecture info dictionary."""
        return {"arch": self._map_arch()}

    def _dump_regs(self, pt_regs: PtRegsWrapper) -> Dict[str, int]:
        """
        Dump registers from the PtRegsWrapper and normalize keys for unicorn_loader.py.
        """
        regs = pt_regs.dump()
        out_regs = {}
        arch = self._map_arch()
        
        # --- Normalization Logic ---
        
        for k, v in regs.items():
            if v is None:
                continue
            
            key = k.lower()
            val = v

            # x86 / x64
            if "x86" in arch or "x64" in arch:
                if key == "eflags":
                    out_regs["efl"] = val
                    continue
                # Loaders x86 map often excludes segment registers to avoid segfaults,
                # but x64 map includes them. We'll pass them; loader ignores if not in its map.
                out_regs[key] = val

            # ARM / AArch64
            elif "arm" in arch:
                if key == "pstate":
                    out_regs["cpsr"] = val
                    continue
                if key == "r13": out_regs["sp"] = val
                if key == "r14": out_regs["lr"] = val
                if key == "r15": out_regs["pc"] = val
                
                # AArch64 specific: x29->fp, x30->lr
                if "64" in arch:
                    if key == "x29": out_regs["fp"] = val
                    if key == "x30": out_regs["lr"] = val
                
                out_regs[key] = val

            # MIPS / MIPS64
            elif "mips" in arch:
                # MIPS loader expects names like 'v0', 'a0', 'zero', not just r0-r31
                # PtRegsWrapper usually provides 'r0'...'r31'.
                # We need to rely on PtRegsWrapper ALIASES if they are in the dump,
                # or map them manually if the dump only gives raw indices.
                # However, PtRegsWrapper.dump() includes the aliases.
                
                # Verify specific MIPS names required by loader:
                # "0" (zero), "at", "v0", "v1", "a0"..."a3", "t0"..."t7", "s0"..."s7", "t8", "t9", "k0", "k1", "gp", "sp", "fp", "ra"
                
                # If wrapper output keys like "zero", "a0" directly, we are good.
                # If it outputs "r0", we might need to map. 
                # Assuming PtRegsWrapper `dump()` produces the canonical aliases:
                if key == "r0": out_regs["0"] = val # Unicorn expects "0" for zero reg
                else: out_regs[key] = val

            # RISC-V
            elif "riscv" in arch:
                if key == "x0": out_regs["zero"] = val
                else: out_regs[key] = val

            else:
                out_regs[key] = val
            
        return out_regs

    def _dump_float(self) -> Dict[str, int]:
        """
        Dump floating point registers.
        Currently stubbed as standard syscall hooks rarely capture full FP state.
        """
        return {}

    def _cache_patches_from_file(self, path: str, offsets: List[int], patch_size: int) -> None:
        """
        Open the file once and populate the cache for all requested offsets.
        """
        if not offsets or not hasattr(plugins, "static_fs"):
            return

        try:
            f_obj = plugins.static_fs.open(path)
            if f_obj:
                try:
                    for offset in offsets:
                        # Skip if already cached by a previous operation
                        if (path, offset) in self._patch_cache:
                            continue
                            
                        f_obj.seek(offset)
                        data = f_obj.read(patch_size)
                        if data and len(data) == patch_size:
                            self._patch_cache[(path, offset)] = data
                finally:
                    f_obj.close()
        except Exception as e:
            self.logger.warning(f"Failed to read patches from {path}: {e}")

    def _dump_process_memory(self, dump_dir: str) -> Generator[Any, Any, List[Dict]]:
        """
        Iterate through memory mappings, dump content to files, and return segment info.
        Performs surgical patching of registered uprobes using granular caching.
        """
        final_segment_list = []
        
        # 1. Get Memory Mappings via OSI
        mappings = yield from plugins.OSI.get_mappings()
        
        if not mappings:
            self.logger.warning("No mappings found.")
            return final_segment_list

        # --- Uprobes Setup ---
        uprobes_list = []
        if hasattr(plugins, "uprobes"):
            uprobes_list = list(plugins.uprobes.probe_info.values())
        
        # Determine patch size based on architecture
        arch = self.panda.arch_name
        if arch in ["x86_64", "i386"]:
            patch_size = 1
        else:
            patch_size = 4

        # 2. Iterate and Dump
        for entry in mappings:
            if entry.start == entry.end:
                continue

            seg_info = {
                "start": entry.start,
                "end": entry.end,
                "name": entry.name,
                "permissions": {
                    "r": entry.read,
                    "w": entry.write,
                    "x": entry.exec,
                },
                "content_file": "",
            }

            if entry.read:
                try:
                    size = entry.end - entry.start
                    
                    # Read memory content (includes dynamic data + breakpoints)
                    seg_content = yield from plugins.mem.read_bytes(entry.start, size)
                    
                    if not seg_content:
                        self.logger.debug(f"Segment empty or unreadable: {entry.start:#x} {entry.name}")
                    else:
                        # 3. Surgical Patching
                        # Only attempt patch if we have uprobes, the segment is executable, and has a name
                        if uprobes_list and entry.exec and entry.name:
                            
                            # Filter probes relevant to this file
                            relevant_probes = [
                                p for p in uprobes_list 
                                if p["path"] == entry.name or p["path"] in entry.name
                            ]
                            
                            if relevant_probes:
                                # Identify probes that fall within this specific memory mapping window
                                base_file_offset = getattr(entry, "offset", 0)
                                mapping_probes = []
                                missing_cache_offsets = []

                                for p in relevant_probes:
                                    p_offset = p["offset"]
                                    if base_file_offset <= p_offset < (base_file_offset + size):
                                        mapping_probes.append(p)
                                        if (entry.name, p_offset) not in self._patch_cache:
                                            missing_cache_offsets.append(p_offset)
                                
                                # Batch fetch any missing patches for this file
                                if missing_cache_offsets:
                                    self._cache_patches_from_file(entry.name, missing_cache_offsets, patch_size)

                                # Apply patches from cache
                                if mapping_probes:
                                    mutable_content = bytearray(seg_content)
                                    patched_count = 0
                                    
                                    for p in mapping_probes:
                                        p_offset = p["offset"]
                                        cache_key = (entry.name, p_offset)
                                        
                                        if cache_key in self._patch_cache:
                                            # Calculate index in the memory buffer
                                            idx = p_offset - base_file_offset
                                            original_bytes = self._patch_cache[cache_key]
                                            
                                            # Ensure bounds
                                            if idx + len(original_bytes) <= len(mutable_content):
                                                mutable_content[idx : idx + len(original_bytes)] = original_bytes
                                                patched_count += 1
                                    
                                    if patched_count > 0:
                                        self.logger.debug(f"Repaired {patched_count} uprobes in {entry.name} @ {entry.start:#x}")
                                        seg_content = bytes(mutable_content)

                        # Compress content
                        compressed_content = zlib.compress(seg_content)
                        
                        # MD5 hash for filename
                        md5_sum = hashlib.md5(compressed_content).hexdigest() + ".bin"
                        seg_info["content_file"] = md5_sum
                        
                        # Write to disk
                        file_path = os.path.join(dump_dir, md5_sum)
                        with open(file_path, "wb") as f:
                            f.write(compressed_content)
                            
                except Exception as e:
                    self.logger.error(f"Exception reading segment {entry.name} at {entry.start:#x}: {e}")
            
            final_segment_list.append(seg_info)
            
        return final_segment_list

    def dump_context(self, pt_regs: PtRegsWrapper,
                     output_subdir: Optional[str] = None) -> Generator[Any, Any, str]:
        """
        Perform the full context dump.
        """
        # 1. Setup Output Directory
        if output_subdir:
            dir_name = output_subdir
        else:
            timestamp = datetime.datetime.fromtimestamp(time.time()).strftime("%Y%m%d_%H%M%S")
            dir_name = f"UnicornContext_{timestamp}"
            
        output_path = os.path.join(self.outdir, dir_name)
        if not os.path.exists(output_path):
            os.makedirs(output_path)
            
        self.logger.info(f"Starting Unicorn context dump to {output_path}")

        # 2. Gather Data
        arch_info = self._dump_arch_info()
        regs_info = self._dump_regs(pt_regs)
        regs_ext_info = self._dump_float()
        
        # dump_process_memory is a generator
        segments_info = yield from self._dump_process_memory(output_path)

        # 3. Construct Context Dictionary
        context = {
            "arch": arch_info,
            "regs": regs_info,
            "regs_extended": regs_ext_info,
            "segments": segments_info,
        }

        # 4. Write Index File
        index_path = os.path.join(output_path, "_index.json")
        with open(index_path, "w") as f:
            json.dump(context, f, indent=4)
            
        self.logger.info(f"Unicorn context dump completed: {index_path}")
        return output_path