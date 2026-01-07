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

Example Usage
-----------------:

.. code-block:: python

    import struct
    from penguin import Plugin, plugins

    class Dumper(Plugin):
        @plugins.syscalls.syscall("on_sys_ioctl_return")
        def on_sys_ioctl_ret(self, regs, *args):
            yield from plugins.unicorn_dumper.dump_context(regs)

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
        patch_size = 1 if arch in ["x86_64", "i386"] else 4

        # 1. Pre-calculate Base Address for every library
        # The base address is the lowest start address associated with a given filename.
        library_bases = {}
        for m in mappings:
            if m.name:
                if m.name not in library_bases:
                    library_bases[m.name] = m.start
                else:
                    library_bases[m.name] = min(library_bases[m.name], m.start)

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
                        if uprobes_list and entry.name:
                            # Filter probes: Strict match on name
                            relevant_probes = [
                                p for p in uprobes_list 
                                if p["path"] == entry.name
                            ]
                            
                            if relevant_probes and entry.name in library_bases:
                                try:
                                    if hasattr(plugins, "static_fs"):
                                        f_obj = plugins.static_fs.open(entry.name)
                                        if f_obj:
                                            try:
                                                mutable_content = bytearray(seg_content)
                                                patched_count = 0
                                                
                                                # Determine Base Address for this library
                                                base_addr = library_bases[entry.name]

                                                for p in relevant_probes:
                                                    p_offset = p["offset"]
                                                    
                                                    # Calculate Target Virtual Address (Base + Offset)
                                                    target_virt_addr = base_addr + p_offset
                                                    
                                                    # Check if this target address falls inside the CURRENT segment
                                                    if entry.start <= target_virt_addr < (entry.start + size):
                                                        
                                                        # Calculate index into this segment's buffer
                                                        idx = target_virt_addr - entry.start
                                                        
                                                        # Seek and read original bytes from file
                                                        # (Assuming p_offset is also valid file offset for shared objs)
                                                        f_obj.seek(p_offset)
                                                        original_bytes = f_obj.read(patch_size)
                                                        
                                                        if len(original_bytes) == patch_size and idx + patch_size <= len(mutable_content):
                                                            current_bytes = mutable_content[idx : idx + patch_size]
                                                            
                                                            # Patch if different
                                                            if current_bytes != original_bytes:
                                                                self.logger.info(
                                                                    f"Patching at {entry.name}+{p_offset:#x} (Virt: {target_virt_addr:#x}): "
                                                                    f"Mem {current_bytes.hex()} -> File {original_bytes.hex()}"
                                                                )
                                                                mutable_content[idx : idx + patch_size] = original_bytes
                                                                patched_count += 1
                                                
                                                if patched_count > 0:
                                                    self.logger.info(f"Repaired {patched_count} uprobes in {entry.name} segment @ {entry.start:#x}")
                                                    seg_content = bytes(mutable_content)
                                            finally:
                                                f_obj.close()
                                except Exception as e:
                                    self.logger.warning(f"Failed to patch uprobes for {entry.name}: {e}")

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