"""
Symbols Plugin (symbols.py) for Penguin
=======================================

This module provides the Symbols plugin for the Penguin framework, serving as a robust,
centralized service for resolving binary symbols to file offsets. It allows other plugins
and scripts to locate functions and variables within guest executables and shared libraries,
even in challenging scenarios like stripped binaries or non-standard architectures.

Features
--------

- **Robust Forward Lookup:** Resolves symbol names to file offsets using a tiered strategy:
  1. Pre-computed JSON cache (fastest).
  2. Native ``nm`` utility (static and dynamic tables).
  3. PyELFtools (section parsing).
  4. Manual PT_DYNAMIC segment parsing (handles "sstripped" binaries with no section headers).
  5. ``readelf`` fallbacks, including MIPS GOT scraping for embedded targets.
- **Reverse Resolution:** Maps file offsets back to the nearest symbol name (useful for stack trace generation).
- **Address Resolution:** Maps virtual addresses to file offsets (useful for handling raw addresses provided by users).
- **Introspection:** Methods to list, filter, and bulk-load symbols for specific binaries.
- **Architecture Aware:** Automatically handles absolute addressing (ET_EXEC) vs relative offsets (ET_DYN) and architecture-specific symbol tables.

Example Usage
-------------

.. code-block:: python

    from penguin import plugins

    # 1. Forward Lookup: Get the binary path and file offset for a function
    #    (Useful for placing hooks or uprobes)
    path, offset = plugins.Symbols.lookup("/usr/bin/httpd", "httpGetEnv")
    if offset:
        print(f"Function located at offset {hex(offset)} in {path}")

    # 2. Address Resolution: Convert a virtual address to a file offset
    offset = plugins.Symbols.resolve_addr("/usr/bin/httpd", 0x400500)

    # 3. Reverse Lookup: Identify a function from a crash/instruction pointer
    name, dist = plugins.Symbols.resolve_offset("/usr/lib/libc.so.0", 0x12345)

Purpose
-------

The Symbols plugin bridges the gap between high-level analysis names (functions) and low-level
binary offsets required for instrumentation.
"""

import os
import lzma
import stat
import shutil
import subprocess
import tempfile
import struct
import cxxfilt
from typing import Dict, Any, Optional, Tuple, List

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.common.exceptions import ELFError

from penguin import Plugin, plugins


class Symbols(Plugin):
    """
    Symbols Plugin
    ==============

    A central service for resolving symbol names to file offsets within the guest.
    """

    def __init__(self):
        self.projdir = self.get_arg("proj_dir")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        self.libsymbols_path = os.path.join(
            self.projdir, "static", "LibrarySymbols.json.xz")

        self.nm_path = shutil.which("nm")
        if not self.nm_path:
            self.logger.warning(
                "Host 'nm' utility not found. Symbol lookup will be slower.")

        self._symbols_cache: Optional[Dict[str, Any]] = None
        self._symbols_loaded = False

    def load_symbols(self, path: str) -> Dict[str, int]:
        """
        Force-loads symbols for a binary into the cache.
        Useful for pre-warming the cache or debugging what symbols are detected.
        """
        # 1. Resolve Path
        resolved_path = path
        if '*' not in path:
            resolved_path = self._resolve_staticfs_symlink(path)

        # 2. Check if already cached
        db = self._load_symbols_db()
        if db and resolved_path in db:
            return db[resolved_path]

        # 3. Trigger a dummy lookup to force population
        # We pass a dummy symbol that likely doesn't exist to trigger the full scan logic
        # logic inside _scan_nm and _scan_file_fallback populates the cache for ALL symbols found
        self.lookup(path, "__FORCE_LOAD_TRIGGER__")

        # 4. Return the now-populated cache
        db = self._load_symbols_db()
        return db.get(resolved_path, {})

    def resolve_offset(self, path: str, offset: int) -> Optional[Tuple[str, int]]:
        """
        Reverse lookup: Given a file offset, find the nearest preceding symbol.
        Returns (SymbolName, DistanceFromStart)

        Example: resolve_offset("/bin/httpd", 0x4005) -> ("main", 5)
        """
        symbols = self.load_symbols(path)
        if not symbols:
            return None

        best_symbol = None
        min_dist = float('inf')

        # Linear scan is fast enough for symbol tables (usually <10k entries)
        for name, sym_offset in symbols.items():
            if sym_offset <= offset:
                dist = offset - sym_offset
                if dist < min_dist:
                    min_dist = dist
                    best_symbol = name

        if best_symbol:
            return best_symbol, min_dist

        return None

    def resolve_addr(self, path: str, vaddr: int, base_addr: Optional[int] = None) -> Optional[int]:
        """
        Resolves a virtual address to a file offset.

        If `base_addr` is provided, the offset is calculated as `vaddr - base_addr`.
        Otherwise, it attempts to map the virtual address to a file offset using ELF segments.
        If that fails, it retries by assuming common base addresses (e.g., 0x400000) and
        checking if the adjusted address maps to a segment or valid file offset.

        Returns the file offset or None if resolution fails.
        """
        # 1. Explicit Base Address
        if base_addr is not None:
            return vaddr - base_addr

        resolved_path = path
        if '*' not in path:
            resolved_path = self._resolve_staticfs_symlink(path)

        fs = plugins.static_fs
        f = None
        try:
            f = fs.open(resolved_path)
            if not f:
                return None

            # 2. ELF Segment Analysis
            try:
                elffile = ELFFile(f)
                is_exec = elffile.header['e_type'] == 'ET_EXEC'
                segments = []
                image_base = 0

                for segment in elffile.iter_segments():
                    if segment['p_type'] == 'PT_LOAD':
                        seg_info = {
                            'vaddr': segment['p_vaddr'],
                            'memsz': segment['p_memsz'],
                            'offset': segment['p_offset']
                        }
                        segments.append(seg_info)
                        if image_base == 0 or seg_info['vaddr'] < image_base:
                            image_base = seg_info['vaddr']

                # A. Try Direct Mapping
                offset = self._vaddr_to_file_offset_optimized(
                    segments, vaddr, is_exec, image_base)
                if offset is not None:
                    return offset

                # B. Try Common Bases
                # Common bases: Linux 64-bit ET_EXEC (0x400000), Ghidra PIE default (0x100000),
                # ARM/MIPS/Older (0x10000), Linux 32-bit (0x8048000).
                common_bases = [0x400000, 0x100000, 0x10000, 0x8048000]
                for base in common_bases:
                    adjusted = vaddr - base
                    if adjusted < 0:
                        continue

                    # Check if adjusted fits in ELF segments
                    offset = self._vaddr_to_file_offset_optimized(
                        segments, adjusted, is_exec, image_base)
                    if offset is not None:
                        self.logger.debug(
                            f"Resolved {vaddr:#x} using common base {base:#x} -> {offset:#x}")
                        return offset

            except ELFError:
                # Not an ELF or parse error, fall through to raw size check
                pass

            # 3. Fallback: Raw File Size Check
            # If ELF parsing failed or no segments matched, check if a common base adjustment
            # yields a valid raw offset within the file.
            try:
                # We need file size. f is already open.
                f.seek(0, 2)
                file_size = f.tell()

                common_bases = [0x400000, 0x100000, 0x10000, 0x8048000]
                for base in common_bases:
                    adjusted = vaddr - base
                    if 0 <= adjusted < file_size:
                        self.logger.debug(
                            f"Resolved {vaddr:#x} using common base {base:#x} -> raw offset {adjusted:#x}")
                        return adjusted
            except Exception:
                pass

    def list_symbols(self, path: str, filter_str: Optional[str] = None) -> List[str]:
        """
        Returns a list of all symbol names found in the binary.
        Optional filter_str performs a substring match.
        """
        symbols = self.load_symbols(path)
        if not symbols:
            return []

        if filter_str:
            return [name for name in symbols.keys() if filter_str in name]

        return list(symbols.keys())

    def lookup(self, path: str, symbol: str) -> Tuple[Optional[str], Optional[int]]:
        """
        Resolve a symbol name to a specific library path and file offset.

        Parameters
        ----------
        path : str
            Path to binary (supports wildcards like "*/libc.so*").
        symbol : str
            Symbol name to look up.

        Returns
        -------
        Tuple[str, int] or (None, None)
        """
        # 1. Resolve Symlinks
        resolved_path = path
        if '*' not in path:
            resolved_path = self._resolve_staticfs_symlink(path)

        # 2. Check JSON/Runtime Database (Fastest)
        res_path, res_offset = self._scan_json(resolved_path, symbol)
        if res_offset is not None:
            return res_path, res_offset

        # Retry with original path if resolved was different
        if resolved_path != path:
            res_path, res_offset = self._scan_json(path, symbol)
            if res_offset is not None:
                return res_path, res_offset

        # 3. Native `nm` Lookup (Fast)
        if self.nm_path and '*' not in resolved_path:
            res_path, res_offset = self._scan_nm(resolved_path, symbol)
            if res_offset is not None:
                return res_path, res_offset

        # 4. Fallback: PyELFtools / Manual Raw / Readelf (Kitchen Sink)
        if '*' not in resolved_path:
            self.logger.debug(
                f"[Fallback] Attempting robust fallback for {resolved_path}")
            return self._scan_file_fallback(resolved_path, symbol)

        return None, None

    def find_all(self, symbol: str) -> List[Tuple[str, int]]:
        """
        Search for a symbol in ALL known libraries in the database.

        Parameters
        ----------
        symbol : str
            Symbol name to look up.

        Returns
        -------
        List[Tuple[str, int]]
            A list of (library_path, file_offset) for every occurrence of the symbol.
        """
        results = []
        db = self._load_symbols_db()
        if not db:
            return results

        # Pre-calculate demangled name once
        demangled_target = None
        if symbol.startswith('_Z'):
            try:
                demangled_target = cxxfilt.demangle(symbol)
            except Exception:
                pass

        for lib_path, lib_symbols in db.items():
            offset = self._resolve_symbol_in_dict(
                lib_symbols, symbol, demangled_target)
            if offset is not None:
                results.append((lib_path, offset))

        return results

    def get_offset(self, path: str, symbol: str) -> Optional[int]:
        _, offset = self.lookup(path, symbol)
        return offset

    # -------------------------------------------------------------------------
    # Internal Logic
    # -------------------------------------------------------------------------

    def _load_symbols_db(self) -> Dict[str, Any]:
        if self._symbols_loaded:
            return self._symbols_cache

        self._symbols_loaded = True
        self._symbols_cache = {}

        if os.path.exists(self.libsymbols_path):
            try:
                with lzma.open(self.libsymbols_path, 'rt', encoding='utf-8') as f:
                    import ujson as json
                    data = json.load(f)
                    self._symbols_cache = data.get("symbols", {})
                self.logger.info(
                    f"Loaded symbols DB from {self.libsymbols_path}")
            except Exception as e:
                self.logger.warning(f"Failed to load symbols DB: {e}")
        return self._symbols_cache

    def _update_cache(self, path: str, new_symbols: Dict[str, int]):
        """Adds newly discovered symbols for a path to the runtime cache."""
        db = self._load_symbols_db()
        if db is not None:
            if path not in db or len(new_symbols) > len(db[path]):
                self.logger.debug(
                    f"[Cache] Updating cache for {path} with {len(new_symbols)} symbols")
            db[path] = new_symbols

    def _scan_json(self, path: str, symbol: str) -> Tuple[Optional[str], Optional[int]]:
        db = self._load_symbols_db()
        if not db:
            return None, None

        demangled_target = None
        if symbol.startswith('_Z'):
            try:
                demangled_target = cxxfilt.demangle(symbol)
            except Exception:
                pass

        if '*' in path:
            pattern = path.replace('*', '')
            for lib_path, lib_symbols in db.items():
                if pattern in lib_path or pattern in os.path.basename(lib_path):
                    offset = self._resolve_symbol_in_dict(
                        lib_symbols, symbol, demangled_target)
                    if offset is not None:
                        return lib_path, offset
            return None, None

        norm_path = os.path.basename(path)
        for lib_path, lib_symbols in db.items():
            lib_basename = os.path.basename(lib_path)
            is_match = (path == lib_path or
                        norm_path == lib_basename or
                        (norm_path.rstrip('-') and lib_basename.startswith(norm_path.rstrip('-'))))

            if is_match:
                offset = self._resolve_symbol_in_dict(
                    lib_symbols, symbol, demangled_target)
                if offset is not None:
                    return lib_path, offset
        return None, None

    def _resolve_symbol_in_dict(self, symbols_dict: Dict[str, int], target: str, demangled_target: Optional[str]) -> Optional[int]:
        if target in symbols_dict:
            return symbols_dict[target]
        if demangled_target:
            for name, offset in symbols_dict.items():
                if name.startswith('_Z'):
                    if cxxfilt.demangle(name) == demangled_target:
                        return offset
        return None

    def _run_nm_command(self, cmd: List[str]) -> Dict[str, int]:
        symbols = {}
        try:
            # self.logger.debug(f"[NM] Running: {' '.join(cmd)}")
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            for line in proc.stdout:
                parts = line.split()
                if len(parts) >= 3 and parts[1].upper() != 'U':
                    try:
                        sym_name = parts[0]
                        vaddr = int(parts[2], 16)
                        symbols[sym_name] = vaddr
                    except ValueError:
                        pass
            proc.terminate()
            if hasattr(proc, 'wait'):
                proc.wait()
        except Exception:
            pass
        return symbols

    def _scan_nm(self, path: str, symbol: str) -> Tuple[Optional[str], Optional[int]]:
        host_path = None
        is_temp = False

        try:
            fs = plugins.static_fs

            f = fs.open(path)
            if not f:
                return None, None

            fd, host_path = tempfile.mkstemp()
            os.close(fd)
            is_temp = True

            with open(host_path, 'wb') as tf:
                shutil.copyfileobj(f, tf)
            f.close()

            # Attempt 1: Static
            cmd = [self.nm_path, '-P', host_path]
            new_symbols = self._run_nm_command(cmd)

            # Attempt 2: Dynamic
            if not new_symbols:
                cmd = [self.nm_path, '-D', '-P', host_path]
                new_symbols = self._run_nm_command(cmd)

            if new_symbols:
                with open(host_path, 'rb') as tf:
                    elffile = ELFFile(tf)
                    is_exec = elffile.header['e_type'] == 'ET_EXEC'
                    image_base = 0
                    segments = []
                    for segment in elffile.iter_segments():
                        if segment['p_type'] == 'PT_LOAD':
                            seg_info = {
                                'vaddr': segment['p_vaddr'],
                                'memsz': segment['p_memsz'],
                                'offset': segment['p_offset']
                            }
                            segments.append(seg_info)
                            if image_base == 0 or seg_info['vaddr'] < image_base:
                                image_base = seg_info['vaddr']

                    converted_symbols = {}
                    for s_name, s_vaddr in new_symbols.items():
                        offset = self._vaddr_to_file_offset_optimized(
                            segments, s_vaddr, is_exec, image_base)
                        if offset is not None:
                            converted_symbols[s_name] = offset

                    self._update_cache(path, converted_symbols)

                    if symbol in converted_symbols:
                        return path, converted_symbols[symbol]

        except Exception as e:
            self.logger.debug(f"nm lookup failed for {path}: {e}")
        finally:
            if is_temp and host_path and os.path.exists(host_path):
                try:
                    os.unlink(host_path)
                except OSError:
                    pass
        return None, None

    def _scan_file_fallback(self, path: str, symbol: str) -> Tuple[Optional[str], Optional[int]]:
        lookup_path = path if path.startswith("/") else "/" + path
        f = None
        new_symbols = {}
        found_offset = None

        segments = []
        is_exec = False
        image_base = 0

        try:
            fs = plugins.static_fs

            f = fs.open(lookup_path)
            if not f:
                return None, None

            # 1. PREP: Read ELF Segments
            try:
                elffile = ELFFile(f)
                is_exec = elffile.header['e_type'] == 'ET_EXEC'

                for segment in elffile.iter_segments():
                    if segment['p_type'] == 'PT_LOAD':
                        seg_info = {
                            'vaddr': segment['p_vaddr'],
                            'memsz': segment['p_memsz'],
                            'offset': segment['p_offset']
                        }
                        segments.append(seg_info)
                        if image_base == 0 or seg_info['vaddr'] < image_base:
                            image_base = seg_info['vaddr']

                # Strategy A: PyELFtools (Sections) - Good for standard binaries
                for section in elffile.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for sym in section.iter_symbols():
                            if sym['st_shndx'] != 'SHN_UNDEF':
                                s_name = sym.name
                                if s_name:
                                    new_symbols[s_name] = sym['st_value']
            except ELFError:
                pass
            except Exception:
                pass

            # Strategy B: Manual Raw Dynamic Parsing - Good for sstrip (no sections)
            if not new_symbols:
                self.logger.debug(
                    f"[Fallback-Manual] Scanning raw PT_DYNAMIC for {path}...")
                new_symbols = self._scan_raw_dynamic_symbols(
                    f, elffile, segments)

            # Strategy C: Readelf Subprocess - The "Final Boss"
            if not new_symbols:
                f.close()
                f = None
                tf_fd, tf_path = tempfile.mkstemp()
                os.close(tf_fd)
                try:
                    with fs.open(lookup_path) as src, open(tf_path, 'wb') as dst:
                        shutil.copyfileobj(src, dst)

                    readelf_path = shutil.which("readelf")
                    if readelf_path:
                        # C1: Standard Symbols
                        cmd = [readelf_path, "--symbols", "-W", tf_path]
                        new_symbols = self._parse_readelf_output(cmd)

                        # C2: Dynamic Symbols
                        if not new_symbols:
                            cmd = [readelf_path, "--dyn-syms", "-W", tf_path]
                            new_symbols = self._parse_readelf_output(cmd)

                        # C3: MIPS GOT (Crucial for MIPS executables)
                        if not new_symbols:
                            cmd = [readelf_path, "-A", "-W", tf_path]
                            new_symbols = self._parse_readelf_mips_got(cmd)

                finally:
                    if os.path.exists(tf_path):
                        os.unlink(tf_path)

            # Process Results
            final_symbols = {}
            for s_name, s_vaddr in new_symbols.items():
                offset = self._vaddr_to_file_offset_optimized(
                    segments, s_vaddr, is_exec, image_base)
                if offset is not None:
                    final_symbols[s_name] = offset
                    if s_name == symbol:
                        found_offset = offset

            if final_symbols:
                self._update_cache(lookup_path, final_symbols)

            if found_offset is not None:
                return lookup_path, found_offset

        except Exception as e:
            self.logger.error(f"Fallback lookup error: {e}")
        finally:
            if f:
                f.close()
        return None, None

    def _scan_raw_dynamic_symbols(self, f, elffile, segments) -> Dict[str, int]:
        """
        Manually parses the PT_DYNAMIC segment to find the Symbol Table and String Table.
        """
        symbols = {}
        try:
            dyn_segment = None
            for seg in elffile.iter_segments():
                if seg['p_type'] == 'PT_DYNAMIC':
                    dyn_segment = seg
                    break

            if not dyn_segment:
                return {}

            dt_symtab = None
            dt_strtab = None
            dt_strsz = 0
            dt_syment = 0
            dt_mips_symtabno = 0

            for tag in dyn_segment.iter_tags():
                if tag.entry.d_tag == 'DT_SYMTAB':
                    dt_symtab = tag.entry.d_val
                elif tag.entry.d_tag == 'DT_STRTAB':
                    dt_strtab = tag.entry.d_val
                elif tag.entry.d_tag == 'DT_STRSZ':
                    dt_strsz = tag.entry.d_val
                elif tag.entry.d_tag == 'DT_SYMENT':
                    dt_syment = tag.entry.d_val
                elif tag.entry.d_tag == 'DT_MIPS_SYMTABNO':
                    dt_mips_symtabno = tag.entry.d_val

            if not dt_symtab or not dt_strtab:
                return {}

            is_64 = elffile.elfclass == 64
            is_little = elffile.little_endian

            endian_char = '<' if is_little else '>'
            if is_64:
                fmt = endian_char + 'IBBHQQ'
                entry_size = 24
            else:
                fmt = endian_char + 'IIIBBH'
                entry_size = 16

            if dt_syment > 0:
                entry_size = dt_syment

            symtab_offset = self._vaddr_to_file_offset_optimized(
                segments, dt_symtab, False, 0)
            strtab_offset = self._vaddr_to_file_offset_optimized(
                segments, dt_strtab, False, 0)

            if symtab_offset is None or strtab_offset is None:
                return {}

            num_symbols = dt_mips_symtabno if dt_mips_symtabno > 0 else 10000

            f.seek(strtab_offset)
            string_table_data = f.read(dt_strsz)

            f.seek(symtab_offset)
            for _ in range(num_symbols):
                raw_bytes = f.read(entry_size)
                if len(raw_bytes) < entry_size:
                    break

                parts = struct.unpack(fmt, raw_bytes)

                if is_64:
                    st_name_idx = parts[0]
                    st_value = parts[4]
                else:
                    st_name_idx = parts[0]
                    st_value = parts[1]

                if st_name_idx == 0 or st_name_idx >= len(string_table_data):
                    continue

                end_idx = string_table_data.find(b'\0', st_name_idx)
                if end_idx == -1:
                    continue
                try:
                    sym_name = string_table_data[st_name_idx:end_idx].decode(
                        'utf-8', errors='ignore')
                    if sym_name:
                        symbols[sym_name] = st_value
                except Exception:
                    pass

        except Exception as e:
            self.logger.debug(f"[Fallback-Manual] Failed: {e}")

        return symbols

    def _parse_readelf_output(self, cmd: List[str]) -> Dict[str, int]:
        symbols = {}
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            for line in proc.stdout:
                parts = line.split()
                if len(parts) >= 8 and parts[1].strip() != "Value":
                    try:
                        if parts[6] != "UND":
                            val_hex = parts[1]
                            sym_name = parts[7]
                            if '@' in sym_name:
                                sym_name = sym_name.split('@')[0]
                            if '[' in sym_name:
                                sym_name = sym_name.split('[')[0]
                            symbols[sym_name] = int(val_hex, 16)
                    except (ValueError, IndexError):
                        pass
            proc.wait()
        except Exception:
            pass
        return symbols

    def _parse_readelf_mips_got(self, cmd: List[str]) -> Dict[str, int]:
        """Scrapes MIPS GOT entries by looking for the distinct '(gp)' signature."""
        symbols = {}
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if len(parts) > 2 and '(gp)' in parts[1]:
                    if "Lazy resolver" in line or "Module pointer" in line:
                        continue
                    if len(parts) < 5:  # Filter out Local entries
                        continue
                    try:
                        vaddr_hex = parts[2]
                        sym_name = parts[-1]
                        if sym_name == vaddr_hex:
                            continue
                        symbols[sym_name] = int(vaddr_hex, 16)
                    except (ValueError, IndexError):
                        pass
            proc.wait()
        except Exception:
            pass
        return symbols

    def _resolve_staticfs_symlink(self, path: str) -> str:
        fs = plugins.static_fs

        current_path = path if path.startswith("/") else "/" + path
        visited = set()

        while True:
            if current_path in visited:
                return path
            visited.add(current_path)

            try:
                mount_source = getattr(fs, "_fs", None)
                if not mount_source:
                    return current_path

                file_info = mount_source.lookup(current_path)
                if not file_info:
                    return current_path

                if stat.S_ISLNK(file_info.mode):
                    link_target = file_info.linkname
                    if link_target.startswith("/"):
                        current_path = link_target
                    else:
                        parent_dir = os.path.dirname(current_path)
                        current_path = os.path.normpath(
                            os.path.join(parent_dir, link_target))
                else:
                    return current_path
            except Exception:
                return path

    def _vaddr_to_file_offset_optimized(self, segments: list, vaddr: int, is_exec: bool = False, image_base: int = 0) -> Optional[int]:
        if not segments:
            return None
        if is_exec and image_base == 0:
            min_vaddr = min(s['vaddr'] for s in segments)
            if min_vaddr > 0:
                image_base = min_vaddr
        for seg in segments:
            if seg['vaddr'] <= vaddr < (seg['vaddr'] + seg['memsz']):
                return seg['offset'] + (vaddr - seg['vaddr'])
        if is_exec and image_base > 0 and vaddr >= image_base:
            return vaddr - image_base
        return None
