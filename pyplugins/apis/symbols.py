"""
"""

import os
import lzma
import stat
import shutil
import subprocess
import tempfile
from typing import Dict, Any, Optional, Tuple, List

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.common.exceptions import ELFError

from penguin import Plugin, plugins

try:
    import cxxfilt
    HAVE_CXXFILT = True
except ImportError:
    HAVE_CXXFILT = False


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

        # 4. PyELFtools Fallback (Slow)
        if '*' not in resolved_path:
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
        if HAVE_CXXFILT and symbol.startswith('_Z'):
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
            db[path] = new_symbols
            self.logger.debug(f"Cached {len(new_symbols)} symbols for {path}")

    def _scan_json(self, path: str, symbol: str) -> Tuple[Optional[str], Optional[int]]:
        db = self._load_symbols_db()
        if not db:
            return None, None

        demangled_target = None
        if HAVE_CXXFILT and symbol.startswith('_Z'):
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
                    try:
                        if cxxfilt.demangle(name) == demangled_target:
                            return offset
                    except:
                        pass
        return None

    def _scan_nm(self, path: str, symbol: str) -> Tuple[Optional[str], Optional[int]]:
        host_path = None
        is_temp = False

        try:
            try:
                fs = plugins.static_fs
            except AttributeError:
                self.logger.error("StaticFS plugin not available.")
                return None, None

            f = fs.open(path)
            if not f:
                return None, None

            fd, host_path = tempfile.mkstemp()
            os.close(fd)
            is_temp = True

            with open(host_path, 'wb') as tf:
                shutil.copyfileobj(f, tf)
            f.close()

            cmd = [self.nm_path, '-D', '-P', host_path]
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True
            )

            new_symbols = {}
            target_vaddr = None

            for line in proc.stdout:
                parts = line.split()
                if len(parts) >= 3 and parts[1].upper() != 'U':
                    try:
                        sym_name = parts[0]
                        vaddr = int(parts[2], 16)
                        new_symbols[sym_name] = vaddr
                        if sym_name == symbol:
                            target_vaddr = vaddr
                    except ValueError:
                        pass

            proc.terminate()
            if hasattr(proc, 'wait'):
                proc.wait()

            if new_symbols:
                with open(host_path, 'rb') as tf:
                    elffile = ELFFile(tf)
                    segments = []
                    for segment in elffile.iter_segments():
                        if segment['p_type'] == 'PT_LOAD':
                            segments.append({
                                'vaddr': segment['p_vaddr'],
                                'memsz': segment['p_memsz'],
                                'offset': segment['p_offset']
                            })

                    converted_symbols = {}
                    for s_name, s_vaddr in new_symbols.items():
                        offset = self._vaddr_to_file_offset_optimized(
                            segments, s_vaddr)
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
        try:
            try:
                fs = plugins.static_fs
            except AttributeError:
                return None, None

            f = fs.open(lookup_path)
            if not f:
                return None, None

            try:
                elffile = ELFFile(f)
                segments = []
                for segment in elffile.iter_segments():
                    if segment['p_type'] == 'PT_LOAD':
                        segments.append({
                            'vaddr': segment['p_vaddr'],
                            'memsz': segment['p_memsz'],
                            'offset': segment['p_offset']
                        })

                new_symbols = {}
                found_offset = None

                for section in elffile.iter_sections():
                    if isinstance(section, SymbolTableSection):
                        for sym in section.iter_symbols():
                            if sym['st_shndx'] != 'SHN_UNDEF':
                                s_name = sym.name
                                offset = self._vaddr_to_file_offset_optimized(
                                    segments, sym['st_value'])
                                if offset is not None:
                                    new_symbols[s_name] = offset
                                    if s_name == symbol:
                                        found_offset = offset

                if new_symbols:
                    self._update_cache(lookup_path, new_symbols)

                if found_offset is not None:
                    return lookup_path, found_offset

            except ELFError:
                pass
            except Exception:
                pass
        except Exception as e:
            self.logger.error(f"StaticFS error: {e}")
        finally:
            if f:
                f.close()
        return None, None

    def _resolve_staticfs_symlink(self, path: str) -> str:
        try:
            fs = plugins.static_fs
        except AttributeError:
            return path

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

    def _vaddr_to_file_offset_optimized(self, segments: list, vaddr: int) -> Optional[int]:
        for seg in segments:
            if seg['vaddr'] <= vaddr < (seg['vaddr'] + seg['memsz']):
                return seg['offset'] + (vaddr - seg['vaddr'])
        return None
