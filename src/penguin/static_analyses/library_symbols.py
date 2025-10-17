import os
import tempfile
import subprocess
import struct
from pathlib import Path
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.common.exceptions import ELFError, ELFParseError
from subprocess import check_output, STDOUT, CalledProcessError
from penguin import getColoredLogger
from .base import StaticAnalysis
from ..arch import arch_end

logger = getColoredLogger("penguin.static_analyses")

class LibrarySymbols(StaticAnalysis):
    """
    Examine libraries in the filesystem for NVRAM keys and exported symbols.

    Uses pyelftools to find definitions for NVRAM_KEYS variables and tracks exported function names.
    """
    NVRAM_KEYS: list[str] = ["Nvrams", "router_defaults"]

    def run(self, extract_dir: str, prior_results: dict) -> dict[str, dict]:
        """
        Analyze libraries for NVRAM keys and symbols.

        :param extract_dir: Directory containing extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Dict with nvram values and symbol paths.
        """
        self.extract_dir = extract_dir
        self.archend = arch_end(prior_results['ArchId'])

        if any([x is None for x in self.archend]):
            self.enabled = False
            print(f"Warning: Unknown architecture/endianness: {self.archend}. Cannot run NVRAM recovery Static Analysis")
            return

        symbols = {}
        nvram = {}
        sym_paths = {}  # path -> symbol names

        for root, _, files in os.walk(self.extract_dir):
            for file in files:
                file_path = Path(root) / file
                if file_path.is_file() and \
                        (str(file_path).endswith(".so") or ".so." in str(file_path)):
                    try:
                        found_nvram, found_syms = self._analyze_library(file_path,
                                                                        self.archend)
                    except Exception as e:
                        logger.error(
                            f"Unhandled exception in _analyze_library for {file_path}: {e}"
                        )
                        continue
                    tmpless_path = str(file_path).replace(str(self.extract_dir), "")
                    sym_paths[tmpless_path] = found_syms
                    for symname, offset in found_syms.items():
                        symbols[(tmpless_path, symname)] = offset
                    for key, value in found_nvram.items():
                        nvram_key = key.rsplit(":", 1)[-1]
                        nvram[(tmpless_path, nvram_key)] = value

        nvram_values = {}
        for (path, key), value in nvram.items():
            if path not in nvram_values:
                nvram_values[path] = {}
            if key is not None and len(key) and value is not None:
                nvram_values[path][key] = value

        return {'nvram': nvram_values,
                'symbols': sym_paths}

    @staticmethod
    def _find_symbol_address(
        elffile: ELFFile,
        symbol_name: str
    ) -> tuple[int | None, int | str | None]:
        try:
            symbol_tables = [
                s
                for s in elffile.iter_sections()
                if isinstance(s, SymbolTableSection)
            ]
        except ELFParseError:
            return None, None

        for section in symbol_tables:
            if symbol := section.get_symbol_by_name(symbol_name):
                symbol = symbol[0]
                return (
                    symbol["st_value"],
                    symbol["st_shndx"],
                )
        return None, None

    @staticmethod
    def _get_string_from_address(
        elffile: ELFFile,
        address: int,
        is_64: bool = False,
        is_eb: bool = False
    ) -> str | None:
        for section in elffile.iter_sections():
            start_addr = section["sh_addr"]
            end_addr = start_addr + section.data_size
            if start_addr <= address < end_addr:
                offset_within_section = address - start_addr
                data = section.data()[offset_within_section:]
                str_end = data.find(b"\x00")
                if str_end != -1:
                    try:
                        return data[:str_end].decode("utf-8")
                    except UnicodeDecodeError:
                        pass
        return None

    @staticmethod
    def _is_elf(filename: str) -> bool:
        try:
            with open(filename, "rb") as f:
                magic = f.read(4)
            return magic == b"\x7fELF"
        except IOError:
            return False

    @staticmethod
    def get_nvram_info(
        elf_path: str,
        archend: str
    ) -> dict[str, str | None]:
        nvram_data = {}
        is_eb = "eb" in archend
        is_64 = "64" in archend
        with open(elf_path, "rb") as f:
            try:
                elffile = ELFFile(f)
            except ELFError:
                if LibrarySymbols._is_elf(elf_path):
                    logger.warning(
                        f"Failed to parse {elf_path} as an ELF file when analyzing libraries"
                    )
                return nvram_data

            for nvram_key in LibrarySymbols.NVRAM_KEYS:
                address, section_index = LibrarySymbols._find_symbol_address(elffile, nvram_key)
                if address is None:
                    continue

                if section_index == "SHN_UNDEF":
                    continue

                try:
                    section = elffile.get_section(section_index)
                except TypeError:
                    logger.warning(
                        f"Failed to get section {section_index} for symbol {nvram_key} in {elf_path} when analyzing libraries"
                    )
                    continue
                data = section.data()
                start_addr = section["sh_addr"]
                offset = address - start_addr

                pointer_size = 8 if is_64 else 4
                unpack_format = f"{'>' if is_eb else '<'}{'Q' if is_64 else 'I'}"

                fail_count = 0
                while offset + (pointer_size * 3) < len(data):
                    ptrs = [
                        struct.unpack(
                            unpack_format,
                            data[
                                offset + i * pointer_size: offset + (i + 1) * pointer_size
                            ],
                        )[0]
                        for i in range(3)
                    ]
                    if ptrs[0] != 0:
                        key = LibrarySymbols._get_string_from_address(elffile, ptrs[0], is_64, is_eb)
                        val = LibrarySymbols._get_string_from_address(elffile, ptrs[1], is_64, is_eb)

                        if (
                            key
                            and not any([x in key for x in ' /\t\n\r<>"'])
                            and not key[0].isnumeric()
                        ):
                            fail_count = 0
                            if key not in nvram_data:
                                nvram_data[key] = val
                        else:
                            fail_count += 1
                    else:
                        pass

                    if fail_count > 5:
                        break

                    offset += pointer_size * 3
            return nvram_data

    @staticmethod
    def _analyze_library(
        elf_path: str,
        archend: str
    ) -> tuple[dict, dict]:
        symbols = {}
        nvram_data = {}

        try:
            with open(elf_path, 'rb') as f:
                archive = f.read(8) == b"!<arch>\n"

            if archive:
                with tempfile.TemporaryDirectory() as temp_dir:
                    subprocess.run(["ar", "x", elf_path], cwd=temp_dir, check=True)
                    for obj_file in os.listdir(temp_dir):
                        obj_path = os.path.join(temp_dir, obj_file)
                        found_nvram, found_syms = LibrarySymbols._analyze_library(obj_path, archend)
                        archive_key = f"{os.path.basename(elf_path)}:{obj_file}"
                        symbols.update({f"{archive_key}:{k}": v for k, v in found_syms.items()})
                        nvram_data.update({f"{archive_key}:{k}": v for k, v in found_nvram.items()})
                return nvram_data, symbols
        except CalledProcessError as e:
            logger.error(f"Error processing archive {elf_path}: {e.output.decode('utf-8', errors='ignore')}")

        try:
            if nm_out := check_output(["nm", "-D", "--defined-only", elf_path],
                                      stderr=STDOUT):
                for line in nm_out.decode("utf8", errors="ignore").split("\n"):
                    if line:
                        parts = line.split()
                        if len(parts) == 3:
                            addr, _, name = parts
                            if '@' in name:
                                name = name.split("@")[0]
                            addr = int(addr, 16)
                            if addr != 0:
                                symbols[name] = addr
                        elif line.strip().endswith("no symbols"):
                            continue
                        else:
                            logger.warning(f"Unexpected nm output format: {line}")
        except CalledProcessError as e:
            if LibrarySymbols._is_elf(elf_path):
                logger.error(f"Error running nm on {elf_path}: {e.output.decode('utf-8', errors='ignore')}")
            return nvram_data, symbols

        if any(sym in symbols for sym in LibrarySymbols.NVRAM_KEYS):
            nvram_data = LibrarySymbols.get_nvram_info(elf_path, archend)

        return nvram_data, symbols
