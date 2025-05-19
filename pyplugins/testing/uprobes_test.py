"""
This plugin verifies that hypercalls are being made correctly.
"""

from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins
from os.path import join, realpath, basename
from glob import glob
import functools

uprobes = plugins.uprobes
portal = plugins.portal


class UprobesTest(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")

        self.logger = getColoredLogger("plugins.uprobes_test")
        libguest, lib_syms = self.find_lib("*ld-musl*")

        targets = [
            ("printf", self.uprobe_printf, self.uprobe_printf_ret),
            ("strncmp", self.uprobe_strncmp, self.uprobe_strncmp_ret),
            ("fopen", self.uprobe_fopen, self.uprobe_fopen_ret),
            ("getenv", self.uprobe_getenv, self.uprobe_getenv_ret),
        ]

        self.test_results = {}

        for symbol, fn, retfn in targets:
            kwargs = {"path": libguest,
                      "symbol": lib_syms[symbol],
                      "process_filter": "uprobes_test.sh"
                      }
            uprobes.uprobe(**kwargs)(fn)
            uprobes.uretprobe(**kwargs)(retfn)
            self.test_results[symbol] = {"entry": False, "return": False}
        
        self.printf_offset = lib_syms["printf"]

    def find_lib(self, lib_name):
        """
        Use the nm command to extract symbol addresses from libc.

        Args:
            lib_name: Name of the library file

        Returns:
            Path to the library file in the guest
            Dictionary mapping symbol names to their addresses
        """
        lib_host, lib_guest = self._lookup_lib(lib_name)
        return lib_guest, self._get_library_symbols(lib_host)

    @functools.lru_cache
    def _lookup_lib(self, lib_name):
        static_files = self.get_arg("conf")["static_files"]
        for f in static_files:
            if "host_path" in static_files[f]:
                dylibs = static_files[f]["host_path"]
                lib_path = glob(f"{dylibs}{lib_name}")
                if lib_path:
                    host_lib = realpath(lib_path[0])
                    guest_lib = realpath(join(f, "..", basename(host_lib)))
                    return host_lib, guest_lib
        else:
            raise Exception(f"Could not find {lib_name} path in static files")

    @functools.lru_cache
    def _get_library_symbols(self, libc_path):
        """
        Use the nm command to extract symbol addresses from libc.

        Args:
            libc_path: Path to the libc library file

        Returns:
            Dictionary mapping symbol names to their addresses
        """
        from subprocess import check_output, CalledProcessError, PIPE

        self.logger.info(f"Extracting symbols from {libc_path}")
        try:
            # Run nm command to get all symbols
            # -D: Display dynamic symbols instead of normal symbols
            # --defined-only: Display only defined symbols
            # -n: Sort numerically by address
            output = check_output(['nm', '-D', '--defined-only', '-n', libc_path],
                                  stderr=PIPE, universal_newlines=True)

            symbols = {}
            # Parse output lines, format is: "address type symbol"
            for line in output.splitlines():
                parts = line.split()
                if len(parts) >= 3:  # address, type, symbol
                    addr = parts[0]
                    symbol_type = parts[1]
                    symbol_name = parts[2]

                    # Only include function symbols (type 'T' or 't')
                    if symbol_type.lower() == 't':
                        try:
                            # Convert hex address to integer
                            addr_int = int(addr, 16)
                            symbols[symbol_name] = addr_int
                        except ValueError:
                            continue

            self.logger.info(
                f"Extracted {len(symbols)} symbols from {libc_path}")
            return symbols
        except CalledProcessError as e:
            self.logger.error(f"Failed to run nm on {libc_path}: {e}")
            if e.stderr:
                self.logger.error(f"stderr: {e.stderr}")
            return {}

    @portal.wrap
    def uprobe_strncmp(self, pt_regs):
        a, b, c = pt_regs.get_args(3)
        av = yield from portal.read_str(a)
        bv = yield from portal.read_str(b)
        expected_str = "Hello from uprobe_test\n"
        if expected_str == av and expected_str == bv:
            self.logger.info(f"strncmp:({av.encode()}, {bv.encode()}, '{c}')")
            self.test_results["strncmp"]["entry"] = True
            self.uprobe_strncmp_val = av
            # Write test result to file
            with open(join(self.outdir, "uprobe_strncmp_test.txt"), "w") as f:
                f.write(
                    f"strncmp entry test passed: compared '{av}' to '{bv}' with length {c}\n")
        else:
            self.uprobe_strncmp_val = None

    @portal.wrap
    def uprobe_strncmp_ret(self, pt_regs):
        if self.uprobe_strncmp_val == "Hello from uprobe_test\n":
            retval = pt_regs.get_retval()
            self.logger.info(f"strncmp return value: {retval}")
            self.test_results["strncmp"]["return"] = True
            # strncmp should return 0 for identical strings
            assert retval == 0, f"Expected strncmp to return 0 for identical strings, got {retval}"

            self.test_results["strncmp"]["return"] = True

            # Append to test result file
            with open(join(self.outdir, "uprobe_strncmp_test.txt"), "a") as f:
                f.write(f"strncmp return test passed: return value {retval}\n")
        if False:
            yield

    @portal.wrap
    def uprobe_printf(self, pt_regs):
        format_str_ptr = pt_regs.get_arg(0)
        format_str = yield from portal.read_str(format_str_ptr)
        self.logger.info(f"printf format string: {format_str}")

        if format_str.startswith("Hello from uprobe_test"):
            m = yield from portal.get_mappings()
            pc = pt_regs.get_pc()

            # Get the mapping associated with printf
            pc_mapping = m.get_mapping_by_addr(pc)

            # look up the first mapping with that name
            first_mapping_addr = m.get_mappings_by_name(pc_mapping.name)[0].start

            # Calculate offset
            offset = pc - first_mapping_addr
            assert offset == self.printf_offset, f"Expected offset {self.printf_offset}, got {offset}"

            # Check for arguments and mask as int
            args = [i & 0xffffffff for i in pt_regs.get_args(12)[1:]]
            expected_args = list(range(11))
            assert args == expected_args, f"Expected args {expected_args}, got {args}"

            self.test_results["printf"]["entry"] = True
            self.uprobe_printf_val = True

            # Write test result to file
            with open(join(self.outdir, "uprobe_printf_test.txt"), "w") as f:
                f.write(
                    f"printf entry test passed: format '{format_str}' with args {args}\n")
        else:
            self.uprobe_printf_val = False

    @portal.wrap
    def uprobe_printf_ret(self, pt_regs):
        if self.uprobe_printf_val:
            retval = pt_regs.get_retval()
            self.logger.info(f"printf return value: {retval}")

            # printf should return the number of characters printed
            expected_len = len(
                "Hello from uprobe_test 0 1 2 3 4 5 6 7 8 9 10\n")
            assert retval == expected_len, f"Expected printf to return {expected_len}, got {retval}"

            self.test_results["printf"]["return"] = True

            # Append to test result file
            with open(join(self.outdir, "uprobe_printf_test.txt"), "a") as f:
                f.write(
                    f"printf return test passed: printed {retval} characters\n")
            if False:
                yield

    @portal.wrap
    def uprobe_fopen(self, pt_regs):
        path_ptr, mode_ptr = pt_regs.get_args(2)
        path = yield from portal.read_str(path_ptr)
        mode = yield from portal.read_str(mode_ptr)

        self.logger.info(f"fopen: path={path}, mode={mode}")

        expected_path = "/proc/self/cmdline"
        expected_mode = "r"
        assert path == expected_path, f"Expected path '{expected_path}', got '{path}'"
        assert mode == expected_mode, f"Expected mode '{expected_mode}', got '{mode}'"

        self.test_results["fopen"]["entry"] = True

        # Write test result to file
        with open(join(self.outdir, "uprobe_fopen_test.txt"), "w") as f:
            f.write(
                f"fopen entry test passed: opening '{path}' with mode '{mode}'\n")

    @portal.wrap
    def uprobe_fopen_ret(self, pt_regs):
        retval = pt_regs.get_retval()
        self.logger.info(f"fopen return value (file descriptor): {retval:#x}")

        # fopen should return a non-null pointer for a valid file
        assert retval != 0, "Expected fopen to return a non-null pointer"

        self.test_results["fopen"]["return"] = True

        # Append to test result file
        with open(join(self.outdir, "uprobe_fopen_test.txt"), "a") as f:
            f.write(
                f"fopen return test passed: got file descriptor {retval:#x}\n")
        if False:
            yield

    @portal.wrap
    def uprobe_getenv(self, pt_regs):
        name_ptr = pt_regs.get_arg(0)
        name = yield from portal.read_str(name_ptr)
        expected_name = "PROJ_NAME"
        self.last_name = name
        if name == expected_name:
            self.logger.info(f"getenv: name={name}")
            self.test_results["getenv"]["entry"] = True

            # Write test result to file
            with open(join(self.outdir, "uprobe_getenv_test.txt"), "w") as f:
                f.write(
                    f"getenv entry test passed: looking up env var '{name}'\n")

    @portal.wrap
    def uprobe_getenv_ret(self, pt_regs):
        retval = pt_regs.get_retval()

        if retval != 0 and self.last_name == "PROJ_NAME":
            env_value = yield from portal.read_str(retval)
            self.logger.info(f"getenv return value: {env_value}")

            # For the test_target configuration, PROJ_NAME should be "test_target"
            expected_value = "test_target"
            assert env_value == expected_value, f"Expected env value '{expected_value}', got '{env_value}'"
            self.test_results["getenv"]["return"] = True

            # Append to test result file
            with open(join(self.outdir, "uprobe_getenv_test.txt"), "a") as f:
                if retval != 0:
                    env_value = yield from portal.read_str(retval)
                    f.write(
                        f"getenv return test passed: PROJ_NAME='{env_value}'\n")
                else:
                    f.write(
                        "getenv return test passed: PROJ_NAME not found (NULL)\n")

    def uninit(self):
        """Write a summary of all test results to a file when the plugin is unloaded"""
        with open(join(self.outdir, "uprobe_tests_summary.txt"), "w") as f:
            all_passed = True
            for func_name, results in self.test_results.items():
                entry_result = "PASSED" if results["entry"] else "FAILED"
                return_result = "PASSED" if results["return"] else "FAILED"

                f.write(f"{func_name}:\n")
                f.write(f"  entry: {entry_result}\n")
                f.write(f"  return: {return_result}\n")

                if not results["entry"] or not results["return"]:
                    all_passed = False

            if all_passed:
                f.write("\nAll uprobe tests PASSED!\n")
            else:
                f.write("\nSome uprobe tests FAILED!\n")
