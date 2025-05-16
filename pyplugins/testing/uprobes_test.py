"""
This plugin verifies that hypercalls are being made correctly.
"""

from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins
from os.path import join, realpath, basename
from glob import glob

uprobes = plugins.uprobes
portal = plugins.portal

IGLOO_DYLIBS_GUEST = "/igloo/dylibs/*"

class UprobesTest(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.conf = self.get_arg("conf")
        self.logger = getColoredLogger("plugins.syscall_test")
        self.done_once = False
        self.libc_path = self._lookup_libc(self.conf["static_files"])
        

        self.libc_symbols = self._get_library_symbols(self.libc_path)
        libc_guest_path = realpath(join(IGLOO_DYLIBS_GUEST, "..", basename(self.libc_path)))
        uprobes.uprobe(libc_guest_path, self.libc_symbols["printf"])(self.uprobe_printf)



            
    def _lookup_libc(self, static_files):
        dylibs = static_files[IGLOO_DYLIBS_GUEST]
        dylibs_host = dylibs["host_path"]
        libc_paths = glob(f"{dylibs_host}*libc*")
        if libc_paths:
            libc_path = realpath(libc_paths[0])
            return libc_path
        else:
            raise Exception("Could not find libc path in static files")
        
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
            
            self.logger.info(f"Extracted {len(symbols)} symbols from {libc_path}")
            return symbols
        except CalledProcessError as e:
            self.logger.error(f"Failed to run nm on {libc_path}: {e}")
            if e.stderr:
                self.logger.error(f"stderr: {e.stderr}")
            return {}
    
    @portal.wrap
    def uprobe_printf(self, pt_regs):
        task = yield from portal.get_proc()
        breakpoint()
    
    @portal.wrap
    def uprobe_malloc(self, pt_regs):
        retval = pt_regs.get_retval()
        m = yield from portal.get_mapping_by_addr(retval)
        breakpoint()
        print("asdf")