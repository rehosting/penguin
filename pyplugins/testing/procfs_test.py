from penguin import Plugin, plugins
from wrappers.ptregs_wrap import PtRegsWrapper
from hyperfile.models.base import ProcFile
from hyperfile.models.read import ReadConstBuf
from hyperfile.models.write import WriteDiscard
from hyperfile.models.ioctl import IoctlZero


class SimpleProcfsFile(ReadConstBuf, WriteDiscard, IoctlZero, ProcFile):
    PATH = "s/i/m/p/l/e/simple_proc"  # No /proc prefix

    def __init__(self):
        super().__init__(buffer=b"Hello from simple_proc!\n")

    def open(self, ptregs: PtRegsWrapper, inode: int, file: int):
        procname = yield from plugins.osi.get_proc_name()
        print(f"SimpleProcfsFile.open called in {procname}")
        ptregs.set_retval(0)

    def release(self, ptregs: PtRegsWrapper, inode: int, file: int):
        procname = yield from plugins.osi.get_proc_name()
        print(f"SimpleProcfsFile.release called in {procname}")
        ptregs.set_retval(0)

class CPUinfoFile(ReadConstBuf, ProcFile):
    PATH = "/proc/cpuinfo"  # No /proc prefix
    def __init__(self):
        data = b"processor       : IGLOO\n"
        super().__init__(buffer=data)


class ModulesFile(ReadConstBuf, ProcFile):
    PATH = "/proc/modules"  # No /proc prefix

    def __init__(self, modules: dict = None):
        self.modules = modules if modules is not None else {}
        formatted = self._format_proc_modules(self.modules)
        data = formatted.encode("utf-8") if formatted else b""
        super().__init__(buffer=data)

    def _format_proc_modules(self, modules: dict) -> str:
        """
        Format a dictionary of modules into /proc/modules output.

        modules: dict mapping module_name -> attribute dict.

        Valid attribute keys (all optional):
            init_size: int
            core_size: int
            refcount: int or "-"
            deps: list[str]
            state: "LIVE", "COMING", "GOING", "UNFORMED"
            base_addr: int
            taints: str (e.g., "O", "P", "OE")
        """

        results = []

        # Kernel state → printed string
        state_map = {
            "GOING": "Unloading",
            "COMING": "Loading",
            "LIVE": "Live",
        }

        for name, attr in modules.items():
            # ----- Defaults -----
            init_size  = attr.get("init_size", 0)
            core_size  = attr.get("core_size", 0)
            total_size = init_size + core_size

            refcount   = attr.get("refcount", "-")
            deps_list  = attr.get("deps", [])
            state      = attr.get("state", "LIVE")
            base_addr  = attr.get("base_addr", 0)
            taints     = attr.get("taints", "")

            # Skip unformed modules like the kernel
            if state == "UNFORMED":
                continue

            # ----- Format fields -----
            line = f"{name} {total_size}"

            # refcount
            if refcount is None:
                refcount = "-"
            line += f" {refcount}"

            # dependencies
            deps = ",".join(deps_list) if deps_list else "-"
            line += f" {deps}"

            # state text
            state_str = state_map.get(state, "Live")
            line += f" {state_str}"

            # address (hex)
            line += f" 0x{base_addr:x}"

            # taints (e.g. "(O)" or "(OE)")
            if taints:
                line += f" ({taints})"

            results.append(line)

        # kernel prints nothing if no modules produce output
        return "\n".join(results) if results else ""



class ProcTest(Plugin):
    def __init__(self):
        plugins.procfs.register_proc(SimpleProcfsFile())
        plugins.procfs.register_proc(CPUinfoFile())
        plugins.procfs.register_proc(ModulesFile())
