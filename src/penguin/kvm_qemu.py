import logging
import os
from pathlib import Path
from typing import Callable, Dict, Iterator, List, Optional

import cffi

logger = logging.getLogger(__name__)


QEMU_INSTALL_LIB_DIR = Path("/usr/local/lib")
QEMU_INSTALL_HEADER_DIR = Path("/usr/local/include/penguin-qemu-cffi")

MINIMAL_CDEF = """
typedef _Bool bool;
typedef uint64_t vaddr;
typedef struct CPUState CPUState;
typedef struct MachineState MachineState;

typedef int (*penguin_guest_hypercall_cb_t)(CPUState *cs, uint64_t nr,
                                            uint64_t a0, uint64_t a1,
                                            uint64_t a2, uint64_t a3,
                                            uint64_t a4, uint64_t a5,
                                            uint64_t *ret, void *opaque);
typedef int (*kvm_penguin_hypercall_cb_t)(CPUState *cs, uint64_t nr,
                                          uint64_t a0, uint64_t a1,
                                          uint64_t a2, uint64_t a3,
                                          uint64_t a4, uint64_t a5,
                                          uint64_t *ret);
typedef int (*kvm_penguin_after_guest_init_cb_t)(MachineState *machine,
                                                 void *opaque);

extern MachineState *current_machine;
extern int (*qemu_main)(void);
void qemu_init(int argc, char **argv);
int qemu_main_loop(void);
void qemu_cleanup(int status);
CPUState *qemu_get_cpu(int index);
int cpu_memory_rw_debug(CPUState *cpu, vaddr addr, void *ptr, size_t len,
                        bool is_write);
void set_penguin_guest_hypercall_callback(penguin_guest_hypercall_cb_t cb,
                                          void *opaque);
void set_kvm_penguin_hypercall_callback(kvm_penguin_hypercall_cb_t cb);
void set_kvm_penguin_after_guest_init_callback(
    kvm_penguin_after_guest_init_cb_t cb, void *opaque);
bool penguin_handle_guest_hypercall(CPUState *cs, uint64_t nr,
                                    uint64_t a0, uint64_t a1,
                                    uint64_t a2, uint64_t a3,
                                    uint64_t a4, uint64_t a5,
                                    uint64_t *ret);
"""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[3]


def _mode_prefix(mode: str) -> str:
    if mode not in {"kvm", "system"}:
        raise ValueError(f"Unsupported QEMU mode: {mode}")
    return mode


def _candidate_paths(mode: str, arch: str, filename: str) -> List[Path]:
    root = _repo_root()
    build_dir = "build-kvm" if mode == "kvm" else "build-system"
    return [
        QEMU_INSTALL_LIB_DIR / filename,
        root / "emulator" / "kvm-qemu" / build_dir / filename,
        root.parent / "emulator" / "kvm-qemu" / build_dir / filename,
    ]


def _resolve_existing(candidates: List[Path], kind: str) -> Path:
    for path in candidates:
        if path.exists():
            return path
    rendered = "\n  ".join(str(path) for path in candidates)
    raise FileNotFoundError(f"Unable to find QEMU {kind}. Checked:\n  {rendered}")


def resolve_qemu_paths(
    mode: str,
    arch: str,
    lib_path: Optional[str] = None,
    header_path: Optional[str] = None,
) -> tuple[Path, Optional[Path]]:
    mode = _mode_prefix(mode)
    lib_env = "PENGUIN_KVM_LIB" if mode == "kvm" else "PENGUIN_QEMU_LIB"
    header_env = "PENGUIN_KVM_CFFI_HEADER" if mode == "kvm" else "PENGUIN_QEMU_CFFI_HEADER"
    lib_name = f"libqemu-{mode}-{arch}.so"
    header_name = f"qemu_cffi_{mode}_{arch}.h"

    lib_value = lib_path or os.environ.get(lib_env)
    if lib_value:
        resolved_lib = Path(lib_value)
    else:
        resolved_lib = _resolve_existing(_candidate_paths(mode, arch, lib_name), "library")
    if not resolved_lib.exists():
        raise FileNotFoundError(f"QEMU library not found: {resolved_lib}")

    header_value = header_path or os.environ.get(header_env)
    if header_value:
        resolved_header = Path(header_value)
        if not resolved_header.exists():
            raise FileNotFoundError(f"QEMU CFFI header not found: {resolved_header}")
    else:
        header_candidates = [
            QEMU_INSTALL_HEADER_DIR / header_name,
            resolved_lib.parent / header_name,
            _repo_root() / "emulator" / "kvm-qemu" / ("build-kvm" if mode == "kvm" else "build-system") / header_name,
        ]
        resolved_header = next((path for path in header_candidates if path.exists()), None)

    return resolved_lib, resolved_header


class KVMArch:
    def __init__(self, panda):
        self.panda = panda
        if "64" in panda.arch_name or panda.arch_name in {"aarch64", "riscv64"}:
            self.call_conventions = {
                "syscall": ["rdi", "rsi", "rdx", "r10", "r8", "r9"],
                "default": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            }
        else:
            self.call_conventions = {
                "syscall": ["ebx", "ecx", "edx", "esi", "edi", "ebp"],
                "default": ["eax", "edx", "ecx"],
            }

    def get_reg(self, cpu, reg_name):
        if reg_name in ["rax", "eax"]:
            return self.panda._current_nr

        conv = self.call_conventions["syscall"]
        if reg_name in conv:
            idx = conv.index(reg_name)
            if idx < len(self.panda._current_args):
                return self.panda._current_args[idx]

        logger.warning("QEMU mode: get_reg('%s') not fully supported, returning 0", reg_name)
        return 0

    def get_arg(self, cpu, index, convention="syscall"):
        if index == 0:
            return self.panda._current_nr
        if 1 <= index <= 6:
            return self.panda._current_args[index - 1]
        raise ValueError(f"Argument index {index} not supported in QEMU mode")


class KVMLibPandaMock:
    def __init__(self, lib, ffi):
        self.lib = lib
        self.ffi = ffi

    def _to_ptr(self, buf, length):
        if buf == self.ffi.NULL:
            return buf
        if isinstance(buf, int):
            return self.ffi.cast("void *", buf)
        if isinstance(buf, self.ffi.CData):
            return self.ffi.cast("void *", buf)
        try:
            return self.ffi.from_buffer(buf)
        except TypeError:
            return self.ffi.cast("void *", buf)

    def __getattr__(self, name):
        if name == "panda_virtual_memory_read_external":
            def wrapper(cpu, addr, buf, length):
                return self.lib.cpu_memory_rw_debug(
                    cpu, addr, self._to_ptr(buf, length), length, False
                )
            return wrapper
        if name == "panda_virtual_memory_write_external":
            def wrapper(cpu, addr, buf, length):
                return self.lib.cpu_memory_rw_debug(
                    cpu, addr, self._to_ptr(buf, length), length, True
                )
            return wrapper

        try:
            return getattr(self.lib, name)
        except AttributeError:
            raise AttributeError(f"KVMLibPandaMock has no attribute '{name}'")


class KVMQemu:
    """
    CFFI wrapper for Penguin's QEMU shared-library builds.

    The historical class name is retained because Penguin plugins expect a
    PANDA-like object. Use mode="kvm" for libqemu-kvm-ARCH.so and
    mode="system" for libqemu-system-ARCH.so.
    """

    def __init__(
        self,
        lib_path: Optional[str],
        arch: str,
        mode: str = "kvm",
        header_path: Optional[str] = None,
    ):
        self.mode = _mode_prefix(mode)
        self.arch_name = arch
        self.bits = 64 if "64" in arch or arch in {"aarch64", "riscv64"} else 32
        self.endianness = "little"
        if arch in {"mipseb", "mips64eb", "powerpc", "powerpc64"}:
            self.endianness = "big"

        self.lib_path, self.header_path = resolve_qemu_paths(
            self.mode, arch, lib_path=lib_path, header_path=header_path
        )
        self.ffi = cffi.FFI()
        self.ffi.cdef(self.header_path.read_text() if self.header_path else MINIMAL_CDEF)

        flags = getattr(os, "RTLD_GLOBAL", 0) | getattr(os, "RTLD_NOW", 0)
        self.lib = self.ffi.dlopen(str(self.lib_path), flags=flags)
        self.libpanda = KVMLibPandaMock(self.lib, self.ffi)

        self._callback = None
        self._after_guest_init_callback = None
        self.hypercall_handlers: Dict[int, List[Callable]] = {}
        self.arch = KVMArch(self)
        self._current_nr = 0
        self._current_args = [0, 0, 0, 0, 0, 0]
        self._pre_shutdown_cb = None
        self.panda_args = []
        self._current_cpu = self.ffi.NULL

        self.set_hypercall_callback(self._dispatch_hypercall)

    @classmethod
    def from_installation(cls, mode: str, arch: str):
        return cls(None, arch, mode=mode)

    def get_cpu(self):
        return self._current_cpu

    def set_hypercall_callback(self, cb: Callable):
        if self.mode == "kvm":
            ctype = (
                "int(CPUState *, uint64_t, uint64_t, uint64_t, uint64_t, "
                "uint64_t, uint64_t, uint64_t, uint64_t *)"
            )
            self._callback = self.ffi.callback(ctype)(cb)
            self.lib.set_kvm_penguin_hypercall_callback(self._callback)
        else:
            ctype = (
                "int(CPUState *, uint64_t, uint64_t, uint64_t, uint64_t, "
                "uint64_t, uint64_t, uint64_t, uint64_t *, void *)"
            )
            self._callback = self.ffi.callback(ctype)(cb)
            self.lib.set_penguin_guest_hypercall_callback(self._callback, self.ffi.NULL)

    def set_after_guest_init_callback(self, cb: Callable):
        ctype = "int(MachineState *, void *)"
        self._after_guest_init_callback = self.ffi.callback(ctype)(cb)
        self.lib.set_kvm_penguin_after_guest_init_callback(
            self._after_guest_init_callback, self.ffi.NULL
        )

    def _dispatch_hypercall(self, cs, nr, a0, a1, a2, a3, a4, a5, ret_ptr, opaque=None):
        self._current_nr = nr
        self._current_args = [a0, a1, a2, a3, a4, a5]
        self._current_cpu = cs

        if nr in self.hypercall_handlers:
            for handler in self.hypercall_handlers[nr]:
                try:
                    res = handler(cs)
                    if isinstance(res, Iterator):
                        for _ in res:
                            pass
                except Exception as e:
                    logger.exception("Error in hypercall handler for %s: %s", nr, e)
            ret_ptr[0] = 0
            return 0

        ret_ptr[0] = 0xDEADC0DE
        return 0

    def hypercall(self, nr):
        def decorator(func):
            self.hypercall_handlers.setdefault(nr, []).append(func)
            return func
        return decorator

    def set_os_name(self, name):
        logger.debug("QEMU mode: ignoring set_os_name('%s')", name)

    def load_plugin(self, name, args=None):
        logger.debug("QEMU mode: ignoring load_plugin('%s', args=%s)", name, args)

    def cb_pre_shutdown(self, f):
        self._pre_shutdown_cb = f
        return f

    def run(self):
        logger.info("QEMU starting main loop from %s", self.lib_path)

        argv = self.ffi.new("char *[]", [arg.encode("utf-8") for arg in self.panda_args])
        self.lib.qemu_init(len(self.panda_args), argv)

        if self.lib.qemu_main != self.ffi.NULL:
            ret = self.lib.qemu_main()
        else:
            ret = self.lib.qemu_main_loop()
            self.lib.qemu_cleanup(ret)

        if self._pre_shutdown_cb:
            self._pre_shutdown_cb()
        return ret
