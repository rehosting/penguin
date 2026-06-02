import os
import shlex
import threading
from pathlib import Path
from typing import Callable, List, Optional

import cffi

from penguin import getColoredLogger

logger = getColoredLogger("pyplugins.qemu_compat")


QEMU_INSTALL_LIB_DIR = Path("/usr/local/lib")
QEMU_INSTALL_HEADER_DIR = Path("/usr/local/include/penguin-qemu-cffi")
SHUTDOWN_CAUSE_HOST_QMP_QUIT = 2

MINIMAL_CDEF = """
typedef _Bool bool;
typedef int64_t target_long;
typedef uint64_t target_ulong;
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
typedef uint64_t (*penguin_mmio_read_cb_t)(uint64_t addr, unsigned size,
                                           void *opaque);
typedef void (*penguin_mmio_write_cb_t)(uint64_t addr, uint64_t data,
                                        unsigned size, void *opaque);

extern MachineState *current_machine;
extern int (*qemu_main)(void);
int main(int argc, char **argv);
void qemu_init(int argc, char **argv);
int qemu_main_loop(void);
void qemu_cleanup(int status);
void qemu_system_shutdown_request(int reason);
void bql_lock_impl(const char *file, int line);
void bql_unlock(void);
void replay_mutex_lock(void);
void replay_mutex_unlock(void);
bool bql_locked(void);
bool replay_mutex_locked(void);
CPUState *qemu_get_cpu(int index);
int cpu_memory_rw_debug(CPUState *cpu, vaddr addr, void *ptr, size_t len,
                        bool is_write);
void set_penguin_guest_hypercall_callback(penguin_guest_hypercall_cb_t cb,
                                          void *opaque);
void penguin_register_guest_hypercall(uint64_t nr);
void penguin_unregister_guest_hypercall(uint64_t nr);
void penguin_clear_guest_hypercalls(void);
bool penguin_guest_hypercall_registered(uint64_t nr);
void set_kvm_penguin_hypercall_callback(kvm_penguin_hypercall_cb_t cb);
void set_kvm_penguin_after_guest_init_callback(
    kvm_penguin_after_guest_init_cb_t cb, void *opaque);
bool penguin_handle_guest_hypercall(CPUState *cs, uint64_t nr,
                                    uint64_t a0, uint64_t a1,
                                    uint64_t a2, uint64_t a3,
                                    uint64_t a4, uint64_t a5,
                                    uint64_t *ret);
int penguin_qemu_add_mmio_region(uint64_t base, uint64_t size,
                                 const char *name,
                                 penguin_mmio_read_cb_t read_cb,
                                 penguin_mmio_write_cb_t write_cb,
                                 void *opaque);
"""


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


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


class QemuArch:
    _CONVENTIONS = {
        "x86_64": {
            "syscall": ["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"],
            "default": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            "nr": "rax",
            "retval": "rax",
        },
        "i386": {
            "syscall": ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"],
            "default": ["eax", "edx", "ecx"],
            "nr": "eax",
            "retval": "eax",
        },
        "aarch64": {
            "syscall": ["x8", "x0", "x1", "x2", "x3", "x4", "x5"],
            "default": ["x0", "x1", "x2", "x3", "x4", "x5"],
            "nr": "x8",
            "retval": "x0",
        },
        "arm": {
            "syscall": ["r7", "r0", "r1", "r2", "r3", "r4", "r5"],
            "default": ["r0", "r1", "r2", "r3", "r4", "r5"],
            "nr": "r7",
            "retval": "r0",
        },
        "mips": {
            "syscall": ["v0", "a0", "a1", "a2", "a3", "a4", "a5"],
            "default": ["a0", "a1", "a2", "a3", "a4", "a5"],
            "nr": "v0",
            "retval": "v0",
        },
        "mipsel": {
            "syscall": ["v0", "a0", "a1", "a2", "a3", "a4", "a5"],
            "default": ["a0", "a1", "a2", "a3", "a4", "a5"],
            "nr": "v0",
            "retval": "v0",
        },
        "mips64": {
            "syscall": ["v0", "a0", "a1", "a2", "a3", "a4", "a5"],
            "default": ["a0", "a1", "a2", "a3", "a4", "a5"],
            "nr": "v0",
            "retval": "v0",
        },
        "mips64el": {
            "syscall": ["v0", "a0", "a1", "a2", "a3", "a4", "a5"],
            "default": ["a0", "a1", "a2", "a3", "a4", "a5"],
            "nr": "v0",
            "retval": "v0",
        },
        "ppc": {
            "syscall": ["r0", "r3", "r4", "r5", "r6", "r7", "r8"],
            "default": ["r3", "r4", "r5", "r6", "r7", "r8"],
            "nr": "r0",
            "retval": "r3",
        },
        "ppc64": {
            "syscall": ["r0", "r3", "r4", "r5", "r6", "r7", "r8"],
            "default": ["r3", "r4", "r5", "r6", "r7", "r8"],
            "nr": "r0",
            "retval": "r3",
        },
        "ppc64le": {
            "syscall": ["r0", "r3", "r4", "r5", "r6", "r7", "r8"],
            "default": ["r3", "r4", "r5", "r6", "r7", "r8"],
            "nr": "r0",
            "retval": "r3",
        },
        "riscv64": {
            "syscall": ["a7", "a0", "a1", "a2", "a3", "a4", "a5"],
            "default": ["a0", "a1", "a2", "a3", "a4", "a5"],
            "nr": "a7",
            "retval": "a0",
        },
        "loongarch64": {
            "syscall": ["a7", "a0", "a1", "a2", "a3", "a4", "a5"],
            "default": ["a0", "a1", "a2", "a3", "a4", "a5"],
            "nr": "a7",
            "retval": "a0",
        },
    }

    def __init__(self, panda):
        self.panda = panda
        self.name = panda.arch_name
        self.family = panda.arch_family
        info = self._CONVENTIONS.get(panda.arch_name, self._CONVENTIONS.get(panda.arch_family))
        if info is None:
            raise ValueError(f"Unsupported QEMU compatibility architecture: {panda.arch_name}")
        self.call_conventions = {
            "syscall": info["syscall"],
            "default": info["default"],
        }
        self._captured_regs = info["syscall"][1:]
        self.nr_reg = info["nr"]
        self.retval_reg = info["retval"]

    def __str__(self):
        return self.family

    def __repr__(self):
        return f"QemuArch({self.name!r})"

    def __eq__(self, other):
        if isinstance(other, str):
            return other in {self.name, self.family}
        return super().__eq__(other)

    def get_reg(self, cpu, reg_name):
        reg_name = reg_name.lower()
        if reg_name in {self.nr_reg, "nr", "syscallno"}:
            return self.panda._current_nr
        if reg_name == "retval":
            return self.panda._current_retval

        if reg_name in self._captured_regs:
            idx = self._captured_regs.index(reg_name)
            if idx < len(self.panda._current_args):
                return self.panda._current_args[idx]
        if reg_name == self.retval_reg:
            return self.panda._current_retval

        logger.warning("QEMU mode: get_reg('%s') not fully supported, returning 0", reg_name)
        return 0

    def get_arg(self, cpu, index, convention="syscall"):
        loc = self._get_arg_loc(index, convention)
        return self.get_reg(cpu, loc)

    def set_arg(self, cpu, index, value, convention="syscall"):
        loc = self._get_arg_loc(index, convention)
        if loc == self.nr_reg:
            self.panda._current_nr = self.panda.to_unsigned_guest(value)
            return
        if loc in self._captured_regs:
            self.panda._current_args[self._captured_regs.index(loc)] = self.panda.to_unsigned_guest(value)
            return
        raise ValueError(
            f"Argument index {index} ({loc}) for convention {convention!r} "
            "is not captured by the QEMU hypercall compatibility layer"
        )

    def _get_arg_loc(self, index, convention):
        if convention not in self.call_conventions:
            raise ValueError(f"Unsupported QEMU compatibility calling convention: {convention}")
        conv = self.call_conventions[convention]
        if index >= len(conv):
            raise ValueError(f"Argument index {index} not supported for convention {convention}")
        return conv[index].lower()

    def set_retval(self, cpu, value, convention="syscall", failure=False):
        self.panda._set_current_retval(value)


class KVMLibPandaMock:
    def __init__(self, lib, ffi, qemu=None):
        self.lib = lib
        self.ffi = ffi
        self.qemu = qemu

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
                ptr = self._to_ptr(buf, length)
                if self.qemu is not None:
                    return self.qemu._cpu_memory_rw_debug(cpu, addr, ptr, length, False)
                return self.lib.cpu_memory_rw_debug(cpu, addr, ptr, length, False)
            return wrapper
        if name == "panda_virtual_memory_write_external":
            def wrapper(cpu, addr, buf, length):
                ptr = self._to_ptr(buf, length)
                if self.qemu is not None:
                    return self.qemu._cpu_memory_rw_debug(cpu, addr, ptr, length, True)
                return self.lib.cpu_memory_rw_debug(cpu, addr, ptr, length, True)
            return wrapper

        try:
            return getattr(self.lib, name)
        except AttributeError:
            raise AttributeError(f"KVMLibPandaMock has no attribute '{name}'")


class QemuCompat:
    _active_instances = []

    @classmethod
    def active_instances(cls):
        return tuple(cls._active_instances)

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
        self.arch_name = self._normalize_arch_name(arch)
        self.arch_family = self._arch_family(self.arch_name)
        self.bits = 64 if "64" in self.arch_name or self.arch_name in {"aarch64", "riscv64"} else 32
        self.endianness = "little"
        if self.arch_name in {"mipseb", "mips64eb", "mips", "mips64", "powerpc", "powerpc64", "ppc", "ppc64"}:
            self.endianness = "big"

        self.lib_path, self.header_path = resolve_qemu_paths(
            self.mode, arch, lib_path=lib_path, header_path=header_path
        )
        self.ffi = cffi.FFI()
        cdef_source = self.header_path.read_text() if self.header_path else MINIMAL_CDEF
        for declaration in (
            "typedef int64_t target_long;",
            "typedef uint64_t target_ulong;",
            "int main(int argc, char **argv);",
            "void bql_lock_impl(const char *file, int line);",
            "bool bql_locked(void);",
            "void replay_mutex_lock(void);",
            "bool replay_mutex_locked(void);",
            "void penguin_register_guest_hypercall(uint64_t nr);",
            "void penguin_unregister_guest_hypercall(uint64_t nr);",
            "void penguin_clear_guest_hypercalls(void);",
            "bool penguin_guest_hypercall_registered(uint64_t nr);",
        ):
            if declaration not in cdef_source:
                cdef_source += f"\n{declaration}\n"
        if "penguin_mmio_read_cb_t" not in cdef_source:
            cdef_source += (
                "\ntypedef uint64_t (*penguin_mmio_read_cb_t)"
                "(uint64_t addr, unsigned size, void *opaque);\n"
            )
        if "penguin_mmio_write_cb_t" not in cdef_source:
            cdef_source += (
                "\ntypedef void (*penguin_mmio_write_cb_t)"
                "(uint64_t addr, uint64_t data, unsigned size, void *opaque);\n"
            )
        if "penguin_qemu_add_mmio_region" not in cdef_source:
            cdef_source += (
                "\nint penguin_qemu_add_mmio_region("
                "uint64_t base, uint64_t size, const char *name, "
                "penguin_mmio_read_cb_t read_cb, "
                "penguin_mmio_write_cb_t write_cb, void *opaque);\n"
            )
        self.ffi.cdef(cdef_source)

        flags = getattr(os, "RTLD_GLOBAL", 0) | getattr(os, "RTLD_NOW", 0)
        self.lib = self.ffi.dlopen(str(self.lib_path), flags=flags)
        self.libpanda = KVMLibPandaMock(self.lib, self.ffi, self)

        self._callback = None
        self._after_guest_init_callback = None
        self._bound_hypercall_plugin = None
        self.arch = QemuArch(self)
        self._thread_state = threading.local()
        self._pre_shutdown_cb = None
        self.panda_args = []

        self._active_instances.append(self)
        self.set_hypercall_callback(self._dispatch_hypercall)
        plugin = self.hypercall_plugin
        if plugin is not None:
            self.bind_hypercall_plugin(plugin)

    def _callback_state(self):
        state = self._thread_state
        if not hasattr(state, "nr"):
            state.nr = 0
            state.args = [0, 0, 0, 0, 0, 0]
            state.ret_ptr = self.ffi.NULL
            state.retval = 0
            state.cpu = self.ffi.NULL
        return state

    @property
    def _current_nr(self):
        return self._callback_state().nr

    @_current_nr.setter
    def _current_nr(self, value):
        self._callback_state().nr = value

    @property
    def _current_args(self):
        return self._callback_state().args

    @_current_args.setter
    def _current_args(self, value):
        self._callback_state().args = value

    @property
    def _current_ret_ptr(self):
        return self._callback_state().ret_ptr

    @_current_ret_ptr.setter
    def _current_ret_ptr(self, value):
        self._callback_state().ret_ptr = value

    @property
    def _current_retval(self):
        return self._callback_state().retval

    @_current_retval.setter
    def _current_retval(self, value):
        self._callback_state().retval = value

    @property
    def _current_cpu(self):
        return self._callback_state().cpu

    @_current_cpu.setter
    def _current_cpu(self, value):
        self._callback_state().cpu = value

    @property
    def direct_syscall_event_writeback(self) -> bool:
        return True

    @classmethod
    def from_installation(cls, mode: str, arch: str):
        return cls(None, arch, mode=mode)

    @staticmethod
    def _normalize_arch_name(arch: str) -> str:
        return {
            "intel64": "x86_64",
            "x86_64": "x86_64",
            "i386": "i386",
            "armel": "arm",
            "arm": "arm",
            "aarch64": "aarch64",
            "mipseb": "mips",
            "mips": "mips",
            "mipsel": "mipsel",
            "mips64eb": "mips64",
            "mips64": "mips64",
            "mips64el": "mips64el",
            "powerpc": "ppc",
            "ppc": "ppc",
            "powerpc64": "ppc64",
            "ppc64": "ppc64",
            "powerpc64le": "ppc64le",
            "ppc64le": "ppc64le",
            "riscv64": "riscv64",
            "loongarch64": "loongarch64",
        }.get(arch, arch)

    @staticmethod
    def _arch_family(arch_name: str) -> str:
        if arch_name in {"x86_64", "i386"}:
            return arch_name
        if arch_name in {"mips", "mipsel", "mips64", "mips64el"}:
            return "mips"
        if arch_name in {"ppc", "ppc64", "ppc64le"}:
            return "ppc"
        if arch_name == "arm":
            return "arm"
        return arch_name

    def get_cpu(self):
        return self._current_cpu

    @property
    def hypercall_plugin(self):
        if self._bound_hypercall_plugin is not None:
            return self._bound_hypercall_plugin

        try:
            from penguin import plugins
        except ImportError:
            return None

        plugin = plugins.__dict__.get("hypercall")
        if plugin is not None:
            return plugin

        try:
            return plugins.hypercall
        except Exception:
            return None

    @property
    def hypercall_handlers(self):
        plugin = self.hypercall_plugin
        if plugin is None:
            return {}
        return plugin.handlers

    def bind_hypercall_plugin(self, plugin):
        self._bound_hypercall_plugin = plugin
        bind_qemu_compat = getattr(plugin, "bind_qemu_compat", None)
        if bind_qemu_compat is not None:
            bind_qemu_compat(self)

    def _lib_symbol(self, name: str):
        try:
            return getattr(self.lib, name)
        except AttributeError:
            return None

    def register_guest_hypercall(self, nr: int) -> bool:
        register = self._lib_symbol("penguin_register_guest_hypercall")
        if register is None:
            return False
        register(int(nr) & 0xFFFFFFFFFFFFFFFF)
        return True

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
        self._current_ret_ptr = ret_ptr
        self._current_retval = 0

        try:
            plugin = self.hypercall_plugin
            if plugin is not None:
                return plugin.dispatch(cs, nr, ret_ptr)
        finally:
            self._current_ret_ptr = self.ffi.NULL

        return 1

    def hypercall(self, nr):
        def decorator(func):
            plugin = self.hypercall_plugin
            if plugin is None:
                raise RuntimeError(
                    "panda.hypercall() is available only after the Penguin "
                    "'hypercall' pyplugin is loaded. Ensure hypercall is loaded "
                    "before plugins that register hypercall handlers."
                )
            plugin.register(nr, func)
            return func
        return decorator

    def _unsupported(self, name):
        raise RuntimeError(
            f"self.panda.{name} is a PANDA API and is not supported by the "
            "Penguin QEMU compatibility backend"
        )

    def set_os_name(self, name):
        self._unsupported("set_os_name")

    def load_plugin(self, name, args=None):
        self._unsupported("load_plugin")

    def unload_plugins(self):
        self._unsupported("unload_plugins")

    def disable_tb_chaining(self):
        self._unsupported("disable_tb_chaining")

    def get_process_name(self, cpu):
        self._unsupported("get_process_name")

    def cb_pre_shutdown(self, f):
        self._pre_shutdown_cb = f
        return f

    def _guest_addr(self, addr):
        mask = (1 << self.bits) - 1
        return self.ffi.cast("vaddr", int(addr) & mask)

    def _call_with_bql(self, fn):
        bql_locked = self._lib_symbol("bql_locked")
        bql_lock = self._lib_symbol("bql_lock_impl")
        bql_unlock = self._lib_symbol("bql_unlock")
        locked_here = False

        if bql_locked and bql_lock and bql_unlock and not bql_locked():
            bql_lock(b"pyplugins/qemu_compat.py", 0)
            locked_here = True
        try:
            return fn()
        finally:
            if locked_here:
                bql_unlock()

    def _cpu_memory_rw_debug(self, cpu, addr, ptr, length, is_write):
        vaddr = self._guest_addr(addr)
        size = self.ffi.cast("size_t", int(length))
        return self._call_with_bql(
            lambda: self.lib.cpu_memory_rw_debug(cpu, vaddr, ptr, size, bool(is_write))
        )

    def _set_current_retval(self, value):
        value = self.to_unsigned_guest(value)
        self._current_retval = value
        if self._current_ret_ptr != self.ffi.NULL:
            self._current_ret_ptr[0] = value

    def from_unsigned_guest(self, value):
        mask = (1 << self.bits) - 1
        sign = 1 << (self.bits - 1)
        value = int(value) & mask
        return value - (1 << self.bits) if value & sign else value

    def to_unsigned_guest(self, value, failure=False):
        return int(value) & ((1 << self.bits) - 1)

    def virtual_memory_read(self, cpu, addr, size, fmt=None):
        buf = self.ffi.new("char[]", size)
        err = self.libpanda.panda_virtual_memory_read_external(cpu, addr, buf, size)
        if err < 0:
            raise ValueError(f"Memory read failed at {addr:#x}")
        data = self.ffi.unpack(buf, size)
        if fmt is None:
            return data
        if fmt == "int":
            return int.from_bytes(data, self.endianness, signed=True)
        if fmt == "uint":
            return int.from_bytes(data, self.endianness, signed=False)
        if fmt == "ptrlist":
            ptr_size = self.bits // 8
            if size % ptr_size:
                raise ValueError(
                    f"ptrlist read size {size} is not aligned to {ptr_size}-byte pointers"
                )
            return [
                int.from_bytes(data[offset:offset + ptr_size], self.endianness, signed=False)
                for offset in range(0, size, ptr_size)
            ]
        raise ValueError(f"Unsupported virtual_memory_read fmt={fmt!r}")

    def virtual_memory_write(self, cpu, addr, data):
        view = memoryview(data)
        cbuf = self.ffi.from_buffer(view)
        err = self.libpanda.panda_virtual_memory_write_external(cpu, addr, cbuf, len(view))
        if err < 0:
            raise ValueError(f"Memory write failed at {addr:#x}")
        return len(view)

    def end_analysis(self):
        if hasattr(self.lib, "qemu_system_shutdown_request"):
            self.lib.qemu_system_shutdown_request(SHUTDOWN_CAUSE_HOST_QMP_QUIT)
        else:
            logger.warning("QEMU library does not expose qemu_system_shutdown_request; end_analysis requested but cannot force shutdown")

    def run(self):
        logger.info("QEMU starting main loop from %s", self.lib_path)
        logger.debug("QEMU argv: %s", shlex.join(self.panda_args))

        argv_storage = [
            self.ffi.new("char[]", arg.encode("utf-8"))
            for arg in self.panda_args
        ]
        argv = self.ffi.new("char *[]", len(argv_storage) + 1)
        for idx, arg in enumerate(argv_storage):
            argv[idx] = arg
        argv[len(argv_storage)] = self.ffi.NULL

        self.lib.qemu_init(len(self.panda_args), argv)
        bql_locked = self._lib_symbol("bql_locked")
        bql_unlock = self._lib_symbol("bql_unlock")
        replay_mutex_lock = self._lib_symbol("replay_mutex_lock")
        replay_mutex_unlock = self._lib_symbol("replay_mutex_unlock")

        if bql_locked and bql_unlock and bql_locked():
            bql_unlock()
        if replay_mutex_unlock:
            replay_mutex_unlock()

        if self.lib.qemu_main != self.ffi.NULL:
            raise RuntimeError(
                "QEMU library requested an alternate qemu_main entry point; "
                "Penguin's QEMU compatibility layer requires direct qemu_main_loop control"
            )

        replay_locked = False
        if replay_mutex_lock:
            replay_mutex_lock()
            replay_locked = True
        self.lib.bql_lock_impl(b"pyplugins/qemu_compat.py", 0)
        try:
            ret = self.lib.qemu_main_loop()
            if self._pre_shutdown_cb:
                self._pre_shutdown_cb()
            self.lib.qemu_cleanup(ret)
        finally:
            if bql_locked and bql_unlock and bql_locked():
                bql_unlock()
            if replay_locked and replay_mutex_unlock:
                replay_mutex_unlock()
        return ret


KVMArch = QemuArch
KVMQemu = QemuCompat
