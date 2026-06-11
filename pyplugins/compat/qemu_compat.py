import json
import os
import re
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
int penguin_read_guest_reg(CPUState *cs, int regnum, uint8_t *buf,
                           int buf_len);
int penguin_write_guest_reg(CPUState *cs, int regnum, const uint8_t *buf,
                            int len);
void *penguin_cpu_env(CPUState *cs);
void penguin_sync_cpu_state(CPUState *cs);
"""

# Alternate spellings under which a QEMU build may have published its
# library/header assets for the same architecture.
_ARCH_FILE_ALIASES = {
    "powerpc64el": ("powerpc64le",),
    "powerpc64le": ("powerpc64el",),
}


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
    arch_names = [arch, *_ARCH_FILE_ALIASES.get(arch, ())]

    lib_value = lib_path or os.environ.get(lib_env)
    if lib_value:
        resolved_lib = Path(lib_value)
    else:
        lib_candidates = [
            path
            for name in arch_names
            for path in _candidate_paths(mode, name, f"libqemu-{mode}-{name}.so")
        ]
        resolved_lib = _resolve_existing(lib_candidates, "library")
    if not resolved_lib.exists():
        raise FileNotFoundError(f"QEMU library not found: {resolved_lib}")

    header_value = header_path or os.environ.get(header_env)
    if header_value:
        resolved_header = Path(header_value)
        if not resolved_header.exists():
            raise FileNotFoundError(f"QEMU CFFI header not found: {resolved_header}")
    else:
        header_candidates = [
            path
            for name in arch_names
            for header_name in [f"qemu_cffi_{mode}_{name}.h"]
            for path in (
                QEMU_INSTALL_HEADER_DIR / header_name,
                resolved_lib.parent / header_name,
                _repo_root() / "emulator" / "kvm-qemu" / ("build-kvm" if mode == "kvm" else "build-system") / header_name,
            )
        ]
        resolved_header = next((path for path in header_candidates if path.exists()), None)

    return resolved_lib, resolved_header


def _build_gdb_regnums():
    """
    GDB core-feature register numbers per architecture, as implemented by
    each target's gdbstub (target/<arch>/gdbstub*.c). Used with the
    penguin_{read,write}_guest_reg QEMU exports; register width is the
    guest's natural word size for every register listed here.
    """
    mips32 = {
        "zero": 0, "at": 1, "v0": 2, "v1": 3,
        "a0": 4, "a1": 5, "a2": 6, "a3": 7,
        "t0": 8, "t1": 9, "t2": 10, "t3": 11,
        "t4": 12, "t5": 13, "t6": 14, "t7": 15,
        "s0": 16, "s1": 17, "s2": 18, "s3": 19,
        "s4": 20, "s5": 21, "s6": 22, "s7": 23,
        "t8": 24, "t9": 25, "k0": 26, "k1": 27,
        "gp": 28, "sp": 29, "fp": 30, "s8": 30, "ra": 31,
        "lo": 33, "hi": 34, "pc": 37,
    }
    # n32/n64 pass syscall args 5-8 in registers 8-11
    mips64 = {**mips32, "a4": 8, "a5": 9, "a6": 10, "a7": 11}
    ppc = {**{f"r{i}": i for i in range(32)}, "sp": 1, "nip": 64, "pc": 64}
    riscv = {
        **{f"x{i}": i for i in range(32)},
        "zero": 0, "ra": 1, "sp": 2, "gp": 3, "tp": 4,
        "t0": 5, "t1": 6, "t2": 7, "s0": 8, "fp": 8, "s1": 9,
        **{f"a{i}": 10 + i for i in range(8)},
        **{f"s{i}": 16 + i for i in range(2, 12)},
        "t3": 28, "t4": 29, "t5": 30, "t6": 31, "pc": 32,
    }
    loongarch = {
        **{f"r{i}": i for i in range(32)},
        "zero": 0, "ra": 1, "tp": 2, "sp": 3,
        **{f"a{i}": 4 + i for i in range(8)},
        **{f"t{i}": 12 + i for i in range(9)},
        "fp": 22, **{f"s{i}": 23 + i for i in range(9)},
        "pc": 33,
    }
    return {
        "x86_64": {
            "rax": 0, "rbx": 1, "rcx": 2, "rdx": 3,
            "rsi": 4, "rdi": 5, "rbp": 6, "rsp": 7,
            **{f"r{i}": i for i in range(8, 16)},
            "sp": 7, "rip": 16, "pc": 16,
        },
        "i386": {
            "eax": 0, "ecx": 1, "edx": 2, "ebx": 3,
            "esp": 4, "ebp": 5, "esi": 6, "edi": 7,
            "sp": 4, "eip": 8, "pc": 8,
        },
        "arm": {
            **{f"r{i}": i for i in range(16)},
            "sp": 13, "lr": 14, "pc": 15,
        },
        "aarch64": {
            **{f"x{i}": i for i in range(31)},
            "lr": 30, "sp": 31, "pc": 32,
        },
        "mips": mips32,
        "mipsel": mips32,
        "mips64": mips64,
        "mips64el": mips64,
        "ppc": ppc,
        "ppc64": ppc,
        "ppc64le": ppc,
        "riscv64": riscv,
        "loongarch64": loongarch,
    }


_GDB_REGNUMS = _build_gdb_regnums()


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
        self._gdb_regs = _GDB_REGNUMS.get(panda.arch_name, _GDB_REGNUMS.get(panda.arch_family, {}))
        self._warned_regs = set()

    def __str__(self):
        return self.family

    def __repr__(self):
        return f"QemuArch({self.name!r})"

    def __eq__(self, other):
        if isinstance(other, str):
            return other in {self.name, self.family}
        return super().__eq__(other)

    def _resolve_cpu(self, cpu):
        if cpu is None or cpu == self.panda.ffi.NULL:
            cpu = self.panda.get_cpu()
        return cpu

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

        regnum = self._gdb_regs.get(reg_name)
        if regnum is not None:
            value = self.panda._read_guest_reg(self._resolve_cpu(cpu), regnum)
            if value is not None:
                return value

        if reg_name not in self._warned_regs:
            self._warned_regs.add(reg_name)
            logger.warning("QEMU mode: get_reg('%s') not supported, returning 0", reg_name)
        return 0

    def set_reg(self, cpu, reg_name, value):
        reg_name = reg_name.lower()
        regnum = self._gdb_regs.get(reg_name)
        if regnum is None:
            raise ValueError(
                f"Unsupported register {reg_name!r} for QEMU compatibility "
                f"architecture {self.name}"
            )
        if not self.panda._write_guest_reg(self._resolve_cpu(cpu), regnum, value):
            raise RuntimeError(f"Failed to write guest register {reg_name!r}")
        # Keep the hypercall-captured view coherent with the guest.
        unsigned = self.panda.to_unsigned_guest(value)
        if reg_name in self._captured_regs:
            idx = self._captured_regs.index(reg_name)
            if idx < len(self.panda._current_args):
                self.panda._current_args[idx] = unsigned
        if reg_name == self.nr_reg:
            self.panda._current_nr = unsigned

    def get_arg(self, cpu, index, convention="syscall"):
        loc = self._get_arg_loc(index, convention)
        return self.get_reg(cpu, loc)

    def set_arg(self, cpu, index, value, convention="syscall"):
        loc = self._get_arg_loc(index, convention)
        unsigned = self.panda.to_unsigned_guest(value)
        captured = False
        if loc == self.nr_reg:
            self.panda._current_nr = unsigned
            captured = True
        elif loc in self._captured_regs:
            self.panda._current_args[self._captured_regs.index(loc)] = unsigned
            captured = True

        # Write through to the real guest register so the change is visible
        # to the guest once the hypercall returns.
        regnum = self._gdb_regs.get(loc)
        if regnum is not None and self.panda._write_guest_reg(self._resolve_cpu(cpu), regnum, unsigned):
            return
        if captured:
            if loc not in self._warned_regs:
                self._warned_regs.add(loc)
                logger.warning(
                    "set_arg(%r): QEMU register write unavailable; the change "
                    "is visible to host-side handlers but not to the guest",
                    loc,
                )
            return
        raise ValueError(
            f"Argument index {index} ({loc}) for convention {convention!r} "
            "is not writable by the QEMU hypercall compatibility layer"
        )

    def _get_arg_loc(self, index, convention):
        if convention not in self.call_conventions:
            raise ValueError(f"Unsupported QEMU compatibility calling convention: {convention}")
        conv = self.call_conventions[convention]
        if index >= len(conv):
            raise ValueError(f"Argument index {index} not supported for convention {convention}")
        return conv[index].lower()

    def set_retval(self, cpu, value, convention="default", failure=False):
        if convention == "syscall" and self.family == "mips":
            # PANDA parity: MIPS syscalls report success/failure in a3, and
            # errors are returned as positive values with a3 set.
            try:
                self.set_reg(cpu, "a3", 1 if failure else 0)
            except (ValueError, RuntimeError):
                if "a3" not in self._warned_regs:
                    self._warned_regs.add("a3")
                    logger.warning(
                        "set_retval: unable to set MIPS a3 success/failure flag"
                    )
            if failure and self.panda.from_unsigned_guest(value) < 0:
                value = -self.panda.from_unsigned_guest(value)
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

        self._requested_arch = arch
        self.lib_path, self.header_path = resolve_qemu_paths(
            self.mode, arch, lib_path=lib_path, header_path=header_path
        )
        self.ffi = cffi.FFI()
        cdef_source = self.header_path.read_text() if self.header_path else MINIMAL_CDEF
        # target_long/target_ulong must match the *guest* word size so that
        # ffi.cast("target_long", x) sign-extends correctly (e.g. a 32-bit
        # guest's 0xFFFFFFFF fd argument casts to -1). PANDA sized these per
        # guest arch; hard-coding int64_t silently broke negative-value /
        # `== -1` checks on 32-bit targets (see rv130 libc_addr regression).
        target_long_t = "int64_t" if self.bits == 64 else "int32_t"
        target_ulong_t = "uint64_t" if self.bits == 64 else "uint32_t"
        for declaration in (
            f"typedef {target_long_t} target_long;",
            f"typedef {target_ulong_t} target_ulong;",
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
        for symbol, declaration in (
            (
                "penguin_read_guest_reg",
                "int penguin_read_guest_reg(CPUState *cs, int regnum, "
                "uint8_t *buf, int buf_len);",
            ),
            (
                "penguin_write_guest_reg",
                "int penguin_write_guest_reg(CPUState *cs, int regnum, "
                "const uint8_t *buf, int len);",
            ),
            (
                "penguin_cpu_env",
                "void *penguin_cpu_env(CPUState *cs);",
            ),
            (
                "penguin_sync_cpu_state",
                "void penguin_sync_cpu_state(CPUState *cs);",
            ),
        ):
            if symbol not in cdef_source:
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

        # Typed CPUArchState access (full per-target env: coprocessor,
        # timer, FPU state). Prefer the compiled CFFI API-mode module
        # (compiler-verified layout, full bitfield/anonymous-member
        # support); fall back to the generated ABI-mode *_env.h header.
        self._env_cdef_loaded = False
        self._env_ffi = None
        self._cpu_state_size = None
        self._load_env_module()
        self._load_env_cdef()

        self._callback = None
        self._after_guest_init_callback = None
        self._bound_hypercall_plugin = None
        self._pending_exception = None
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
            "powerpc64el": "ppc64le",
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

    def _arch_alias_names(self) -> List[str]:
        return [self._requested_arch,
                *_ARCH_FILE_ALIASES.get(self._requested_arch, ())]

    def _load_env_module(self):
        manifest_name = f"qemu_cffi_{self.mode}_manifest.json"
        manifest_path = next(
            (path for path in (QEMU_INSTALL_HEADER_DIR / manifest_name,
                               self.lib_path.parent / manifest_name)
             if path.exists()), None)
        if manifest_path is None:
            return
        try:
            manifest = json.loads(manifest_path.read_text())
        except Exception as exc:
            logger.warning("Unreadable cffi manifest %s: %s", manifest_path, exc)
            return
        arch_names = self._arch_alias_names()
        module_name = next(
            (entry.get("env_module") for entry in manifest.get("headers", [])
             if entry.get("arch") in arch_names and entry.get("env_module")),
            None)
        if module_name is None:
            return
        module_path = next(
            (path for path in (
                QEMU_INSTALL_LIB_DIR / "penguin-qemu-env" / module_name,
                self.lib_path.parent / "penguin-qemu-env" / module_name)
             if path.exists()), None)
        if module_path is None:
            return
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                module_path.name.split(".", 1)[0], module_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:
            logger.warning(
                "Failed to import compiled env module %s (Python ABI "
                "mismatch?): %s", module_path, exc)
            return
        self._env_ffi = module.ffi
        logger.debug("Loaded compiled CPUArchState module %s", module_path)

    def _locate_env_header(self) -> Optional[Path]:
        candidates = []
        if self.header_path is not None:
            candidates.append(
                self.header_path.with_name(self.header_path.stem + "_env.h"))
        arch_names = [self._requested_arch,
                      *_ARCH_FILE_ALIASES.get(self._requested_arch, ())]
        for name in arch_names:
            fname = f"qemu_cffi_{self.mode}_{name}_env.h"
            candidates.append(QEMU_INSTALL_HEADER_DIR / fname)
            candidates.append(self.lib_path.parent / fname)
        return next((path for path in candidates if path.exists()), None)

    def _load_env_cdef(self):
        env_header = self._locate_env_header()
        if env_header is None:
            return
        try:
            source = env_header.read_text()
            self.ffi.cdef(source)
        except Exception as exc:
            logger.warning("Failed to load CPUArchState declarations from %s: %s",
                           env_header, exc)
            return
        match = re.search(r"#define\s+PENGUIN_CPU_STATE_SIZE\s+(\d+)", source)
        if match:
            self._cpu_state_size = int(match.group(1))
        self._env_cdef_loaded = True
        logger.debug("Loaded CPUArchState declarations from %s", env_header)

    @property
    def env_supported(self) -> bool:
        return self._env_ffi is not None or self._env_cdef_loaded

    def sync_cpu_state(self, cpu):
        """
        Synchronize register state out of the accelerator into env (and mark
        the vCPU dirty so env writes are pushed back). No-op under TCG or
        when the QEMU library lacks the export.
        """
        sync = self._lib_symbol("penguin_sync_cpu_state")
        if sync is not None and cpu is not None and cpu != self.ffi.NULL:
            sync(cpu)

    def cpu_env(self, cpu=None, sync=None):
        """
        Return a typed `CPUArchState *` for the given CPU (default: the
        current hypercall CPU), giving access to the full per-target state:
        coprocessor registers, timers, FPU, etc. Requires the *_env.h header
        generated alongside the QEMU library. Under KVM the CPU state is
        synchronized first so reads are fresh and writes stick; pass
        sync=False to skip that.
        """
        if not self.env_supported:
            raise RuntimeError(
                "CPUArchState declarations unavailable: no compiled env "
                f"module or generated qemu_cffi_{self.mode}_"
                f"{self._requested_arch}_env.h was found alongside the "
                "QEMU library"
            )
        if cpu is None:
            cpu = self.get_cpu()
        if cpu is None or cpu == self.ffi.NULL:
            raise ValueError("cpu_env requires a valid CPU pointer")
        if sync is None:
            sync = self.mode == "kvm"
        if sync:
            self.sync_cpu_state(cpu)
        env_fn = self._lib_symbol("penguin_cpu_env")
        if env_fn is not None:
            raw = env_fn(cpu)
        elif self._cpu_state_size is not None:
            # Older lib without the export: CPUArchState immediately
            # follows CPUState (layout validated by QEMU at build time).
            raw = self.ffi.cast("char *", cpu) + self._cpu_state_size
        else:
            raise RuntimeError(
                "QEMU library lacks penguin_cpu_env and the env header has "
                "no PENGUIN_CPU_STATE_SIZE")
        if self._env_ffi is not None:
            # The compiled module owns the typed view; carry the pointer
            # across FFI instances by address.
            addr = int(self.ffi.cast("uintptr_t", raw))
            return self._env_ffi.cast("CPUArchState *", addr)
        return self.ffi.cast("CPUArchState *", raw)

    def _read_guest_reg(self, cpu, regnum):
        """
        Read a guest register by GDB core-feature register number. Returns
        the unsigned value, or None if the QEMU library lacks the export or
        the read fails.
        """
        read_reg = self._lib_symbol("penguin_read_guest_reg")
        if read_reg is None or cpu is None or cpu == self.ffi.NULL:
            return None
        buf = self.ffi.new("uint8_t[16]")
        length = read_reg(cpu, int(regnum), buf, 16)
        if length <= 0:
            return None
        data = bytes(self.ffi.buffer(buf, length))
        return int.from_bytes(data, self.endianness)

    def _write_guest_reg(self, cpu, regnum, value):
        """
        Write a guest register by GDB core-feature register number. Returns
        True on success, False if the QEMU library lacks the export or the
        write fails.
        """
        write_reg = self._lib_symbol("penguin_write_guest_reg")
        if write_reg is None or cpu is None or cpu == self.ffi.NULL:
            return False
        width = self.bits // 8
        data = (int(value) & ((1 << self.bits) - 1)).to_bytes(width, self.endianness)
        buf = self.ffi.new("uint8_t[]", data)
        return write_reg(cpu, int(regnum), buf, width) == 0

    def _record_callback_exception(self, exc):
        """
        Record a fatal error raised inside a guest callback and request
        shutdown, mirroring PyPANDA's fail-fast behavior. The exception is
        re-raised from run() once QEMU's main loop exits.
        """
        if self._pending_exception is None:
            self._pending_exception = exc
        self.end_analysis()

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
            # PyPANDA parity: fmt="int" decodes unsigned (pointers and
            # addresses are read this way throughout the pyplugins).
            return int.from_bytes(data, self.endianness, signed=False)
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
        if self._pending_exception is not None:
            exc = self._pending_exception
            self._pending_exception = None
            raise exc
        return ret


KVMArch = QemuArch
KVMQemu = QemuCompat
