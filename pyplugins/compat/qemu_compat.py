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
typedef bool (*penguin_qmp_cb_t)(const char *command, const char *args,
                                 char **result, void *opaque);
void set_penguin_qmp_callback(penguin_qmp_cb_t cb, void *opaque);
bool penguin_handle_qmp(const char *command, const char *args, char **result);
char *strdup(const char *s);
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
            "bool penguin_save_snapshot(const char *name);",
            "bool penguin_load_snapshot(const char *name);",
            "void penguin_schedule_snapshot(const char *name, bool load);",
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
        if "penguin_qmp_cb_t" not in cdef_source:
            cdef_source += (
                "\ntypedef bool (*penguin_qmp_cb_t)(const char *command, "
                "const char *args, char **result, void *opaque);\n"
            )
        if "set_penguin_qmp_callback" not in cdef_source:
            cdef_source += (
                "\nvoid set_penguin_qmp_callback("
                "penguin_qmp_cb_t cb, void *opaque);\n"
            )
        if "char *strdup" not in cdef_source:
            cdef_source += "\nchar *strdup(const char *s);\n"
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
        self._qmp_callback = None
        self._bound_qmp_plugin = None
        self.panda_args = []

        self._active_instances.append(self)
        self.set_hypercall_callback(self._dispatch_hypercall)
        plugin = self.hypercall_plugin
        if plugin is not None:
            self.bind_hypercall_plugin(plugin)
        qmp_plugin = self.qmp_plugin
        if qmp_plugin is not None:
            # Let the plugin decide whether to install now: it binds this
            # instance and installs the C trampoline lazily, only if it already
            # has commands registered.
            bind = getattr(qmp_plugin, "bind_qemu_compat", None)
            if bind is not None:
                bind(self)
            else:
                self.install_qmp_dispatch(qmp_plugin)

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

    @property
    def qmp_plugin(self):
        if self._bound_qmp_plugin is not None:
            return self._bound_qmp_plugin

        try:
            from penguin import plugins
        except ImportError:
            return None

        plugin = plugins.__dict__.get("qmp")
        if plugin is not None:
            return plugin

        try:
            return plugins.qmp
        except Exception:
            return None

    def install_qmp_dispatch(self, plugin):
        """Bind the Qmp pyplugin and install the single C-level QMP trampoline.

        The plugin owns the command name -> handler registry; the compat layer
        only forwards unrecognized QMP commands to it (mirroring how the
        hypercall trampoline forwards to the Hypercall plugin). Idempotent: the
        C callback is installed once and re-binding just updates the plugin.
        """
        self._bound_qmp_plugin = plugin

        setter = self._lib_symbol("set_penguin_qmp_callback")
        if setter is None:
            logger.warning(
                "QEMU library does not expose set_penguin_qmp_callback; "
                "custom QMP commands require a rebuilt penguin-qemu")
            return
        if self._qmp_callback is None:
            ctype = "bool(const char *, const char *, char **, void *)"
            self._qmp_callback = self.ffi.callback(ctype)(self._dispatch_qmp)
            setter(self._qmp_callback, self.ffi.NULL)

    def _dispatch_qmp(self, command_ptr, args_ptr, result_ptr, opaque=None):
        # command_ptr/args_ptr are C strings; decode up front so log lines show
        # the command name (not "<cdata 'char *'>").
        command = self.ffi.string(command_ptr).decode("utf-8", "replace")
        plugin = self.qmp_plugin
        if plugin is None:
            return False
        try:
            raw_args = self.ffi.string(args_ptr).decode("utf-8", "replace")
            try:
                args = json.loads(raw_args) if raw_args else {}
            except json.JSONDecodeError:
                args = {}
            outcome = plugin.dispatch(command, args)
        except Exception:
            # The current QMP ABI (bool + result string) can't carry a
            # structured error, so a failing handler is reported to the client
            # as CommandNotFound. Log the real cause host-side.
            logger.exception("QMP handler for %r raised", command)
            return False
        if outcome is None or outcome is False:
            return False
        if outcome is not True:
            try:
                payload = json.dumps(outcome).encode("utf-8")
            except (TypeError, ValueError):
                logger.exception(
                    "QMP handler for %r returned non-serializable result",
                    command)
                return False
            # Ownership of the returned buffer transfers to QEMU, which
            # g_free()s it after decoding. glib's g_free is compatible with
            # the system allocator, so a libc strdup() buffer is correct; a
            # cffi-managed ffi.new() buffer would be GC-freed underneath QEMU.
            result_ptr[0] = self.lib.strdup(payload)
        return True

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

    def save_snapshot(self, name: str) -> bool:
        """Save an internal VM snapshot named ``name`` (savevm).

        Wraps the fork's penguin_save_snapshot(). The underlying
        save_snapshot() stops the VM, serialises device + RAM state into the
        active block device's internal-snapshot store, and resumes. Must be
        invoked from the main loop context (e.g. a readiness/event callback,
        not a vCPU-thread hypercall handler) to avoid contending with the
        snapshot's own main-loop pumping; the BQL is taken here if needed.
        Returns True on success.
        """
        fn = self._lib_symbol("penguin_save_snapshot")
        if fn is None:
            logger.warning(
                "QEMU library does not expose penguin_save_snapshot; "
                "snapshot support requires a penguin-qemu build that exports "
                "it (flake input `penguin-qemu`, staged by "
                "nix/mk-penguin-qemu.nix)")
            return False
        cname = self.ffi.new("char[]", name.encode("utf-8"))
        ok = bool(self._call_with_bql(lambda: fn(cname)))
        if not ok:
            logger.error("savevm '%s' failed (see QEMU stderr)", name)
        return ok

    def load_snapshot(self, name: str) -> bool:
        """Restore an internal VM snapshot named ``name`` (loadvm).

        Wraps the fork's penguin_load_snapshot(), which stops the VM, restores
        device + RAM state, and restores the prior runstate. Same calling-context
        rules as :meth:`save_snapshot`. Returns True on success.
        """
        fn = self._lib_symbol("penguin_load_snapshot")
        if fn is None:
            logger.warning(
                "QEMU library does not expose penguin_load_snapshot; "
                "snapshot support requires a penguin-qemu build that exports "
                "it (flake input `penguin-qemu`, staged by "
                "nix/mk-penguin-qemu.nix)")
            return False
        cname = self.ffi.new("char[]", name.encode("utf-8"))
        ok = bool(self._call_with_bql(lambda: fn(cname)))
        if not ok:
            logger.error("loadvm '%s' failed (see QEMU stderr)", name)
        return ok

    def schedule_snapshot(self, name: str, load: bool = False) -> bool:
        """Schedule a savevm (load=False) or loadvm (load=True) on the main loop.

        Fire-and-forget and safe to call from a vCPU-thread callback (e.g. a
        guest hypercall / readiness handler): the snapshot runs in the main
        loop context where it can stop the vCPUs without deadlocking. Prefer
        this over :meth:`save_snapshot`/:meth:`load_snapshot` from such
        callbacks. Returns True if the request was successfully scheduled (not
        whether the snapshot itself succeeded — that is logged to QEMU stderr).
        """
        fn = self._lib_symbol("penguin_schedule_snapshot")
        if fn is None:
            logger.warning(
                "QEMU library does not expose penguin_schedule_snapshot; "
                "snapshot support requires a penguin-qemu build that exports "
                "it (flake input `penguin-qemu`, staged by "
                "nix/mk-penguin-qemu.nix)")
            return False
        cname = self.ffi.new("char[]", name.encode("utf-8"))
        self._call_with_bql(lambda: fn(cname, bool(load)))
        return True

    # ---- fastsnap: device state in a block -------------------------------
    #
    # A second, faster reset path beside savevm/loadvm, and deliberately a
    # lower-fidelity one: it restores DEVICE state only, never RAM. What that
    # buys is not just a smaller write -- load_snapshot() goes through
    # vm_stop(RUN_STATE_RESTORE_VM), which accel/tcg turns into a full
    # tb_flush, and the guest then re-translates everything it runs. On this
    # lane's target that re-translation cost more than the restore itself, and
    # it lands as throughput afterwards rather than latency during, so a
    # restore-latency number does not show it. A device-only restore changes
    # no RAM, so nothing it does can invalidate a translated block, and the
    # flush is skipped as unnecessary rather than merely deferred.
    #
    # Fire-and-forget, like schedule_snapshot(), and for the same reason: the
    # work needs the BQL and stopped vCPUs, and a pyplugin callback has
    # neither. Poll fastsnap_seq() for completion.

    FASTSNAP_TAKE = 0
    FASTSNAP_RESTORE = 1
    FASTSNAP_RELEASE = 2
    FASTSNAP_PROBE = 3
    # Restore, then digest the result before the guest gets to run again.
    # A caller cannot verify a restore with PROBE alone: the earliest it can
    # schedule one is from a later guest event, by which time cpu and timer
    # state have moved and the digest can never match what the block was taken
    # at. This op re-serialises inside the same bottom half, vCPUs still
    # stopped, so last_digest() is directly comparable to the one TAKE left.
    # last_us() still reports the restore alone.
    FASTSNAP_RESTORE_VERIFY = 4

    # Digest the WHOLE guest -- every RAM block, then the device block -- with
    # the vCPUs stopped. This exists because the two channels penguin already
    # has cannot see a corrupt guest: the device digest covers devices by
    # construction, and crashes.yaml hooks USERSPACE fatal signals, so a run
    # that panicked the kernel 98 times produced a crashes.yaml the same shape
    # as a healthy one. "No crashes recorded" is therefore not evidence of a
    # healthy guest; this is the signal that does not need the guest well
    # enough to deliver a signal. Read the halves separately --
    # fastsnap_last_digest() for devices, fastsnap_last_ram_digest() for RAM --
    # so a divergence says WHICH half moved.
    FASTSNAP_STATE_DIGEST = 5

    # The fork oracle. FORK_REF forks at the stopped-vCPU safe point; the child
    # blocks every signal and parks in pause(), so its copy of guest RAM stays
    # byte-identical to the instant of the fork. FORK_DIFF reads it back with
    # process_vm_readv() -- fork preserves the address-space layout, so a
    # RAMBlock is at the same host address in both -- and compares page by
    # page. A digest answers "did the state come back"; only this answers
    # "come back WHERE", which is the question a dirty-tracking bug turns on.
    #
    # Independent of the mechanism it checks, deliberately: the reference is
    # never the source the restore reads from. FORK_REF refuses outright if any
    # block carries RAM_SHARED, because a shared block is the SAME memory in
    # both processes and the "reference" would track the parent's live state
    # and report zero differences forever.
    #
    # FORK_DROP reaps the child. A parked reference holds a full CoW copy of
    # guest RAM, so drop it when done.
    FASTSNAP_FORK_REF = 6
    FASTSNAP_FORK_DIFF = 7
    FASTSNAP_FORK_DROP = 8

    # How many guest pages a stretch of execution writes to, via QEMU's own
    # migration dirty bitmap. The clear IS the arm: TCG re-marks a page's TLB
    # entry TLB_NOTDIRTY only once its dirty bits are gone. DIRTY_COUNT reads
    # the set accumulated since the last arm or count and clears it again, so a
    # loop of counts yields one number per interval. Take no savevm/loadvm in
    # the interval -- the migration code walks and clears the same bitmap.
    FASTSNAP_DIRTY_ARM = 9
    FASTSNAP_DIRTY_COUNT = 10
    FASTSNAP_DIRTY_STOP = 11

    # The RAM half. RAM_SNAPSHOT copies every block AND arms tracking in one
    # operation -- as separate ops the guest would run in the gap and those
    # writes would be lost silently. RAM_RESTORE copies back the pages dirtied
    # since, invalidates translated code for exactly those ranges, and re-arms.
    FASTSNAP_RAM_SNAPSHOT = 12
    FASTSNAP_RAM_RESTORE = 13
    FASTSNAP_RAM_RELEASE = 14

    # A complete reset, as two ops. LOOP_ARM takes the device block, snapshots
    # RAM, arms tracking and forks the reference, all in ONE bottom half: the
    # guest executes between bottom halves, so a reference taken even one op
    # later holds a different moment than the snapshot, and every later
    # comparison would report a failing reset forever for a reset that was
    # correct. LOOP_RESET is device block then dirty RAM pages.
    #
    # Neither half is sound alone. Restoring devices without RAM rewinds the
    # CPU's page-table base into RAM that was never rewound; measured on real
    # firmware that destroys the guest within a handful of restores (kernel
    # panic in rcu_process_callbacks, swap_dup errors, OOM kills) while an
    # identical cadence with the restore removed stays clean.
    FASTSNAP_LOOP_ARM = 15
    FASTSNAP_LOOP_RESET = 16

    # Reset AND diff against the fork reference in one bottom half. This is
    # the only form usable on a guest that is running: as two ops the guest
    # executes in the gap and dirties pages of ordinary kernel work, so a
    # perfectly correct reset reports hundreds of differing pages. last_us()
    # reports the reset alone and fastsnap_diff_us() the comparison, because
    # the comparison reads all of guest RAM back and is ~80x the reset -- a
    # loop pays for the reset every iteration and for the oracle only when it
    # asks.
    FASTSNAP_LOOP_RESET_VERIFY = 17

    # The C symbols these bindings call. A PYTHON-level preflight -- checking
    # that a QemuCompat method exists -- cannot see a missing one of these, and
    # that distinction is not academic: the methods below were added here and
    # the matching declarations were not added to the generated cffi header, so
    # `_lib_symbol` returned None, every accessor handed back its "absent"
    # fallback, and a 256 MB RAM snapshot reported itself as 0 bytes for a
    # whole run without anything raising. The question a caller needs answered
    # is about the LIBRARY, so ask the library.
    FASTSNAP_SYMBOLS = (
        "penguin_fastsnap_set_denylist",
        "penguin_fastsnap_set_allowlist",
        "penguin_fastsnap_section_names",
        "penguin_fastsnap_schedule",
        "penguin_fastsnap_seq",
        "penguin_fastsnap_last_rc",
        "penguin_fastsnap_last_us",
        "penguin_fastsnap_bh_done_us",
        "penguin_fastsnap_last_digest",
        "penguin_fastsnap_last_ram_digest",
        "penguin_fastsnap_diff_pages",
        "penguin_fastsnap_diff_us",
        "penguin_fastsnap_diff_bytes_checked",
        "penguin_fastsnap_diff_report",
        "penguin_fastsnap_ram_restored_pages",
        "penguin_fastsnap_ram_restored_code_pages",
        "penguin_fastsnap_ram_snapshot_bytes",
        "penguin_fastsnap_dirty_pages",
        "penguin_fastsnap_dirty_pages_scanned",
        "penguin_fastsnap_dirty_page_size",
        "penguin_fastsnap_dirty_report",
        "penguin_fastsnap_dirty_blocks",
        "penguin_fastsnap_block_size",
        "penguin_fastsnap_section_count",
        "penguin_fastsnap_dev_diff_sections",
        "penguin_fastsnap_dev_unrestorable_sections",
        "penguin_fastsnap_dev_diff_report",
    )

    def fastsnap_missing_symbols(self) -> list:
        """Which of FASTSNAP_SYMBOLS this build does not expose.

        A symbol can be absent two ways and both look the same from here: the
        QEMU library genuinely lacks it, or the generated cffi header never
        declared it so ffi.cdef has no prototype. Either way calling it is
        impossible, and either way the honest answer to the caller is a name in
        this list rather than a plausible-looking zero.
        """
        return [n for n in self.FASTSNAP_SYMBOLS if self._lib_symbol(n) is None]

    def _fastsnap_fn(self, name):
        fn = self._lib_symbol(name)
        if fn is None:
            raise RuntimeError(
                f"{name} is not callable in this build -- either the QEMU "
                f"library does not export it or the generated cffi header does "
                f"not declare it. Returning a default here would put a made-up "
                f"number into a measurement; check fastsnap_missing_symbols() "
                f"before the run instead.")
        return fn

    def fastsnap_available(self) -> bool:
        """True if this QEMU build exports the fastsnap ABI."""
        return self._lib_symbol("penguin_fastsnap_schedule") is not None

    def fastsnap_set_denylist(self, names) -> bool:
        """Exclude these section ids from the next block.

        Not a tuning knob -- a correctness requirement on any machine with
        virtio. A virtio device's state is split between the device model
        (last_avail_idx/used_idx) and the vring, which lives in GUEST RAM. A
        device-only restore puts back the first and leaves the second as the
        guest has since made it, and virtio_load() rejects the result:

            VQ 1 size 0x100 < last_avail_idx 0x9 - used_idx 0x11

        Measured on a booted firmware image. So the fast path gives up the
        devices whose state is co-located with guest RAM -- the announced
        trade, not a defect.
        """
        fn = self._lib_symbol("penguin_fastsnap_set_denylist")
        if fn is None:
            return False
        if not isinstance(names, str):
            names = ",".join(names or [])
        cname = self.ffi.new("char[]", names.encode("utf-8"))
        fn(cname)
        return True

    def fastsnap_set_allowlist(self, names) -> bool:
        """Keep ONLY these section ids in the next block. Clears any denylist.

        This is the largest single lever on reset cost -- measured, a full
        seventeen-section block restores in 0.752 ms and a {cpu, timer} block
        in 0.043 ms, against a RAM half of tens of microseconds -- and the
        most dangerous setting in this ABI. A denylist is conservative: a
        device nobody named is still restored. An allowlist drops everything
        the caller did not think of, and a dropped section does not fail. It
        drifts, and the guest misbehaves thousands of iterations later with
        nothing pointing back here.

        Do not use it without reading :meth:`fastsnap_dev_diff_sections` on
        verification laps. That is the check that turns "faster" into
        "faster and still putting the guest back".
        """
        fn = self._lib_symbol("penguin_fastsnap_set_allowlist")
        if fn is None:
            return False
        if not isinstance(names, str):
            names = ",".join(names or [])
        cname = self.ffi.new("char[]", names.encode("utf-8"))
        fn(cname)
        return True

    def fastsnap_dev_diff_sections(self) -> int:
        """Device sections differing from the arm-time reference, after the
        last LOOP_RESET_VERIFY.

        The reference always covers the FULL section set, whatever the block is
        scoped to, so this sees the sections an allowlist left out. Zero means
        the reset put every section back -- including the omitted ones, which
        is the case that licenses the allowlist: a section the workload never
        touches costs nothing to skip.

        -1 means the comparison could not be made (no reference taken, or the
        walk failed) and must NOT be read as zero.
        """
        return int(self._fastsnap_fn("penguin_fastsnap_dev_diff_sections")())

    def fastsnap_dev_unrestorable_sections(self) -> int:
        """Sections that WERE in the block, were restored from it, and still
        do not serialise to the reference's bytes.

        Separate from :meth:`fastsnap_dev_diff_sections` because the two
        license opposite actions. A scope miss is fixed by widening the scope;
        this is not. Either the device's save is not a pure function of its
        restorable state -- ``mc146818rtc`` reads the live clock in
        ``rtc_pre_save`` and re-derives its timers in ``rtc_post_load``, so it
        can never come back byte-identical however correct the restore is -- or
        the restore is genuinely broken for that device.

        Neither is fixed by adding a section to an allowlist it is already in,
        which is exactly what conflating the two produced: a run added it, the
        report did not change, and throughput halved.

        -1 when no comparison could be made. Not zero.
        """
        return int(self._fastsnap_fn(
            "penguin_fastsnap_dev_unrestorable_sections")())

    def fastsnap_dev_diff_report(self) -> str:
        """Comma-separated ids of the differing device sections. A leading '-'
        marks one that vanished since the arm, '+' one that appeared."""
        fn = self._fastsnap_fn("penguin_fastsnap_dev_diff_report")
        return self.ffi.string(fn()).decode("utf-8", "replace")

    def fastsnap_section_names(self) -> list:
        """Every section a block would cover on this machine."""
        fn = self._lib_symbol("penguin_fastsnap_section_names")
        if fn is None:
            return []
        raw = self.ffi.string(fn()).decode("utf-8", "replace")
        return [x for x in raw.split("\n") if x]

    def fastsnap_schedule(self, op: int) -> bool:
        """Schedule a device-block take (0), restore (1) or release (2).

        Safe from a vCPU-thread callback. Returns True if the request was
        scheduled, not whether it succeeded -- read :meth:`fastsnap_last_rc`
        once :meth:`fastsnap_seq` has advanced.
        """
        fn = self._lib_symbol("penguin_fastsnap_schedule")
        if fn is None:
            logger.warning(
                "QEMU library does not expose penguin_fastsnap_schedule; "
                "fastsnap requires a penguin-qemu build that exports it "
                "(flake input `penguin-qemu`, staged by "
                "nix/mk-penguin-qemu.nix)")
            return False
        self._call_with_bql(lambda: fn(int(op)))
        return True

    def fastsnap_seq(self) -> int:
        """Completed-operation counter; advances once per scheduled op."""
        fn = self._lib_symbol("penguin_fastsnap_seq")
        return int(fn()) if fn is not None else 0

    def fastsnap_last_rc(self) -> int:
        fn = self._lib_symbol("penguin_fastsnap_last_rc")
        return int(fn()) if fn is not None else -1

    def fastsnap_last_us(self) -> int:
        """Duration of the last completed take/restore, microseconds.

        Measured inside QEMU: the operations are hundreds of microseconds and
        a pyplugin round trip is comparable to them, so timing this from
        Python would be measuring the instrument.
        """
        fn = self._lib_symbol("penguin_fastsnap_last_us")
        return int(fn()) if fn is not None else -1

    def fastsnap_last_digest(self) -> int:
        """Hash of the device state from the last PROBE.

        Compare across probes; the value is not stable across builds or
        machines. This is the only way, on a target with nothing safe to poke,
        to show a restore actually moved device state -- one that silently did
        nothing is otherwise indistinguishable from a correct one.
        """
        fn = self._lib_symbol("penguin_fastsnap_last_digest")
        return int(fn()) if fn is not None else 0

    def fastsnap_last_ram_digest(self) -> int:
        """Hash of guest RAM from the last STATE_DIGEST, separate from the
        device half so a divergence says which half moved."""
        return int(self._fastsnap_fn("penguin_fastsnap_last_ram_digest")())

    def fastsnap_bh_done_us(self) -> int:
        """CLOCK_MONOTONIC microseconds at which the last bottom half finished.

        Subtract from ``time.clock_gettime(time.CLOCK_MONOTONIC) * 1e6``. Use
        that explicit form rather than ``perf_counter()``: both are
        CLOCK_MONOTONIC on Linux, but only the explicit one is documented to
        be, and an epoch mismatch here would show up as a plausible-looking
        latency rather than as an error.

        This is what separates "the reset is slow" from "the round trip is
        slow" -- the operation's own duration is :meth:`fastsnap_last_us`, and
        everything else in an iteration is either main-loop latency before this
        timestamp or guest execution after it.
        """
        return int(self._fastsnap_fn("penguin_fastsnap_bh_done_us")())

    def fastsnap_diff_pages(self) -> int:
        """Pages differing from the fork reference at the last FORK_DIFF.

        Zero means the reset put every byte back. A NEGATIVE value means the
        comparison itself failed -- a read error is never folded into "no
        differences", because an oracle that reports success when it could not
        look is worse than no oracle. (That distinction is what surfaced guest
        RAM being MADV_DONTFORK: the diff returned -1, not 0.)
        """
        v = int(self._fastsnap_fn("penguin_fastsnap_diff_pages")())
        # The C side returns uint64_t; -1 arrives as 2**64-1.
        return -1 if v == (1 << 64) - 1 else v

    def fastsnap_diff_us(self) -> int:
        """Cost of the last fork-oracle comparison, microseconds -- kept out of
        `fastsnap_last_us` so a verified reset is not reported at the oracle's
        price."""
        return int(self._fastsnap_fn("penguin_fastsnap_diff_us")())

    def fastsnap_diff_bytes_checked(self) -> int:
        """Bytes the last FORK_DIFF actually compared. The denominator for
        `diff_pages`: without it, zero differences over zero bytes reads the
        same as a clean reset."""
        return int(self._fastsnap_fn("penguin_fastsnap_diff_bytes_checked")())

    def fastsnap_diff_report(self) -> str:
        """First few differing guest addresses from the last FORK_DIFF."""
        fn = self._fastsnap_fn("penguin_fastsnap_diff_report")
        return self.ffi.string(fn()).decode("utf-8", "replace")

    def fastsnap_ram_restored_pages(self) -> int:
        """Pages copied back by the last RAM_RESTORE/LOOP_RESET -- the size of
        the dirty set the reset actually paid for."""
        return int(self._fastsnap_fn("penguin_fastsnap_ram_restored_pages")())

    def fastsnap_ram_restored_code_pages(self) -> int:
        """Of the pages the last reset restored, how many held translated code.

        The rest were data, and invalidating their translated blocks was work
        with no effect. This exists because a reset's cost does not end when
        the reset does: the guest pays afterwards to rebuild whatever the
        invalidation threw away, and that cost is on nobody's clock.
        """
        return int(self._fastsnap_fn(
            "penguin_fastsnap_ram_restored_code_pages")())

    def fastsnap_ram_snapshot_bytes(self) -> int:
        return int(self._fastsnap_fn("penguin_fastsnap_ram_snapshot_bytes")())

    def fastsnap_dirty_pages(self) -> int:
        return int(self._fastsnap_fn("penguin_fastsnap_dirty_pages")())

    def fastsnap_dirty_pages_scanned(self) -> int:
        """Pages examined by the last DIRTY_COUNT, so "0 dirty" is
        distinguishable from "looked at nothing"."""
        return int(self._fastsnap_fn("penguin_fastsnap_dirty_pages_scanned")())

    def fastsnap_dirty_page_size(self) -> int:
        return int(self._fastsnap_fn("penguin_fastsnap_dirty_page_size")())

    def fastsnap_dirty_report(self) -> str:
        fn = self._fastsnap_fn("penguin_fastsnap_dirty_report")
        return self.ffi.string(fn()).decode("utf-8", "replace")

    def fastsnap_dirty_blocks(self) -> str:
        """Per-RAMBlock breakdown of the dirty count. This is what separates a
        guest working set from a flash write; a block with RAM_MIGRATABLE clear
        is prefixed '!' so an under-count has somewhere to show up."""
        fn = self._fastsnap_fn("penguin_fastsnap_dirty_blocks")
        return self.ffi.string(fn()).decode("utf-8", "replace")

    def fastsnap_block_size(self) -> int:
        fn = self._lib_symbol("penguin_fastsnap_block_size")
        return int(fn()) if fn is not None else 0

    def fastsnap_section_count(self) -> int:
        """Device sections a block would cover on this machine."""
        fn = self._lib_symbol("penguin_fastsnap_section_count")
        return int(fn()) if fn is not None else 0

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
