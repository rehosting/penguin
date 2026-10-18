"""
HostOSI: OS introspection from the hypervisor
=============================================

The guest kernel's own data structures, read by QEMU: processes, open files,
memory mappings and the process list, walked in C (``system/penguin-osi.c``)
through ``task_struct``, ``cred``, ``mm_struct`` (its maple tree, or the VMA
list of older kernels), ``files_struct``/``fdtable``, ``dentry`` and
``mount``.  The layout of those structures comes from the kernel's ISF
(``plugins.kffi``), once, through dwarffi; the walks read guest memory
directly.

No guest code runs: no portal, no kernel module, no guest syscall.  Kernel
memory never faults.  A process's own memory (arguments, environment) can:
the current task's is read through ``plugins.mem`` as any callback's read
(the task takes the fault when it must); another task's through its page
tables, without faults (None if a page is out).

The calls are ``plugins.osi``'s, as generators (``yield from``)::

    proc = yield from plugins.HostOSI.get_proc()
    args = yield from plugins.HostOSI.get_args()
    fds = yield from plugins.HostOSI.get_fds()
    maps = yield from plugins.HostOSI.get_mappings()

They answer for the current task (the task of the syscall trap callback that
runs them; ``compat/syscall_trap.py`` sets it) or another one by ``pid=``.
Results are plain records (``types.SimpleNamespace``) with the field names of
igloo's ``osi_proc``, ``osi_fd_entry`` and ``osi_module``.  Names are the
kernel's own, as ``/proc`` shows them: ``d_path()`` for files
(``socket:[ino]``, ``pipe:[ino]``, ``anon_inode:[eventfd]``, ``... (deleted)``)
and ``/proc/<pid>/maps``' for mappings (``[heap]``, ``[stack]``, special
mappings such as ``[vdso]``, the x86 gate area ``[vsyscall]``).

The same walks serve the syscall engine's filters, in C, before any Python
runs: see ``penguin_sc_hook.exe_filter`` and fd-path argument filters.

Every answer is labelled (compat/osi_label.py): rung L0; safe-point for the
current task at its trap (with more than one vCPU, only its own fields:
its mm and files may be shared with threads that keep running),
possibly-torn for another task or the process list, unavailable for None::

    args = yield from plugins.HostOSI.get_args(pid=20)
    plugins.HostOSI.last_label      # Label('L0', 'possibly-torn', '...')

Supported: 64-bit little-endian kernels (x86_64, aarch64).
"""

from types import SimpleNamespace
from typing import Any, Generator, List, Optional

import threading

from penguin import Plugin, plugins
from compat.osi_layout import set_osi_layout
from compat.osi_label import Label, SAFE, TORN, UNAVAILABLE, answer, last_label

AT_FDCWD = -100
STRS = 1 << 18          # name bytes one call can return
MAX_FDS = 4096
MAX_VMAS = 8192
MAX_PROCS = 16384
ARGS_MAX = 128 * 1024

PROC_FIELDS = ("map_count", "start_brk", "brk", "start_stack", "start_code",
               "end_code", "start_data", "end_data", "arg_start", "arg_end",
               "env_start", "env_end", "mmap_base", "task_size")


_TASK = ("task_struct", "cred", "signal_struct")
_PATH = ("file", "path", "dentry", "qstr", "hlist_bl_node", "inode", "mount", "vfsmount",
         "dentry_operations")
_MM = _TASK + ("mm_struct",)
STRUCTS = {
    "task": _TASK, "all": _TASK, "args": _MM,
    "fds": _TASK + ("files_struct", "fdtable") + _PATH,
    "cwd": _TASK + ("fs_struct",) + _PATH,
    "exe": _MM + _PATH,
    "maps": _MM + ("vm_area_struct", "vm_operations_struct", "vm_special_mapping",
                   "maple_tree", "maple_node", "maple_range_64", "maple_arange_64",
                   "maple_metadata") + _PATH,
}


def _offsets(walks):
    """the label's offsets: "isf", or the other sources a struct the answer
    walks rests on, "+"-joined ("invariant", "l1-graded"; compat/isf_trust.py)"""
    from compat.isf_trust import graded_used, invariant_used
    walked = set(STRUCTS[walks])
    kinds = [k for k, used in (("invariant", invariant_used()), ("l1-graded", graded_used()))
             if walked & {n.split(".", 1)[0] for n in used}]
    return "+".join(kinds) or "isf"


def _judge(scope, walks="task"):
    """an answer's label: about the task's own fields ("task"), state it may
    share with other threads ("shared"), or every process ("all"); @walks
    names the structures it reads (STRUCTS)"""
    def judge(self, value):
        if value is None:
            return Label("L0", UNAVAILABLE, "no answer (no current task, not mapped, or the walk failed)")
        o = _offsets(walks)
        if scope == "all":
            return Label("L0", TORN, "the process list, walked while tasks may fork or exit", o)
        if not getattr(self._asked, "current", False):
            return Label("L0", TORN, "another task: it may be preempted inside the kernel, mid-update", o)
        if scope == "shared" and self._smp > 1:
            return Label("L0", TORN, "the task's mm or files: threads sharing them may run on another vCPU", o)
        return Label("L0", SAFE, "the task, stopped at its system call boundary", o)
    return judge


class HostOSI(Plugin):
    """OS introspection by QEMU, from the kernel's ISF."""

    def __init__(self) -> None:
        self.lib, self.ffi = self.panda.lib, self.panda.ffi
        self.isf = plugins.kffi.ffi
        # little-endian kernels: 64-bit, and 32-bit ARM (set_osi_layout says)
        if not set_osi_layout(self.panda, self.isf):
            raise RuntimeError("HostOSI: not a kernel QEMU's walks read (64-bit or 32-bit "
                               "ARM, little-endian), or QEMU refused its layout")
        f = self.ffi
        self._proc = f.new("struct penguin_osi_proc *")
        self._strs = f.new("char[]", STRS)
        self._fds = f.new("struct penguin_osi_fd[]", MAX_FDS)
        self._vmas = f.new("struct penguin_osi_vma[]", MAX_VMAS)
        self._tasks = f.new("uint64_t[]", MAX_PROCS)
        self._ubuf = f.new("char[]", ARGS_MAX)
        self._asked = threading.local()         # is the call's task the current one?
        try:
            self._smp = int(((self.get_arg("conf") or {}).get("core") or {}).get("smp", 1))
        except (AttributeError, TypeError, ValueError):
            self._smp = 1

    @property
    def last_label(self) -> Label:
        """the last answer's label, on this thread (compat/osi_label.py)"""
        return last_label(self)

    # --- helpers ---

    def _cpu(self):
        return self.panda.get_cpu()

    def _current(self) -> int:
        return getattr(self.panda._callback_state(), "task", 0) or 0

    def _task(self, pid: Optional[int]) -> int:
        cur = self._current()
        task = cur if pid is None else self.lib.penguin_osi_task(self._cpu(), pid)
        self._asked.current = bool(task) and task == cur
        return task

    @staticmethod
    def _fd(fd: int) -> int:
        """an fd as the kernel takes it: the low 32 bits, signed (a register's
        -1 is 0xffff_ffff_ffff_ffff)"""
        return ((int(fd) & 0xffffffff) ^ 0x80000000) - 0x80000000

    def _str(self, off: int) -> str:
        return self.ffi.string(self._strs + off).decode("latin-1")

    def _record(self, task: int) -> Optional[SimpleNamespace]:
        p = self._proc
        if not task or not self.lib.penguin_osi_proc(self._cpu(), task, p):
            return None
        r = SimpleNamespace(
            taskd=p.task, pgd=p.pgd, pid=p.pid, tgid=p.tgid, ppid=p.ppid,
            name=self.ffi.string(p.comm).decode("latin-1"), create_time=p.create_time,
            uid=p.uid, gid=p.gid, euid=p.euid, egid=p.egid)
        for f in PROC_FIELDS:
            setattr(r, f, getattr(p, f))
        return r

    def _area(self, pid: Optional[int], which: str) -> Generator[Any, Any, Optional[bytes]]:
        task = self._task(pid)
        if not task or not self.lib.penguin_osi_proc(self._cpu(), task, self._proc):
            return None
        lo = getattr(self._proc, f"{which}_start")
        hi = getattr(self._proc, f"{which}_end")
        if not lo or hi <= lo:
            return None
        n = min(hi - lo, ARGS_MAX)
        if task == self._current():
            return (yield from plugins.mem.read_bytes(lo, n))
        got = self.lib.penguin_osi_user_read(self._cpu(), task, lo, self._ubuf, n)
        return self.ffi.buffer(self._ubuf, got)[:] if got == n else None

    # --- the calls (plugins.osi's) ---

    @answer(_judge("task", "task"))
    def get_proc(self, pid: Optional[int] = None) -> Generator[Any, Any, Optional[SimpleNamespace]]:
        """the task's osi_proc fields"""
        return self._record(self._task(pid))
        yield

    @answer(_judge("all", "all"))
    def get_all_procs(self) -> Generator[Any, Any, Optional[List[SimpleNamespace]]]:
        """every process (thread group leader)"""
        n = self.lib.penguin_osi_procs(self._cpu(), self._tasks, MAX_PROCS)
        if n < 0:
            return None
        return [r for r in (self._record(self._tasks[i]) for i in range(min(n, MAX_PROCS)))
                if r is not None]
        yield

    @answer(_judge("shared", "args"))
    def get_args(self, pid: Optional[int] = None) -> Generator[Any, Any, Optional[List[str]]]:
        """the argument vector, from mm->arg_start..arg_end"""
        data = yield from self._area(pid, "arg")
        if data is None:
            return None
        return data.rstrip(b"\0").decode("latin-1").split("\0")

    @answer(_judge("shared", "args"))
    def get_env(self, pid: Optional[int] = None) -> Generator[Any, Any, Optional[dict]]:
        """the environment, from mm->env_start..env_end"""
        data = yield from self._area(pid, "env")
        if data is None:
            return None
        env = {}
        for kv in data.rstrip(b"\0").decode("latin-1").split("\0"):
            k, _, v = kv.partition("=")
            env[k] = v
        return env

    @answer(_judge("shared", "args"))
    def get_proc_name(self, pid: Optional[int] = None) -> Generator[Any, Any, Optional[str]]:
        """argv[0]'s base name, or the comm"""
        args = yield from self.get_args(pid)
        if args and args[0]:
            return args[0].rsplit("/", 1)[-1]
        p = self._record(self._task(pid))
        return p.name if p else None

    @answer(_judge("shared", "fds"))
    def get_fds(self, pid: Optional[int] = None, start_fd: int = 0,
                count: Optional[int] = None) -> Generator[Any, Any, Optional[List[SimpleNamespace]]]:
        """open files from @start_fd: fd and d_path() name"""
        task = self._task(pid)
        n = self.lib.penguin_osi_fds(self._cpu(), task, max(self._fd(start_fd or 0), 0), self._fds,
                                     min(count or MAX_FDS, MAX_FDS), self._strs, STRS) if task else -1
        if n < 0:
            return None
        return [SimpleNamespace(fd=e.fd, file=e.file, name=self._str(e.name))
                for e in (self._fds[i] for i in range(n))]
        yield

    @answer(_judge("shared", "fds"))
    def get_fd_name(self, fd: int, pid: Optional[int] = None) -> Generator[Any, Any, Optional[str]]:
        """one fd's name (AT_FDCWD: the working directory)"""
        task = self._task(pid)
        n = self.lib.penguin_osi_fd_path(self._cpu(), task, self._fd(fd), self._strs,
                                         STRS) if task else -1
        return self.ffi.string(self._strs, n).decode("latin-1") if n >= 0 else None
        yield

    @answer(_judge("shared", "cwd"))
    def get_cwd(self, pid: Optional[int] = None) -> Generator[Any, Any, Optional[str]]:
        return (yield from self.get_fd_name(AT_FDCWD, pid))

    @answer(_judge("shared", "exe"))
    def get_proc_exe(self, pid: Optional[int] = None) -> Generator[Any, Any, Optional[str]]:
        """mm->exe_file's path"""
        task = self._task(pid)
        n = self.lib.penguin_osi_exe_path(self._cpu(), task, self._strs, STRS) if task else -1
        return self.ffi.string(self._strs, n).decode("latin-1") if n >= 0 else None
        yield

    @answer(_judge("shared", "maps"))
    def get_mappings(self, pid: Optional[int] = None) -> Generator[Any, Any, Optional[List[SimpleNamespace]]]:
        """the mappings in address order, as /proc/<pid>/maps lists them"""
        task = self._task(pid)
        n = self.lib.penguin_osi_mappings(self._cpu(), task, self._vmas, MAX_VMAS,
                                          self._strs, STRS) if task else -1
        if n < 0:
            return None
        out = []
        for i in range(min(n, MAX_VMAS)):
            v = self._vmas[i]
            out.append(SimpleNamespace(
                base=v.start, size=v.end - v.start, offset=v.offset, flags=v.flags,
                perms=self.ffi.string(v.perms).decode(), name=self._str(v.name), file=v.file))
        return out
        yield
