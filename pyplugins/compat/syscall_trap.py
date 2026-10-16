"""
Syscalls on QEMU's syscall trap
===============================

A backend for the Syscalls plugin (apis/syscalls.py) on the penguin QEMU's
syscall trap engine (system/penguin-syscalls.c) in place of igloo_driver's
kernel hooks.  The engine has igloo's hook model: struct syscall_hook, its
filters, its dispatch order.  Hooks are registered with QEMU directly, with
no portal round trip; the events come from the vCPU's syscall instruction
and from its return to user mode.

Callbacks are unchanged.  They get (pt_regs, proto, syscall, *args) and may
be coroutines that yield PortalCmds: QEMU carries out the memory commands
(HYPER_OP_READ, _READ_STR, _WRITE) itself, and when the task has not mapped
the memory yet, the task takes the fault and the callback stays suspended
across it.  Other commands (OSI, kffi, ...) go to igloo's portal when the
module is there: the trap queues a portal interrupt and has the task make a
getpid; igloo takes the interrupt on that call's way in and serves the
command, and the callback has the answer when the task is back at its own
call.  That needs a callback that may inject (Syscalls.inject: an entry,
or a return the kernel is not restarting, of an ABI QEMU injects into);
otherwise, or with no module, the command gets the portal's failure, None.

- ``syscall``: the engine's event, with the fields of igloo's
  syscall_event; changes to args, retval and skip_syscall reach the call.
- ``pt_regs``: the task's registers, read from the vCPU when first used,
  as the kernel's pt_regs has them (at the entry, ax -ENOSYS and orig_ax
  the number on x86_64); a copy, as in igloo's path.  Use it during the
  callback.
- mem's direct reads and writes, during a callback, go to the engine: the
  vCPU's own view, never faulting; a write needs the guest's permission
  (a debug write would reach a read-only or copy-on-write page).
- A callback may yield ``InjectCmd`` (Syscalls.inject): the task makes
  that system call first, and the callback gets its return value.  At a
  return the call's own registers and the callback's return value are put
  back after it.  pt_regs is read when first used: read it before injecting.

TCG; x86_64 and AArch64 guests, with their 32-bit compat ABIs.  Enabled by
the Syscalls argument ``backend: trap`` (``plugins: syscalls: backend: trap``).

With no kernel ISF (``plugins.kffi`` has none: a vendor kernel with no DWARF
and no kallsyms) the backend still runs: names and numbers from uapi
(compat/syscall_numbers.py), pt_regs in the arch's fixed layout, and none of
what needs the kernel's symbols: no fault guard (commands on unmapped memory
fail), no reaper, no exec hook (execve cannot be injected), no comm, pid or
scope filters in C, no OSI layout.  Injection works: it needs the numbers.
"""

import re
import struct
from collections.abc import Iterator

from penguin import plugins, getColoredLogger
from hyper.consts import HYPER_OP as hop
from wrappers.ptregs_wrap import get_pt_regs_wrapper

logger = getColoredLogger("plugins.syscalls.trap")

OP_NONE, OP_READ, OP_READ_STR, OP_WRITE, OP_ABORT, OP_SYSCALL = range(6)
OP_PORTAL = -1                  # ours: a command for igloo's portal
PORTAL_TRIES = 3                # getpids that may pass without the interrupt
OK, PARTIAL, FAIL = range(3)
ABIS = {"x86_64": 0, "i386": 1, "aarch64": 2, "arm": 3}
NATIVE = {"x86_64": ("x86_64", "i386"), "aarch64": ("aarch64", "arm")}
STR_TYPES = range(11, 15)       # SYSCALLS_HC_FILTER_STR_*
ENOSYS = 38
CURRENT_PID = 0xffffffff        # hyper.portal's CURRENT_PID_NUM
M64 = (1 << 64) - 1

# The compat ABIs' numbers, from the uapi headers (asm/unistd_32.h,
# asm/unistd-eabi.h): names in number order, "-" for none.  The kernel's
# syscall metadata only numbers the native calls.
COMPAT = {
    'i386': """
        restart_syscall exit fork read write open close waitpid creat link unlink
        execve chdir time mknod chmod lchown break oldstat lseek getpid mount umount
        setuid getuid stime ptrace alarm oldfstat pause utime stty gtty access nice
        ftime sync kill rename mkdir rmdir dup pipe times prof brk setgid getgid
        signal geteuid getegid acct umount2 lock ioctl fcntl mpx setpgid ulimit
        oldolduname umask chroot ustat dup2 getppid getpgrp setsid sigaction
        sgetmask ssetmask setreuid setregid sigsuspend sigpending sethostname
        setrlimit getrlimit getrusage gettimeofday settimeofday getgroups setgroups
        select symlink oldlstat readlink uselib swapon reboot readdir mmap munmap
        truncate ftruncate fchmod fchown getpriority setpriority profil statfs
        fstatfs ioperm socketcall syslog setitimer getitimer stat lstat fstat
        olduname iopl vhangup idle vm86old wait4 swapoff sysinfo ipc fsync sigreturn
        clone setdomainname uname modify_ldt adjtimex mprotect sigprocmask
        create_module init_module delete_module get_kernel_syms quotactl getpgid
        fchdir bdflush sysfs personality afs_syscall setfsuid setfsgid _llseek
        getdents _newselect flock msync readv writev getsid fdatasync _sysctl mlock
        munlock mlockall munlockall sched_setparam sched_getparam sched_setscheduler
        sched_getscheduler sched_yield sched_get_priority_max sched_get_priority_min
        sched_rr_get_interval nanosleep mremap setresuid getresuid vm86 query_module
        poll nfsservctl setresgid getresgid prctl rt_sigreturn rt_sigaction
        rt_sigprocmask rt_sigpending rt_sigtimedwait rt_sigqueueinfo rt_sigsuspend
        pread64 pwrite64 chown getcwd capget capset sigaltstack sendfile getpmsg
        putpmsg vfork ugetrlimit mmap2 truncate64 ftruncate64 stat64 lstat64 fstat64
        lchown32 getuid32 getgid32 geteuid32 getegid32 setreuid32 setregid32
        getgroups32 setgroups32 fchown32 setresuid32 getresuid32 setresgid32
        getresgid32 chown32 setuid32 setgid32 setfsuid32 setfsgid32 pivot_root
        mincore madvise getdents64 fcntl64 - - gettid readahead setxattr lsetxattr
        fsetxattr getxattr lgetxattr fgetxattr listxattr llistxattr flistxattr
        removexattr lremovexattr fremovexattr tkill sendfile64 futex
        sched_setaffinity sched_getaffinity set_thread_area get_thread_area io_setup
        io_destroy io_getevents io_submit io_cancel fadvise64 - exit_group
        lookup_dcookie epoll_create epoll_ctl epoll_wait remap_file_pages
        set_tid_address timer_create timer_settime timer_gettime timer_getoverrun
        timer_delete clock_settime clock_gettime clock_getres clock_nanosleep
        statfs64 fstatfs64 tgkill utimes fadvise64_64 vserver mbind get_mempolicy
        set_mempolicy mq_open mq_unlink mq_timedsend mq_timedreceive mq_notify
        mq_getsetattr kexec_load waitid - add_key request_key keyctl ioprio_set
        ioprio_get inotify_init inotify_add_watch inotify_rm_watch migrate_pages
        openat mkdirat mknodat fchownat futimesat fstatat64 unlinkat renameat linkat
        symlinkat readlinkat fchmodat faccessat pselect6 ppoll unshare
        set_robust_list get_robust_list splice sync_file_range tee vmsplice
        move_pages getcpu epoll_pwait utimensat signalfd timerfd_create eventfd
        fallocate timerfd_settime timerfd_gettime signalfd4 eventfd2 epoll_create1
        dup3 pipe2 inotify_init1 preadv pwritev rt_tgsigqueueinfo perf_event_open
        recvmmsg fanotify_init fanotify_mark prlimit64 name_to_handle_at
        open_by_handle_at clock_adjtime syncfs sendmmsg setns process_vm_readv
        process_vm_writev kcmp finit_module sched_setattr sched_getattr renameat2
        seccomp getrandom memfd_create bpf execveat socket socketpair bind connect
        listen accept4 getsockopt setsockopt getsockname getpeername sendto sendmsg
        recvfrom recvmsg shutdown userfaultfd membarrier mlock2 copy_file_range
        preadv2 pwritev2 pkey_mprotect pkey_alloc pkey_free statx arch_prctl
        io_pgetevents rseq - - - - - - semget semctl shmget shmctl shmat shmdt
        msgget msgsnd msgrcv msgctl clock_gettime64 clock_settime64 clock_adjtime64
        clock_getres_time64 clock_nanosleep_time64 timer_gettime64 timer_settime64
        timerfd_gettime64 timerfd_settime64 utimensat_time64 pselect6_time64
        ppoll_time64 - io_pgetevents_time64 recvmmsg_time64 mq_timedsend_time64
        mq_timedreceive_time64 semtimedop_time64 rt_sigtimedwait_time64 futex_time64
        sched_rr_get_interval_time64 pidfd_send_signal io_uring_setup io_uring_enter
        io_uring_register open_tree move_mount fsopen fsconfig fsmount fspick
        pidfd_open clone3 close_range openat2 pidfd_getfd faccessat2 process_madvise
        epoll_pwait2 mount_setattr quotactl_fd landlock_create_ruleset
        landlock_add_rule landlock_restrict_self memfd_secret process_mrelease""",
    'arm': """
        restart_syscall exit fork read write open close - creat link unlink execve
        chdir - mknod chmod lchown - - lseek getpid mount - setuid getuid - ptrace -
        - pause - - - access nice - sync kill rename mkdir rmdir dup pipe times -
        brk setgid getgid - geteuid getegid acct umount2 - ioctl fcntl - setpgid - -
        umask chroot ustat dup2 getppid getpgrp setsid sigaction - - setreuid
        setregid sigsuspend sigpending sethostname setrlimit - getrusage
        gettimeofday settimeofday getgroups setgroups - symlink - readlink uselib
        swapon reboot - - munmap truncate ftruncate fchmod fchown getpriority
        setpriority - statfs fstatfs - - syslog setitimer getitimer stat lstat fstat
        - - vhangup - - wait4 swapoff sysinfo - fsync sigreturn clone setdomainname
        uname - adjtimex mprotect sigprocmask - init_module delete_module - quotactl
        getpgid fchdir bdflush sysfs personality - setfsuid setfsgid _llseek
        getdents _newselect flock msync readv writev getsid fdatasync _sysctl mlock
        munlock mlockall munlockall sched_setparam sched_getparam sched_setscheduler
        sched_getscheduler sched_yield sched_get_priority_max sched_get_priority_min
        sched_rr_get_interval nanosleep mremap setresuid getresuid - - poll
        nfsservctl setresgid getresgid prctl rt_sigreturn rt_sigaction
        rt_sigprocmask rt_sigpending rt_sigtimedwait rt_sigqueueinfo rt_sigsuspend
        pread64 pwrite64 chown getcwd capget capset sigaltstack sendfile - - vfork
        ugetrlimit mmap2 truncate64 ftruncate64 stat64 lstat64 fstat64 lchown32
        getuid32 getgid32 geteuid32 getegid32 setreuid32 setregid32 getgroups32
        setgroups32 fchown32 setresuid32 getresuid32 setresgid32 getresgid32 chown32
        setuid32 setgid32 setfsuid32 setfsgid32 getdents64 pivot_root mincore
        madvise fcntl64 - - gettid readahead setxattr lsetxattr fsetxattr getxattr
        lgetxattr fgetxattr listxattr llistxattr flistxattr removexattr lremovexattr
        fremovexattr tkill sendfile64 futex sched_setaffinity sched_getaffinity
        io_setup io_destroy io_getevents io_submit io_cancel exit_group
        lookup_dcookie epoll_create epoll_ctl epoll_wait remap_file_pages - -
        set_tid_address timer_create timer_settime timer_gettime timer_getoverrun
        timer_delete clock_settime clock_gettime clock_getres clock_nanosleep
        statfs64 fstatfs64 tgkill utimes arm_fadvise64_64 pciconfig_iobase
        pciconfig_read pciconfig_write mq_open mq_unlink mq_timedsend
        mq_timedreceive mq_notify mq_getsetattr waitid socket bind connect listen
        accept getsockname getpeername socketpair send sendto recv recvfrom shutdown
        setsockopt getsockopt sendmsg recvmsg semop semget semctl msgsnd msgrcv
        msgget msgctl shmat shmdt shmget shmctl add_key request_key keyctl
        semtimedop vserver ioprio_set ioprio_get inotify_init inotify_add_watch
        inotify_rm_watch mbind get_mempolicy set_mempolicy openat mkdirat mknodat
        fchownat futimesat fstatat64 unlinkat renameat linkat symlinkat readlinkat
        fchmodat faccessat pselect6 ppoll unshare set_robust_list get_robust_list
        splice arm_sync_file_range tee vmsplice move_pages getcpu epoll_pwait
        kexec_load utimensat signalfd timerfd_create eventfd fallocate
        timerfd_settime timerfd_gettime signalfd4 eventfd2 epoll_create1 dup3 pipe2
        inotify_init1 preadv pwritev rt_tgsigqueueinfo perf_event_open recvmmsg
        accept4 fanotify_init fanotify_mark prlimit64 name_to_handle_at
        open_by_handle_at clock_adjtime syncfs sendmmsg setns process_vm_readv
        process_vm_writev kcmp finit_module sched_setattr sched_getattr renameat2
        seccomp getrandom memfd_create bpf execveat userfaultfd membarrier mlock2
        copy_file_range preadv2 pwritev2 pkey_mprotect pkey_alloc pkey_free statx
        rseq io_pgetevents migrate_pages kexec_file_load - clock_gettime64
        clock_settime64 clock_adjtime64 clock_getres_time64 clock_nanosleep_time64
        timer_gettime64 timer_settime64 timerfd_gettime64 timerfd_settime64
        utimensat_time64 pselect6_time64 ppoll_time64 - io_pgetevents_time64
        recvmmsg_time64 mq_timedsend_time64 mq_timedreceive_time64 semtimedop_time64
        rt_sigtimedwait_time64 futex_time64 sched_rr_get_interval_time64
        pidfd_send_signal io_uring_setup io_uring_enter io_uring_register open_tree
        move_mount fsopen fsconfig fsmount fspick pidfd_open clone3 close_range
        openat2 pidfd_getfd faccessat2 process_madvise epoll_pwait2 mount_setattr
        quotactl_fd landlock_create_ruleset landlock_add_rule landlock_restrict_self
        - process_mrelease""",
}


class InjectCmd:
    """A command a callback yields: the task makes system call ``num`` (a
    name, or a number of the task's ABI) with ``args``; the answer is its
    return value, or None if it could not run (Syscalls.inject)"""
    __slots__ = ("num", "args")

    def __init__(self, num, args):
        self.num = num if isinstance(num, str) else int(num)
        self.args = tuple(int(a) & M64 for a in args)

    def __repr__(self):
        return f"InjectCmd({self.num}, {self.args})"


def _s64(v):
    v = int(v) & M64
    return v - (1 << 64) if v >> 63 else v


class _Addr:
    """A pointer field as dwarffi gives it: .address"""
    __slots__ = ("address",)

    def __init__(self, address):
        self.address = address

    def __int__(self):
        return self.address

    __index__ = __int__

    def __eq__(self, other):
        return int(self) == int(other)

    def __hash__(self):
        return hash(self.address)

    def __repr__(self):
        return f"<ptr {self.address:#x}>"


class _Args:
    """The event's arguments; values wrap to 64 bits as dwarffi's do"""
    __slots__ = ("_a",)

    def __init__(self, a):
        self._a = a

    def __getitem__(self, i):
        if isinstance(i, slice):
            return [self._a[j] for j in range(6)[i]]
        if not -6 <= i < 6:
            raise IndexError(i)
        return self._a[i % 6]

    def __setitem__(self, i, v):
        if not -6 <= i < 6:
            raise IndexError(i)
        self._a[i % 6] = int(v) & M64

    def __len__(self):
        return 6

    def __iter__(self):
        return (self._a[i] for i in range(6))


class TrapEvent:
    """The engine's event (struct penguin_sc_event), as Syscalls' callbacks
    know igloo's syscall_event (a dwarffi instance)."""
    __slots__ = ("_ev", "_cs", "_ffi", "_name", "hook")

    def __init__(self, ffi, cs, ev):
        object.__setattr__(self, "_ev", ev)
        object.__setattr__(self, "_cs", cs)
        object.__setattr__(self, "_ffi", ffi)
        object.__setattr__(self, "_name", None)
        object.__setattr__(self, "hook", _Addr(ev.hook))

    @property
    def name(self):
        if self._name is None:
            object.__setattr__(self, "_name", self._ffi.string(
                self._ev.syscall_name).decode("utf-8", errors="replace"))
        return self._name

    def __getattr__(self, attr):
        ev = self._ev
        if attr in ("task", "regs"):
            return _Addr(getattr(ev, attr))
        if attr == "args":
            return _Args(ev.args)
        if attr == "syscall_name":
            return self.name.encode()
        return getattr(ev, attr)

    def __setattr__(self, attr, value):
        if attr == "retval":
            self._ev.retval = _s64(value)
        elif attr == "skip_syscall":
            self._ev.skip_syscall = bool(value)
        elif attr == "args":
            for i, v in enumerate(list(value)[:6]):
                self._ev.args[i] = int(v) & M64
        else:
            setattr(self._ev, attr, value)


class _LazyPtRegs:
    """The callback's pt_regs, a PtRegsWrapper made on first use: most
    callbacks never look at it"""
    __slots__ = ("_make", "_w")

    def __init__(self, make):
        object.__setattr__(self, "_make", make)
        object.__setattr__(self, "_w", None)

    def _get(self):
        w = self._w
        if w is None:
            w = self._make()
            object.__setattr__(self, "_w", w)
        return w

    def __getattr__(self, attr):
        return getattr(self._get(), attr)

    def __setattr__(self, attr, value):
        setattr(self._get(), attr, value)

    def __dir__(self):
        return dir(self._get())

    def __repr__(self):
        return repr(self._get())


def _kernel_isf():
    """the kernel's ISF (dwarffi), or None if there is none"""
    try:
        return getattr(plugins.kffi, "ffi", None)
    except Exception:
        return None


# struct pt_regs where no ISF says: the fields the backend fills, at their
# offsets since 4.x (x86_64) and 3.7 (arm64), and a size that holds every
# kernel's (the copy is the hook's; fields past these are zero)
_FIXED_REGS = {
    "x86_64": dict(r15=0, r14=8, r13=16, r12=24, bp=32, bx=40, r11=48, r10=56, r9=64,
                   r8=72, ax=80, cx=88, dx=96, si=104, di=112, orig_ax=120, ip=128,
                   cs=136, flags=144, sp=152, ss=160, size=168),
    "aarch64": dict(regs=0, sp=248, pc=256, pstate=264, orig_x0=272, syscallno=280,
                    size=336),
}
_FIXED_REGS["x86_64"]["ctype"] = "struct psc_x86_64_pt_regs *"
_FIXED_REGS["aarch64"]["ctype"] = "struct psc_aarch64_pt_regs *"
FIXED_REGS_CDEF = """
struct psc_x86_64_pt_regs {
    uint64_t r15, r14, r13, r12, bp, bx, r11, r10, r9, r8, ax, cx, dx, si, di,
             orig_ax, ip, cs, flags, sp, ss;
};
struct psc_aarch64_pt_regs {
    uint64_t regs[31];
    uint64_t sp, pc, pstate, orig_x0;
    int32_t syscallno;
    uint32_t unused2;
    uint64_t rest[6];
};
"""


class TrapBackend:
    def __init__(self, syscalls):
        self.s = syscalls
        self.panda = panda = syscalls.panda
        self.ffi, self.lib = panda.ffi, panda.lib
        arch = getattr(panda, "arch_name", None)
        if (getattr(panda, "mode", None) != "system" or arch not in NATIVE or
                not hasattr(self.lib, "set_penguin_syscall_callback")):
            raise RuntimeError(
                f"syscall trap: needs the penguin QEMU's syscall engine under TCG "
                f"on x86_64 or aarch64 (mode {getattr(panda, 'mode', None)}, arch {arch})")
        self.arch = arch
        self.native, self.compat = NATIVE[arch]
        self.big = panda.endianness == "big"
        self.numbers = {}       # native syscall name -> number (at boot)
        # the compat ABI's (uapi): an AArch32 task's EABI numbers
        self.compat_numbers = {n: i for i, n in enumerate(COMPAT[self.compat].split())
                               if n != "-"}
        self.runs = {}          # call id -> the coroutine waiting for its answer
        self.wbufs = {}         # call id -> the bytes it writes, until answered
        self.unsupported = set()
        self.delegated = {}     # call id -> its command at igloo's portal
        self.portal_q = []      # those commands, until the portal takes them
        self.portal_handler = False
        self.kffi = _kernel_isf()
        if self.kffi is None:
            if not getattr(self.ffi, "_psc_fixed_regs", False):
                self.ffi.cdef(FIXED_REGS_CDEF)
                self.ffi._psc_fixed_regs = True
            logger.warning("syscall trap: no kernel ISF; uapi numbers, no guard, reaper, "
                           "exec hook, OSI layout or comm/pid/scope filters")
        self._cb = self.ffi.callback(
            "void(CPUState *, struct penguin_sc_event *, struct penguin_sc_cmd *, void *)",
            self._on_event, onerror=self._on_error)
        self._boot_cb = self.ffi.callback("void(CPUState *, void *)", self._on_boot,
                                          onerror=self._on_error)
        self._regs_layout()
        layout = self._layout()
        if not self.lib.penguin_syscall_set_layout(layout):
            raise RuntimeError("syscall trap: layout refused")
        # the OSI walks the fd-path and exe filters use
        from compat.osi_layout import set_osi_layout
        if self.kffi is None or not set_osi_layout(self.panda, self.kffi):
            logger.warning("syscall trap: no OSI layout; fd-path and exe filters never match")
        if not self.lib.set_penguin_syscall_callback(self._cb, self.ffi.NULL):
            raise RuntimeError("syscall trap: QEMU's syscall events have another consumer")
        self.lib.set_penguin_syscall_boot_callback(self._boot_cb, self.ffi.NULL)
        # faults only once the kernel's signal for a refused one is hooked
        if not self.lib.penguin_syscall_set_guard(self._sym("force_sig_fault"),
                                                  self._sym("force_sig_info")):
            logger.warning("syscall trap: no guard; commands on unmapped memory fail")
        if not self.lib.penguin_syscall_set_reaper(self._sym("release_task")):
            logger.warning("syscall trap: no reaper; a killed task's calls stay until evicted")
        if not self.lib.penguin_syscall_set_exec(self._sym("__set_task_comm")):
            logger.warning("syscall trap: no exec hook; execve cannot be injected")
        # core.analysis_scope, as the Scope plugin reads it: on unless "none"
        conf = syscalls.get_arg("conf") or {}
        scope = (conf.get("core") or {}).get("analysis_scope", "firmware")
        self.lib.penguin_syscall_set_scope(
            scope is not False and str(scope).strip().lower() != "none")
        logger.info("syscall hooks on QEMU's syscall trap (%s)", arch)

    # kernel facts, from the kernel's ISF

    def _sym(self, name):
        if self.kffi is None:
            return 0
        s = self.kffi.get_symbol(name)
        return int(getattr(s, "address", 0) or 0) if s else 0

    def _off(self, t, field):
        if self.kffi is None:
            return _FIXED_REGS[self.arch].get(field, -1) if t == "struct pt_regs" else -1
        try:
            return int(self.kffi.offsetof(t, field))
        except Exception:
            return -1

    def _layout(self):
        if self.arch == "x86_64":
            hot = self._sym("pcpu_hot")
            cur = hot + self._off("struct pcpu_hot", "current_task") if hot \
                else self._sym("current_task")
        else:
            cur = self._sym("__entry_task")
        return self.ffi.new("struct penguin_sc_layout *", dict(
            cur_mask=M64 if cur else 0, cur_offset=cur, ptr_size=8,
            task_pid=self._off("struct task_struct", "pid"),
            task_comm=self._off("struct task_struct", "comm"),
            task_start_time=self._off("struct task_struct", "start_time"),
            task_nsproxy=self._off("struct task_struct", "nsproxy"),
            nsproxy_uts_ns=self._off("struct nsproxy", "uts_ns"),
            init_uts_ns=self._sym("init_uts_ns")))

    def _regs_layout(self):
        """where the gdb registers go in struct pt_regs: [(gdb register,
        offset)], 8 bytes each"""
        o = self._off
        if self.arch == "x86_64":
            names = ("ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
                     *(f"r{i}" for i in range(8, 16)), "ip", "flags", "cs", "ss")
            self._rmap = [(i, o("struct pt_regs", n)) for i, n in enumerate(names)]
            self._ngdb = len(names)
        else:
            base = o("struct pt_regs", "regs")
            self._rmap = [(i, base + 8 * i) for i in range(31)]
            self._rmap += [(31, o("struct pt_regs", "sp")), (33, o("struct pt_regs", "pstate"))]
            self._ngdb = 34
        self._roff = {n: o("struct pt_regs", n) for n in
                      ("ax", "cx", "r11", "ip", "flags", "orig_ax", "regs", "pc", "pstate",
                       "orig_x0", "syscallno")}
        self._rsize = (_FIXED_REGS[self.arch]["size"] if self.kffi is None
                       else self.kffi.sizeof("struct pt_regs"))
        e = ">" if self.big else "<"
        self._q, self._i = struct.Struct(e + "Q"), struct.Struct(e + "i")

    def _on_boot(self, cs, opaque):
        """The first trap: syscall_metadata is numbered by now"""
        if self.kffi is None:
            return self._uapi_names()
        buf = self.ffi.new("uint8_t[4]")
        offs = [self._off("struct syscall_metadata", f) for f in ("syscall_nr", "nb_args")]
        nargs = {}
        for name, sym in self.kffi.symbols.items():
            if not name.startswith("__syscall_meta__") or not getattr(sym, "address", 0):
                continue
            vals = []
            for off in offs:
                if off < 0 or not self.lib.penguin_syscall_read_memory(
                        cs, sym.address + off, buf, 4):
                    break
                vals.append(int.from_bytes(bytes(buf), "big" if self.big else "little",
                                           signed=True))
            if len(vals) == 2 and vals[0] >= 0:
                sc = name[len("__syscall_meta__"):]
                self.lib.penguin_syscall_set_name(ABIS[self.native], vals[0], sc.encode(),
                                                  vals[1])
                nargs[sc] = vals[1]
                self.numbers[sc] = vals[0]
        self.nargs = nargs
        self._table_numbers(cs)
        self._compat_names(nargs)

    def _uapi_names(self):
        """no ISF: the native names, numbers and argument counts from uapi"""
        from compat.syscall_numbers import native_table
        nargs = {}
        for name, (num, n) in native_table(self.arch).items():
            self.lib.penguin_syscall_set_name(ABIS[self.native], num, name.encode(), n)
            self.numbers[name] = num
            nargs[name] = n
        self.nargs = nargs
        self._compat_names(nargs)
        logger.info("syscall trap: %d native numbers from uapi (no ISF)", len(nargs))

    def _compat_names(self, nargs):
        n = 0
        for num, uname in enumerate(COMPAT[self.compat].split()):
            for cand in (uname, re.sub(r"(32|64)$", "", uname), uname.lstrip("_")):
                if cand in nargs:
                    self.lib.penguin_syscall_set_name(ABIS[self.compat], num, cand.encode(),
                                                      nargs[cand])
                    n += 1
                    break
        logger.debug("syscall trap: %d native and %d compat names", len(nargs), n)

    _TABLE_MAX = 1024            # entries; past the end, a non-function stops it
    _TABLE_PREFIXES = ("__x64_sys_", "__arm64_sys_", "sys_", "SyS_")

    def _table_numbers(self, cs):
        """Native numbers the syscall metadata lacks (calls not defined with
        SYSCALL_DEFINE, as arm64's mmap before 4.13), for inject(): each
        sys_call_table entry is named by the function it points to"""
        table = self._sym("sys_call_table")
        if not table:
            return
        byaddr = {}
        for name, sym in self.kffi.symbols.items():
            a = getattr(sym, "address", 0)
            if a:
                byaddr.setdefault(a, []).append(name)
        buf = self.ffi.new("uint8_t[512]")
        order = "big" if self.big else "little"
        added, agree, differ = [], 0, []
        num = 0                         # entries read: the table's length at the end
        while num < self._TABLE_MAX:
            if num % 64 == 0:
                if not self.lib.penguin_syscall_read_memory(cs, table + num * 8, buf, 512):
                    break
                raw = bytes(buf)
            o = num % 64 * 8
            names = byaddr.get(int.from_bytes(raw[o:o + 8], order), ())
            bases = [n[len(p):] for n in names for p in self._TABLE_PREFIXES
                     if n.startswith(p)]
            # past the end: not a syscall function
            if not bases:
                break
            # sys_ni_syscall: its aliases name calls not built in
            if not any(b.endswith("ni_syscall") for b in bases):
                base = bases[0]
                if base not in self.numbers:
                    self.numbers[base] = num
                    added.append(f"{base}={num}")
                elif self.numbers[base] == num:
                    agree += 1
                else:
                    differ.append(f"{base}={self.numbers[base]}/{num}")
            num += 1
        # where the metadata numbers a call too, the two must agree
        (logger.warning if differ else logger.info)(
            "syscall trap: sys_call_table: %d entries, %d numbers added, %d agree "
            "with the metadata%s", num, len(added), agree,
            f", differ: {' '.join(differ[:8])}" if differ else "")
        logger.debug("syscall trap: from sys_call_table: %s", " ".join(added))

    # hooks

    def _filter(self, f, spec, keep):
        """spec as Syscalls takes it: a ValueFilter, an int (exact), a str
        (starts with), or None"""
        f.enabled = False
        if spec is None:
            return
        pattern = None
        if spec.__class__.__name__ == "ValueFilter":
            t, value = spec.filter_type, spec.value
            f.min_value, f.max_value = _s64(spec.min_value), _s64(spec.max_value)
            f.bitmask = int(spec.bitmask) & M64
            pattern = spec.pattern
        elif isinstance(spec, (int, float)):
            t, value = 0, int(spec)
        elif isinstance(spec, str):
            t, value, pattern = 13, 0, spec.encode() + b"\0"   # STR_STARTSWITH
        else:
            return
        f.enabled, f.type, f.value = True, int(t), _s64(value)
        if getattr(spec, "subject", None) == "fd_path":
            f.subject = 1                       # PENGUIN_SC_SUBJECT_FD_PATH
        if pattern and int(t) in STR_TYPES:
            b = self.ffi.new("char[]", pattern)
            keep.append(b)
            f.pattern = b
            f.pattern_len = len(pattern) - (1 if pattern.endswith(b"\0") else 0)

    def register(self, cfg):
        """A hook from Syscalls' hook config; returns its id"""
        h = self.ffi.new("struct penguin_sc_hook *")
        keep = []
        h.enabled = bool(cfg.get("enabled", True))
        h.on_enter = bool(cfg.get("on_enter"))
        h.on_return = bool(cfg.get("on_return"))
        h.on_all = bool(cfg.get("on_all"))
        h.on_unknown = bool(cfg.get("on_unknown"))
        h.name = (cfg.get("name") or "").encode()[:47]
        if cfg.get("procname") is not None:
            h.comm_filter_enabled = True
            h.comm_filter = cfg["procname"].encode()[:15]
        if cfg.get("pid_filter") is not None:
            h.pid_filter_enabled = True
            h.filter_pid = int(cfg["pid_filter"])
        scope = cfg.get("scope_filter")
        h.scope_filter_enabled = True if scope is None else bool(scope)
        arg_filters = cfg.get("arg_filters") or []
        for i in range(6):
            self._filter(h.arg_filters[i], arg_filters[i] if i < len(arg_filters) else None,
                         keep)
        self._filter(h.retval_filter, cfg.get("retval_filter"), keep)
        self._filter(h.exe_filter, cfg.get("exe_filter"), keep)
        hid = self.lib.penguin_syscall_register(h)
        if not hid:
            raise RuntimeError(f"syscall trap: hook refused: {cfg.get('name')!r}")
        return hid

    def unregister(self, hid):
        return bool(self.lib.penguin_syscall_unregister(hid))

    def stats(self):
        st = self.ffi.new("struct penguin_sc_stats *")
        self.lib.penguin_syscall_stats(st)
        return {k: getattr(st, k) for k in dir(st)}

    # events

    def pt_regs(self, sce):
        cs, ev = sce._cs, sce._ev
        return _LazyPtRegs(lambda: get_pt_regs_wrapper(self.panda, self._regs(cs, ev)))

    def _regs(self, cs, ev):
        """struct pt_regs as the kernel has it at the hook"""
        v = self.ffi.new("uint64_t[]", self._ngdb)
        n = self.lib.penguin_syscall_regs(cs, 0, self._ngdb, v)
        b = bytearray(self._rsize)
        q, off = self._q.pack_into, self._roff
        for g, o in self._rmap:
            if g < n and o >= 0:
                q(b, o, v[g])
        if self.arch == "x86_64":
            q(b, off["ip"], ev.pc)
            if ev.abi == ABIS["x86_64"]:
                # what the syscall instruction leaves in rcx and r11
                q(b, off["cx"], ev.pc)
                q(b, off["r11"], v[17] if n > 17 else 0)
            q(b, off["orig_ax"], ev.num & M64)
            q(b, off["ax"], (-ENOSYS if ev.is_enter else ev.retval) & M64)
        else:
            if ev.abi != ABIS["aarch64"]:
                # an AArch32 task: r0-r14 in regs[]; PSR_MODE32_BIT, user mode
                for i in range(15, 31):
                    q(b, off["regs"] + 8 * i, 0)
                q(b, off["pstate"], 0x10)
            q(b, off["pc"], ev.pc)
            q(b, off["orig_x0"], ev.args[0])
            self._i.pack_into(b, off["syscallno"], ev.num)
            if not ev.is_enter:
                q(b, off["regs"], ev.retval & M64)
        if self.kffi is None:
            return self.ffi.from_buffer(_FIXED_REGS[self.arch]["ctype"], b)
        return self.kffi.from_buffer("struct pt_regs", b)

    def number(self, name):
        """the native ABI's number for syscall @name, or None"""
        return self.numbers.get(name)

    def _command(self, c):
        """a yielded PortalCmd or InjectCmd as (op, addr, size, data), or
        None if QEMU cannot carry it out"""
        if isinstance(c, InjectCmd):
            num = c.num
            if isinstance(num, str):
                # the task's ABI's number: native, or its compat ABI's
                table = (self.numbers if getattr(self, "_abi", ABIS[self.native])
                         == ABIS[self.native] else self.compat_numbers)
                num = table.get(num)
                if num is None:
                    return OP_SYSCALL, -1, (), None         # refused: nothing runs
            return OP_SYSCALL, num, c.args, None
        op = getattr(c, "op", None)
        if getattr(c, "pid", CURRENT_PID) in (CURRENT_PID, None):
            addr = int(getattr(c, "addr", 0) or 0) & M64
            if op == hop.HYPER_OP_READ:
                return OP_READ, addr, int(c.size), None
            if op == hop.HYPER_OP_READ_STR:
                return OP_READ_STR, addr, int(c.size or 0), None
            if op == hop.HYPER_OP_WRITE:
                data = bytes(c.data or b"")
                return OP_WRITE, addr, len(data), data
        if op is not None and self._portal_ready():
            return OP_PORTAL, c, None, None
        if op not in self.unsupported:
            self.unsupported.add(op)
            logger.warning("syscall trap: portal command %r not served; "
                           "the callback gets None", op)
        return None

    def _portal_ready(self):
        """can a command go to igloo's portal (see the module docstring)?"""
        portal = getattr(plugins, "portal", None)
        if portal is None or not getattr(portal, "portal_interrupt", None) \
                or self.number("getpid") is None:
            return False
        if not self.portal_handler:
            portal.register_interrupt_handler("syscall_trap", self._serve_portal)
            self.portal_handler = True
        return True

    def _serve_portal(self):
        """the portal interrupt's handler: igloo serves the queued commands"""
        while self.portal_q:
            slot = self.portal_q.pop(0)
            slot["value"] = yield slot["cmd"]
            slot["done"] = True

    def _delegate(self, call, slot):
        """queue @slot's command at the portal; the task's getpid carries it"""
        if slot not in self.portal_q:
            self.portal_q.append(slot)
        plugins.portal.queue_interrupt("syscall_trap")
        self.delegated[call] = slot
        return OP_SYSCALL, self.number("getpid"), (), None

    def _delegated_answer(self, call, slot, cmd):
        """a delegated command's answer, or another getpid's (op, ...) if
        the portal has not taken it yet"""
        if slot.get("done"):
            return slot.get("value"), None
        slot["tries"] = slot.get("tries", 0) + 1
        if cmd.status == OK and slot["tries"] < PORTAL_TRIES:
            return None, self._delegate(call, slot)
        if slot in self.portal_q:
            self.portal_q.remove(slot)
        op = getattr(slot["cmd"], "op", None)
        if ("late", op) not in self.unsupported:
            self.unsupported.add(("late", op))
            logger.warning("syscall trap: portal command %r not taken by igloo's portal "
                           "(%s); the callback gets None", op,
                           "no injecting here" if cmd.status != OK else "no interrupt")
        return None, None

    def _answer(self, cmd):
        """what the portal sends the coroutine (Portal.wrap)"""
        if cmd.op in (OP_READ, OP_READ_STR) and cmd.status != FAIL:
            return bytes(self.ffi.buffer(cmd.buf, cmd.len)) if cmd.len else b""
        if cmd.op == OP_SYSCALL and cmd.status == OK:
            if getattr(self, "_abi", None) in (ABIS["arm"], ABIS["i386"]):
                # a 32-bit task's: its register, unsigned unless an errno
                r = cmd.ret & 0xffffffff
                return r - (1 << 32) if r > 0xfffff000 else r
            return cmd.ret
        return None

    def _on_event(self, cs, ev, cmd, opaque):
        """a run of a hook: start it, or send it the answer to its command"""
        if cmd.op == OP_ABORT:
            g = self.runs.pop(ev.call, None)
            self.wbufs.pop(ev.call, None)
            slot = self.delegated.pop(ev.call, None)
            if slot in self.portal_q:
                self.portal_q.remove(slot)
            if g is not None:
                g.close()
            return
        # qemu_compat's per-thread state: the current CPU, and mem's direct
        # accesses go to the engine
        state = self.panda._callback_state()
        prev = state.cpu
        state.cpu = cs
        state.syscall_trap = True
        state.task = ev.task                    # for apis/hostosi.py
        self._abi = ev.abi                      # for InjectCmd's names
        again = None
        try:
            if cmd.op == OP_NONE:
                g = self.s._trap_event(TrapEvent(self.ffi, cs, ev))
                if not isinstance(g, Iterator):
                    return                      # done: cmd.op stays NONE
                val = None
            else:
                g = self.runs.pop(ev.call)
                self.wbufs.pop(ev.call, None)
                slot = self.delegated.pop(ev.call, None)
                if slot is None:
                    val = self._answer(cmd)
                else:
                    val, again = self._delegated_answer(ev.call, slot, cmd)
            try:
                if again is not None:
                    k = again
                else:
                    c = g.send(val)
                    while (k := self._command(c)) is None:
                        c = g.send(None)
                    if k[0] == OP_PORTAL:
                        k = self._delegate(ev.call, {"cmd": k[1]})
            except StopIteration:
                cmd.op = OP_NONE
                return
        except Exception as exc:
            cmd.op = OP_NONE
            self._fatal(exc, ev)
            return
        finally:
            state.syscall_trap = False
            state.task = 0
            state.cpu = prev
        self.runs[ev.call] = g
        if k[0] == OP_SYSCALL:
            cmd.op, cmd.num = OP_SYSCALL, k[1]
            for i in range(6):
                cmd.args[i] = k[2][i] if i < len(k[2]) else 0
            return
        cmd.op, cmd.addr, cmd.size = k[0], k[1], k[2]
        if k[3] is not None:
            b = self.ffi.new("char[]", k[3])
            self.wbufs[ev.call] = b
            cmd.data = b

    def _fatal(self, exc, ev):
        # fail fast, as the hypercall path does
        logger.exception("Fatal error in syscall callback (%s): %s",
                         self.ffi.string(ev.syscall_name).decode(errors="replace"), exc)
        record = getattr(self.panda, "_record_callback_exception", None)
        if record is not None:
            record(exc)

    def _on_error(self, exc_type, exc, tb):
        logger.error("syscall trap callback: %s", exc, exc_info=(exc_type, exc, tb))
