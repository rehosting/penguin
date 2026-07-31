"""penguest -- in-guest Python bindings for the Penguin host.

This is the guest-side complement to the host's portalcall dispatcher
(``pyplugins/apis/portalcall.py``). It gives Python scripts running *inside* the
emulated guest the same reach the C helpers already have via
``penguin/guest-utils/native/portal_call.h``.

The one primitive is :func:`portal_call`, a thin ctypes shim that reuses the
existing portalcall ABI -- it does not invent a new mechanism. A portalcall
lowers to::

    syscall(SYS_sendto, PORTAL_MAGIC, user_magic, argc, &args, 0, 0)

which the host intercepts (it filters ``on_sys_sendto_enter`` on ``PORTAL_MAGIC``)
and dispatches to the ``@plugins.portalcall.portalcall(user_magic)`` handler
registered for that magic. So a guest ``portal_call(M, ...)`` lands at the
matching host ``@portalcall(M)`` handler with zero new host plumbing.

Multi-arch note
---------------
``portal_call.h`` gets ``SYS_sendto`` from the C toolchain at compile time; a
ctypes shim must resolve it at runtime. The authoritative source is the
``PENGUEST_SYS_SENDTO`` environment variable, which the host stager sets from the
(known) target architecture -- so production never relies on guesswork. The
built-in per-arch table below is only a best-effort fallback for standalone use;
using the raw ``sendto`` syscall (rather than libc's ``sendto()`` wrapper) mirrors
``portal_call.h`` exactly and avoids arches that might route ``sendto()`` through
the legacy ``socketcall`` multiplexer.
"""

import ctypes
import os

from . import vsock

__all__ = [
    "PORTAL_MAGIC", "PortalError", "portal_call", "log", "report", "vsock",
]

# Must match PORTAL_MAGIC in portal_call.h and pyplugins/apis/portalcall.py.
PORTAL_MAGIC = 0xC1D1E1F1

# Guest -> host logging over the portal. Must match PENGUEST_LOG_MAGIC in
# the host bridge (pyplugins/apis/penguest.py).
PENGUEST_LOG_MAGIC = 0x7067104C  # 'pg' + log
_LOG_LEVELS = {"debug": 0, "info": 1, "warning": 2, "error": 3, "finding": 4}

_UINT64_MASK = (1 << 64) - 1
_MAX_ARGS = 10  # matches portal_callN()'s fixed buffer in portal_call.h

# __NR_sendto per Linux ABI. Keyed on the family inferred from
# os.uname().machine. Overridden by $PENGUEST_SYS_SENDTO when set (authoritative).
_SENDTO_NR = {
    "x86_64": 44,
    "aarch64": 206,    # asm-generic
    "arm": 290,        # arm EABI
    "riscv": 206,      # asm-generic
    "loongarch": 206,  # asm-generic
    "powerpc": 335,    # ppc / ppc64 (endianness-invariant)
    "mips_o32": 4183,  # 4000 + 183
    "mips_n64": 5045,  # 5000 + 45
}


class PortalError(RuntimeError):
    """Raised when a portalcall cannot be issued (e.g. unknown architecture)."""


def _machine_to_key(machine):
    m = machine.lower()
    if m in ("x86_64", "amd64"):
        return "x86_64"
    if m == "aarch64" or m.startswith("arm64"):
        return "aarch64"
    if m.startswith("arm"):
        return "arm"
    if m.startswith("riscv"):
        return "riscv"
    if m.startswith("loongarch"):
        return "loongarch"
    if m.startswith("ppc") or m.startswith("powerpc"):
        return "powerpc"
    if m.startswith("mips64"):
        return "mips_n64"
    if m.startswith("mips"):
        return "mips_o32"
    return None


def _resolve_sendto_nr():
    """Return the target's __NR_sendto: env override, then the per-arch table."""
    env = os.environ.get("PENGUEST_SYS_SENDTO")
    if env:
        return int(env, 0)
    key = _machine_to_key(os.uname().machine)
    if key is not None and key in _SENDTO_NR:
        return _SENDTO_NR[key]
    raise PortalError(
        "cannot resolve the sendto syscall number for this architecture "
        f"({os.uname().machine!r}); set PENGUEST_SYS_SENDTO to __NR_sendto")


_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


def _syscall(nr, *args):
    """Invoke libc ``syscall(nr, *args)``; every value is passed register-width.

    Split out from :func:`portal_call` so tests can substitute it without a real
    guest kernel.
    """
    return int(_libc.syscall(ctypes.c_long(nr),
                             *[ctypes.c_long(a) for a in args]))


def portal_call(user_magic, *args):
    """Make a portalcall to the host handler registered for ``user_magic``.

    Mirrors ``portal_call.h``: lowers to
    ``syscall(SYS_sendto, PORTAL_MAGIC, user_magic, argc, &args, 0, 0)``. Each
    positional arg is coerced to an unsigned 64-bit integer (the host reads the
    array via ``read_uint64_array``). Returns the handler's integer result.
    """
    argc = len(args)
    if argc > _MAX_ARGS:
        raise PortalError(f"portal_call takes at most {_MAX_ARGS} args, got {argc}")
    # A zero-length ctypes array is invalid; allocate at least one slot. argc,
    # not the buffer length, tells the host how many to read.
    arr = (ctypes.c_uint64 * (argc or 1))(*[int(a) & _UINT64_MASK for a in args])
    nr = _resolve_sendto_nr()
    return _syscall(nr,
                    PORTAL_MAGIC,
                    int(user_magic) & _UINT64_MASK,
                    argc,
                    ctypes.addressof(arr),
                    0,
                    0)


def log(msg, level="info"):
    """Send a log line to the host; it lands in the run's penguin log.

    Lowers to a portalcall carrying (pointer, length, level); the host bridge
    reads the bytes out of guest memory and logs them. ``level`` is one of
    ``debug``/``info``/``warning``/``error``/``finding`` (unknown -> ``info``).
    """
    data = msg.encode("utf-8", "replace") if isinstance(msg, str) else bytes(msg)
    lvl = _LOG_LEVELS.get(level, _LOG_LEVELS["info"])
    n = len(data)
    # Keep the buffer alive across the call; the host reads it synchronously
    # while the sendto syscall is intercepted. A zero-length string still needs
    # a 1-byte allocation, but we tell the host to read 0 bytes.
    buf = ctypes.create_string_buffer(data, n or 1)
    return portal_call(PENGUEST_LOG_MAGIC, ctypes.addressof(buf), n, lvl)


def report(msg):
    """Report a finding to the host loop -- a log line tagged as a ``finding``
    (the hook the #835 AI-rehosting loop consumes)."""
    return log(msg, level="finding")
