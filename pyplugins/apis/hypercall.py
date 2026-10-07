import json
import os
import struct
import threading
import time
from collections import Counter, defaultdict
from collections.abc import Iterator
from typing import Any, Callable, DefaultDict, List

from penguin import Plugin


def _hypercall_aliases(nr: int) -> tuple[int, ...]:
    raw = int(nr)
    unsigned32 = raw & 0xFFFFFFFF
    signed32 = unsigned32 - 0x100000000 if unsigned32 & 0x80000000 else unsigned32
    unsigned64 = raw & 0xFFFFFFFFFFFFFFFF
    return tuple(dict.fromkeys((raw, unsigned32, signed32, unsigned64)))


# Hypercall mailbox (igloo_driver portal/mailbox.h, DESIGN-mailbox.md).
IGLOO_HYPER_REGISTER_MAILBOX = 0x7904
IGLOO_HYPER_MAILBOX = 0x7905
MB_MODE_OFF, MB_MODE_HC, MB_MODE_HVC = 0, 1, 2
MB_MAGIC = b"IGLOOMB1"
MB_PAGE = 4096
MB_RET_OFFSET = 64
MB_PAYLOAD_OFFSET = 112


class MailboxCall:
    """One mailbox hypercall: what the guest put in the mailbox."""
    __slots__ = ("nr", "args", "region_pa", "event_pa", "event_len",
                 "str_arg", "_buf")

    def __init__(self, nr, args, region_pa, event_pa, event_len, str_arg, buf):
        self.nr = nr
        self.args = args
        self.region_pa = region_pa
        self.event_pa = event_pa
        self.event_len = event_len
        self.str_arg = str_arg
        self._buf = buf

    @property
    def payload_str(self) -> str:
        raw = bytes(self._buf[MB_PAYLOAD_OFFSET:])
        end = raw.find(b"\0")
        return raw[:end if end >= 0 else len(raw)].decode("utf-8", "replace")


class Hypercall(Plugin):
    """
    QEMU backend hypercall registry.

    This replaces the old PANDA C hypercall plugin with a Penguin pyplugin that
    owns the magic-number to callback mapping. qemu_compat only forwards backend
    hypercall exits here.
    """

    def __init__(self) -> None:
        self.handlers: DefaultDict[int, List[Callable]] = defaultdict(list)
        self.qemu_compats = []
        self._bind_active_qemu_compats()

        # Mailbox state: vCPU (CPUState address) -> mapped mailbox page.
        self.mailboxes = {}
        self.mb_shared_pa = None
        # The MailboxCall being dispatched on this vCPU thread, if any. Per
        # thread: with smp > 1, two vCPUs can be inside a dispatch at once.
        self._mb_tls = threading.local()
        self.mb_calls = Counter()
        self.mb_synced = Counter()
        self._mb_enabled = os.environ.get("PENGUIN_HC_MAILBOX", "1") != "0"
        endian = "<" if self.panda.endianness == "little" else ">"
        self._mb_hdr = struct.Struct(f"{endian}8sQ6QQQQQQQ")
        self._mb_ret = struct.Struct(f"{endian}Q")
        self._mb_outdir = self.get_arg("outdir")
        self._mb_last_dump = 0.0
        self.register(IGLOO_HYPER_REGISTER_MAILBOX, self._mb_register)
        self.register(IGLOO_HYPER_MAILBOX, self._mb_doorbell)

    def _bind_active_qemu_compats(self) -> None:
        try:
            from compat.qemu_compat import QemuCompat
        except Exception:
            try:
                from pyplugins.compat.qemu_compat import QemuCompat
            except Exception:
                return

        for qemu_compat in QemuCompat.active_instances():
            self.bind_qemu_compat(qemu_compat)

    def bind_qemu_compat(self, qemu_compat) -> None:
        if qemu_compat not in self.qemu_compats:
            self.qemu_compats.append(qemu_compat)
        for nr in self.handlers:
            self._register_qemu_hypercall(nr, qemu_compat)

    def _register_qemu_hypercall(self, nr: int, qemu_compat=None) -> None:
        qemu_compats = [qemu_compat] if qemu_compat is not None else self.qemu_compats
        for qemu in qemu_compats:
            qemu.register_guest_hypercall(nr)

    def register(self, nr: int, func: Callable) -> Callable:
        for alias in _hypercall_aliases(nr):
            self.handlers[alias].append(func)
            self._register_qemu_hypercall(alias)
        return func

    def hypercall(self, nr: int) -> Callable[[Callable], Callable]:
        def decorator(func: Callable) -> Callable:
            return self.register(nr, func)
        return decorator

    def __call__(self, nr: int) -> Callable[[Callable], Callable]:
        return self.hypercall(nr)

    def _handle_portal_cmd(self, cmd: Any) -> Any:
        from hyper.consts import HYPER_OP as hop

        if cmd.op in {hop.HYPER_OP_READ, hop.HYPER_OP_READ_STR}:
            return self.panda.virtual_memory_read(self.panda.get_cpu(), cmd.addr, cmd.size)
        if cmd.op == hop.HYPER_OP_WRITE:
            self.panda.virtual_memory_write(self.panda.get_cpu(), cmd.addr, cmd.data or b"")
            return cmd.size

        raise RuntimeError(
            f"Hypercall compatibility layer cannot service PortalCmd op={cmd.op:#x} "
            "without the guest portal interrupt path"
        )

    def _run_result(self, result: Any) -> Any:
        if not isinstance(result, Iterator):
            return result

        value = None
        while True:
            try:
                cmd = result.send(value)
            except StopIteration as stop:
                return stop.value

            value = None
            if cmd.__class__.__name__ == "PortalCmd":
                value = self._handle_portal_cmd(cmd)

    @property
    def mb(self):
        return getattr(self._mb_tls, "call", None)

    def _lookup(self, nr: int):
        for alias in _hypercall_aliases(nr):
            handlers = self.handlers.get(alias)
            if handlers:
                return handlers
        return None

    def dispatch(self, cpu, nr: int, ret_ptr) -> int:
        handlers = self._lookup(nr)
        if not handlers:
            return 1

        self._run_handlers(cpu, nr, handlers)

        if ret_ptr[0] == 0:
            ret_ptr[0] = self.panda._current_retval
        return 0

    def _vcpu(self, cpu) -> int:
        return int(self.panda.ffi.cast("uintptr_t", cpu))

    def _mb_register(self, cpu):
        """IGLOO_HYPER_REGISTER_MAILBOX(mailbox_pa, shared_pa, cpu, size), on that CPU."""
        mb_pa, shared_pa, guest_cpu, size = self.panda._current_args[:4]
        if not self._mb_enabled:
            return MB_MODE_OFF
        try:
            ptr, plen = self.panda.physical_map(mb_pa, MB_PAGE)
        except Exception as exc:
            self.logger.warning("mailbox: cannot map %#x: %s", mb_pa, exc)
            return MB_MODE_OFF
        if ptr == self.panda.ffi.NULL or plen < MB_PAGE:
            self.logger.warning("mailbox: %#x is not mappable RAM", mb_pa)
            return MB_MODE_OFF
        buf = self.panda.ffi.buffer(ptr, MB_PAGE)
        if bytes(buf[0:8]) != MB_MAGIC or size != MB_PAYLOAD_OFFSET:
            self.logger.warning("mailbox: bad magic or layout at %#x (size %d)", mb_pa, size)
            return MB_MODE_OFF
        self.mailboxes[self._vcpu(cpu)] = buf
        self.mb_shared_pa = shared_pa
        mode = MB_MODE_HC
        if getattr(self.panda, "mode", None) == "kvm":
            # The hvc doorbell needs QEMU's no-sync KVM exit path.
            lib_symbol = getattr(self.panda, "_lib_symbol", None)
            if lib_symbol is not None and lib_symbol("penguin_kvm_mailbox_supported") is not None:
                mode = MB_MODE_HVC
        self.logger.info("mailbox: guest cpu %d at %#x, mode %d", guest_cpu, mb_pa, mode)
        return mode

    def _mb_doorbell(self, cpu):
        """IGLOO_HYPER_MAILBOX: everything is in the calling vCPU's mailbox."""
        buf = self.mailboxes.get(self._vcpu(cpu))
        if buf is None:
            self.logger.error("mailbox doorbell from an unregistered vCPU")
            return None
        (_magic, nr, a0, a1, a2, a3, a4, a5, _ret, region_pa, event_pa,
         event_len, str_arg, _seq) = self._mb_hdr.unpack_from(buf, 0)
        args = [a0, a1, a2, a3, a4, a5]
        panda = self.panda
        panda._current_nr = nr
        panda._current_args = args
        panda._current_retval = 0
        ret = a0
        handlers = self._lookup(nr)
        if handlers:
            tls = self._mb_tls
            tls.call = MailboxCall(nr, args, region_pa, event_pa, event_len, str_arg, buf)
            panda.mb_begin(cpu)
            try:
                self._run_handlers(cpu, nr, handlers)
            finally:
                synced = panda.mb_end()
                tls.call = None
            ret = panda._current_retval
            if synced:
                self.mb_synced[nr] += 1
        self.mb_calls[nr] += 1
        self._mb_ret.pack_into(buf, MB_RET_OFFSET, ret & 0xFFFFFFFFFFFFFFFF)
        now = time.monotonic()
        if now - self._mb_last_dump > 2.0:
            self._mb_last_dump = now
            self._mb_dump()
        return None

    def mb_physical_read(self, addr: int, size: int) -> bytes:
        return self.panda.physical_memory_read(addr, size)

    def mb_physical_write(self, addr: int, data: bytes) -> int:
        return self.panda.physical_memory_write(addr, data)

    def _mb_dump(self) -> None:
        if not self._mb_outdir:
            return
        stats = {
            "calls": {f"{k:#x}": v for k, v in self.mb_calls.items()},
            "dispatches_that_synced": {f"{k:#x}": v for k, v in self.mb_synced.items()},
            "guard": dict(getattr(self.panda, "mb_guard", {})),
        }
        try:
            path = os.path.join(self._mb_outdir, "mailbox_stats.json")
            with open(path + ".tmp", "w") as f:
                json.dump(stats, f, indent=1, sort_keys=True)
            os.replace(path + ".tmp", path)
        except OSError:
            pass

    def uninit(self) -> None:
        self._mb_dump()

    def _run_handlers(self, cpu, nr: int, handlers) -> None:
        for handler in handlers:
            try:
                result = handler(cpu)
                result = self._run_result(result)
                if isinstance(result, int):
                    self.panda._set_current_retval(result)
            except Exception as exc:
                # Fail fast (PyPANDA parity): record the error and stop the
                # emulation rather than letting the guest continue with a
                # half-serviced hypercall.
                self.logger.exception("Fatal error in hypercall handler for %#x: %s", nr, exc)
                record = getattr(self.panda, "_record_callback_exception", None)
                if record is None:
                    raise
                record(exc)
                break
