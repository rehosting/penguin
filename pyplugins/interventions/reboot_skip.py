"""Neutralise (and trace) userspace ``reboot(2)`` calls that would end the run.

Some firmware issues a clean userspace ``reboot(2)`` during first boot -- e.g.
asuswrt reboots itself right after ``## Restoring defaults... ##`` (the
"restore nvram defaults then reboot to apply" first-boot dance). Under
``-no-reboot`` QEMU that ends the run, so nothing downstream is ever observed.

This plugin hooks ``reboot(2)`` on entry, logs who called it (pid/name/exe +
parent + the reboot cmd) for diagnosis, and skips the syscall (returns 0) so boot
keeps going and the next blocker becomes visible. A safety cap bounds how many
reboots are neutralised so a genuine reboot loop cannot spin forever.

``reboot(2)``: ``int reboot(int magic1, int magic2, unsigned cmd, void *arg)``;
``cmd 0x01234567`` = ``LINUX_REBOOT_CMD_RESTART``.
"""
from pydantic import Field

from penguin import Plugin, PluginArgs, plugins


class reboot_skip(Plugin):
    class Args(PluginArgs):
        max_neutralise: int = Field(
            default=50,
            description="skip at most this many reboot(2) calls, then let them proceed")
        log_only: bool = Field(
            default=False,
            description="only trace reboot(2) callers, do not skip")

    def __init__(self):
        self.n = 0
        self.max_neutralise = self.get_arg("max_neutralise")
        if self.max_neutralise is None:
            self.max_neutralise = 50
        self.log_only = bool(self.get_arg("log_only"))
        self.logger.setLevel("INFO")
        mode = "trace-only" if self.log_only else f"skip (cap {self.max_neutralise})"
        self.logger.info(f"reboot_skip loaded ({mode})")

    @plugins.syscalls.syscall("on_sys_reboot_enter")
    def _reboot(self, regs, proto, syscall, *args):
        self.n += 1
        cmd = args[2] if len(args) >= 3 else None
        pid = name = exe = ppid = pname = pexe = "?"
        try:
            proc = yield from plugins.OSI.get_proc()
            if proc:
                pid, name, ppid = proc.pid, proc.name, proc.ppid
                exe = yield from plugins.OSI.get_proc_exe()
                parent = yield from plugins.OSI.get_proc(ppid)
                if parent:
                    pname = parent.name
                    pexe = yield from plugins.OSI.get_proc_exe(ppid)
        except Exception as e:  # noqa: BLE001 - diagnostic best-effort
            self.logger.warning(f"reboot_skip: OSI lookup failed: {e}")

        cmd_s = f"{cmd:#x}" if isinstance(cmd, int) else str(cmd)
        self.logger.info(
            f"[{self.n}] reboot(2) cmd={cmd_s} by pid={pid} name={name!r} "
            f"exe={exe!r} <- ppid={ppid} pname={pname!r} pexe={pexe!r}")

        if self.log_only:
            return
        if self.n <= self.max_neutralise:
            syscall.skip_syscall = True
            syscall.retval = 0
            self.logger.info(f"[{self.n}] reboot neutralised (skip, rv=0)")
        else:
            self.logger.info(
                f"[{self.n}] over cap {self.max_neutralise}, letting reboot proceed")
