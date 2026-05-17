"""
Lifeguard: Signal Blocking Plugin
=================================

This module provides a plugin for the Penguin framework to block specified Linux
signals during analysis or emulation. Signals sent through kill(2) are blocked
before the kernel sends them. Lifeguard also consumes the signal_monitor API for
configured signals so non-kill(2) delivery paths can be observed and dropped when
the driver hook is effective.

Features
--------

- Block user-specified signals (e.g., SIGKILL, SIGTERM) for target processes.
- Log signal delivery and syscall interception events to a CSV file.
- Optionally enable verbose logging for debugging.

Usage
-----

To use this plugin, specify the signals to block in the configuration:

.. code-block:: json

    {
        "blocked_signals": [9, 15]  # Block SIGKILL and SIGTERM
    }

The plugin will log blocked signal events to lifeguard.csv in the specified output
directory.

Limitations
-----------

Delivery-time drops are not equivalent to preventing a signal from being sent.
For process-preserving behavior, Lifeguard still suppresses kill(2) before the
kernel applies signal semantics. SIGKILL and SIGSTOP cannot be caught or ignored
by Linux processes, so Lifeguard only suppresses kill(2)-generated instances of
those signals. Synchronous fault signals such as SIGILL or SIGSEGV may need
guest state repair when dropped; otherwise execution can return to the same
faulting instruction.
"""

from penguin import plugins, Plugin

LIFELOG: str = "lifeguard.csv"

signals = {
    "SIGHUP": 1,
    "SIGINT": 2,
    "SIGQUIT": 3,
    "SIGILL": 4,
    "SIGTRAP": 5,
    "SIGABRT": 6,
    "SIGIOT": 6,
    "SIGBUS": 7,
    "SIGFPE": 8,
    "SIGKILL": 9,
    "SIGUSR1": 10,
    "SIGSEGV": 11,
    "SIGUSR2": 12,
    "SIGPIPE": 13,
    "SIGALRM": 14,
    "SIGTERM": 15,
    "SIGSTKFLT": 16,
    "SIGCHLD": 17,
    "SIGCONT": 18,
    "SIGSTOP": 19,
    "SIGTSTP": 20,
    "SIGTTIN": 21,
    "SIGTTOU": 22,
    "SIGURG": 23,
    "SIGXCPU": 24,
    "SIGXFSZ": 25,
    "SIGVTALRM": 26,
    "SIGPROF": 27,
    "SIGWINCH": 28,
    "SIGIO": 29,
    "SIGPWR": 30,
    "SIGSYS": 31,
    "SIGRTMIN": 32
}

# make reversible
for i, v in list(signals.items()):
    signals[v] = i

SYSCALL_ONLY_SIGNALS = {
    signals["SIGKILL"],
    signals["SIGSTOP"],
}

STATE_REPAIR_SIGNALS = {
    signals["SIGILL"],
    signals["SIGTRAP"],
    signals["SIGBUS"],
    signals["SIGFPE"],
    signals["SIGSEGV"],
    signals["SIGSYS"],
}


class Lifeguard(Plugin):
    """
    Plugin to block specified signals.

    kill(2)-generated signals are suppressed before send time. For configured
    signals other than SIGKILL and SIGSTOP, Lifeguard also subscribes to
    signal_monitor so delivery paths outside kill(2) can be observed and dropped
    when the driver hook can do so safely.

    **Attributes**
    - `outdir` (`str`): Output directory for logs.
    - `blocked_signals` (`list[int]`): List of blocked signal numbers.
    """

    outdir: str
    blocked_signals: list[int]
    delivery_blocked_signals: set[int]
    syscall_blocked_signals: set[int]

    def __init__(self) -> None:
        """
        **Initialize the Lifeguard plugin.**

        **Args**
        - `panda` (`object`): The PANDA instance.

        **Returns**
        - `None`
        """
        self.outdir = self.get_arg("outdir")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        self.blocked_signals = []
        conf = self.get_arg("conf")
        if "blocked_signals" in conf:
            self.blocked_signals = [int(x) for x in conf["blocked_signals"]]

        self.syscall_blocked_signals = set(self.blocked_signals)
        self.delivery_blocked_signals = {
            sig for sig in self.blocked_signals if sig not in SYSCALL_ONLY_SIGNALS
        }
        state_repair_signals = self.delivery_blocked_signals & STATE_REPAIR_SIGNALS

        with open(f"{self.outdir}/{LIFELOG}", "w") as f:
            f.write("signal,target_process,blocked,mechanism\n")

        if len(self.blocked_signals) > 0:
            self.logger.info(f"Blocking signals: {self.blocked_signals}")

        if self.delivery_blocked_signals:
            self.plugins.subscribe(
                self.plugins.signal_monitor,
                "signal_deliver",
                self.on_signal_deliver,
            )
            for sig in sorted(self.delivery_blocked_signals):
                self.plugins.signal_monitor.register_hook(sig=sig)
            self.logger.info(
                f"Using signal_monitor delivery hooks for non-kill paths: "
                f"{sorted(self.delivery_blocked_signals)}"
            )

        if state_repair_signals:
            self.logger.warning(
                f"Signals {sorted(state_repair_signals)} often require guest "
                "state repair when dropped; Lifeguard only drops delivery. "
                "Use a signal_monitor consumer such as sigill_bypass when the "
                "faulting state must be advanced or emulated."
            )

        if self.syscall_blocked_signals:
            self.logger.info(
                f"Using kill(2) syscall interception for signals: "
                f"{sorted(self.syscall_blocked_signals)}"
            )

    def log_signal(self, sig: int, pid: int, blocked: bool, mechanism: str) -> None:
        with open(f"{self.outdir}/{LIFELOG}", "a") as f:
            f.write(f"{sig},{pid},{1 if blocked else 0},{mechanism}\n")

    def on_signal_deliver(self, cpu, event) -> None:
        """
        Block configured signals after the kernel has selected a delivery target.
        """
        if event.sig not in self.delivery_blocked_signals:
            return

        self.logger.debug(
            f"Blocking delivered {signals.get(event.sig, '[?]')}({event.sig}) "
            f"for {event.comm}({event.pid})"
        )
        self.log_signal(event.sig, event.pid, True, "delivery")
        event.drop = True

    @plugins.syscalls.syscall(
        name_or_pattern="sys_kill",
        on_enter=True,
        on_return=False,
    )
    def on_sys_kill_enter(self, pt_regs, proto, syscall, *args):
        """
        **Handler for the kill syscall. Blocks signals if configured.**

        **Args**
        - `pt_regs` (`object`): The CPU registers at syscall entry.
        - `proto` (`object`): The syscall prototype.
        - `syscall` (`object`): The syscall event object.
        - `args` (`tuple`): The arguments passed to the syscall.

        **Returns**
        - `None`
        """
        (pid, sig) = args[0:2]
        save = sig in self.syscall_blocked_signals
        self.log_signal(sig, pid, save, "syscall")

        proc = yield from plugins.osi.get_proc()
        if proc:
            ppid = proc.pid
        else:
            ppid = "[?]"
        pname = yield from plugins.osi.get_proc_name()
        kpname = yield from plugins.osi.get_proc_name(pid)
        if not kpname:
            kpname = "[?]"
        expl = signals.get(sig, "[?]")
        self.logger.debug(f"{pname}({ppid}) kill({kpname}({pid}), {expl}({sig})) {'blocked' if save else ''}")

        if save:
            # Blocking before send time is the reliable way to preserve a target
            # process for kill(2)-generated signals.
            syscall.skip_syscall = True
            syscall.retval = 0
