"""
Lifeguard: Signal Blocking Plugin
=================================

This module provides a plugin for the Penguin framework to block specified Linux signals
by replacing them with a harmless SIGCONT. It is useful for preventing certain signals
from terminating or interrupting processes during analysis or emulation.

Features
--------

- Block user-specified signals (e.g., SIGKILL, SIGTERM) for target processes.
- Log all signal delivery attempts to a CSV file.
- Optionally enable verbose logging for debugging.

Usage
-----

To use this plugin, specify the signals to block in the configuration:

.. code-block:: json

    {
        "blocked_signals": [9, 15]  # Block SIGKILL and SIGTERM
    }

The plugin will log all signal attempts to lifeguard.csv in the specified output directory.
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


class Lifeguard(Plugin):
    """
    Plugin to block specified signals by replacing them with SIGCONT.

    **Attributes**
    - `outdir` (`str`): Output directory for logs.
    - `blocked_signals` (`list[int]`): List of blocked signal numbers.
    """

    outdir: str
    blocked_signals: list[int]

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

        with open(f"{self.outdir}/{LIFELOG}", "w") as f:
            f.write("signal,target_process,blocked\n")

        if len(self.blocked_signals) > 0:
            self.logger.info(f"Blocking signals: {self.blocked_signals}")

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
        save = sig in self.blocked_signals
        with open(f"{self.outdir}/{LIFELOG}", "a") as f:
            f.write(f"{sig},{pid},{1 if save else 0}\n")

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
            # Old approach was to change to SIGCONT, but some architectures (e.g., mips64eb/powerpc64) have syscall contexts that cause that to break
            syscall.skip_syscall = True
            syscall.retval = 0
