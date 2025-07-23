"""
# Lifeguard: Signal Blocking Plugin

This module provides a plugin for the Penguin framework to block specified Linux signals
by replacing them with a harmless `SIGCONT`. It is useful for preventing certain signals
from terminating or interrupting processes during analysis or emulation.

## Features

- Block user-specified signals (e.g., SIGKILL, SIGTERM) for target processes.
- Log all signal delivery attempts to a CSV file.
- Optionally enable verbose logging for debugging.

## Usage

To use this plugin, specify the signals to block in the configuration:

```json
{
    "blocked_signals": [9, 15]  # Block SIGKILL and SIGTERM
}
```

The plugin will log all signal attempts to `lifeguard.csv` in the specified output directory.
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
    - `panda`: The PANDA instance.
    - `outdir` (`str`): Output directory for logs.
    - `blocked_signals` (`list[int]`): List of blocked signal numbers.
    """

    panda: object
    outdir: str
    blocked_signals: list[int]

    def __init__(self, panda: object) -> None:
        """
        **Initialize the Lifeguard plugin.**

        **Args**
        - `panda` (`object`): The PANDA instance.

        **Returns**
        - `None`
        """
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        if self.get_arg_bool("penguin_verbose"):
            self.logger.setLevel("DEBUG")

        self.blocked_signals = []
        conf = self.get_arg("conf")
        if "blocked_signals" in conf:
            self.blocked_signals = [int(x) for x in conf["blocked_signals"]]

        with open(f"{self.outdir}/{LIFELOG}", "w") as f:
            f.write("signal,target_process,blocked\n")

        if len(self.blocked_signals) > 0:
            self.logger.info(f"Blocking signals: {self.blocked_signals}")

    def get_proc_by_pid(self, cpu: object, pid: int) -> str:
        """
        **Get the process name for a given PID.**

        **Args**
        - `cpu` (`object`): The CPU context.
        - `pid` (`int`): The process ID.

        **Returns**
        - `str`: The process name, or None if not found.
        """
        for p in self.panda.get_processes(cpu):
            if p.pid == abs(pid):
                return self.panda.ffi.string(p.name).decode("latin-1", errors="ignore")

    @plugins.syscalls.syscall("on_sys_kill_enter")
    def on_sys_kill_enter(self, regs, proto: object, sysret: object, pid: int, sig: int) -> None:
        """
        **Handler for the kill syscall. Blocks signals if configured.**

        **Args**
        - `proto` (`object`): The syscall prototype.
        - `sysret` (`object`): The syscall return object.
        - `pid` (`int`): The target process ID.
        - `sig` (`int`): The signal number.

        **Returns**
        - `None`
        """
        cpu = self.panda.get_cpu()
        save = sig in self.blocked_signals
        with open(f"{self.outdir}/{LIFELOG}", "a") as f:
            f.write(f"{sig},{pid},{1 if save else 0}\n")

        proc = self.panda.plugins['osi'].get_current_process(cpu)
        if proc != self.panda.ffi.NULL:
            pname = self.panda.ffi.string(proc.name).decode("latin-1", errors="ignore")
            ppid = proc.pid
        else:
            pname = "[?]"
            ppid = "[?]"
        pname = yield from plugins.osi.get_proc_name()
        kpname = self.get_proc_by_pid(cpu, pid) or "[?]"
        expl = signals.get(sig, "[?]")
        self.logger.debug(f"{pname}({ppid}) kill({kpname}({pid}), {expl}({sig})) {'blocked' if save else ''}")

        if save:
            sysret.args[2] = 18
