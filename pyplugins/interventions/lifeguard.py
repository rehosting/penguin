from penguin import plugins, Plugin

"""
Block specified signals by replacing them with a harmless SIGCONT
"""

LIFELOG = "lifeguard.csv"

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
    def __init__(self, panda):
        self.panda = panda
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
        plugins.syscalls.syscall("on_sys_kill_return")(self.on_sys_kill_enter)

    def get_proc_by_pid(self, cpu, pid):
        for p in self.panda.get_processes(cpu):
            if p.pid == abs(pid):
                return self.panda.ffi.string(p.name).decode("latin-1", errors="ignore")

    def on_sys_kill_enter(self, cpu, proto, sysret, pid, sig):
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
