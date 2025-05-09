import logging
from collections import Counter
from copy import deepcopy
from os.path import join as pjoin
from typing import List

from pandare2 import PyPlugin

from penguin import getColoredLogger, plugins
from penguin.analyses import PenguinAnalysis
from penguin.graphs import Configuration, Failure, Mitigation

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


class Lifeguard(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.logger = getColoredLogger("plugins.lifeguard")
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
        self.panda.hsyscall("on_sys_kill_return")(self.on_sys_kill_enter)

    def get_proc_by_pid(self, cpu, pid):
        for p in self.panda.get_processes(cpu):
            if p.pid == abs(pid):
                return self.panda.ffi.string(p.name).decode("latin-1", errors="ignore")

    @plugins.portal.wrap
    def on_sys_kill_enter(self, cpu, proto, sysret, hook, pid, sig):
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
        pname = yield from plugins.portal.get_proc_name()
        kpname = self.get_proc_by_pid(cpu, pid) or "[?]"
        expl = signals.get(sig, "[?]")
        self.logger.debug(f"{pname}({ppid}) kill({kpname}({pid}), {expl}({sig})) {'blocked' if save else ''}")

        if save:
            sysret.args[2] = 18


class SigInt(PenguinAnalysis):
    """
    Examine signals reported by lifeguard. Propose mitigations to block signals that seem suspicious.
    """

    ANALYSIS_TYPE = "signals"
    VERSION = "1.0.0"
    SHADY_SIGNALS = [
        6,  # SIGABRT
        9,  # SIGKILL
        15,  # SIGTERM
        17,  # SIGCHLD
    ]

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(self.ANALYSIS_TYPE)
        self.logger.setLevel(logging.DEBUG)

    def parse_failures(self, output_dir) -> List[Failure]:
        # blocked_signals = []
        # with open(pjoin(output_dir, "core_config.yaml")) as f:
        #     config = yaml.safe_load(f)
        # if "blocked_signals" in config:
        #     blocked_signals = [int(x) for x in config["blocked_signals"]]

        # Look through lifeguard.csv and identify unblocked signals that might be sus
        blockable_singals = Counter()

        with open(pjoin(output_dir, LIFELOG)) as f:
            lines = f.readlines()
            lines = lines[1:]
            for line in lines:
                sig, pid, blocked = line.split(",")
                sig = int(sig)
                pid = int(pid)
                blocked = int(blocked)
                if not blocked and sig in self.SHADY_SIGNALS:
                    blockable_singals[sig] += 1

        # Each blockable signal is a failure we could try to mitigate. Weight is fraction of total blockable signals
        # Weight will be 100x number of times we saw the signal
        return [
            Failure(f"sig{sig}", self.ANALYSIS_TYPE, {"signal": sig})
            for sig, count in blockable_singals.items()
        ]

    def get_potential_mitigations(self, config, failure: Failure) -> List[Mitigation]:
        """
        Propose blocking each failed signal, so long as it's not already blocked
        """
        sig = failure.info["signal"]
        if sig in config.get("blocked_signals", []):
            return []
        return [
            Mitigation(
                f"block_sig{sig}", self.ANALYSIS_TYPE, {"signal": sig, "weight": 50},
                patch={"blocked_signals": [sig]}, failure_name=failure.friendly_name
            )
        ]

    def implement_mitigation(
        self, config: Configuration, failure: Failure, mitigation: Mitigation
    ) -> List[Configuration]:
        """
        Add the signal to the list of blocked signals
        """
        new_config = deepcopy(config.info)
        sig = mitigation.info["signal"]

        if "blocked_signals" not in new_config:
            new_config["blocked_signals"] = []

        if sig in new_config["blocked_signals"]:
            return []  # It was already blocked. Weird
        new_config["blocked_signals"].append(sig)
        return [Configuration(f"block_sig{sig}", new_config)]
