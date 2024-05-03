import logging
from typing import List
from os.path import join as pjoin
from collections import Counter
from copy import deepcopy
from pandare import PyPlugin

from penguin import yaml
from penguin.analyses import PenguinAnalysis
from penguin.graphs import Failure, Mitigation, Configuration

'''
Block specified signals by replacing them with a harmless SIGCONT
'''

LIFELOG = "lifeguard.csv"

class Lifeguard(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.logger = logging.getLogger("lifeguard")

        blocked_signals = []
        conf = self.get_arg("conf")
        if 'blocked_signals' in conf:
            blocked_signals = [int(x) for x in conf['blocked_signals']]

        with open(f'{self.outdir}/{LIFELOG}', 'w') as f:
            f.write(f'signal,target_process,blocked\n')

        if len(blocked_signals) > 0:
            self.logger.info(f"Blocking signals: {blocked_signals}")

        @panda.ppp("syscalls2", "on_sys_kill_enter")
        def on_sys_kill_enter(cpu, pc, pid, sig):
            save = sig in blocked_signals

            with open(f'{self.outdir}/{LIFELOG}', 'a') as f:
                f.write(f'{sig},{pid},{1 if save else 0}\n')

            self.logger.debug(f"kill({pid}, {sig}) {'blocked' if save else ''}")

            if save:
                panda.arch.set_arg(cpu, 2, 18, convention="syscall")


class SigInt(PenguinAnalysis):
    '''
    Examine signals reported by lifeguard. Propose mitigations to block signals that seem suspicious.
    '''
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
        blocked_signals = []
        with open(pjoin(output_dir, 'core_config.yaml')) as f:
            config = yaml.safe_load(f)
        if 'blocked_signals' in config:
            blocked_signals = [int(x) for x in config['blocked_signals']]

        # Look through lifeguard.csv and identify unblocked signals that might be sus
        blockable_singals = Counter()

        with open(pjoin(output_dir, LIFELOG)) as f:
            lines = f.readlines()
            lines = lines[1:]
            for line in lines:
                sig, pid, blocked = line.split(',')
                sig = int(sig)
                pid = int(pid)
                blocked = int(blocked)
                if not blocked and sig in self.SHADY_SIGNALS:
                    blockable_singals[sig] += 1

        # Each blockable signal is a failure we could try to mitigate. Weight is fraction of total blockable signals
        # Weight will be 100x number of times we saw the signal
        return [Failure(f"sig{sig}", self.ANALYSIS_TYPE, {'signal': sig}) \
                for sig, count in blockable_singals.items()]
    
    def get_potential_mitigations(self, config, failure : Failure) -> List[Mitigation]:
        '''
        Propose blocking each failed signal, so long as it's not already blocked
        '''
        sig = failure.info['signal']
        if sig in config.get('blocked_signals', []):
            return []
        return [Mitigation(f"block_sig{sig}", self.ANALYSIS_TYPE, {'signal': sig, 'weight': 50})]

    def implement_mitigation(self, config : Configuration, failure : Failure, mitigation : Mitigation) -> List[Configuration]:
        '''
        Add the signal to the list of blocked signals
        '''
        new_config = deepcopy(config.info)
        sig = mitigation.info['signal']

        if 'blocked_signals' not in new_config:
            new_config['blocked_signals'] = []

        if sig in new_config['blocked_signals']:
            return [] # It was alrady blocked. Weird
        new_config['blocked_signals'].append(sig)
        return [Configuration(f'block_sig{sig}', new_config)]
