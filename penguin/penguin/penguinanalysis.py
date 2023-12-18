from typing import List, Any, Union, Dict, Optional
from abc import ABC, abstractmethod

class PenguinAnalysis(ABC):
    ANALYSIS_TYPE = None

    def __init__(self, debug: bool = False):
        self.debug = debug

    def __repr__(self):
        return f'Penguin_Analysis:{self.ANALYSIS_TYPE}'

    @abstractmethod
    def parse_failures(self, output_dir: str) -> Dict[Any,Any]:
        '''
        Given a run's output directory, parse the failures as reported by
        our corresponding PyPlugin and return a list some self-parsable errors
        '''
        pass

    @abstractmethod
    def get_potential_mitigations(self, state: Optional[Dict[Any,Any]], global_state: Any) -> Optional[List[Any]]:

        '''
        Given a configuration and the global state, what potential mitigations
        could be deployed?
        '''
        pass

    @abstractmethod
    def implement_mitigation(self, config: Any, fail_cause: Any, mitigation: Any) -> Any:
        '''
        Given a configuration a fail cause and a mitigation, return a new configuration
        with the mitigation applied.
        '''
        pass