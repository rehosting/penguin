from abc import ABC

class StaticAnalysis(ABC):
    """
    Abstract base class for static analyses.
    """
    def __init__(self) -> None:
        pass

    def run(self, extract_dir: str, prior_results: dict) -> None:
        pass
