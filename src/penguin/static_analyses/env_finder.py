import re
from penguin import getColoredLogger
from .base import StaticAnalysis
from penguin.helpers.filesystem_helper import FileSystemHelper

logger = getColoredLogger("penguin.static_analyses")

class EnvFinder(StaticAnalysis):
    """
    Identify potential environment variables and their values in the filesystem.
    """
    BORING_VARS: list[str] = ["TERM"]

    def run(self, extract_dir: str, prior_results: dict) -> dict[str, list | None]:
        """
        Find environment variables and their possible values.

        :param extract_dir: Directory containing extracted filesystem.
        :param prior_results: Results from previous analyses.
        :return: Dict of environment variable names to possible values.
        """

        task_options = [0xBF000000, 0x7F000000, 0x3F000000]

        potential_env = {
            "igloo_task_size": task_options,
            "igloo_init": prior_results['InitFinder']
        }

        pattern = re.compile(r"\/proc\/cmdline.*?([A-Za-z0-9_]+)=", re.MULTILINE)
        potential_keys = FileSystemHelper.find_regex(pattern, extract_dir, ignore=self.BORING_VARS).keys()

        for k in potential_keys:
            known_vals = None
            pattern = re.compile(k + r"=([A-Za-z0-9_]+)", re.MULTILINE)
            potential_vals = FileSystemHelper.find_regex(pattern, extract_dir,
                                                         ignore=self.BORING_VARS).keys()

            if len(potential_vals):
                known_vals = list(potential_vals)

            potential_env[k] = known_vals

        return potential_env
