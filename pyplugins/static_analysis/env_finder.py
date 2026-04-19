import re
from penguin.static_plugin import StaticAnalysisPlugin

class EnvFinder(StaticAnalysisPlugin):
    """
    Identify potential environment variables and their values in the filesystem.
    """
    depends_on = ['InitFinder']
    BORING_VARS: list[str] = ["TERM"]

    def run(self) -> dict[str, list | None]:
        # Need to dynamically load FileSystemHelper to avoid circular import if needed,
        # but since we're in the same directory, we can import it.
        from .file_system_helper import FileSystemHelper

        task_options = [0xBF000000, 0x7F000000, 0x3F000000]

        potential_env = {
            "igloo_task_size": task_options,
            "igloo_init": self.prior_results.get('InitFinder', [])
        }

        pattern = re.compile(r"\/proc\/cmdline.*?([A-Za-z0-9_]+)=", re.MULTILINE)
        potential_keys = FileSystemHelper.find_regex(pattern, self.extracted_fs, ignore=self.BORING_VARS).keys()

        for k in potential_keys:
            known_vals = None
            pattern = re.compile(k + r"=([A-Za-z0-9_]+)", re.MULTILINE)
            potential_vals = FileSystemHelper.find_regex(pattern, self.extracted_fs,
                                                         ignore=self.BORING_VARS).keys()

            if len(potential_vals):
                known_vals = list(potential_vals)

            potential_env[k] = known_vals

        return potential_env
