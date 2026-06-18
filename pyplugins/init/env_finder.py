"""
Identify potential environment variables and their values in the filesystem.
"""

import re

from penguin.defaults import well_known_env_vars
from penguin.init_plugin import InitPlugin, cached_analysis
from penguin.static_analyses import FileSystemHelper


class EnvFinder(InitPlugin):
    """
    Identify potential environment variables and their values in the filesystem.
    """
    # Standard kernel cmdline params + penguin-internal knobs we should never
    # "discover" as vendor-specific env vars (shared with the runtime tracker).
    BORING_VARS: list[str] = well_known_env_vars

    # Reject implausibly long keys - a glued scrape, not a real var name.
    MAX_ENV_KEY_LEN: int = 64

    @cached_analysis
    def env(self) -> dict[str, list | None]:
        """
        Find environment variables and their possible values.

        :return: Dict of environment variable names to possible values.
        """
        extract_dir = str(self.ctx.extracted_fs)

        # To start, we know there's `igloo_task_size` (a knob we created to configure), and
        # igloo_init (another knob we created) to specify the init program. We'll find
        # values for both
        # Three magic values for igloo_task_size
        task_options = [0xBF000000, 0x7F000000, 0x3F000000]

        potential_env = {
            "igloo_task_size": task_options,
            "igloo_init": self.plugins.InitFinder.inits
        }

        # Now search the filesystem for shell scripts accessing /proc/cmdline
        pattern = re.compile(r"\/proc\/cmdline.*?([A-Za-z0-9_]+)=", re.MULTILINE)
        potential_keys = FileSystemHelper.find_regex(pattern, extract_dir, ignore=self.BORING_VARS).keys()

        # Drop well-known params (case-insensitive) and implausible/glued keys.
        boring_lower = {v.lower() for v in self.BORING_VARS}
        potential_keys = [
            k for k in potential_keys
            if k.lower() not in boring_lower
            and not k.isnumeric()
            and len(k) <= self.MAX_ENV_KEY_LEN
        ]

        # For each key, try pulling out potential values from the filesystem
        for k in potential_keys:
            known_vals = None
            pattern = re.compile(k + r"=([A-Za-z0-9_]+)", re.MULTILINE)
            potential_vals = FileSystemHelper.find_regex(pattern, extract_dir,
                                                         ignore=self.BORING_VARS).keys()

            if len(potential_vals):
                known_vals = list(potential_vals)

            potential_env[k] = known_vals

        return potential_env

    def static_result(self) -> dict[str, list | None]:
        return self.env
