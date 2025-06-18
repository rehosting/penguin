"""
# Bash Command Plugin

This module provides a plugin for capturing and logging Bash command executions within the Penguin hypervisor environment.
It listens for Bash command events and writes details to a CSV file for coverage or auditing purposes.

## Usage

The plugin is typically loaded by the Penguin framework and does not require direct invocation.

### Example CSV Output

```csv
filename,lineno,pid,command
/home/user/script.sh,12,1234,ls -l
```

## Arguments

- `outdir`: Output directory for the CSV file.
- `verbose`: If set, enables debug logging.

## Classes

- `BashCommand`: Main plugin class for handling Bash command events.

"""

import csv
import os
from penguin import plugins, Plugin


class BashCommand(Plugin):
    """
    BashCommand is a plugin that logs Bash command executions to a CSV file.

    It subscribes to the "bash_command" hypercall and writes each command's
    filename, line number, process ID, and command string to a CSV file.

    **Arguments:**
    - `outdir` (str): Output directory for the CSV file.
    - `verbose` (bool): Enables debug logging if True.
    """

    def __init__(self) -> None:
        """
        Initialize the BashCommand plugin.

        - Sets up the output CSV file in the specified directory.
        - Configures logging level if verbose is enabled.
        - Subscribes to the "bash_command" hypercall.

        **Returns:** None
        """
        self.outdir = self.get_arg("outdir")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        # Bash
        outdir = self.get_arg("outdir")
        path = os.path.join(outdir, "bash_cov.csv")
        self.bash_cov_csv = open(path, "w")
        csv.writer(self.bash_cov_csv).writerow(
            ["filename", "lineno", "pid", "command"])
        self.bash_cov_csv.flush()

    @plugins.SendHypercall.subscribe("bash_command")
    def cmd_bash_command(self, cmd: str, path: str, lineno: int, pid: int) -> tuple[int, str]:
        """
        Handle a Bash command event and log it to the CSV file.

        **Parameters:**
        - `cmd` (str): The Bash command executed.
        - `path` (str): The file path where the command was executed.
        - `lineno` (int): The line number in the file.
        - `pid` (int): The process ID of the Bash process.

        **Returns:**
        - `(int, str)`: Tuple containing status code (0 for success) and an empty string.
        """
        csv.writer(self.bash_cov_csv).writerow([path, lineno, pid, cmd])
        self.bash_cov_csv.flush()
        self.logger.debug(f"bash_command {path}:{lineno} {pid}: {cmd}")
        return 0, ""
