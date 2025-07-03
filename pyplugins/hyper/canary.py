"""
# Canary Plugin

This module implements a plugin for the Penguin hypervisor environment that listens for "canary" hypercalls.
It is used to monitor and record the status of a canary value, typically for security or integrity checking.

## Usage

The plugin is loaded by the Penguin framework and responds to "canary" events.

### Example Output

If a canary status of `0` is received, the plugin writes a file named `canary.txt` containing `1` to the specified output directory.

```text
canary.txt
-----------
1
```

## Arguments

- `outdir`: Output directory for the canary status file.
- `verbose`: If set, enables debug logging.

## Classes

- `Canary`: Main plugin class for handling canary status events.

"""

import os
from penguin import plugins, Plugin


class Canary(Plugin):
    """
    Canary is a plugin that listens for "canary" hypercalls and writes a status file.

    **Arguments:**
    - `outdir` (str): Output directory for the canary status file.
    - `verbose` (bool): Enables debug logging if True.
    """

    def __init__(self) -> None:
        """
        Initialize the Canary plugin.

        - Sets up the output directory.
        - Configures logging level if verbose is enabled.
        - Subscribes to the "canary" hypercall.

        **Returns:** None
        """
        self.outdir = self.get_arg("outdir")

        if self.get_arg_bool("penguin_verbose"):
            self.logger.setLevel("DEBUG")

    @plugins.SendHypercall.subscribe("canary")
    def cmd_canary(self, status: int) -> tuple[int, str]:
        """
        Handle a canary status event and write the status to a file if appropriate.

        **Parameters:**
        - `status` (int): The canary status value received.

        **Returns:**
        - `(int, str)`: Tuple containing status code (0 for success) and an empty string.
        """
        path = os.path.join(self.outdir, "canary.txt")
        self.logger.debug(f"Received canary status {status}")
        if int(status) == 0:
            with open(path, "w") as f:
                f.write("1")
        return 0, ""
