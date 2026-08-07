"""
RunOnBind integration test plugin.

Verifies that run_on_bind actually executed its configured commands, by checking the
side effects those commands were supposed to produce:

    - A marker file created on the host filesystem by a host-mode command.
    - Expected strings appearing in run_on_bind's output artifact.

Both checks are optional; configure whichever the commands under test produce.

Arguments:
    - outdir (str): Output directory shared with run_on_bind.
    - host_marker (str, optional): Path to a file a host-mode command is expected to
        create. Three formats:
            1. Relative to the project root: 'hello.txt' or 'scripts/output.txt'
            2. Relative to the results dir:  'results/marker.txt'
            3. Absolute:                     '/host_PROJECT/file.txt'
        Relative paths resolve against penguin's `proj_dir`, which is the working
        directory run_on_bind gives host commands, so a command writing 'hello.txt'
        lands where this plugin looks for it.
    - output_contains (list[str], optional): Strings expected in run_on_bind_output.txt.
        Example: ['root', 'uid=0']
    - wait_timeout (int, optional): Seconds to wait for each expected file to appear
        before declaring it missing. Default: 30.

Writes results to `<outdir>/run_on_bind_test.txt`.
"""

import os
import time
from os.path import join, exists

from penguin import Plugin


OUTPUT_FILENAME = "run_on_bind_output.txt"
RESULTS_FILENAME = "run_on_bind_test.txt"
DEFAULT_WAIT_TIMEOUT = 30


class RunOnBindTest(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.host_marker = self.get_arg("host_marker")
        self.output_contains = self.get_arg("output_contains") or []

        if not isinstance(self.output_contains, list):
            raise ValueError("output_contains must be a list of strings.")

        if not all(isinstance(entry, str) for entry in self.output_contains):
            raise ValueError("output_contains must contain only strings.")

        self.wait_timeout = int(self.get_arg("wait_timeout") or DEFAULT_WAIT_TIMEOUT)

    def _resolve_marker_path(self):
        """
        Resolve the configured marker into an absolute path.

        Relative paths resolve against `proj_dir` -- the same directory run_on_bind runs
        host commands in -- so that a command writing a relative path and this check agree
        on where the file lands.
        """
        marker = self.host_marker

        if os.path.isabs(marker):
            return marker

        if marker.startswith("results/"):
            return join(self.outdir, marker.replace("results/", "", 1))

        return join(self.get_arg("proj_dir") or os.getcwd(), marker)

    def _wait_for(self, path):
        """Poll for a path until it exists or wait_timeout elapses."""
        deadline = time.time() + self.wait_timeout
        while time.time() < deadline:
            if exists(path):
                return True
            time.sleep(1)
        return exists(path)

    def _check_marker(self, f):
        marker_path = self._resolve_marker_path()
        self.logger.info(f"RunOnBindTest: checking for host marker at {marker_path}")

        if self._wait_for(marker_path):
            self.logger.info("RunOnBindTest: host marker passed")
            f.write("host_marker: passed\n")
        else:
            self.logger.error(
                f"RunOnBindTest: host marker failed - not found at {marker_path} "
                f"after {self.wait_timeout}s")
            f.write("host_marker: failed\n")

    def _check_output_contains(self, f):
        output_file = join(self.outdir, OUTPUT_FILENAME)
        self.logger.info(f"RunOnBindTest: checking command output at {output_file}")

        if not self._wait_for(output_file):
            self.logger.error(
                f"RunOnBindTest: output check failed - {OUTPUT_FILENAME} not found")
            f.write("output_contains: failed (output file not found)\n")
            return

        with open(output_file, "r") as of:
            content = of.read()

        missing = [s for s in self.output_contains if s not in content]

        if missing:
            self.logger.error(
                f"RunOnBindTest: output check failed - missing strings: {missing}")
            f.write(f"output_contains: failed (missing: {', '.join(missing)})\n")
        else:
            self.logger.info("RunOnBindTest: output check passed")
            f.write("output_contains: passed\n")

    def uninit(self):
        if not self.host_marker and not self.output_contains:
            self.logger.warning("RunOnBindTest: nothing configured to check")

        with open(join(self.outdir, RESULTS_FILENAME), "w") as f:
            if self.host_marker:
                self._check_marker(f)

            if self.output_contains:
                self._check_output_contains(f)
