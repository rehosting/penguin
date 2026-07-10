"""
FetchWeb integration test plugin.

Subscribes to the same VPN on_bind events as fetch_web and verifies that:
    - fetch_web creates an output file for each web service
    - Each output file has non-zero content

Arguments:
    - outdir (str): Output directory shared with fetch_web.
    - cmd_on_bind_marker (str, optional): Path to a marker file that cmd_on_bind (host mode)
                                           is expected to create on the host filesystem.
                                           Supports three path formats:
                                           1. Relative to project root: 'hello.txt' or 'scripts/output.txt'
                                           2. Relative to results dir: 'results/marker.txt'
                                           3. Absolute path: '/host_PROJECT/file.txt'
    - cmd_on_bind_guest_output_contains (list, optional): List of strings that should appear in
                                                           guest_commands_output.txt file.
                                                           Example: ['root', 'uid=0']
    - cmd_wait_timeout (int, optional): Seconds to wait for cmd_on_bind commands to complete
                                        before checking results. Default: 30

"""

from penguin import plugins, Plugin
from os.path import join, exists
import threading
import time


class FetchWebTest(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.cmd_on_bind_marker = self.get_arg("cmd_on_bind_marker")
        self.cmd_on_bind_guest_output_contains = self.get_arg(
            "cmd_on_bind_guest_output_contains")
        self.cmd_wait_timeout = int(self.get_arg("cmd_wait_timeout") or 30)
        self.results = {}
        self.lock = threading.Lock()
        self._threads = []
        plugins.subscribe(plugins.VPN, "on_bind", self.on_bind)

    def on_bind(
            self,
            proto,
            guest_ip,
            guest_port,
            host_port,
            host_ip,
            procname):
        if proto != "tcp" or guest_port not in [80, 443]:
            return
        log_file = join(self.outdir, f"web_{guest_ip}_{guest_port}")
        t = threading.Thread(
            target=self._check_output, args=(
                guest_ip, guest_port, log_file))
        t.daemon = True
        t.start()
        with self.lock:
            self._threads.append(t)

    def _check_output(self, guest_ip, guest_port, log_file, timeout=90):
        """Wait for fetch_web to create the output file, then verify if it has content."""
        key = f"web_{guest_ip}_{guest_port}"
        deadline = time.time() + timeout

        while time.time() < deadline:
            if exists(log_file) or exists(log_file + ".alt"):
                break
            time.sleep(2)

        actual = log_file if exists(log_file) else log_file + ".alt"

        if not exists(actual):
            self.logger.error(
                f"FetchWebTest: {key} - no output file after {timeout}s")
            with self.lock:
                self.results[key] = False
            return

        with open(actual, "rb") as f:
            content = f.read()

        if len(content) > 0:
            self.logger.info(
                f"FetchWebTest: {key} - passed ({len(content)} bytes)")
            with self.lock:
                self.results[key] = True
        else:
            self.logger.error(f"FetchWebTest: {key} - output file is empty")
            with self.lock:
                self.results[key] = False

    def uninit(self):
        for t in self._threads:
            t.join(timeout=10)

        # If checking guest output or host marker, wait for commands to
        # complete
        if self.cmd_on_bind_guest_output_contains or self.cmd_on_bind_marker:
            self.logger.info(
                f"Waiting {self.cmd_wait_timeout} seconds for cmd_on_bind commands to complete...")
            time.sleep(self.cmd_wait_timeout)

        with open(join(self.outdir, "fetch_web_test.txt"), 'w') as f:
            if not self.results:
                self.logger.warning("FetchWebTest: no web services detected")
                f.write("FetchWebTest: no web services detected\n")

            for key, passed in self.results.items():
                result = "passed" if passed else "failed"
                self.logger.info(f"FetchWebTest: {key}: {result}")
                f.write(f"{key}: {result}\n")

            # Check host mode marker file
            if self.cmd_on_bind_marker:
                import os
                marker = self.cmd_on_bind_marker

                # Determine marker file path
                if os.path.isabs(marker):
                    marker_path = marker
                elif marker.startswith('results/'):
                    marker_path = os.path.join(
                        self.outdir, marker.replace(
                            'results/', '', 1))
                else:
                    project_root = os.path.abspath(
                        os.path.join(self.outdir, "../.."))
                    marker_path = os.path.join(project_root, marker)

                self.logger.info(
                    f'FetchWebTest: Checking for host marker at {marker_path}')

                if exists(marker_path):
                    self.logger.info('FetchWebTest: cmd_on_bind (host) passed')
                    f.write("cmd_on_bind_host: passed\n")
                else:
                    self.logger.error(
                        f'FetchWebTest: cmd_on_bind (host) failed - marker not found at {marker_path}')
                    f.write("cmd_on_bind_host: failed\n")

            # Check guest command output contains expected strings
            if self.cmd_on_bind_guest_output_contains:
                guest_output_file = join(
                    self.outdir, "guest_commands_output.txt")
                self.logger.info(
                    f'FetchWebTest: Checking guest output at {guest_output_file}')

                if exists(guest_output_file):
                    with open(guest_output_file, 'r') as gf:
                        content = gf.read()

                    missing_strings = []
                    for expected_str in self.cmd_on_bind_guest_output_contains:
                        if expected_str not in content:
                            missing_strings.append(expected_str)

                    if not missing_strings:
                        self.logger.info(
                            'FetchWebTest: cmd_on_bind (guest) passed - all expected strings found')
                        f.write("cmd_on_bind_guest: passed\n")
                    else:
                        self.logger.error(
                            f'FetchWebTest: cmd_on_bind (guest) failed - missing strings: {missing_strings}')
                        f.write(
                            f"cmd_on_bind_guest: failed (missing: {
                                ', '.join(missing_strings)})\n")
                else:
                    self.logger.error(
                        'FetchWebTest: cmd_on_bind (guest) failed - guest_commands_output.txt not found')
                    f.write("cmd_on_bind_guest: failed (output file not found)\n")
