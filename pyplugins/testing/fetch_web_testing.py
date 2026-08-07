"""
FetchWeb integration test plugin.

Subscribes to the same VPN on_bind events as fetch_web and verifies that:
    - fetch_web creates an output file for each web service
    - Each output file has non-zero content

Bind-triggered command execution moved to the run_on_bind plugin; see run_on_bind_testing
for the checks that cover it.

Arguments:
    - outdir (str): Output directory shared with fetch_web.
"""

from penguin import plugins, Plugin
from os.path import join, exists
import threading
import time


class FetchWebTest(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
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

        with open(join(self.outdir, "fetch_web_test.txt"), 'w') as f:
            if not self.results:
                self.logger.warning("FetchWebTest: no web services detected")
                f.write("FetchWebTest: no web services detected\n")

            for key, passed in self.results.items():
                result = "passed" if passed else "failed"
                self.logger.info(f"FetchWebTest: {key}: {result}")
                f.write(f"{key}: {result}\n")
