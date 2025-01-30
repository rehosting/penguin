import os
import subprocess
import threading
import queue
from collections import Counter
import math
import time

from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins


def calculate_entropy(buffer: bytes) -> float:
    byte_counts = Counter(buffer)
    total_bytes = len(buffer)
    entropy = -sum((count / total_bytes) * math.log2(count / total_bytes) for count in byte_counts.values())
    return entropy


class FetchWeb(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.shutdown_after_www = self.get_arg_bool("shutdown_after_www")
        self.shutdown_on_failure = self.get_arg_bool("shutdown_on_failure")
        self.task_queue = queue.Queue()
        plugins.subscribe(plugins.VPN, "on_bind", self.fetchweb_on_bind)
        self.logger = getColoredLogger("plugins.fetch_web")
        self.shutting_down = False

        self.worker_thread = threading.Thread(target=self.worker)
        self.worker_thread.daemon = True
        self.worker_thread.start()
        self.start_time = time.time()

    def fetchweb_on_bind(self, proto, guest_ip, guest_port, host_port, host_ip, procname):
        """
        There was a bind - if it's a web port (80, 443), enqueue the task for fetching the page.
        """
        if self.shutting_down or proto != "tcp" or guest_port not in [80, 443]:
            return

        log_file_name = os.path.join(self.outdir, f"web_{guest_ip}_{guest_port}")
        self.task_queue.put((guest_ip, host_ip, guest_port, host_port, log_file_name))

    def worker(self):
        """
        Worker thread that processes fetch tasks one at a time.
        """
        success = False  # track if we've had a successful response (for quitting)
        first = False  # track if we've had a task yet
        while not self.shutting_down:
            try:
                # Wait for a task, sleeping 5s between every check
                guest_ip, host_ip, guest_port, host_port, log_file_name = self.task_queue.get(timeout=5)
                success = self.fetch(guest_ip, host_ip, guest_port, host_port, log_file_name)
                self.task_queue.task_done()
                first = True

                if success and self.shutdown_after_www:
                    break

            except queue.Empty:
                if first and self.shutdown_on_failure:
                    self.logger.info("No responsive servers found.")
                    break
                # Continue checking for new tasks until we shut down
                continue

        if self.shutdown_after_www or self.shutdown_on_failure:
            self.shutting_down = True
            timestamp = f"{(time.time() - self.start_time):.02f}s"
            self.logger.info(f"Shutting down after fetching {guest_ip}:{guest_port} ({timestamp} after boot)")
            self.panda.end_analysis()

    def fetch(self, guest_ip, host_ip, guest_port, host_port, log_file_name):
        if os.path.isfile(log_file_name):
            log_file_name += ".alt"

        time.sleep(20)  # Give service plenty of time to start
        cmd = ["wget", "-q", f"https://{host_ip}:{host_port}" if guest_port == 443 else f"http://{host_ip}:{host_port}",
               "--no-check-certificate", "-O", log_file_name]
        timestamp = f"{(time.time() - self.start_time):.02f}s"
        try:
            subprocess.check_output(cmd, timeout=30)
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"{timestamp}: Error running wget: {e}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.warning(f"{timestamp}: No response to wget for {host_ip}:{host_port} after 30s")
            return False

        with open(log_file_name, "rb") as f:
            buffer = f.read()
            entropy = calculate_entropy(buffer)
            self.logger.info(f"Service on {guest_ip}:{guest_port} responds with {len(buffer)} bytes, entropy {entropy:.02f}")
        return True
