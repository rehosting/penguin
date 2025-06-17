"""
fetch_web.py - FetchWeb Plugin for Penguin/Cleanguin

This module provides the FetchWeb plugin, which automatically fetches web pages from guest services
exposed to the host (typically on ports 80 and 443) via the VPN plugin. It listens for 'on_bind' events
published by the VPN plugin and attempts to retrieve web content from the corresponding host ports.
The plugin is responsible for:

- Subscribing to VPN 'on_bind' events to detect new web services exposed to the host.
- Enqueuing fetch tasks for HTTP/HTTPS ports (80, 443) and processing them in a worker thread.
- Fetching web content using wget and logging the response size and entropy.
- Optionally shutting down the emulation after a successful fetch or after failure, based on arguments.

Arguments:
    outdir (str): Output directory for storing fetched web content.
    shutdown_after_www (bool, optional): If True, shut down emulation after a successful fetch.
    shutdown_on_failure (bool, optional): If True, shut down emulation if no responsive servers are found.

Plugin Interface:
    - Subscribes to the VPN plugin's 'on_bind' event to trigger web fetches.
    - Does not provide a direct interface for other plugins, but writes fetched content to files in the output directory.

Overall Purpose:
    The FetchWeb plugin automates the retrieval and analysis of web content from guest services exposed to the host,
    aiding in service validation and content inspection during emulation.
"""

import os
import subprocess
import threading
import queue
from collections import Counter
import math
import time
from penguin import plugins, Plugin


def calculate_entropy(buffer: bytes) -> float:
    """
    Calculate the Shannon entropy of a byte buffer.

    Args:
        buffer (bytes): The data buffer to analyze.
    Returns:
        float: The calculated entropy value.
    """
    byte_counts = Counter(buffer)
    total_bytes = len(buffer)
    entropy = -sum((count / total_bytes) * math.log2(count / total_bytes) for count in byte_counts.values())
    return entropy


class FetchWeb(Plugin):
    def __init__(self) -> None:
        """
        Initialize the FetchWeb plugin, subscribe to VPN on_bind events, and set up state.
        """
        self.outdir = self.get_arg("outdir")
        self.shutdown_after_www = self.get_arg_bool("shutdown_after_www")
        self.shutdown_on_failure = self.get_arg_bool("shutdown_on_failure")
        self.logger = getColoredLogger("plugins.fetch_web")
        if (delay := self.get_arg("fetch_delay")):
            self.fetch_delay = int(delay)
            self.logger.info(f"Fetch delay set to {self.fetch_delay} seconds")
        else:
            self.fetch_delay = 20
        self.task_queue = queue.Queue()
        plugins.subscribe(plugins.VPN, "on_bind", self.fetchweb_on_bind)
        self.shutting_down = False

        self.worker_thread = threading.Thread(target=self.worker)
        self.worker_thread.daemon = True
        self.worker_thread.start()
        self.start_time = time.time()

    def fetchweb_on_bind(self, proto: str, guest_ip: str, guest_port: int, host_port: int, host_ip: str, procname: str) -> None:
        """
        Handle a new bind event from the VPN plugin and enqueue a fetch task for web ports.

        Args:
            proto (str): Protocol (e.g., 'tcp').
            guest_ip (str): Guest IP address.
            guest_port (int): Guest port.
            host_port (int): Host port mapped to the guest service.
            host_ip (str): Host IP address.
            procname (str): Name of the process binding the port.
        """
        """
        There was a bind - if it's a web port (80, 443), enqueue the task for fetching the page.
        """
        if self.shutting_down or proto != "tcp" or guest_port not in [80, 443]:
            return

        log_file_name = os.path.join(self.outdir, f"web_{guest_ip}_{guest_port}")
        self.task_queue.put((guest_ip, host_ip, guest_port, host_port, log_file_name))

    def worker(self) -> None:
        """
        Worker thread that processes fetch tasks from the queue.
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

    def fetch(self, guest_ip: str, host_ip: str, guest_port: int, host_port: int, log_file_name: str) -> bool:
        """
        Fetch web content from the specified host port and log the response.

        Args:
            guest_ip (str): Guest IP address.
            host_ip (str): Host IP address.
            guest_port (int): Guest port.
            host_port (int): Host port.
            log_file_name (str): Path to the file for storing fetched content.
        Returns:
            bool: True if fetch was successful, False otherwise.
        """
        if os.path.isfile(log_file_name):
            log_file_name += ".alt"

        time.sleep(self.fetch_delay)  # Give service plenty of time to start
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
