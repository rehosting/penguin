"""
FetchWeb Plugin (fetch_web.py) for Penguin
==========================================

This module provides the FetchWeb plugin, which automatically fetches web pages from guest services
exposed to the host (typically on ports 80 and 443) via the VPN plugin. It listens for 'on_bind' events
published by the VPN plugin and attempts to retrieve web content from the corresponding host ports.
The plugin is responsible for:

- Subscribing to VPN 'on_bind' events to detect new web services exposed to the host.
- Enqueuing fetch tasks for HTTP/HTTPS ports (80, 443) and processing them in a worker thread.
- Fetching web content using wget and logging the response size and entropy.
- Optionally shutting down the emulation after a successful fetch or after failure, based on arguments.

Arguments
---------

- outdir (str): Output directory for storing fetched web content.
- shutdown_after_www (bool, optional): If True, shut down emulation after a successful fetch.
- shutdown_on_failure (bool, optional): If True, shut down emulation if no responsive servers are found.
- shutdown_after_cmd (bool, optional): If True, shut down emulation after cmd_on_bind commands complete.
- fetch_delay (int, optional): Delay in seconds before fetching/running commands after bind. Default: 20.
- cmd_on_bind (str, list, or dict, optional): Command(s) to run after bind-triggered fetch.
    Supports three formats:

    1. Single string (runs in guest mode by default):
        cmd_on_bind: python3 example.py

    2. List of strings (runs in guest mode by default):
        cmd_on_bind:
            - python3 analyze.py
            - python3 report.py

    3. Structured format with explicit mode specification:
        cmd_on_bind:
            - mode: host
              cmd:
                  - python3 ./exploit.py
            - mode: guest
              cmd:
                  - echo "test" > /tmp/test.txt

    Mode options:
        - host: Run command on the host system (inside container, working directory is project root)
        - guest: Run command inside the emulated guest system via guest_cmd.py (DEFAULT)

    Note: If mode is not specified, defaults to 'guest'. Guest mode requires guest_cmd: true in config.yaml core settings.

Plugin Interface
----------------

- Subscribes to the VPN plugin's 'on_bind' event to trigger web fetches.
- Does not provide a direct interface for other plugins, but writes fetched content to files in the output directory.

Overall Purpose
---------------

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
from typing import Optional, Any
from pydantic import Field
from penguin import plugins, Plugin, PluginArgs
import shlex


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
    entropy = -sum(
        (count / total_bytes) * math.log2(count / total_bytes)
        for count in byte_counts.values()
    )
    return entropy


class FetchWeb(Plugin):
    class Args(PluginArgs):
        fetch_delay: Optional[int] = Field(
            default=None, description="Seconds to wait before fetching a newly bound web service. Defaults to 20 when unset."
        )
        shutdown_after_www: bool = Field(
            default=False, description="If true, shut down emulation after a successful web fetch."
        )
        shutdown_on_failure: bool = Field(
            default=False, description="If true, shut down emulation if no responsive servers are found."
        )
        shutdown_after_cmd: bool = Field(
            default=False, description="If true, shut down emulation after cmd_on_bind commands complete."
        )
        cmd_on_bind: Optional[Any] = Field(
            default=None, description="Command(s) to run after bind. Supports string, list, or structured format with mode (host/guest)."
        )

    def __init__(self) -> None:
        """
        Initialize the FetchWeb plugin, subscribe to VPN on_bind events, and set up state.
        """
        self.outdir = self.get_arg("outdir")
        self.shutdown_after_www = self.get_arg_bool("shutdown_after_www")
        self.shutdown_on_failure = self.get_arg_bool("shutdown_on_failure")
        self.shutdown_after_cmd = self.get_arg_bool("shutdown_after_cmd")

        # Parse cmd_on_bind properly
        self.cmd_on_bind = self.get_arg("cmd_on_bind")

        if self.cmd_on_bind is not None:
            # Check if it's list of dicts with mode/cmd
            if isinstance(self.cmd_on_bind, list) and len(self.cmd_on_bind) > 0:
                if isinstance(self.cmd_on_bind[0], dict):
                    self.cmd_on_bind_structured = self.cmd_on_bind
                    self.logger.info(
                        "Using structured cmd_on_bind with mode specification"
                    )
                else:
                    # List of strings (backward compatibility)
                    self.cmd_on_bind_structured = [
                        {"mode": "guest", "cmd": [str(c)]} for c in self.cmd_on_bind
                    ]
                    self.logger.info("Converting legacy cmd_on_bind format")
            elif isinstance(self.cmd_on_bind, str):
                # Single string command (backward compatibility)
                self.cmd_on_bind_structured = [
                    {"mode": "guest", "cmd": [str(self.cmd_on_bind)]}
                ]
                self.logger.info("Converting single string cmd_on_bind")
            else:
                self.cmd_on_bind_structured = []

            # Guest-cmd must be enabled if any guest commands exist
            has_guest_cmds = any(
                entry.get("mode") == "guest" for entry in self.cmd_on_bind_structured
            )
            if has_guest_cmds and not self.get_arg("conf")["core"]["guest_cmd"]:
                self.logger.error(
                    "cmd_on_bind with guest mode requires guest_cmd: true in config.yaml"
                )
                raise ValueError("guest_cmd must be enabled for guest mode commands")
        else:
            self.cmd_on_bind_structured = []

        if delay := self.get_arg("fetch_delay"):
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

    def fetchweb_on_bind(
        self,
        proto: str,
        guest_ip: str,
        guest_port: int,
        host_port: int,
        host_ip: str,
        procname: str,
    ) -> None:
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

        if self.shutting_down or proto != "tcp" or guest_port not in [80, 443]:
            return

        # Only trigger cmd_on_bind for 0.0.0.0 to avoid running commands multiple times
        if self.cmd_on_bind_structured and guest_ip == "0.0.0.0":
            self.logger.info(
                f"Bind detected on {guest_ip}:{guest_port}, spawning cmd_on_bind thread"
            )
            t = threading.Thread(
                target=self._delayed_bind_workflow, args=(guest_ip, guest_port)
            )
            t.daemon = True
            t.start()

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
                guest_ip, host_ip, guest_port, host_port, log_file_name = (
                    self.task_queue.get(timeout=5)
                )
                success = self.fetch(
                    guest_ip, host_ip, guest_port, host_port, log_file_name
                )
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
            self.logger.info(
                f"Shutting down after fetching {guest_ip}:{guest_port} ({timestamp} after boot)"
            )
            self.panda.end_analysis()

    def _run_on_bind_command(self) -> bool:
        """Execute the commands supplied via cmd_on_bind.

        Returns:
            bool: True if all commands succeeded, False otherwise.
        """
        overall_success = True

        for entry in self.cmd_on_bind_structured:
            mode = entry.get("mode", "guest")
            cmds = entry.get("cmd", [])

            # Normalize to list if single command
            if isinstance(cmds, str):
                cmds = [cmds]

            for cmd in cmds:
                if mode == "host":
                    # Run on host directly
                    self.logger.info(f"Running HOST command: {cmd}")
                    try:
                        # Split the command string into a list for subprocess
                        cmd_list = shlex.split(cmd) if isinstance(cmd, str) else cmd

                        # Determine working directory for host mode
                        if self.outdir:
                            cwd = os.path.abspath(os.path.join(self.outdir, "../.."))
                            self.logger.info(f"Derived project root from outdir: {cwd}")
                            if not os.path.isdir(cwd):
                                self.logger.warning(
                                    f"Project root does not exist: {cwd}"
                                )
                                cwd = os.getcwd()
                        else:
                            cwd = os.getcwd()

                        self.logger.info(f"Working directory: {cwd}")

                        result = subprocess.run(
                            cmd_list,
                            capture_output=True,
                            text=True,
                            check=False,
                            cwd=cwd,
                        )
                        self.logger.info(f"Host command output:\n{result.stdout}")
                        if result.stderr:
                            self.logger.warning(
                                f"Host command stderr:\n{result.stderr}"
                            )
                        if result.returncode != 0:
                            self.logger.warning(
                                f"Host command failed with code {result.returncode}"
                            )
                            overall_success = False
                    except Exception as exc:
                        import traceback

                        self.logger.warning(f"Host command execution error: {exc}")
                        self.logger.warning(f"Traceback:\n{traceback.format_exc()}")
                        overall_success = False

                elif mode == "guest":
                    # Run in guest via guest_cmd.py wrapper
                    # Pass the command as a single string to guest_cmd.py, don't split it
                    full_cmd = [
                        "python3",
                        "/igloo_static/guesthopper/guest_cmd.py",
                        cmd  # Pass as single argument
                    ]
                    self.logger.info(f"Running GUEST command: {cmd}")
                    try:
                        result = subprocess.run(
                            full_cmd,
                            capture_output=True,
                            text=True,
                            check=False,
                        )
                        self.logger.info(f"Guest command output:\n{result.stdout}")
                        if result.stderr:
                            self.logger.warning(
                                f"Guest command stderr:\n{result.stderr}"
                            )
                        if result.returncode != 0:
                            self.logger.warning(
                                f"Guest command failed with code {result.returncode}"
                            )
                            overall_success = False
                        
                        # Append guest command output to a single file
                        output_file = os.path.join(self.outdir, "guest_commands_output.txt")
                        with open(output_file, 'a') as f:
                            f.write(f"\n{'='*60}\n")
                            f.write(f"Command: {cmd}\n")
                            f.write(f"Return code: {result.returncode}\n")
                            f.write(f"{'='*60}\n")
                            f.write(f"STDOUT:\n{result.stdout}\n")
                            if result.stderr:
                                f.write(f"STDERR:\n{result.stderr}\n")
                        self.logger.info(f"Guest command output appended to: {output_file}")
                        
                    except Exception as exc:
                        self.logger.warning(f"Guest command execution error: {exc}")
                        overall_success = False
                else:
                    self.logger.error(
                        f"Unknown mode '{mode}' - must be 'host' or 'guest'"
                    )
                    overall_success = False

        return overall_success

    def _delayed_bind_workflow(self, guest_ip: str, guest_port: int) -> None:
        """Execute cmd_on_bind commands after a delay"""
        self.logger.info(f"cmd_on_bind thread started for {guest_ip}:{guest_port}")
        self.logger.info(f"Sleeping {self.fetch_delay}s before running commands")

        time.sleep(self.fetch_delay)

        self.logger.info(
            f"Woke up, executing {len(self.cmd_on_bind_structured)} command groups"
        )

        success = self._run_on_bind_command()

        if success and self.shutdown_after_cmd:
            self.logger.info("Shutting down after bind commands")
            self.shutting_down = True
            self.panda.end_analysis()

    def fetch(
        self,
        guest_ip: str,
        host_ip: str,
        guest_port: int,
        host_port: int,
        log_file_name: str,
    ) -> bool:
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
        cmd = [
            "wget",
            "-q",
            (
                f"https://{host_ip}:{host_port}"
                if guest_port == 443
                else f"http://{host_ip}:{host_port}"
            ),
            "--no-check-certificate",
            "-O",
            log_file_name,
        ]
        timestamp = f"{(time.time() - self.start_time):.02f}s"
        try:
            subprocess.check_output(cmd, timeout=30)
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"{timestamp}: Error running wget: {e}")
            return False
        except subprocess.TimeoutExpired:
            self.logger.warning(
                f"{timestamp}: No response to wget for {host_ip}:{host_port} after 30s"
            )
            return False

        with open(log_file_name, "rb") as f:
            buffer = f.read()
            entropy = calculate_entropy(buffer)
            self.logger.info(
                f"Service on {guest_ip}:{guest_port} responds with {len(buffer)} bytes, entropy {entropy:.02f}"
            )
        return True
