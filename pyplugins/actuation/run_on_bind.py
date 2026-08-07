"""
RunOnBind Plugin (run_on_bind.py) for Penguin
=============================================

Executes user-defined host or guest commands when a guest service binds a port that is exposed
to the host by the VPN plugin.

Execution model
---------------

Bind events are filtered, de-duplicated per endpoint, and queued. A single worker thread drains
that queue, so command runs are serialized, two endpoints binding at once can never produce
concurrent `guest_cmd.py` invocations.

An attempt runs every configured command and succeeds if ANY of them does, since configurations
routinely include commands that only apply to some targets. The first successful attempt is the
last: the plugin stops accepting endpoints and, if `shutdown_after_cmd` is set, ends the
analysis. A failed attempt is not terminal -- the next endpoint to bind gets its own try,
uncapped, which keeps a run from wedging when the first endpoint to appear (often a loopback
bind) isn't the one that works.

Every command has a hard timeout, and every command's outcome is recorded whether it passed or failed.

Arguments
---------

- outdir (str): Output directory for command-output artifacts.
- commands (str, list, or dict, REQUIRED): Command(s) to run after a matching bind event.
    Loading the plugin without commands raises at init.

    Supports three formats:

    1. Single string (runs in guest mode by default):
        commands: python3 example.py

    2. List of strings (runs in guest mode by default):
        commands:
            - python3 analyze.py
            - python3 report.py

    3. Structured format with explicit mode specification:
        commands:
            - mode: host
              run:
                  - python3 ./test.py
            - mode: guest
              run:
                  - echo "test" > /tmp/test.txt

    Mixed lists of strings and dictionaries are not supported.

    Mode options:
        - host: Run commands on the host system (inside the container), using the project
          directory penguin supplies as the working directory.
        - guest: Run commands inside the emulated guest via the `guest_cmd.py` wrapper
          (default). Requires `guest_cmd: true` under `core` in config.yaml.

- endpoints (list[str], optional): Guest endpoints that may trigger the commands,
    formatted as `guest_ip:guest_port`. Either component may be `*` to match anything.
    If omitted, any bind event passing the protocol/port filters may trigger.

        Example:
            endpoints:
                - "0.0.0.0:80"
                - "*:8080"

    Prefer a wildcard over an exact IP: an allowlist that never matches means the commands
    never run and nothing ever ends the run.

- ports (list[int], optional): Restrict triggering to these guest ports. Default: any.
- proto (str, optional): Protocol to match. Default: 'tcp'. Use '*' for any.
- delay (int, optional): Delay in seconds after a bind before running commands. Default: 20.
- timeout (int, optional): Per-command timeout in seconds. Default: 120. A command that
    exceeds it is killed and counted as a failure.
- shutdown_after_cmd (bool, optional): If True, end emulation after the first successful run.

Plugin Interface
----------------

- Subscribes to the VPN plugin's 'on_bind' event.
- Writes command output to `<outdir>/run_on_bind_output.txt`, one block per command per attempt, each carrying a `Status:` of SUCCESS or FAILED.
- Exposes `succeeded` (bool) and `attempts` (int) for other plugins or tests to inspect.
"""

import os
import queue
import shlex
import subprocess
import threading
import time
import traceback
from typing import Any, Dict, List, Optional

from pydantic import Field
from penguin import plugins, Plugin, PluginArgs


DEFAULT_DELAY = 20
DEFAULT_TIMEOUT = 120
GUEST_CMD_WRAPPER = "/igloo_static/guesthopper/guest_cmd.py"
VALID_MODES = ("host", "guest")
OUTPUT_FILENAME = "run_on_bind_output.txt"


def normalize_commands(spec: Any) -> List[Dict[str, Any]]:
    """
    Normalize the three supported `commands` formats into a single structured form.

    Args:
        spec: A string, a list of strings, a list of {mode, cmd} dicts, or None.
    Returns:
        list[dict]: Entries of the form {"mode": "host"|"guest", "cmd": [str, ...]}.
        None and empty input map to an empty list; the plugin, not this function, decides
        whether that is an error.
    Raises:
        ValueError: If the spec is malformed or mixes formats.
    """
    if spec is None:
        return []

    if isinstance(spec, str):
        return [{"mode": "guest", "cmd": [spec]}]

    if isinstance(spec, dict):
        spec = [spec]

    if not isinstance(spec, list):
        raise ValueError(f"commands must be a string, list, or structured list, but received: {type(spec).__name__}")

    if not spec:
        return []

    if all(isinstance(entry, str) for entry in spec):
        return [{"mode": "guest", "cmd": [entry]} for entry in spec]

    if not all(isinstance(entry, dict) for entry in spec):
        raise ValueError("commands must be either a list of strings or a list of structured command dictionaries. Mixing formats is not supported.")

    normalized: List[Dict[str, Any]] = []
    for entry in spec:
        mode = entry.get("mode", "guest")
        if mode not in VALID_MODES:
            raise ValueError(f"commands mode must be one of {VALID_MODES}, but received: {mode!r}")

        cmds = entry.get("run")
        if cmds is None:
            raise ValueError(f"commands entry is missing a 'run' key: {entry!r}")
        if isinstance(cmds, str):
            cmds = [cmds]
        if not isinstance(cmds, list) or not all(isinstance(c, str) for c in cmds):
            raise ValueError(f"commands 'run' must be a string or list of strings, but received: {cmds!r}")

        normalized.append({"mode": mode, "cmd": list(cmds)})

    return normalized


def parse_endpoints(entries: Optional[List[str]]) -> List[str]:
    """
    Validate and normalize the `endpoints` allowlist.

    Args:
        entries: List of 'guest_ip:guest_port' strings, where either side may be '*'.
    Returns:
        list[str]: The validated entries.
    Raises:
        ValueError: If any entry is malformed.
    """
    validated: List[str] = []

    for endpoint in entries or []:
        try:
            guest_ip, guest_port = endpoint.rsplit(":", 1)

            if not guest_ip:
                raise ValueError

            if guest_port != "*":
                port = int(guest_port)
                if not 1 <= port <= 65535:
                    raise ValueError

        except (AttributeError, ValueError):
            raise ValueError(f"Each endpoints entry must use 'guest_ip:guest_port' format with a valid port, but received: {endpoint!r}")

        validated.append(endpoint)

    return validated


def endpoint_matches(guest_ip: str, guest_port: int, allowlist: List[str]) -> bool:
    """
    Check a bind event against the endpoint allowlist.

    An empty allowlist matches everything. Either component of an allowlist entry may be '*'.
    """
    if not allowlist:
        return True

    for entry in allowlist:
        allowed_ip, allowed_port = entry.rsplit(":", 1)
        if allowed_ip not in ("*", guest_ip):
            continue
        if allowed_port != "*" and int(allowed_port) != int(guest_port):
            continue
        return True

    return False


class RunOnBind(Plugin):
    class Args(PluginArgs):
        commands: Any = Field(
            ...,
            description="Required. Command(s) to run after bind. Supports string, list, or structured format with mode (host/guest).")
        endpoints: Optional[List[str]] = Field(
            default=None,
            description="Optional list of guest endpoints that may trigger commands, formatted as guest_ip:guest_port ('*' allowed for either side). If unset, any matching bind may trigger.")
        ports: Optional[List[int]] = Field(
            default=None,
            description="Optional list of guest ports that may trigger commands. If unset, any port may trigger.")
        proto: str = Field(
            default="tcp",
            description="Protocol to match on bind events. Use '*' to match any protocol.")
        delay: Optional[int] = Field(
            default=None,
            description="Seconds to wait after a bind before running commands. Defaults to 20 when unset.")
        timeout: Optional[int] = Field(
            default=None,
            description="Per-command timeout in seconds. Defaults to 120 when unset. Prevents an unresponsive guest from hanging the run.")
        shutdown_after_cmd: bool = Field(
            default=False,
            description="If true, end emulation after the first successful command run.")

    def __init__(self) -> None:
        """
        Initialize the RunOnBind plugin, validate configuration, and subscribe to VPN binds.
        """
        self.outdir = self.get_arg("outdir")
        self.shutdown_after_cmd = self.get_arg_bool("shutdown_after_cmd")
        self.proto_filter = self.get_arg("proto") or "tcp"
        self.port_filter = [int(p) for p in (self.get_arg("ports") or [])]
        self.endpoints = parse_endpoints(self.get_arg("endpoints"))
        self.commands = normalize_commands(self.get_arg("commands"))

        self._flat_commands = [
            (entry["mode"], cmd) for entry in self.commands for cmd in entry["cmd"]
        ]

        delay = self.get_arg("delay")
        self.delay = DEFAULT_DELAY if delay is None else int(delay)

        timeout = self.get_arg("timeout")
        self.timeout = DEFAULT_TIMEOUT if timeout is None else int(timeout)

        if not self.commands:
            self.logger.error("RunOnBind requires at least one command; got an empty commands.")
            raise ValueError("commands is required and must contain at least one command")

        # Guest mode requires the guest_cmd wrapper to be enabled.
        if any(entry["mode"] == "guest" for entry in self.commands):
            if not self.get_arg("conf")["core"]["guest_cmd"]:
                self.logger.error("commands with guest mode requires guest_cmd: true in config.yaml")
                raise ValueError("guest_cmd must be enabled for guest mode commands")

        self.host_cwd = self._resolve_host_cwd()

        if self.host_cwd == os.sep and any(e["mode"] == "host" for e in self.commands):
            self.logger.error("Host commands are configured but the host working directory resolved to '/'. Relative paths will not resolve; use absolute paths in your host commands.")

        self._seen_endpoints = set()
        self._lock = threading.Lock()
        self.task_queue = queue.Queue()
        self.shutting_down = False
        self.succeeded = False
        self.attempts = 0
        self.start_time = time.time()

        self.logger.info(
            f"RunOnBind armed with {len(self.commands)} command group(s), "
            f"delay {self.delay}s, timeout {self.timeout}s, "
            f"endpoints={self.endpoints or 'any'}, "
            f"ports={self.port_filter or 'any'}, proto={self.proto_filter}")

        plugins.subscribe(plugins.VPN, "on_bind", self.on_bind_handler)

        self.worker_thread = threading.Thread(target=self.worker, daemon=True)
        self.worker_thread.start()

    def on_bind_handler(
        self,
        proto: str,
        guest_ip: str,
        guest_port: int,
        host_port: int,
        host_ip: str,
        procname: str,
    ) -> None:
        """
        Handle a bind event from the VPN plugin and, if it matches, queue an attempt.

        Args:
            proto (str): Protocol (e.g., 'tcp').
            guest_ip (str): Guest IP address.
            guest_port (int): Guest port.
            host_port (int): Host port mapped to the guest service.
            host_ip (str): Host IP address.
            procname (str): Name of the process binding the port.
        """
        if self.shutting_down or self.succeeded:
            return

        if self.proto_filter != "*" and proto != self.proto_filter:
            return

        if self.port_filter and int(guest_port) not in self.port_filter:
            return

        if not endpoint_matches(guest_ip, guest_port, self.endpoints):
            self.logger.debug(f"Bind on {guest_ip}:{guest_port} does not match endpoints {self.endpoints}; skipping")
            return

        guest_endpoint = f"{guest_ip}:{guest_port}"

        with self._lock:
            if guest_endpoint in self._seen_endpoints:
                self.logger.debug(f"commands already queued for {guest_endpoint}; skipping")
                return
            self._seen_endpoints.add(guest_endpoint)

        self.logger.info(f"Bind detected on {guest_endpoint} ({procname}); queueing commands attempt")
        self.task_queue.put((guest_endpoint, host_ip, host_port, time.time()))

    def worker(self) -> None:
        """
        Drain queued endpoints one at a time, stopping at the first successful run.

        Serializing here is deliberate: concurrent guest_cmd.py invocations against the same
        guest are a reliable way to wedge the emulation.
        """
        while not self.shutting_down and not self.succeeded:
            try:
                guest_endpoint, host_ip, host_port, queued_at = self.task_queue.get(timeout=5)
            except queue.Empty:
                continue

            try:
                self._run_attempt(guest_endpoint, host_ip, host_port, queued_at)
            except Exception as exc:  # never let the worker die silently
                self.logger.warning(f"commands attempt raised: {exc}")
                self.logger.warning(f"Traceback:\n{traceback.format_exc()}")
            finally:
                self.task_queue.task_done()

    def _run_attempt(
        self,
        guest_endpoint: str,
        host_ip: str,
        host_port: int,
        queued_at: float,
    ) -> None:
        """
        Wait out the remaining delay for one endpoint, run the commands, and decide what next.
        """
        remaining = self.delay - (time.time() - queued_at)
        if remaining > 0:
            self.logger.info(
                f"Sleeping {remaining:.01f}s before running commands for {guest_endpoint}")
            time.sleep(remaining)

        if self.shutting_down or self.succeeded:
            self.logger.info(
                f"Run already resolved; skipping commands for {guest_endpoint}")
            return

        self.attempts += 1
        self.logger.info(f"Attempt {self.attempts}: executing {len(self.commands)} command group(s) for {guest_endpoint} (host {host_ip}:{host_port})")

        success = self.run_commands(guest_endpoint)

        if success:
            self.succeeded = True
            timestamp = f"{(time.time() - self.start_time):.02f}s"
            self.logger.info(f"commands succeeded for {guest_endpoint} ({timestamp} after boot)")
            if self.shutdown_after_cmd:
                self.logger.info("Shutting down after successful bind commands")
                self.shutting_down = True
                self.panda.end_analysis()
            return

        self.logger.warning(f"commands failed for {guest_endpoint}; waiting for another endpoint to try")

    def run_commands(self, guest_endpoint: str = "") -> bool:
        """
        Execute every configured command once and report whether any of them succeeded.

        A single success resolves the run. Configurations routinely include commands that
        only apply to some targets, so requiring every one to pass would keep retrying
        endpoints on account of commands that were never going to work.

        Args:
            guest_endpoint (str): Endpoint that triggered this run, for the output artifact.
        Returns:
            bool: True if at least one command succeeded.
        """
        succeeded, failed = [], []

        for mode, cmd in self._flat_commands:
            if mode == "host":
                ok = self._run_host_command(cmd, guest_endpoint)
            else:
                ok = self._run_guest_command(cmd, guest_endpoint)
            (succeeded if ok else failed).append(cmd)

        self.logger.info(
            f"{len(succeeded)}/{len(self._flat_commands)} command(s) succeeded for {guest_endpoint}")
        if failed:
            self.logger.info(f"Command(s) that did not succeed: {failed}")

        return bool(succeeded)

    def _resolve_host_cwd(self) -> str:
        """
        Pick the working directory for host-mode commands.

        Returns:
            str: penguin's `proj_dir` arg, or the process cwd if it is missing or not a
            directory -- in which case relative paths in host commands will not resolve.
        """
        proj_dir = self.get_arg("proj_dir")

        if proj_dir:
            resolved = os.path.abspath(proj_dir)
            if os.path.isdir(resolved):
                self.logger.info(f"Host working directory from proj_dir: {resolved}")
                return resolved
            self.logger.warning(f"proj_dir is set but is not a directory: {resolved}")
        else:
            self.logger.warning("penguin did not supply proj_dir; cannot locate the project root")

        fallback = os.getcwd()
        self.logger.warning(
            "Falling back to the penguin process cwd for host commands: "
            f"{fallback}. Use absolute paths in host commands if they cannot find their files.")
        return fallback

    def _run_host_command(self, cmd: str, guest_endpoint: str = "") -> bool:
        """
        Run a single command on the host, rooted at the resolved project directory.
        """
        self.logger.info(f"Running HOST command: {cmd}")
        try:
            cmd_list = shlex.split(cmd) if isinstance(cmd, str) else cmd

            cwd = self.host_cwd
            if not os.path.isdir(cwd):
                self.logger.warning(f"Host working directory disappeared since startup: {cwd}; re-resolving")
                cwd = self.host_cwd = self._resolve_host_cwd()
            self.logger.info(f"Working directory: {cwd}")

            result = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                check=False,
                cwd=cwd,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Host command exceeded {self.timeout}s and was killed: {cmd}")
            self._record_output("host", cmd, None, "", f"timed out after {self.timeout}s", guest_endpoint)
            return False
        except FileNotFoundError as exc:
            self.logger.warning(f"Host command executable not found: {exc}. Working directory was {self.host_cwd}")
            self._record_output("host", cmd, None, "", str(exc), guest_endpoint)
            return False
        except Exception as exc:
            self.logger.warning(f"Host command execution error: {exc}")
            self.logger.warning(f"Traceback:\n{traceback.format_exc()}")
            self._record_output("host", cmd, None, "", str(exc), guest_endpoint)
            return False

        self.logger.info(f"Host command output:\n{result.stdout}")
        if result.stderr:
            self.logger.warning(f"Host command stderr:\n{result.stderr}")
        if result.returncode != 0:
            self.logger.warning(
                f"Host command failed with code {result.returncode}")

        self._record_output(
            "host", cmd, result.returncode, result.stdout, result.stderr, guest_endpoint)
        return result.returncode == 0

    def _run_guest_command(self, cmd: str, guest_endpoint: str = "") -> bool:
        """
        Run a single command inside the guest via the guest_cmd.py wrapper.

        The command is passed as one argument so the guest shell, not the host, splits it.
        """
        full_cmd = ["python3", GUEST_CMD_WRAPPER, cmd]
        self.logger.info(f"Running GUEST command: {cmd}")
        try:
            result = subprocess.run(
                full_cmd,
                capture_output=True,
                text=True,
                check=False,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Guest command exceeded {self.timeout}s and was killed: {cmd}")
            self._record_output("guest", cmd, None, "", f"timed out after {self.timeout}s", guest_endpoint)
            return False
        except Exception as exc:
            self.logger.warning(f"Guest command execution error: {exc}")
            self.logger.warning(f"Traceback:\n{traceback.format_exc()}")
            self._record_output("guest", cmd, None, "", str(exc), guest_endpoint)
            return False

        self.logger.info(f"Guest command output:\n{result.stdout}")
        if result.stderr:
            self.logger.warning(f"Guest command stderr:\n{result.stderr}")
        if result.returncode != 0:
            self.logger.warning(
                f"Guest command failed with code {result.returncode}")

        self._record_output("guest", cmd, result.returncode, result.stdout, result.stderr, guest_endpoint)
        return result.returncode == 0

    def _record_output(
        self,
        mode: str,
        cmd: str,
        returncode: Optional[int],
        stdout: str,
        stderr: str,
        guest_endpoint: str = "",
    ) -> None:
        """
        Append a command's result to the shared output artifact for the Verifier to inspect.
        """
        output_file = os.path.join(self.outdir, OUTPUT_FILENAME)
        try:
            with open(output_file, "a") as f:
                f.write(f"\n{'=' * 60}\n")
                f.write(f"Endpoint: {guest_endpoint or 'unknown'}\n")
                f.write(f"Attempt: {self.attempts}\n")
                f.write(f"Mode: {mode}\n")
                f.write(f"Command: {cmd}\n")
                f.write(f"Status: {'SUCCESS' if returncode == 0 else 'FAILED'}\n")
                f.write(f"Return code: {returncode}\n")
                f.write(f"{'=' * 60}\n")
                f.write(f"STDOUT:\n{stdout}\n")
                if stderr:
                    f.write(f"STDERR:\n{stderr}\n")
        except OSError as exc:
            self.logger.warning(f"Could not write command output artifact: {exc}")
            return

        self.logger.info(f"Command output appended to: {output_file}")
