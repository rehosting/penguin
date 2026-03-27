"""
penguin.manager
===============

Management utilities for running and scoring Penguin emulation experiments.

This module provides functions and classes for calculating experiment scores,
handling subprocess execution and timeouts, and managing Panda emulation runs.

Functions
---------
- calculate_score

Classes
-------
- PandaRunner
"""
import csv
import os
import signal
import subprocess
import time
import logging
from penguin import getColoredLogger
from .common import yaml

logger = getColoredLogger("penguin.manager.calculate_score")

SCORE_CATEGORIES: list[str] = [
    "execs",
    "bound_sockets",
    "devices_accessed",
    "processes_run",
    "modules_loaded",
    "blocks_covered",
    "nopanic",
    "script_lines_covered",
    "blocked_signals",
]


def calculate_score(result_dir: str, have_console: bool = True) -> dict[str, int]:
    """
    Return a dict of the distinct metrics we care about name: value.

    This function loads experiment results and computes a score based on
    various health and coverage metrics. It handles missing or corrupt files
    gracefully by logging warnings and defaulting scores to 0.

    :param result_dir: Directory containing experiment results.
    :param have_console: Whether console output is available.
    :return: Dictionary of score metrics.
    :raises RuntimeError: If the critical .ran file is missing, indicating a failed run.
    """
    # FAIL FAST: This is a critical failure. If .ran isn't there, the results are invalid.
    if not os.path.isfile(os.path.join(result_dir, ".ran")):
        logger.error(
            f"calculate_score: {result_dir} does not have a .ran file - run likely failed."
        )
        return {}

    # --- Initialize all potential score values to 0 ---
    # This ensures we always return a full dictionary.
    config = {}
    health_data = {}
    panic = False
    shell_cov = 0
    processes_run = 0
    modules_loaded = 0
    blocks_covered = 0
    blocked_signals = 0

    # Consistently use try/except for all file parsing.
    # --- Load core_config.yaml ---
    try:
        with open(os.path.join(result_dir, "core_config.yaml")) as f:
            config = yaml.safe_load(f) or {} # Ensure config is a dict even if file is empty
    except FileNotFoundError:
        logger.warning(f"Config file not found in {result_dir}. Cannot determine blocked signals.")
    except yaml.YAMLError as e:
        logger.error(f"Error parsing core_config.yaml in {result_dir}: {e}")

    # --- System Health: execs, sockets, devices ---
    try:
        with open(os.path.join(result_dir, "health_final.yaml")) as f:
            health_data = yaml.safe_load(f) or {} # Ensure health_data is a dict
    except FileNotFoundError:
        # Instead of returning {}, just log a warning and continue. Scores will default to 0.
        logger.warning(f"{result_dir}/health_final.yaml not found - health scores will be 0.")
    except yaml.YAMLError as e:
        logger.error(f"Error parsing health_final.yaml in {result_dir}: {e}")


    # --- Panic or not (nopanic) ---
    console_log_path = os.path.join(result_dir, "console.log")
    if have_console and os.path.isfile(console_log_path):
        try:
            with open(console_log_path, "r", encoding="utf-8", errors="ignore") as f:
                if any("Kernel panic" in line for line in f):
                    panic = True
        except IOError as e:
            logger.error(f"Could not read {console_log_path}: {e}")
    elif have_console:
        logger.warning(f"{console_log_path} not found - cannot check for kernel panic.")

    # --- Shell coverage ---
    shell_cov_path = os.path.join(result_dir, "shell_cov.csv")
    if os.path.isfile(shell_cov_path):
        try:
            with open(shell_cov_path) as f:
                shell_cov = len(f.readlines()) - 1
        except IOError as e:
            logger.error(f"Could not read {shell_cov_path}: {e}")

    # --- Coverage: processes, modules, blocks ---
    coverage_csv_path = os.path.join(result_dir, "coverage.csv")
    if os.path.isfile(coverage_csv_path):
        try:
            with open(coverage_csv_path, newline="") as f:
                reader = csv.reader(f)
                processes, modules, module_offset_pairs = set(), set(), set()
                for i, row in enumerate(reader):
                    # Handle malformed CSV rows gracefully.
                    if len(row) == 3:
                        process, module, offset = row
                        processes.add(process)
                        modules.add(module)
                        module_offset_pairs.add((module, offset))
                    else:
                        logger.warning(f"Skipping malformed row {i+1} in {coverage_csv_path}: {row}")
            processes_run = len(processes)
            modules_loaded = len(modules)
            blocks_covered = len(module_offset_pairs)
        except (IOError, csv.Error) as e:
            logger.error(f"Could not read or parse {coverage_csv_path}: {e}")


    if config:
        blocked_signals = -len(config.get("blocked_signals", []))

    score = {
        "execs": health_data.get("nexecs", 0),
        "bound_sockets": health_data.get("nbound_sockets", 0),
        "devices_accessed": health_data.get("nuniquedevs", 0),
        "processes_run": processes_run,
        "modules_loaded": modules_loaded,
        "blocks_covered": blocks_covered,
        "script_lines_covered": shell_cov,
        "nopanic": 1 if not panic else 0,
        "blocked_signals": blocked_signals,  # Negative because we want to minimize!
    }

    for k in score.keys():
        if k not in SCORE_CATEGORIES:
            raise ValueError(f"BUG: score type {k} is unknown")
    return score


class PandaRunner:
    """
    Wrapper class for running penguin_run in a subprocess.

    This class manages subprocess execution, timeouts, and signal handling
    to ensure robust experiment runs even in the presence of crashes or hangs.
    """

    def __init__(self) -> None:
        """
        Initialize the PandaRunner.
        """
        self.logger = getColoredLogger("penguin.run_manager")

    def _send_sigusr1(self, pid: int) -> bool:
        """
        Send SIGUSR1 to the process group of the given PID.

        :param pid: Process ID.
        :type pid: int
        :return: True if successful, False otherwise.
        :rtype: bool
        """
        try:
            os.killpg(os.getpgid(pid), signal.SIGUSR1)
            return True
        except ProcessLookupError:
            self.logger.warning(f"Process {pid} not found when trying to send SIGUSR1")
            return False

    def catch_and_forward_sigint(self, p: subprocess.Popen) -> None:
        """
        Install a SIGINT handler that escalates to SIGKILL on repeated Ctrl+C.

        :param p: Subprocess to forward signals to.
        :type p: subprocess.Popen
        """
        self._sigint_count = 0

        def handler(signum, frame):
            self._sigint_count += 1
            if self._sigint_count == 1:
                self.logger.warning("SIGINT received, forwarding to subprocess group (Ctrl+C again to force kill)...")
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGINT)
                except Exception as e:
                    self.logger.error(f"Failed to send SIGINT to process group: {e}")
            else:
                self.logger.error("Second SIGINT received, force killing subprocess group!")
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except Exception as e:
                    self.logger.error(f"Failed to send SIGKILL to process group: {e}")
        signal.signal(signal.SIGINT, handler)

    def run(
        self,
        conf_yaml: str,
        proj_dir: str,
        out_dir: str,
        init: str | None = None,
        timeout: int | None = None,
        show_output: bool = False,
        verbose: bool = False,
        resolved_kernel: str | None = None,
    ) -> None:
        """
        Run the penguin emulation experiment in a subprocess.

        :param conf_yaml: Path to configuration YAML file.
        :type conf_yaml: str
        :param proj_dir: Project directory.
        :type proj_dir: str
        :param out_dir: Output directory.
        :type out_dir: str
        :param init: Optional init script.
        :type init: str or None
        :param timeout: Optional timeout in seconds.
        :type timeout: int or None
        :param show_output: Whether to show output.
        :type show_output: bool
        :param verbose: Whether to enable verbose output.
        :type verbose: bool
        :param resolved_kernel: Optional resolved kernel path.
        :type resolved_kernel: str or None

        :raises RuntimeError: If the run was not successful.
        """
        # If init or timeout are set they override config
        # penguin_run will run panda directly which might exit (or crash/hang)
        # and definitely will close stdout/stderr which will break subsequent
        # python prints.
        # So we run it in an isolated process through penguin.penguin_run
        # which is a wrapper to call that script with: run_config(config=argv[1], out=argv[2], qcows=argv[3])

        # Let's call via system instead of subprocess
        timeout_s = None
        timeout_cmd = []

        if timeout:
            # We'll give 3x run time to account for startup and shutdown processing time?
            timeout_s = timeout + 120  # First send singal 2 minutes after timeout
            timeout_ks = 120  # If signal is ignored, kill 2 minutes later
            timeout_cmd = [
                "timeout",
                "-s",
                "SIGUSR1",
                "-k",
                str(timeout_ks),
                str(timeout_s),
            ]

        # SYSTEM() - not my favorite, but we need to kill the subprocess if it hangs.
        # Qemu output goes into out_dir/../qemu_std{out,err}.txt
        # Some initial python output will be returned in the system() call, so let's print it
        # full_cmd = f"{timeout_cmd}python3 -m penguin.penguin_run {conf_yaml} {out_dir} {proj_dir}/qcows"
        # print(system(full_cmd))

        # Python subprocess. No pipe (pipes can get full and deadlock the child!)
        assert os.path.isfile(conf_yaml), f"Config file {conf_yaml} not found"
        cmd = timeout_cmd + [
            "python3",
            "-m",
            "penguin.penguin_run",
            proj_dir,
            conf_yaml,
            out_dir,
        ]

        # CLI arg parsing is gross. Sorry. We add init/None, timeout/None, show/noshow and optionally verbose at the end
        if init:
            cmd.append(init)
        else:
            cmd.append("None")

        if timeout:
            cmd.append(str(timeout))
        else:
            cmd.append("None")

        if show_output:
            cmd.append("show")
        else:
            cmd.append("noshow")

        if verbose:
            cmd.append("verbose")

        # Add resolved kernel if provided to avoid duplicate analysis
        if resolved_kernel:
            cmd.append("--resolved-kernel")
            cmd.append(resolved_kernel)

        start = time.time()
        try:
            # Without stdout argument, the output will be printed to the console - great
            p = subprocess.Popen(cmd, preexec_fn=os.setsid)
            self.catch_and_forward_sigint(p)
            p.wait(timeout=timeout_s + 10 if timeout_s else None)
        except subprocess.TimeoutExpired:
            self.logger.info(
                f"Timeout expired for {conf_yaml} after {timeout_s} seconds"
            )
            self._send_sigusr1(p.pid)
            p.wait(timeout=10)
            if p:
                p.kill()
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Error running {conf_yaml}: {e}")

        elapsed = time.time() - start
        self.logger.info(f"Emulation finishes after {elapsed:.02f} seconds with return code {p.returncode if p else 'N/A'} for {conf_yaml}")

        ran_file = os.path.join(out_dir, ".ran")
        if not os.path.isfile(ran_file):
            self.logger.error(f"Missing .ran file with {conf_yaml}. This likely means the run was not successful.")
            raise RuntimeError(
                f"Missing {out_dir}/.ran after run with config={conf_yaml} proj_dir={proj_dir}"
            )
