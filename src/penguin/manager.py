import csv
import os
import signal
import subprocess
import time

from penguin import getColoredLogger

from .common import yaml

SCORE_CATEGORIES = [
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


def calculate_score(result_dir, have_console=True):
    """
    Return a dict of the distinct metrics we care about name: value
    XXX should have a global of how many fields this is

    XXX: We should call into our loaded plugins to calculate
    this score metric! Plugins could raise a fatal error
    or return a dict with names and values
    """
    if not os.path.isfile(os.path.join(result_dir, ".ran")):
        raise RuntimeError(
            f"calculate_score: {result_dir} does not have a .ran file - check logs for error"
        )

    # load config
    with open(f"{result_dir}/core_config.yaml") as f:
        config = yaml.safe_load(f)

    # System Health: execs, sockets, devices
    if not os.path.isfile(os.path.join(result_dir, "health_final.yaml")):
        # Sometimes this file is missing. I can't figure out why. It's related to the unint
        # method not getting called in health/core after a timeout. But I'm not sure why.
        print(f"WARNING: {result_dir}/health_final.yaml not found - cannot check for health")
        return {}

    with open(f"{result_dir}/health_final.yaml") as f:
        health_data = yaml.safe_load(f)

    # Panic or not (inverted so we can maximize)
    panic = False

    # We can only read console output if it's saved to disk
    # (instead of being shown on stdout)
    # if not self.global_state.info['show_output']:

    if not os.path.isfile(f"{result_dir}/console.log"):
        print(f"WARNING: {result_dir}/console.log not found - cannot check for kernel panic")
        have_console = False

    if have_console:
        with open(
            f"{result_dir}/console.log", "r", encoding="utf-8", errors="ignore"
        ) as f:
            for line in f.readlines():
                if "Kernel panic" in line:
                    panic = True
                    break

    # Shell cov: number of lines (minus one) in shell_cov.csv
    with open(f"{result_dir}/shell_cov.csv") as f:
        shell_cov = len(f.readlines()) - 1

    # Coverage: processes, modules, blocks
    if os.path.isfile(f"{result_dir}/coverage.csv"):
        with open(f"{result_dir}/coverage.csv", newline="") as f:
            reader = csv.reader(f)
            # Initialize sets to store unique values and a list for all rows
            processes = set()
            modules = set()
            module_offset_pairs = set()

            for row in reader:
                # Assuming the structure is process, module, offset
                process, module, offset = row
                processes.add(process)
                modules.add(module)
                module_offset_pairs.add((module, offset))

        processes_run = len(processes)
        modules_loaded = len(modules)
        blocks_covered = len(module_offset_pairs)

    else:
        # print(f"WARNING: No coverage.csv found in {result_dir}")
        processes_run = 0
        modules_loaded = 0
        blocks_covered = 0

    score = {
        "execs": health_data["nexecs"],
        "bound_sockets": health_data["nbound_sockets"],
        "devices_accessed": health_data["nuniquedevs"],
        "processes_run": processes_run,
        "modules_loaded": modules_loaded,
        "blocks_covered": blocks_covered,
        "script_lines_covered": shell_cov,
        "nopanic": 1 if not panic else 0,
        "blocked_signals": -len(
            config["blocked_signals"] if "blocked_signals" in config else []
        ),  # Negative because we want to minimize!
    }

    for k in score.keys():
        if k not in SCORE_CATEGORIES:
            raise ValueError(f"BUG: score type {k} is unknown")
    return score


class PandaRunner:
    """
    This class is a gross wrapper around the fact that we want to call penguin_run
    in a subprocess because it might hang/crash (from C code) which would kill
    our python process. From this class we kill the subprocess if it takes too long
    (deadlock) or if it crashes.
    """

    def __init__(self):
        self.logger = getColoredLogger("penguin.run_manager")

    def _send_sigusr1(self, pid):
        try:
            os.killpg(os.getpgpid(pid), signal.SIGUSR1)
            return True
        except ProcessLookupError:
            self.logger.warning(f"Process {pid} not found when trying to send SIGUSR1")
            return False

    def catch_and_forward_sigint(self, p):
        """Install a SIGINT handler that escalates to SIGKILL on repeated Ctrl+C."""
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
        conf_yaml,
        proj_dir,
        out_dir,
        init=None,
        timeout=None,
        show_output=False,
        verbose=False,
    ):
        """
        If init or timeout are set they override config
        """
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
