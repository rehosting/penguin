import os
import signal
import threading
import time
from copy import deepcopy

from pandare2 import PyPlugin

from penguin import getColoredLogger
from penguin.defaults import vnc_password

try:
    from penguin import yaml
    from penguin.analyses import PenguinAnalysis
    from penguin.graphs import Configuration, Mitigation
except ImportError:
    # We can still run as a PyPlugin, but we can't do post-run analysis
    import yaml

    PenguinAnalysis = object


class Core(PyPlugin):
    """
    Simple sanity checks and basic core logic.
    Also provides a callback on hypercall events for open/openat calls.

    1) Validate we're getting the expected args.
    2) Write config and loaded plugins to output dir
    3) On siguser1 gracefully shutdown emulation
    4) After a (non-crash) shutdown, create a .ran file in the output
       if and only if there's no kernel crash in console.log.

    TODO: can we detect if another pyplugin raised an uncaught
    exception and abort?
    """

    def __init__(self, panda):
        for arg in "plugins conf fs fw outdir".split():
            if not self.get_arg(arg):
                raise ValueError(f"[core] Missing required argument: {arg}")

        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.pending_procname = None
        self.pending_sin_addr = None

        self.logger = getColoredLogger("plugins.core")

        plugins = self.get_arg("plugins")
        conf = self.get_arg("conf")

        telnet_port = self.get_arg("telnet_port")

        # If we have an option of root_shell we need to add ROOT_SHELL=1 into env
        # so that the init script knows to start a root shell
        if conf["core"].get("root_shell", False):
            conf["env"]["ROOT_SHELL"] = "1"
            # Print port info
            if container_ip := os.environ.get("CONTAINER_IP", None):
                self.logger.info(
                    f"Root shell will be available at: {container_ip}:{telnet_port}"
                )
                if telnet_port == 23:
                    self.logger.info(f"Connect with: telnet {container_ip}")
                else:
                    self.logger.info(
                        f"Connect with: telnet {container_ip} {telnet_port}"
                    )
            elif container_name := os.environ.get("CONTAINER_NAME", None):
                self.logger.info(
                    f"Root shell will be available in container {container_name} on port {telnet_port}"
                )
                if telnet_port == 23:
                    self.logger.info(
                        f"Connect with: docker exec -it {container_name} telnet localhost"
                    )
                else:
                    self.logger.info(
                        f"Connect with: docker exec -it {container_name} telnet localhost {telnet_port}"
                    )
            else:
                self.logger.info(
                    f"Root shell enabled. Connect with docker exec -it [your_container_name] telnet localhost {telnet_port}"
                )

        if conf["core"].get("graphics", False):
            if container_ip := os.environ.get("CONTAINER_IP", None):
                self.logger.info(
                    f"VNC @ {container_ip}:5900 with password '{vnc_password}'"
                )

        # Same thing, but for a shared directory
        if conf["core"].get("shared_dir", False):
            conf["env"]["SHARED_DIR"] = "1"

        if conf["core"].get("strace", False) is True:
            conf["env"]["STRACE"] = "1"

        if conf["core"].get("ltrace", False) is True:
            conf["env"]["IGLOO_LTRACE"] = "1"

        if conf["core"].get("force_www", False):
            if conf.get("static_files", {}).get("/igloo/utils/www_cmds", None) is None:
                self.logger.warning(
                    "Force WWW unavailable - no webservers were statically identified (/igloo/utils/www_cmds is empty)"
                )
            else:
                conf["env"]["WWW"] = "1"

        # Add PROJ_NAME into env based on dirname of config
        if proj_name := self.get_arg("proj_name"):
            conf["env"]["PROJ_NAME"] = proj_name

        # Record loaded plugins
        with open(os.path.join(self.outdir, "core_plugins.yaml"), "w") as f:
            f.write(yaml.dump(plugins))  # Names and args

        # Record config in outdir:
        with open(os.path.join(self.outdir, "core_config.yaml"), "w") as f:
            f.write(yaml.dump(self.get_arg("conf")))

        signal.signal(signal.SIGUSR1, self.graceful_shutdown)

        # Load the "timeout" plugin which is a misnomer - it's just going
        # to report the number of blocks executed at shutdown.
        # XXX bb_limit / unique_bbs break our pypanda based analyses
        # because end_analysis is never called

        if self.get_arg("timeout") is not None:
            # If a timeout is provided, enforce it
            timeout = int(self.get_arg("timeout"))

            # Not supported in ng.
            # Simple plugin that just counts the number of blocks executed
            # Log info on how many blocks get executed
            # log_path = self.outdir + "/core_shutdown.csv"
            # panda.load_plugin(
            #     "timeout",
            #     {
            #         # "bb_limit": BB_MAX,
            #         # 'unique_bbs': UNIQUE,
            #         "log": log_path
            #     },
            # )

            self.shutdown_event = threading.Event()
            self.shutdown_thread = threading.Thread(
                target=self.shutdown_after_timeout,
                args=(panda, timeout, self.shutdown_event),
            )
            self.shutdown_thread.start()

    def shutdown_after_timeout(self, panda, timeout, shutdown_event):
        wait_time = 0
        while wait_time < timeout:
            # Check if the event is set
            if shutdown_event.is_set():
                try:
                    self.logger.warning(
                        "Shutdown thread: Guest shutdown detected, exiting thread."
                    )
                except OSError:
                    pass  # Can't print but it's not important
                return

            # Sleep briefly
            time.sleep(1)
            wait_time += 1

        try:
            self.logger.warning(
                f"Shutdown thread: execution timed out after {timeout}s - shutting down guest"
            )
        except OSError:
            # During shutdown, stdout might be closed!
            pass

        open(os.path.join(self.outdir, ".ran"), "w").close()

        # Unload all plugins explicitly before ending analysis
        # to ensure our unint methods are called
        panda.unload_plugins()
        time.sleep(1)

        panda.end_analysis()

    def graceful_shutdown(self, sig, frame):
        self.logger.info("Caught SIGUSR1 - gracefully shutdown emulation")
        open(os.path.join(self.outdir, ".ran"), "w").close()
        self.uninit()  # explicitly call uninit?
        self.panda.end_analysis()

    def uninit(self):
        # Create .ran
        open(os.path.join(self.outdir, ".ran"), "w").close()

        if hasattr(self, "shutdown_event") and not self.shutdown_event.is_set():
            # Tell the shutdown thread to exit if it was started
            self.shutdown_event.set()


class CoreAnalysis(PenguinAnalysis):
    ANALYSIS_TYPE = "core"
    VERSION = "1.0.0"

    def parse_failures(self, output_dir):
        """
        We don't really parse failures mitigations, we just make sure there's no python
        errors during our analysis.

        XXX Manager ads a failure of type 'core' IFF no other failures are detected
        and execution was terminated early. In htis case, we mitigate by adding a no-op
        extend option to the config - this increases depth which increases the timeout.
        """
        # First: sanity checks. Do we see any errors in console.log? If so abort
        with open(os.path.join(output_dir, "console.log"), "rb") as f:
            for line in f:
                if b" BUG " in line:
                    print(f"KERNEL BUG: {repr(line)}")
                    raise RuntimeError(
                        f"Found BUG in {output_dir}/console.log")

        # qemu logs are above output directory
        stderr = os.path.join(os.path.dirname(output_dir), "qemu_stderr.txt")
        if os.path.isfile(stderr):
            with open(stderr) as f:
                for line in f.readlines():
                    if "Traceback " in line:
                        raise RuntimeError(
                            f"Python analysis crashed in {output_dir}")
        else:
            print(f"WARNING missing {stderr}")
        return {}

    def get_mitigations_from_static(self, varname, values):
        return []

    def get_potential_mitigations(self, config, failure):
        # If there's a failure named 'truncation', we'll propose a mitigateion of "extend"
        if failure.friendly_name == "truncation":
            return [
                Mitigation(
                    "extend",
                    self.ANALYSIS_TYPE,
                    {"duration": failure.info["truncated"]},
                    failure_name=failure.friendly_name,
                )
            ]

    def implement_mitigation(self, config, failure, mitigation):
        new_config = deepcopy(config.info)
        # How many seconds were truncated?
        how_truncated = mitigation.info["duration"]
        new_config["plugins"]["core"][
            "extend"
        ] = how_truncated  # This doesn't actually make sense, but it will be unique
        return [Configuration("extended_{how_truncated}", new_config)]
