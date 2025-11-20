"""
core.py - Core plugin for Penguin
=================================

This module provides the Core plugin, which performs basic sanity checks, configuration management,
and core logic for the penguin emulation environment. It is responsible for:

- Validating required arguments at initialization.
- Writing configuration and loaded plugin information to the output directory.
- Handling SIGUSR1 for graceful shutdown of emulation.
- Creating a `.ran` file in the output directory after a non-crash shutdown.
- Optionally enforcing a timeout for emulation and shutting down after the specified period.
- Logging information about available services (e.g., root shell, VNC) based on configuration and environment.

Arguments
---------

- timeout (int, optional): Timeout in seconds for automatic shutdown.

Plugin Interface
----------------

This plugin does not provide a direct interface for other plugins, but it writes configuration
and plugin information to files in the output directory, which other plugins or tools may read.

Overall Purpose
---------------

The Core plugin ensures the emulation environment is correctly set up, manages shutdown
procedures, and records essential information for reproducibility and debugging.
"""

import os
import signal
import threading
import time
from typing import Tuple
from collections.abc import Mapping, Sequence
from penguin import Plugin, yaml, plugins
from penguin.defaults import vnc_password

GET_CONFIG_MAGIC = 0x6E7C04F0


class Core(Plugin):
    """
    Core plugin for PyPlugins.

    Performs sanity checks, manages configuration, handles shutdown signals,
    and enforces optional timeouts for the emulation environment.
    """

    def __init__(self) -> None:
        """
        Initialize the Core plugin.

        Raises:
            ValueError: If any required argument is missing.
        """
        for arg in "plugins conf fs fw outdir".split():
            if not self.get_arg(arg):
                raise ValueError(f"[core] Missing required argument: {arg}")

        self.outdir = self.get_arg("outdir")
        self.pending_procname = None
        self.pending_sin_addr = None

        plugs = self.get_arg("plugins")
        conf = self.get_arg("conf")
        self.config = conf.args  # since the config is an ArgsBox

        telnet_port = self.get_arg("telnet_port")

        # Essential plugins are always loaded with core
        essential_plugins = [
            "live_image",
            "igloodriver",
            "kmods",
        ]

        for essential_plugin in essential_plugins:
            p = getattr(plugins, essential_plugin)
            if hasattr(p, "ensure_init"):
                p.ensure_init()

        if conf["core"].get("root_shell", False):
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

        # Warn if env is set for any of the old options. Can happen with old configs.
        legacy_env_vars = ["ROOT_SHELL", "SHARED_DIR", "STRACE", "IGLOO_LTRACE", "WWW", "PROJ_NAME"]
        core_env = conf["core"].get("env", {})

        found_legacy_vars = []
        for var in legacy_env_vars:
            if var in core_env:
                found_legacy_vars.append(var)

        if found_legacy_vars:
            self.logger.warning(
                f"Legacy environment variables found in core.env: {', '.join(found_legacy_vars)}. "
                "This likely indicates you are running an old project and this message can safely be ignored."
                "However, if you have set them intentionally, be aware they will stop working in the future."
            )

        if conf["core"].get("force_www", False):
            if conf.get("static_files", {}).get(
                    "/igloo/utils/www_cmds", None) is None:
                self.logger.warning(
                    "Force WWW unavailable - no webservers were statically identified (/igloo/utils/www_cmds is empty)"
                )

        # Add proj_name to config based on dirname of config (kinda evil)
        if proj_name := self.get_arg("proj_name"):
            conf["core"]["proj_name"] = proj_name

        # Record loaded plugins
        with open(os.path.join(self.outdir, "core_plugins.yaml"), "w") as f:
            f.write(yaml.dump(plugs))  # Names and args

        # Record config in outdir:
        with open(os.path.join(self.outdir, "core_config.yaml"), "w") as f:
            f.write(yaml.dump(self.get_arg("conf").args))

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
                args=(timeout, self.shutdown_event),
            )
            self.shutdown_thread.start()

    def shutdown_after_timeout(
        self,
        timeout: int,
        shutdown_event: threading.Event
    ) -> None:
        """
        Shutdown the emulation after a specified timeout.

        Args:
            panda (Panda): The Panda emulation object.
            timeout (int): Timeout in seconds before shutdown.
            shutdown_event (threading.Event): Event to signal early shutdown.
        """
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
        self.panda.unload_plugins()
        time.sleep(1)

        self.panda.end_analysis()

    def graceful_shutdown(self, sig: int, frame) -> None:
        """
        Handle SIGUSR1 for graceful shutdown.

        Args:
            sig (int): Signal number.
            frame: Current stack frame.
        """
        self.logger.info("Caught SIGUSR1 - gracefully shutdown emulation")
        open(os.path.join(self.outdir, ".ran"), "w").close()
        plugins.unload_all()
        self.panda.end_analysis()

    def uninit(self) -> None:
        """
        Perform cleanup and signal shutdown event if running.
        """
        # Create .ran
        open(os.path.join(self.outdir, ".ran"), "w").close()

        plugins = self.get_arg("plugins")
        # Record loaded plugins
        with open(os.path.join(self.outdir, "core_plugins.yaml"), "w") as f:
            f.write(yaml.dump(plugins))  # Names and args

        # Record config in outdir:
        with open(os.path.join(self.outdir, "core_config.yaml"), "w") as f:
            f.write(yaml.dump(self.get_arg("conf").args))

        if hasattr(self, "shutdown_event") and not self.shutdown_event.is_set():
            # Tell the shutdown thread to exit if it was started
            self.shutdown_event.set()

    @plugins.portalcall.portalcall(GET_CONFIG_MAGIC)
    def portalcall_getconfig(self, key_ptr, output_ptr, buf_size):
        """
        Config accessor used by the guest
        """
        key = yield from plugins.mem.read_str(key_ptr)
        keys = key.split('.')
        current = self.config
        self.logger.debug(f"get_config called for key: {key}")

        try:
            for key in keys:
                if isinstance(current, Mapping) and key in current:
                    current = current[key]
                elif isinstance(current, Sequence) and not isinstance(current, str):
                    try:
                        index = int(key)
                        current = current[index]
                    except (ValueError, IndexError):
                        raise
                elif hasattr(current, key):
                    current = getattr(current, key)
                else:
                    raise KeyError
            value = str(current)
        except (KeyError, AttributeError, TypeError):
            value = ""
        self.logger.debug(f"get_config found value {value} for key: {key}")
        yield from plugins.mem.write_str(output_ptr, value[:buf_size-1])
