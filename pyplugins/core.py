import os
import signal
import threading
import time
from copy import deepcopy

from pandare import PyPlugin

from penguin import getColoredLogger

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
        for arg in "plugins CID conf fs fw outdir".split():
            if not self.get_arg(arg):
                raise ValueError(f"[core] Missing required argument: {arg}")

        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.pending_procname = None
        self.pending_sin_addr = None

        self.logger = getColoredLogger("plugins.core")

        plugins = self.get_arg("plugins")
        conf = self.get_arg("conf")

        # If we have an option of root_shell we need to add ROOT_SHELL=1 into env
        # so that the init script knows to start a root shell
        if conf["core"].get("root_shell", False):
            conf["env"]["ROOT_SHELL"] = "1"
            # Print port info
            if container_ip := os.environ.get("CONTAINER_IP", None):
                self.logger.info(
                    f"Root shell will be available at: {container_ip}:23"
                )
                self.logger.info(f"Connect with: telnet {container_ip}")
            elif container_name := os.environ.get("CONTAINER_NAME", None):
                self.logger.info(
                    f"Root shell will be available in container {container_name} on port 23"
                )
                self.logger.info(
                    f"Connect with: docker exec -it {container_name} telnet 127.0.0.1"
                )
            else:
                self.logger.info(
                    "Root shell enabled. Connect with docker exec -it [your_container_name] telnet 127.0.0.1"
                )

        # Same thing, but for a shared directory
        if conf["core"].get("shared_dir", False):
            conf["env"]["SHARED_DIR"] = "1"

        if conf["core"].get("strace", False):
            conf["env"]["STRACE"] = "1"

        if conf["core"].get("ltrace", False):
            conf["env"]["IGLOO_LTRACE"] = "1"

        if conf["core"].get("force_www", False):
            if conf.get("static_files", {}).get("/igloo/utils/www_cmds", None) is None:
                self.logger.warning(
                    "WARNING: Force WWW unavailable - no webservers were statically identified (/igloo/utils/www_cmds is empty)"
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

            # Log info on how many blocks get executed
            log_path = self.outdir + "/core_shutdown.csv"
            panda.load_plugin(
                "timeout",
                {
                    # "bb_limit": BB_MAX,
                    # 'unique_bbs': UNIQUE,
                    "log": log_path
                },
            )

            self.shutdown_event = threading.Event()
            self.shutdown_thread = threading.Thread(
                target=self.shutdown_after_timeout,
                args=(panda, timeout, self.shutdown_event),
            )
            self.shutdown_thread.start()

        # Now define HC callbacks
        # Define callbacks that are triggered from hypercalls
        for cb in [
            "igloo_open",
            "igloo_string_cmp",
            "igloo_getenv",
            "igloo_strstr",
            "igloo_bind",
            "igloo_ioctl",
            "igloo_syscall",
            "igloo_nvram_get",
            "igloo_nvram_set",
            "igloo_nvram_clear",
            "igloo_send_hypercall",
        ]:
            self.ppp_cb_boilerplate(cb)

    @PyPlugin.ppp_export
    def handle_hc(self, cpu, num):
        try:
            self._handle_hc(cpu, num & (2**32 - 1))
        except ValueError:
            # Argument couldn't be read
            self.panda.arch.set_arg(cpu, 0, 1)
        except RuntimeError:
            # Not one of ours
            return False
        except Exception as e:
            self.logger.warning(f"Error running hypercall {num}")
            self.logger.exception(e)
            self.panda.arch.dump_regs(cpu)
            pass  # Technically we processed it, just badly. Need to ensure we still return bool instead of raising exn
        return True

    def _handle_hc(self, cpu, num):
        if num == 100:
            # open/openat (filename*, fd/retval)
            arg1 = self.panda.arch.get_arg(cpu, 1)
            fd = self.panda.arch.get_arg(cpu, 2)
            fname = self.panda.read_str(cpu, arg1)
            self.ppp_run_cb("igloo_open", cpu, fname, fd)

        elif num in [101, 102]:
            # strcmp/strncmp - non-DYNVAL string that's being compared
            arg1 = self.panda.arch.get_arg(cpu, 1)
            value = self.panda.read_str(cpu, arg1)
            self.ppp_run_cb("igloo_string_cmp", cpu, value)

        elif num == 103:
            # getenv (name*)
            arg1 = self.panda.arch.get_arg(cpu, 1)
            value = self.panda.read_str(cpu, arg1)
            self.ppp_run_cb("igloo_getenv", cpu, value)

        elif num == 104:
            # strstr (haystack*, needle*)
            arg1 = self.panda.arch.get_arg(cpu, 1)
            arg2 = self.panda.arch.get_arg(cpu, 2)
            value1 = self.panda.read_str(cpu, arg1)
            value2 = self.panda.read_str(cpu, arg2)

            self.ppp_run_cb("igloo_strstr", cpu, value1, value2)

        elif num == 105:
            # ioctl (filename*, cmd)
            arg1 = self.panda.arch.get_arg(cpu, 1)
            value1 = self.panda.read_str(cpu, arg1)
            arg2 = self.panda.arch.get_arg(cpu, 2)

            self.ppp_run_cb("igloo_ioctl", cpu, value1, arg2)

        elif num == 107:
            # NVRAM miss
            buffer = self.panda.arch.get_arg(cpu, 1)
            buffer_len = self.panda.arch.get_arg(cpu, 2)
            s = self.panda.read_str(cpu, buffer, max_length=buffer_len)
            self.ppp_run_cb("igloo_nvram_get", cpu, s, False)

        elif num == 108:
            # NVRAM hit
            buffer = self.panda.arch.get_arg(cpu, 1)
            buffer_len = self.panda.arch.get_arg(cpu, 2)
            s = self.panda.read_str(cpu, buffer, max_length=buffer_len)
            self.ppp_run_cb("igloo_nvram_get", cpu, s, True)

        elif num == 109:
            # NVRAM set
            buffer = self.panda.arch.get_arg(cpu, 1)
            val = self.panda.arch.get_arg(cpu, 2)
            s1 = self.panda.read_str(cpu, buffer)
            s2 = self.panda.read_str(cpu, val)
            self.ppp_run_cb("igloo_nvram_set", cpu, s1, s2)

        elif num == 110:
            # NVRAM clear
            buffer = self.panda.arch.get_arg(cpu, 1)
            buffer_len = self.panda.arch.get_arg(cpu, 2)
            s = self.panda.read_str(cpu, buffer, max_length=buffer_len)
            self.ppp_run_cb("igloo_nvram_clear", cpu, s)

        elif num in [200, 202]:
            # 200: ipv4 setup, 202: ipv6 setup
            arg1 = self.panda.arch.get_arg(cpu, 1)

            arg2 = self.panda.arch.get_arg(cpu, 2)
            ipv4 = num == 200

            if ipv4:
                # Passed by value as it fits in a 32-bit register
                sin_addr = int.to_bytes(arg2, 4, "little")
            else:
                # Passed as a pointer since it's 16 bytes
                sin_addr = self.panda.virtual_memory_read(cpu, arg2, 16)

            self.pending_procname = self.panda.read_str(cpu, arg1)
            self.pending_sin_addr = sin_addr

        elif num in [201, 203]:
            # 201: ipv4 bind, 203: ipv6 bind
            ipv4 = num == 201
            port = self.panda.arch.get_arg(cpu, 1)
            is_stream = self.panda.arch.get_arg(cpu, 2) != 0
            self.ppp_run_cb(
                "igloo_bind",
                cpu,
                self.pending_procname,
                ipv4,
                is_stream,
                port,
                self.pending_sin_addr,
            )
            self.pending_procname = None
            self.pending_sin_addr = None

        elif num == 0x6408400B:
            # syscall
            buf_addr = self.panda.arch.get_arg(cpu, 1)
            self.ppp_run_cb("igloo_syscall", cpu, buf_addr)

        elif num == 0xB335A535:
            # send_hypercall
            buf_addr = self.panda.arch.get_arg(cpu, 1)
            buf_num_ptrs = self.panda.arch.get_arg(cpu, 2)
            self.ppp_run_cb("igloo_send_hypercall", cpu, buf_addr, buf_num_ptrs)

        else:
            raise RuntimeError(f"handle_hc called with unknown hypercall: {num}")

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
                    raise RuntimeError(f"Found BUG in {output_dir}/console.log")

        # qemu logs are above output directory
        stderr = os.path.join(os.path.dirname(output_dir), "qemu_stderr.txt")
        if os.path.isfile(stderr):
            with open(stderr) as f:
                for line in f.readlines():
                    if "Traceback " in line:
                        raise RuntimeError(f"Python analysis crashed in {output_dir}")
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
                )
            ]

    def implement_mitigation(self, config, failure, mitigation):
        new_config = deepcopy(config.info)
        how_truncated = mitigation.info["duration"]  # How many seconds were truncated?
        new_config["plugins"]["core"][
            "extend"
        ] = how_truncated  # This doesn't actually make sense, but it will be unique
        return [Configuration("extended_{how_truncated}", new_config)]
