from penguin import Plugin, plugins
import subprocess
import os
import shlex

INDIV_DEBUG_PORTALCALL_MAGIC = 0xfeedbeef


def guest_cmd(cmd):
    """Run a command in the guest, logging output to a file"""

    subprocess.Popen(["python3", "/igloo_static/guesthopper/guest_cmd.py", cmd])


class IndivDebug(Plugin):
    """
    Plugin for debugging individual programs

    This plugin is for running debugging tools such as strace, ltrace, and gdbserver
    on individual processes rather than the entire system.
    You might want to do this if, for example, you want to debug the HTTP server process
    without the overhead or loss of fidelity from tracing the entire system.
    """

    def __init__(self):
        self.conf = self.get_arg("conf")
        self.guesthopper_enabled = self.conf.get("core").get("guest_cmd", False)
        self.guesthopper_running = False
        if self.guesthopper_enabled:
            plugins.portalcall.portalcall(INDIV_DEBUG_PORTALCALL_MAGIC, self._initialize_debug)
        else:
            self.logger.debug("IndivDebug: guest_cmd is disabled")

    def _initialize_debug(self):
        if self.guesthopper_enabled:
            plugins.subscribe(plugins.Execs, "exec_event", self._on_execve_common)
            self.guesthopper_running = True
            return 0
        else:
            self.logger.warning("Guesthopper is running, but is not enabled")
            return 1

    def _on_execve_common(self, event):
        if event["retval"] < 0:
            # exec failed, so nothing to debug
            return

        path = event["procname"]
        pid = event["proc"].pid

        # Check whether we should pause the process.
        # These functions return True if they detect the process should start paused.
        should_pause = (
            self._maybe_trace(pid, path, "strace")
            or self._maybe_trace(pid, path, "ltrace")
            or self._maybe_gdbserver(pid, path)
        )

        if should_pause:
            yield from plugins.signals.self_signal("SIGSTOP")

    def _maybe_trace(self, pid: int, path: str, trace_tool: str) -> bool:
        """Common helper function for tools like strace and ltrace"""

        trace = self.conf["core"][trace_tool]

        # Bail if process shouldn't be traced
        if (
            not isinstance(trace, list)
            or (path not in trace and os.path.basename(path) not in trace)
        ):
            return False

        # Create output dir and launch tool to trace process
        log_name = f"{trace_tool}_{path.replace('/', '_')}_{pid}.txt"
        guest_cmd(f"""
            /igloo/utils/busybox mkdir -p /igloo/shared/trace
            /igloo/utils/{trace_tool} -p {str(pid)} \
                >/igloo/shared/trace/{shlex.quote(log_name)} 2>&1
        """)

        # Wait until the tracing program attaches to the process and resume it
        # Checking this field of /proc/PID/stat seems to be a reliable way to do this.
        # When the process is paused, it is "T" and changes to "t" when a ptrace debugger attaches.
        guest_cmd(f"""
            while [ "$(/igloo/utils/busybox cut -d ' ' -f 3 /proc/{str(pid)}/stat)" != "t" ]; do
                /igloo/utils/busybox sleep 0.1
            done
            /igloo/utils/busybox kill -SIGCONT {str(pid)}
        """)

        return True

    def _maybe_gdbserver(self, pid: int, path: str) -> bool:
        gdbserver = self.conf["core"].get("gdbserver", dict())
        port = gdbserver.get(path) or gdbserver.get(os.path.basename(path))

        # Bail if user doesn't want gdbserver for this process
        if port is None:
            return False

        guest_cmd(f"/igloo/utils/gdbserver --attach 0.0.0.0:{port} {str(pid)}")

        return True
