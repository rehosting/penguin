from pandare2 import PyPlugin
import subprocess
import os
import shlex


def guest_cmd(cmd):
    """Run a command in the guest, logging output to a file"""

    subprocess.Popen(["python3", "/igloo_static/guesthopper/guest_cmd.py", cmd])


class IndivDebug(PyPlugin):
    """
    Plugin for debugging individual programs

    This plugin is for running debugging tools such as strace, ltrace, and gdbserver
    on individual processes rather than the entire system.
    You might want to do this if, for example, you want to debug the HTTP server process
    without the overhead or loss of fidelity from tracing the entire system.
    """
    def __init__(self, panda):
        self.conf = self.get_arg("conf")
        self.args_tmp = []
        self.filename = None

        # These three hypercalls are sent by the kernel on execve(),
        # to give this plugin information about the process and ask whether it
        # should start paused

        @panda.hypercall(0x0c6ea29a)
        def indiv_debug_get_filename(cpu):
            filename_ptr = panda.arch.get_arg(cpu, 1, convention="syscall")
            self.filename = panda.read_str(cpu, filename_ptr)

        @panda.hypercall(0x0ae7babc)
        def indiv_debug_get_arg(cpu):
            arg_ptr = panda.arch.get_arg(cpu, 1, convention="syscall")
            i = panda.arch.get_arg(cpu, 2, convention="syscall")
            if i == 0:
                self.args_tmp = []
            assert len(self.args_tmp) == i
            arg = panda.read_str(cpu, arg_ptr)
            self.args_tmp.append(arg)

        @panda.hypercall(0x7b7287d5)
        def indiv_debug_ask_sig_stop(cpu):
            if self.filename is None:
                return

            pause_flag_ptr = panda.arch.get_arg(cpu, 1, convention="syscall")
            pid = panda.arch.get_arg(cpu, 2, convention="syscall")

            # Check whether we should pause the process, and tell the kernel if so.
            # These functions return True if they detect the process should start paused.
            pause_flag = (
                self.maybe_trace_common(pid, "strace")
                or self.maybe_trace_common(pid, "ltrace")
                or self.maybe_gdbserver(pid)
            )
            if pause_flag:
                panda.virtual_memory_write(cpu, pause_flag_ptr, bytes([pause_flag]))

            # Reset state
            self.filename = None
            self.args_tmp = []

    def maybe_trace_common(self, pid: int, trace_tool: str) -> bool:
        """Common helper function for tools like strace and ltrace"""

        trace = self.conf["core"][trace_tool]

        # Bail if process shouldn't be traced
        if (
            not isinstance(trace, list)
            or (self.filename not in trace and os.path.basename(self.filename) not in trace)
        ):
            return False

        # Create output dir and launch tool to trace process
        log_name = f"{trace_tool}_{self.filename.replace('/', '_')}_{pid}.txt"
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

    def maybe_gdbserver(self, pid: int) -> bool:
        gdbserver = self.conf["core"].get("gdbserver", dict())
        port = gdbserver.get(self.filename) or gdbserver.get(os.path.basename(self.filename))

        # Bail if user doesn't want gdbserver for this process
        if port is None:
            return False

        guest_cmd(f"/igloo/utils/gdbserver --attach localhost:{port} {str(pid)}")

        return True
