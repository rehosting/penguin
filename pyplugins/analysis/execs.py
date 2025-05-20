from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins
from wrappers.generic import Wrapper

portal = plugins.portal
syscalls = plugins.syscalls

class Execs(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.logger = getColoredLogger("plugins.execs")
        syscalls.syscall("on_sys_execve_enter")(self.on_execve)
        syscalls.syscall("on_sys_execveat_enter")(self.on_execveat)
        plugins.register(self, "igloo_exec")

    @portal.wrap
    def on_execve(self, proto, syscall, fname_ptr, argv_ptr, envp):
        yield from self._handle_exec(fname_ptr, argv_ptr, envp)

    @portal.wrap
    def on_execveat(self, proto, syscall, dfd, fname_ptr, argv_ptr, envp, flags):
        yield from portal.get_fd_name(dfd)
        yield from self._handle_exec(fname_ptr, argv_ptr, envp)

    @portal.wrap
    def _handle_exec(self, fname_ptr, argv_ptr, envp_ptr):
        fname = yield from portal.read_str(fname_ptr)
        argv_buf = yield from portal.read_ptrlist(argv_ptr, 8)
        argv = []
        for ptr in argv_buf:
            if ptr == 0:
                break
            val = yield from portal.read_str(ptr)
            if val == "":
                argv.append(f"(error: 0x{ptr:x})")
            else:
                argv.append(val)
        # Read environment variables
        env_buf = yield from portal.read_ptrlist(envp_ptr, 8)
        env = []
        for ptr in env_buf:
            if ptr == 0:
                break
            val = yield from portal.read_str(ptr)
            env.append(val)
        # Get calling process info
        proc = yield from portal.get_proc()
        if proc is None:
            return
        exec_instance = {
            "fname": fname,
            "argv": argv,
            "env": env,
            "parent_name": proc.name,
            "ppid": proc.pid,
            "pppid": proc.ppid,
        }

        yield from plugins.publish(self, "igloo_exec", Wrapper(exec_instance))
