
from penguin import plugins, Plugin

class KmodTracker(Plugin):

    def track_kmod(self, kmod_path):
        """
        Track a kernel module by its path.
        This method can be used to monitor the loading and unloading of kernel modules.
        """
        self.logger.info(f"Tracking kernel module: {kmod_path}")
        with open(self.get_arg("outdir") + "/modules.log", "a") as f:
            f.write(f"{kmod_path}\n")

    @plugins.syscalls.syscall("on_sys_init_module_return")
    def init_module(self, regs, proto, syscall, module_image, size, param_values):
        # module = yield from plugins.mem.read_bytes(module_image, size)
        args = yield from plugins.osi.get_args()
        igloo_mod_args = ['/igloo/utils/busybox', 'insmod', '/igloo/shared/host_files/igloo.ko']
        if args == igloo_mod_args:
            return
        matching_ko = [arg for arg in args if arg.endswith('.ko')]
        syscall.retval = 0
        if any(matching_ko):
            self.logger.info(f"Detected kernel module load: {matching_ko[-1]}")
            self.track_kmod(matching_ko[-1])
            return
        fds = yield from plugins.osi.get_fds()

        breakpoint()
        print("asfd")
    
    @plugins.syscalls.syscall("on_sys_finit_module_return")
    def finit_module(self, regs, proto, syscall, fd, param_values, flags):
        fdname = yield from plugins.osi.get_fd_name(fd)
        self.track_kmod(fdname)
        syscall.retval = 0