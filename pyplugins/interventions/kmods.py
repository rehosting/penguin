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

    @plugins.syscalls.syscall("on_sys_init_module_enter")
    def init_module(self, regs, proto, syscall, module_image, size, param_values):
        # Determine if this is our module!
        args = yield from plugins.osi.get_args()
        igloo_mod_args = ['/igloo/utils/busybox', 'insmod', '/igloo/boot/igloo.ko']
        if args == igloo_mod_args:
            return

        # We never allow actual module loading other than igloo.ko
        # So we just fake success here.
        syscall.retval = 0
        syscall.skip_syscall = True

        # Analyze information to determine the module being loaded

        # Check args for .ko file
        matching_ko = [arg for arg in args if arg.endswith('.ko')]
        if any(matching_ko):
            self.logger.info(f"Detected kernel module load: {matching_ko[-1]}")
            self.track_kmod(matching_ko[-1])
            return

        # Check open fds for .ko file
        fds = yield from plugins.osi.get_fds()
        for fd, fdname in fds.items():
            if fdname.endswith('.ko'):
                self.track_kmod(fdname)
                return

        # We can give up here or try to read the module image from memory
        # for now we give up
        # module = yield from plugins.mem.read_bytes(module_image, size)
        self.logger.info(f"Could not determine kernel module path from args: {args} or fds: {fds}")

    @plugins.syscalls.syscall("on_sys_finit_module_enter")
    def finit_module(self, regs, proto, syscall, fd, param_values, flags):
        # We never allow actual module loading other than igloo.ko
        # So we just fake success here.
        syscall.skip_syscall = True
        syscall.retval = 0

        # Analyze information to determine the module path
        fdname = yield from plugins.osi.get_fd_name(fd)
        self.track_kmod(fdname)
