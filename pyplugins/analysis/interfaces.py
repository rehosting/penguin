import re
from penguin import plugins, Plugin

iface_log = "iface.log"
ioctl_log = "iface_ioctl.log"

# Regex pattern for a valid Linux interface name
intf_pattern = r'^[a-zA-Z][a-zA-Z0-9._/-]{0,15}$'
ENODEV = 19

ignored_interfaces = ["lo"]


class Interfaces(Plugin):
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.conf = self.get_arg("conf")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        open(f"{self.outdir}/{iface_log}", "w").close()
        open(f"{self.outdir}/{ioctl_log}", "w").close()

        self.added_ifaces = self.conf.get("netdevs", [])

        self.missing_ifaces = set()
        self.failed_ioctls = set()

    def handle_interface(self, iface):
        if iface is None or not len(iface):
            return

        if iface in self.added_ifaces or iface in self.missing_ifaces \
                or iface in ignored_interfaces:
            return

        if not re.match(intf_pattern, iface):
            self.logger.debug(f"Invalid interface name {iface}")
            return

        self.missing_ifaces.add(iface)
        with open(f"{self.outdir}/{iface_log}", "a") as f:
            f.write(f"{iface}\n")
        self.logger.debug(f"Detected new missing interface {iface}")

    def failing_ioctl(self, ioctl, iface, rv):
        if iface and not re.match(intf_pattern, iface):
            self.logger.debug(f"Invalid interface name {iface}")
            iface = None

        if (ioctl, iface) in self.failed_ioctls:
            return

        self.failed_ioctls.add((ioctl, iface))
        self.logger.debug(
            f"Detected new failing ioctl {hex(ioctl)} for {iface or '[?]'}")

        with open(f"{self.outdir}/{ioctl_log}", "a") as f:
            f.write(f"{hex(ioctl)},{iface or '[?]'},{rv}\n")

    def get_iface_from_ioctl(self, cpu, arg):
        try:
            return self.panda.read_str(cpu, arg, max_length=16)
        except ValueError:
            return None

    @plugins.syscalls.syscall("on_sys_ioctl_return")
    def after_ioctl(self, regs, proto, syscall, fd, request, arg):
        if 0x8000 < request < 0x9000:
            iface = yield from plugins.mem.read_str(arg)
            rv = syscall.retval

            # try to catch missing interfaces
            if rv == -ENODEV:
                self.handle_interface(iface)

            if rv < 0:
                # try to catch failing ioctls
                self.failing_ioctl(request, iface, rv)

    @plugins.subscribe(plugins.Execs, "exec_event")
    def iface_on_exec(self, event):
        argv = event.get('argv', [])
        fname = event.get('procname', None)
        # note argv[0] is the binary name, similar to fname
        if argv is None or len(argv) == 0:
            return

        if fname and fname.startswith("/igloo/utils"):
            # This is us adding interfaces in /igloo_init
            return

        iface = None
        if fname and (fname.endswith("/ip") or (argv and argv[0] == "ip")):
            # (ip .* dev \K[a-zA-Z0-9.]+(?=))'
            for idx, arg in enumerate(argv):
                if not arg:
                    continue
                if "dev" in arg and idx < len(argv) - 1:
                    iface = argv[idx + 1]

        if fname and (fname.endswith("/ifconfig") or (argv and argv[0] == "ifconfig")):
            # device is the first argument
            if len(argv) > 1:
                iface = argv[1]
        self.handle_interface(iface)
