from os.path import join as pjoin
from pandare2 import PyPlugin
from penguin import getColoredLogger, plugins

mount_log = "mounts.csv"


class MountTracker(PyPlugin):
    """
    Track when the guest tries mounting filesystems.

    If it's an unsupported type (i.e., mount returns EINVAL), we record
    so we could potentially add kernel support.

    If it's trying to mount a missing device, we record that too.

    For now this is just a passive tracker to inform us if we need to build more analyses or update
    our default kernel options.

    We could support a 'mount shim' option in our config that we'd use to intercept mount calls
    and hide errors and/or mount a different filesystem (i.e., from our static FS extraction).

    I.e., we'd see a mount, report failure, propose mitigation of shimming, then we'd run
    with the mount faked, see what files get opened within the mount path, then try
    finding a good way to make those files appear
    """

    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        plugins.subscribe(plugins.Health, "igloo_exec", self.find_mount)
        self.mounts = set()
        self.fake_mounts = self.get_arg("fake_mounts") or []
        self.all_succeed = self.get_arg("all_succeed") or False
        self.logger = getColoredLogger("plugins.mount")
        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")
 
        self.panda.hsyscall("on_sys_mount_return")(self.post_mount)

    @plugins.portal.wrap
    def post_mount(self, cpu, proto, syscall, hook, source, target, fs_type, flags, data):
        source_str = yield from plugins.portal.read_str(source)
        target_str = yield from plugins.portal.read_str(target)
        fs_type_str = yield from plugins.portal.read_str(fs_type)
        results = {
            "source": source_str,
            "target": target_str,
            "fs_type": fs_type_str,
        }

        retval = syscall.retval
        self.log_mount(retval, results)
        if retval == -16:  # EBUSY
            # Already mounted - we could perhaps use this info to drop the mount from our init script?
            # Just pretend it was a success
            syscall.retval = 0

        elif retval < 0:
            if results["target"] in self.fake_mounts:
                self.logger.debug(f"Fake mount: {results['target']}")
                syscall.retval = 0

        if self.all_succeed:
            # Always pretend it was a success?
            syscall.retval = 0

    def find_mount(self, cpu, fname, argv):
        if fname == "/bin/mount":
            argc = len(argv)

            if argc >= 5 and argv[0] == "mount" and argv[1] == "-t":
                results = {
                    "source": argv[3],
                    "target": argv[4],
                    "fs_type": argv[2],
                }
                self.log_mount(-1, results)

    def log_mount(self, retval, results):
        src = results["source"]
        tgt = results["target"]
        fs = results["fs_type"]

        if (src, tgt, fs) not in self.mounts:
            self.mounts.add((src, tgt, fs))
            with open(pjoin(self.outdir, mount_log), "a") as f:
                f.write(f"{src},{tgt},{fs},{retval}\n")
            self.logger.debug(f"Mount returns {retval} for: mount -t {fs} {src} {tgt}")
