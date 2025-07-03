"""
# Mount Tracker Plugin

This module provides a passive tracker for mount attempts within a guest environment.
It is intended for use with the Penguin analysis framework and is implemented as a plugin.

## Purpose

- Tracks when the guest tries to mount filesystems.
- Records unsupported filesystem types (e.g., when mount returns EINVAL) to inform kernel support decisions.
- Logs attempts to mount missing devices.
- Can optionally fake mount successes for specific targets or all mounts, aiding in analysis and mitigation.

## Usage

The plugin can be configured with the following arguments:
- `outdir`: Output directory for logs.
- `fake_mounts`: List of mount targets to fake as successful.
- `all_succeed`: If set, all mount attempts are faked as successful.
- `verbose`: Enables debug logging.

## Example

All mount attempts are logged to `mounts.csv` in the specified output directory.

"""

from os.path import join as pjoin
from penguin import plugins, Plugin

mount_log = "mounts.csv"


class MountTracker(Plugin):
    """
    MountTracker is a Penguin plugin that tracks and logs mount attempts in the guest.

    ## Attributes
    - outdir (`str`): Output directory for logs.
    - mounts (`set[tuple[str, str, str]]`): Set of (source, target, fs_type) tuples already logged.
    - fake_mounts (`list[str]`): List of mount targets to fake as successful.
    - all_succeed (`bool`): If True, all mount attempts are faked as successful.

    ## Behavior
    - Subscribes to exec events to detect `/bin/mount` invocations.
    - Hooks the mount syscall return to log and optionally fake mount results.
    """

    def __init__(self):
        """
        Initialize the MountTracker plugin.

        - Reads configuration arguments.
        - Subscribes to exec events and mount syscall returns.
        - Sets up logging and internal state.

        **Arguments**:
        - None (uses plugin argument interface)

        **Returns**:
        - None
        """
        self.outdir = self.get_arg("outdir")
        # Use the Execs plugin interface for exec events
        plugins.subscribe(plugins.Execs, "exec_event", self.find_mount)
        self.mounts = set()
        self.fake_mounts = self.get_arg("fake_mounts") or []
        self.all_succeed = self.get_arg("all_succeed") or False
        if self.get_arg_bool("penguin_verbose"):
            self.logger.setLevel("DEBUG")

        plugins.syscalls.syscall("on_sys_mount_return")(self.post_mount)

    def post_mount(self, regs, proto, syscall, source, target, fs_type, flags, data):
        """
        Coroutine callback for the mount syscall return.

        Reads the mount arguments from memory, logs the attempt, and optionally fakes the result.

        **Arguments**:
        - `regs`: Register state
        - proto: Protocol context (opaque, framework-specific)
        - syscall: Syscall context, with `.retval` for return value
        - source: Pointer to source device string
        - target: Pointer to mount target string
        - fs_type: Pointer to filesystem type string
        - flags: Mount flags (int)
        - data: Pointer to mount data

        **Returns**:
        - None (coroutine, may yield)
        """
        source_str = yield from plugins.mem.read_str(source)
        target_str = yield from plugins.mem.read_str(target)
        fs_type_str = yield from plugins.mem.read_str(fs_type)
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

    def find_mount(self, event: dict) -> None:
        """
        Detects `/bin/mount` invocations from exec events and logs them.

        **Arguments**:
        - event (`dict`): Exec event dictionary, expected to have 'procname' and 'argv' keys.

        **Returns**:
        - None
        """
        fname = event.get('procname', None)
        argv = event.get('argv', [])
        if fname == "/bin/mount":
            argc = len(argv)
            if argc >= 5 and argv[0] == "mount" and argv[1] == "-t":
                results = {
                    "source": argv[3],
                    "target": argv[4],
                    "fs_type": argv[2],
                }
                self.log_mount(-1, results)

    def log_mount(self, retval: int, results: dict) -> None:
        """
        Logs a mount attempt to the output CSV file if not already logged.

        **Arguments**:
        - retval (`int`): Return value of the mount syscall or -1 for exec events.
        - results (`dict`): Dictionary with keys 'source', 'target', 'fs_type'.

        **Returns**:
        - None
        """
        src = results["source"]
        tgt = results["target"]
        fs = results["fs_type"]

        if (src, tgt, fs) not in self.mounts:
            self.mounts.add((src, tgt, fs))
            with open(pjoin(self.outdir, mount_log), "a") as f:
                f.write(f"{src},{tgt},{fs},{retval}\n")
            self.logger.debug(
                f"Mount returns {retval} for: mount -t {fs} {src} {tgt}")
