"""
# Pseudofiles Plugin

This module implements a Penguin plugin for modeling and tracking accesses to pseudo-files
(e.g., `/dev`, `/proc`, `/sys`) in embedded Linux environments. It provides mechanisms to
simulate device files, log missing file accesses, and model file behaviors for analysis.

## Purpose

- Models pseudo-files and device files for analysis and emulation.
- Logs missing or failed file accesses for further investigation.
- Supports custom read, write, and ioctl models for each pseudo-file.
- Integrates with the HyperFile plugin for advanced modeling.
- Optionally launches symbolic execution for ioctl failures.

## Usage

The plugin can be configured with the following arguments:
- `outdir`: Output directory for logs.
- `proj_dir`: Project directory for relative file paths.
- `conf`: Configuration dictionary with pseudo-file models.
- `verbose`: Enables debug logging.

All missing or failed file accesses are logged to `pseudofiles_failures.yaml` in the specified output directory.

"""

import logging
import re
from os.path import dirname, isfile, isabs
from os.path import join as pjoin
from sys import path as syspath
from penguin import Plugin, plugins, yaml

syspath.append(dirname(__file__))

KNOWN_PATHS = [
    "/dev/",
    "/dev/pts",
    "/sys",
    "/proc",
    "/run",
    "/tmp",  # Directories not in static FS that are added by igloo_init (mostly irrelevant with wrong prefixes)
    "/dev/ttyS0",
    "/dev/console",
    "/dev/root",
    "/dev/ram",
    "/dev/ram0"  # We set these up in our init script, common device types
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",  # Standard devices we should see in devtmpfs
    # TODO: pull in devices like how we do during static analysis (e.g., /resources/proc_sys.txt)
    "/proc/penguin_net",
]


# Missing files go into our first log
outfile_missing = "pseudofiles_failures.yaml"
# Files we're modeling go into the second. Particularly useful for defaults
outfile_models = "pseudofiles_modeled.yaml"
MAGIC_SYMEX_RETVAL = 999


def path_interesting(path):
    if "/pipe:[" in path:
        return False

    if "\\" in path:
        # non-printable chars get escaped somewhere
        # These are junk
        return False

    if path.startswith("/dev/"):
        return True

    if path.startswith("/proc/"):
        return True

    if path.startswith("/sys/"):
        return True

    return False


def proc_interesting(path):
    # Avoid standard procfs files
    # Transformed PID references
    if path.startswith("/proc/PID"):
        return False
    if path.startswith("/proc/self"):
        return False
    if path.startswith("/proc/thread-self"):
        return False

    return path.startswith("/proc/")


def ignore_cmd(ioctl):
    """
    Ignore TTY ioctls, see ioctls.h for T*, TC*, and TIO* ioctls
    """
    if ioctl >= 0x5400 and ioctl <= 0x54FF:
        return True
    return False


def ignore_ioctl_path(path):
    # Paths we don't care about:
    # /firmadyne/libnvram anything - this reveals the nvram values read though
    # socket:{RAW,UDP,TCP,...}
    # /proc/*/{mounts,stat,cmdline} - boring?
    if path.startswith("/firmadyne/libnvram"):
        return True
    if path.startswith("/proc/"):
        return True
    if path.startswith("socket:"):
        # XXX We do want to log socket failures and eventually model them!
        return True
    if "/pipe:[" in path:
        return True
    return False


# Closure so we can pass details through
def make_rwif(details, fn_ref):
    def rwif(*args):
        return fn_ref(*args, details)

    return rwif


def get_total_counts(d):
    """Get the sum of all "count" values of a nested dictionary"""
    return (
        (
            d["count"]
            if "count" in d else
            sum(map(get_total_counts, d.values()))
        )
        if isinstance(d, dict) else 0
    )


def sort_file_failures(d):
    """Get a sorted version of the file failures dictionary."""
    # This relies on dict iteration being the same as insertion order,
    # which is an implementation detail in CPython,
    # but OrderedDict is harder to serialize with pyyaml.
    return (
        dict(
            sorted(
                ((k, sort_file_failures(v)) for k, v in d.items()),
                key=lambda pair: get_total_counts(pair[1]),
                reverse=True,
            )
        )
        if isinstance(d, dict) else d
    )


class Pseudofiles(Plugin):
    """
    Pseudofiles is a Penguin plugin that models and logs accesses to pseudo-files in the guest.

    ## Attributes
    - outdir (`str`): Output directory for logs.
    - proj_dir (`str`): Project directory for relative file paths.
    - written_data (`dict[str, bytes]`): Tracks data written to files.
    - ENOENT (`int`): Error code for "No such file or directory".
    - warned (`set`): Set of syscalls seen but not known.
    - file_failures (`dict`): Tracks failed file accesses.
    - config (`dict`): Plugin configuration.
    - devfs, procfs, sysfs (`list`): Lists of device, proc, and sys files.
    - hf_config (`dict`): HyperFile configuration.
    - did_mtd_warn (`bool`): Warned about MTD device config.
    - need_ioctl_hooks (`bool`): Whether ioctl hooks are needed.
    """

    def __init__(self):
        """
        Initialize the Pseudofiles plugin.

        - Reads configuration arguments.
        - Loads HyperFile models.
        - Subscribes to relevant events.
        - Sets up logging and internal state.

        **Arguments**:
        - None (uses plugin argument interface)

        **Returns**:
        - None
        """
        self.outdir = self.get_arg("outdir")
        self.proj_dir = self.get_arg("proj_dir")
        self.written_data = {}  # filename -> data that was written to it
        if self.get_arg_bool("verbose"):
            self.logger.setLevel(logging.DEBUG)
        self.did_mtd_warn = False  # Set if we've warned about misconfigured MTD devices
        # XXX: It has seemed like this should be 1 for some architectures, but that can't be right?
        self.ENOENT = 2
        self.warned = set()  # Syscalls we don't know about that we've seen

        # We track when processes try accessing or IOCTLing on missing files here:
        self.file_failures = (
            {}
        )  # path: {event: {count: X}}. Event is like open/read/ioctl/stat/lstat.

        if self.get_arg("conf") is None or "pseudofiles" not in self.get_arg("conf"):
            raise ValueError("No 'pseudofiles' in config: {self.get_arg('conf')}")

        self.config = self.get_arg("conf")
        self.devfs = []
        self.procfs = []
        self.sysfs = []
        # self.last_symex = None
        self.warned = set()
        self.need_ioctl_hooks = False
        self.hf_config = self.populate_hf_config()

        self.logger.debug("Registered pseudofiles:")
        for filename, details in self.hf_config.items():
            self.logger.debug(f"  {filename}")

        # filename -> {read: model, write: model, ioctls: model}
        # Coordinates with hyperfile for modeling behavior!
        # Can we just pass our config straight over and load both?
        # Need to implement read, write, and IOCTLs
        # IOCTLs with symex gets scary, others are easy though?
        from hyperfile import HyperFile
        plugins.load(
            HyperFile,
            {
                "models": self.hf_config,
                "log_file": pjoin(self.outdir, outfile_models),
                "logger": self.logger,
            },
        )
        # Clear results file - we'll update it as we go
        self.dump_results()

        plugins.subscribe(plugins.Events, "igloo_hyp_enoent", self.hyp_enoent)

        # Open/openat is a special case with hypercalls helping us out
        # because openat requires guest introspection to resolve the dfd, but we just
        # did it in the kernel
        plugins.subscribe(plugins.Events, "igloo_open", self.fail_detect_opens)
        plugins.subscribe(plugins.Events, "igloo_ioctl", self.fail_detect_ioctl)

        # On ioctl return we might want to start symex. We detect failures with a special handler though
        if self.need_ioctl_hooks:
            plugins.syscalls.syscall("on_sys_ioctl_return")(self.symex_ioctl_return)

    def gen_hyperfile_function(self, filename: str, details: dict, ftype: str):
        """
        Generate a HyperFile function for a given file and operation type.

        **Arguments**:
        - filename (`str`): Name of the pseudo-file.
        - details (`dict`): File modeling details.
        - ftype (`str`): Operation type ('read', 'write', 'ioctl').

        **Returns**:
        - Callable implementing the model for the operation.
        """
        if ftype not in details or "model" not in details[ftype]:
            model = "default"  # default is default
        else:
            model = details[ftype]["model"]

        if hasattr(self, f"{ftype}_{model}"):
            # Have a model specified
            fn = getattr(self, f"{ftype}_{model}")
        elif model == "from_plugin":
            plugin_name = details[ftype]["plugin"]
            plugin = getattr(plugins, plugin_name)
            func = details[ftype].get("function", ftype)
            if hasattr(plugin, func):
                fn = getattr(plugin, func)
            else:
                raise ValueError(f"Hyperfile {filename} depends on plugin {plugin} which does not have function {func}")
        else:
            if ftype == "ioctl":
                guess = {"pseudofiles": {filename: {"*": details}}}
                raise ValueError(
                    f"Invalid ioctl settings. Must specify ioctl number (or '*') within ioctl dictionary, then map each to a model. Did you mean: {guess}"
                )
            raise ValueError(
                f"Unsupported hyperfile {ftype}_{model} for {filename}: {details[ftype] if ftype in details else None}"
            )
        return make_rwif(
            details[ftype] if ftype in details else {}, fn
        )

    def populate_hf_config(self) -> dict:
        """
        Populate the HyperFile configuration from the plugin config.

        **Arguments**:
        - None

        **Returns**:
        - `dict`: HyperFile configuration dictionary.
        """
        # XXX We need this import in here, otherwise when we load psueodfiles with panda.load_plugin /path/to/pseudofiles.py
        # it sees both FileFailures AND HyperFile. But we only want hyperfile to be loaded by us here, not by our caller.
        # we are not currently using HYPER_WRITE so we do not import it
        from hyper.consts import hyperfs_file_ops as fops
        from hyperfile import (HyperFile, hyper)
        HYP_IOCTL = fops.HYP_IOCTL
        HYP_READ = fops.HYP_READ
        hf_config = {}
        for filename, details in self.config["pseudofiles"].items():
            hf_config[filename] = {}

            for targ, prefix in [
                (self.devfs, "/dev/"),
                (self.procfs, "/proc/"),
                (self.sysfs, "/sys/"),
            ]:
                if filename.startswith(prefix):
                    targ.append(filename[len(prefix):])

            hf_config[filename]["size"] = details.get("size", 0)

            # Check if any details with non /dev/mtd names has a 'name' property
            if not filename.startswith("/dev/mtd") and "name" in details:
                raise ValueError(
                    "Pseudofiles: name property can only be set for MTD devices"
                )
            if filename.startswith("/dev/mtd") and "name" not in details:
                raise ValueError(
                    "Pseudofiles: name property must be set for MTD devices"
                )

            for ftype in "read", "write", "ioctl":
                hf_config[filename][hyper(ftype)] = self.gen_hyperfile_function(filename, details, ftype)
                if (
                    ftype == "ioctl"
                    and ftype in details
                    and "model" not in details[ftype]
                    and any([x["model"] == "symex" for x in details[ftype].values()])
                ):
                    # If we have a symex model we'll need to enable some extra introspection
                    self.need_ioctl_hooks = True

        if len(self.get_arg("conf").get("netdevs", [])):
            # If we have netdevs in our config, we'll make the /proc/penguin_net pseudofile with the contents of it
            # Here we'll use our make_rwif closure
            netdev_val = " ".join(self.get_arg("conf")["netdevs"])
            hf_config["/proc/penguin_net"] = {
                HYP_READ: make_rwif({"val": netdev_val}, self.read_const_buf),
                "size": len(netdev_val),
            }

        hf_config["/proc/mtd"] = {
            # Note we don't use our make_rwif closure helper here because these are static
            HYP_READ: self.proc_mtd_check,
            HYP_IOCTL: HyperFile.ioctl_unhandled,
            "size": 0,
        }
        return hf_config

    def symex_ioctl_return(self, cpu, proto, syscall, fd, cmd, arg):
        """
        Handle the return from an ioctl syscall and launch symbolic execution if needed.

        **Arguments**:
        - cpu: CPU context (opaque, framework-specific)
        - proto: Protocol context (opaque, framework-specific)
        - syscall: Syscall context, with `.retval` for return value
        - fd: File descriptor
        - cmd: IOCTL command
        - arg: IOCTL argument

        **Returns**:
        - None
        """
        # We'll return -999 as a magic placeholder value that indicates we should
        # Start symex. Is this a terrible hack. You betcha!
        rv = syscall.retval

        if rv != MAGIC_SYMEX_RETVAL:
            return

        if not hasattr(self, "symex"):
            # Initialize symex on first use
            from symex import PathExpIoctl

            self.symex = PathExpIoctl(self.outdir, self.config["core"]["fs"])

        # Look through our config and find the filename with a symex model
        # XXX: This is a bit of a hack - we're assuming we only have one symex model
        filename = None
        for fname, file_model in self.config["pseudofiles"].items():
            if "ioctl" in file_model:
                for _, model in file_model["ioctl"].items():
                    if model["model"] == "symex":
                        filename = fname
                        break

        if filename is None:
            raise ValueError(
                "No filename with symex model found in config, but we got a symex ioctl. Unexpected"
            )

        # It's time to launch symex!
        self.symex.do_symex(self.panda, cpu, syscall.pc, filename, cmd)

        # We write down the "failure" so we can see that it happened (and know to query symex
        # to get results)
        self.log_ioctl_failure(filename, cmd)

        # set retval to 0 with no error.
        syscall.retval = 0

    def hyp_enoent(self, cpu, file: str):
        """
        Handle ENOENT (file not found) events for pseudo-files.

        **Arguments**:
        - cpu: CPU context (opaque, framework-specific)
        - file (`str`): File path accessed

        **Returns**:
        - None
        """
        if any(file.startswith(x) for x in ("/dev/", "/proc/", "/sys/")):
            self.centralized_log(file, "syscall")

    #######################################
    def centralized_log(self, path: str, event: str, event_details=None):
        """
        Log a failure to access a given path if it is interesting.

        **Arguments**:
        - path (`str`): File path accessed
        - event (`str`): Event type (e.g., 'open', 'read', 'ioctl')
        - event_details: Optional additional event details

        **Returns**:
        - None
        """
        # Log a failure to open a given path if it's interesting
        # We just track count
        if not path_interesting(path):
            return

        if path.startswith("/proc/"):
            # replace /proc/<pid> with /proc/<PID> to avoid a ton of different paths
            path = re.sub(r"/proc/\d+", "/proc/PID", path)

        if path not in self.file_failures:
            self.file_failures[path] = {}

        if event not in self.file_failures[path]:
            self.file_failures[path][event] = {"count": 0}

        if "count" not in self.file_failures[path][event]:
            # If we ioctl'd before opening, we'll have a count-free entry
            self.file_failures[path][event]["count"] = 0

        self.file_failures[path][event]["count"] += 1

        if event_details is not None:
            if "details" not in self.file_failures[path][event]:
                self.file_failures[path][event]["details"] = []
            self.file_failures[path][event]["details"].append(event_details)

    def proc_mtd_check(self, filename: str, buffer, length: int, offset: int, details=None):
        """
        Populate /proc/mtd dynamically based on configured MTD devices.
        return (data, 0)  # data, rv

    def read_const_buf(self, filename, buffer, length, offset, details=None):
        data = details["val"].encode() + b"\x00"  # Null terminate?
        final_data = data[offset: offset + length]
        # XXX if offset > len(data) should we return an error instead of 0?

        **Arguments**:            return (b"", 0)  # -EINVAL
        - filename (`str`): File being read (should be '/proc/mtd')
        return (final_data, len(final_data))  # data, rv
        - buffer: Buffer to read into (unused)
        - length (`int`): Number of bytes to read
        - offset (`int`): Offset into the file
        - details: Additional details (unused)buffer

        **Returns**:        if "pad" in details:
        - Tuple[bytes, int]: Data read and number of bytes read
        """                pad = details["pad"].encode()
        assert filename == "/proc/mtd""pad"], int):

        # For each device in our config that's /dev/mtdX, we'll add a line to the buffer
        # Buffer size is limited to 512 in kernel for now. ValueError("const_map: pad value must be string or int")
        buf = ""
        did_warn = Falseails else 0x10000
        for filename, details in self.config["pseudofiles"].items():
            if not filename.startswith("/dev/mtd"):
                continueghest
: v for k, v in sorted(vals.items(), key=lambda item: item[0])}
            idx = filename.split("/dev/mtd")[1]
            if idx.startswith("/"):  # i.e., /dev/mtd/0 -> 0        # now we flatten. For each offset, val pair
                idx = idx[1:]
ist(vals.keys())[0] if len(vals.keys()) else 0)
            if not idx.isdigit():
                if not self.did_mtd_warn:
                    did_warn = True
                    self.logger.warning(            # may be a string, a list of ints (for non-printable chars)
                        f"Mtd device {filename} is non-numeric. Skipping in /proc/mtd report"null terminators
                    )
                continue
                val = val.encode()
            if "name" not in details:
                if not self.did_mtd_warn:
                    did_warn = True
                    self.logger.warning(
                        f"Mtd device {filename} has no name. Skipping in /proc/mtd report"
                    ) type. Could support a list of lists e.g., ["key=val", [0x41, 0x00, 0x42], ...]?
                continue
                for this_val in val[1:]:
            buf += 'mtd{}: {:08x} {:08x} "{}"\n'.format(his_val, type(first_val)):
                int(idx), 0x1000000, 0x20000, details["name"]lueError(
            )atching vals but we have {this_val} and {first_val}"
                        )
        if did_warn:
            self.did_mtd_warn = Truet_val, int):
ints - these are non-printable chars
        buf = buf[offset: offset + length].encode()

        if len(buf) == 0:
            with open(pjoin(self.outdir, "pseudofiles_proc_mtd.txt"), "w") as f:n this list with null bytes
                f.write("/proc/mtd was read with no devices in config")                    val = b"\x00".join([x.encode() for x in val])

            # The guest read /proc/mtd, but we didn't have anything set up in it! Perhaps
            # it's looking for a device of a specific name - potential failure we can mitigateals must be strings lists of ints/strings"
            # self.file_failures['/proc/mtd'] = {'read': {'count': 1, 'details': 'special: no mtd devices in pseudofiles'}}                )

        return (buf, len(buf))lue

    def fail_detect_ioctl(self, cpu, fname: str, cmd: int):
        """
        Detect and log ioctl failures on pseudo-files.}"
ad * (size - len(data))
        **Arguments**:        return data
        - cpu: CPU context (opaque, framework-specific)
        - fname (`str`): File path accessedngth, offset, details=None):
        - cmd (`int`): IOCTL command        data = self._render_file(details)
: offset + length]
        **Returns**:
        - Noneno bytes read
        """
        # A regular (non-dyndev) device was ioctl'd and is returning -ENOTTY so our hypercall triggers        return (final_data, len(final_data))  # data, length
        self.log_ioctl_failure(fname, cmd)
e, buffer, length, offset, details=None):
    def fail_detect_opens(self, cpu, fname: str, fd: int):ified pad, size, vals
        """e guest, we read from the host file.
        Detect and log open failures (ENOENT) on pseudo-files.

        **Arguments**:
        - cpu: CPU context (opaque, framework-specific)            # Paths are relative to the project directory, unless absolute
        - fname (`str`): File path accessed
        - fd (`int`): File descriptor returned

        **Returns**:
        - None            data = self._render_file(details)
        """le
        fd = self.panda.from_unsigned_guest(fd)

        if fd == -self.ENOENT:
            # enoent let's gooooo
            self.centralized_log(fname, "open")) as f:

    def log_ioctl_failure(self, path: str, cmd: int):ength)
        """
        Log an ioctl failure for a given path and command.en(final_data))  # data, length

        **Arguments**:filename, buffer, length, offset, details=None):
        - path (`str`): File path accessedlename} with {length} bytes at {offset}:")
        - cmd (`int`): IOCTL commandilename"]  # Host file

        **Returns**:        if not isabs(fname):
        - Nonenless absolute
        """            fname = pjoin(self.proj_dir, fname)
        # This might trigger twice, depending on the -ENOTTY path
        # between our dyndev ioctl handler and do_vfs_ioctl?

        if ignore_ioctl_path(path) or ignore_cmd(cmd):            data = f.read(length)
            # Uninteresting
            return

        if path not in self.file_failures:    def write_to_file(self, filename, buffer, length, offset, contents, details=None):
            self.file_failures[path] = {} # Host file
):
        if "ioctl" not in self.file_failures[path]:to the project directory, unless absolute
            self.file_failures[path]["ioctl"] = {}            fname = pjoin(self.proj_dir, fname)

        first = False            f"Writing {fname} with {length} bytes at {offset}: {contents[:100]}"
        if cmd not in self.file_failures[path]["ioctl"]:
            self.file_failures[path]["ioctl"][cmd] = {"count": 0}
            first = True") as f:

        self.file_failures[path]["ioctl"][cmd]["count"] += 1
        if first:
            # The first time we see an IOCTL update our results on disk
            # This is just relevant if someone's watching the output during a run
            # final results are always written at the end.    def write_discard(self, filename, buffer, length, offset, contents, details=None):
            self.dump_results()iscard - not sure where it's used right now and default is a better model in general
            self.logger.debug(f"New ioctl failure observed: {cmd:x} on {path}")default(filename, buffer, length, offset, contents, details)

    def read_zero(self, filename: str, buffer, length: int, offset: int, details=None):    def write_default(self, filename, buffer, length, offset, contents, details=None):
        """ontents for this file
        Model a read that returns zero bytes or previously written data.        # print(f"{filename} writes {length} bytes at {offset}: {contents[:100]}")

        **Arguments**:
        - filename (`str`): File being read
        - buffer: Buffer to read into (unused)        previous = self.written_data[filename][:offset]
        - length (`int`): Number of bytes to read
        - offset (`int`): Offset into the file
        - details: Additional details (unused)

        **Returns**:
        - Tuple[bytes, int]: Data read and number of bytes read
        """
        data = b"0"filename][offset + length:]
        if filename in self.written_data:en_data[filename]) > offset + length
            data = self.written_data[filename]

        final_data = data[offset: offset + length]
        # XXX if offset > len(data) should we return an error instead of 0?
        return (final_data, len(final_data))  # data, rv
ld we explicitly error and require a model?
    def read_one(self, filename: str, buffer, length: int, offset: int, details=None):nts, details=None):
        """d_log(filename, 'write')
        Model a read that returns one bytes or previously written data.rn -22 # -EINVAL - we don't support writes

        **Arguments**:- log failures
        - filename (`str`): File being read    def read_default(self, filename, buffer, length, offset, details=None):
        - buffer: Buffer to read into (unused)
        - length (`int`): Number of bytes to read
        - offset (`int`): Offset into the file
        - details: Additional details (unused)
    # default is a bit of a misnomer, it's our default ioctl handler which
        **Returns**:i.e., error) on issue of unspecified ioctls,
        - Tuple[bytes, int]: Data read and number of bytes read
        """, ioctl_details):
        data = b"1"
        if filename in self.written_data:        Given a cmd and arg, return a value
            data = self.written_data[filename]

        final_data = data[offset: offset + length]
        # XXX if offset > len(data) should we return an error instead of 0?
        return (final_data, len(final_data))  # data, rv
ry to use cmd as our key, but '*' is a fallback
    def read_empty(self, filename: str, buffer, length: int, offset: int, details=None):
        """:
        Model a read that returns an empty buffer.ails[cmd]

        **Arguments**:l_details["*"]
        - filename (`str`): File being read # is_wildcard = True
        - buffer: Buffer to read into (unused)
        - length (`int`): Number of bytes to readilure(filename, cmd)
        - offset (`int`): Offset into the fileY
        - details: Additional details (unused)
"]
        **Returns**:
        - Tuple[bytes, int]: Empty data and zero bytes readt":
        """v = cmd_details["val"]
        data = b""
        # XXX if offset > len(data) should we return an error instead of 0?
        return (data, 0)  # data, rv        elif model == "symex":
fferent from normal models.
    def read_const_buf(self, filename: str, buffer, length: int, offset: int, details=None):            # First off, these models need to specify a 'val' just like any other
        """and, to be honest, during) symex.
        Model a read that returns a constant buffer.s use 0 when doing symex!

        **Arguments**:            # if self.last_symex:
        - filename (`str`): File being readt and encode info in our retval
        - buffer: Buffer to read into (unused)lly
        - length (`int`): Number of bytes to read
        - offset (`int`): Offset into the file
        - details: Additional details, must contain 'val' key
            return MAGIC_SYMEX_RETVAL  # We'll detect this on the return and know what to do. I think?
        **Returns**:n":
        - Tuple[bytes, int]: Data read and number of bytes read
        """
        data = details["val"].encode() + b"\x00"  # Null terminate?", "ioctl")
        final_data = data[offset: offset + length]
        # XXX if offset > len(data) should we return an error instead of 0?c)
        if offset > len(data):
            return (b"", 0)  # -EINVALyperfile {filename} depends on plugin {plugin} which does not have function {func}")
etails)
        return (final_data, len(final_data))  # data, rv
rmed. Bail
    def _render_file(self, details: dict) -> bytes:orted ioctl model {model} for cmd {cmd}")
        """
        Render a file's contents from a details dictionary.

        **Arguments**:
        - details (`dict`): File modeling detailsopen(pjoin(self.outdir, outfile_missing), "w") as f:

        **Returns**:
        - `bytes`: Rendered file data
        """        if hasattr(self, "symex"):
        pad = b"\x00"symex to export results as well
        if "pad" in details:
            if isinstance(details["pad"], str):
                pad = details["pad"].encode()
            elif isinstance(details["pad"], int):                pad = bytes([details["pad"]])            else:                raise ValueError("const_map: pad value must be string or int")        size = details["size"] if "size" in details else 0x10000        vals = details["vals"]
        # sort vals dict by key, lowest to highest
        vals = {k: v for k, v in sorted(vals.items(), key=lambda item: item[0])}

        # now we flatten. For each offset, val pair
        # Need to grab first offset, then pad to that
        data = b""  # pad * (list(vals.keys())[0] if len(vals.keys()) else 0)

        for off, val in vals.items():
            # We have offset: value where value
            # may be a string, a list of ints (for non-printable chars)
            # or a list of strings to be joined by null terminators

            if isinstance(val, str):
                val = val.encode()

            elif isinstance(val, list):
                if not len(val):
                    continue  # Wat?

                # All shoudl be same type. Could support a list of lists e.g., ["key=val", [0x41, 0x00, 0x42], ...]?
                first_val = val[0]
                for this_val in val[1:]:
                    if not isinstance(this_val, type(first_val)):
                        raise ValueError(
                            f"Need matching vals but we have {this_val} and {first_val}"
                        )

                if isinstance(first_val, int):
                    # We have a list of ints - these are non-printable chars
                    val = bytes(val)

                elif isinstance(first_val, str):
                    # Join this list with null bytes
                    val = b"\x00".join([x.encode() for x in val])
            else:
                raise ValueError(
                    "_render_file: vals must be strings lists of ints/strings"
                )

            # Pad before this value, then add the value
            data += pad * (off - len(data)) + val

        # Finally pad up to size
        assert len(data) <= size, f"Data is too long: {len(data)} > size {size}"
        data += pad * (size - len(data))
        return data

    def read_const_map(self, filename: str, buffer, length: int, offset: int, details=None):
        """
        Model a read that returns data from a constant map.

        **Arguments**:
        - filename (`str`): File being read
        - buffer: Buffer to read into (unused)
        - length (`int`): Number of bytes to read
        - offset (`int`): Offset into the file
        - details: Additional details (must contain 'vals' and optionally 'pad', 'size')

        **Returns**:
        - Tuple[bytes, int]: Data read and number of bytes read
        """
        data = self._render_file(details)
        final_data = data[offset: offset + length]
        if offset > len(data):
            return (b"", 0)  # No data, no bytes read

        return (final_data, len(final_data))  # data, length

    def read_const_map_file(self, filename: str, buffer, length: int, offset: int, details=None):
        """
        Model a read that returns data from a host file, creating it if needed.

        **Arguments**:
        - filename (`str`): File being read
        - buffer: Buffer to read into (unused)
        - length (`int`): Number of bytes to read
        - offset (`int`): Offset into the file
        - details: Additional details (must contain 'filename', 'vals', etc.)

        **Returns**:
        - Tuple[bytes, int]: Data read and number of bytes read
        """
        hostfile = details["filename"]

        if not isabs(hostfile):
            # Paths are relative to the project directory, unless absolute
            hostfile = pjoin(self.proj_dir, hostfile)

        # Create initial host file
        if not isfile(hostfile):
            data = self._render_file(details)
            # Create initial file
            with open(hostfile, "wb") as f:
                f.write(data)

        # Read from host file
        with open(hostfile, "rb") as f:
            f.seek(offset)
            final_data = f.read(length)

        return (final_data, len(final_data))  # data, length

    def read_from_file(self, filename: str, buffer, length: int, offset: int, details=None):
        """
        Model a read that returns data from a specified host file.

        **Arguments**:
        - filename (`str`): File being read
        - buffer: Buffer to read into (unused)
        - length (`int`): Number of bytes to read
        - offset (`int`): Offset into the file
        - details: Additional details (must contain 'filename')

        **Returns**:
        - Tuple[bytes, int]: Data read and number of bytes read
        """
        self.logger.debug(f"Reading {filename} with {length} bytes at {offset}:")
        fname = details["filename"]  # Host file

        if not isabs(fname):
            # Paths are relative to the project directory, unless absolute
            fname = pjoin(self.proj_dir, fname)

        with open(fname, "rb") as f:
            f.seek(offset)
            data = f.read(length)

        return (data, len(data))

    def write_to_file(self, filename: str, buffer, length: int, offset: int, contents: bytes, details=None) -> int:
        """
        Model a write that writes data to a specified host file.

        **Arguments**:
        - filename (`str`): File being written
        - buffer: Buffer to write from (unused)
        - length (`int`): Number of bytes to write
        - offset (`int`): Offset into the file
        - contents (`bytes`): Data to write
        - details: Additional details (must contain 'filename')

        **Returns**:
        - `int`: Number of bytes written
        """
        fname = details["filename"]  # Host file
        if not isabs(fname):
            # Paths are relative to the project directory, unless absolute
            fname = pjoin(self.proj_dir, fname)
        self.logger.debug(
            f"Writing {fname} with {length} bytes at {offset}: {contents[:100]}"
        )

        with open(fname, "ab") as f:
            f.seek(offset)
            f.write(contents)

        return length

    def write_discard(self, filename: str, buffer, length: int, offset: int, contents: bytes, details=None) -> int:
        """
        Model a write that discards data (no-op).

        **Arguments**:
        - filename (`str`): File being written
        - buffer: Buffer to write from (unused)
        - length (`int`): Number of bytes to write
        - offset (`int`): Offset into the file
        - contents (`bytes`): Data to write
        - details: Additional details (unused)

        **Returns**:
        - `int`: Number of bytes written (same as input length)
        """
        # TODO: make this actually discard - not sure where it's used right now and default is a better model in general
        return self.write_default(filename, buffer, length, offset, contents, details)

    def write_default(self, filename: str, buffer, length: int, offset: int, contents: bytes, details=None) -> int:
        """
        Model a write that stores data in memory for the file.

        **Arguments**:
        - filename (`str`): File being written
        - buffer: Buffer to write from (unused)
        - length (`int`): Number of bytes to write
        - offset (`int`): Offset into the file
        - contents (`bytes`): Data to write
        - details: Additional details (unused)

        **Returns**:
        - `int`: Number of bytes written
        """
        # Store the contents for this file
        # print(f"{filename} writes {length} bytes at {offset}: {contents[:100]}")
        if filename not in self.written_data:
            self.written_data[filename] = b""
        # Seek to offset and write contents
        previous = self.written_data[filename][:offset]
        if len(previous) < offset:
            # Pad with null bytes
            previous += b"\x00" * (offset - len(previous))
        self.written_data[filename] = (
            previous
            + contents
            + (
                self.written_data[filename][offset + length:]
                if len(self.written_data[filename]) > offset + length
                else b""
            )
        )
        return length

    # XXX on write we can allow and store by default. Or should we explicitly error and require a model?
    # def write_default(self, filename, buffer, length, offset, contents, details=None):
    #    self.centralized_log(filename, 'write')
    #    return -22 # -EINVAL - we don't support writes

    # default models - log failures
    def read_default(self, filename: str, buffer, length: int, offset: int, details=None):
        """
        Default model for reads: logs the failure and returns error.

        **Arguments**:
        - filename (`str`): File being read
        - buffer: Buffer to read into (unused)
        - length (`int`): Number of bytes to read
        - offset (`int`): Offset into the file
        - details: Additional details (unused)

        **Returns**:
        - Tuple[bytes, int]: Empty data and error code (-22)
        """
        self.centralized_log(filename, "read")
        return (b"", -22)  # -EINVAL - we don't support reads

    # IOCTL is more complicated than read/write.
    # default is a bit of a misnomer, it's our default ioctl handler which
    # implements default behavior (i.e., error) on issue of unspecified ioctls,
    # but implements what it's told for others
    def ioctl_default(self, filename: str, cmd: int, arg, ioctl_details: dict) -> int:
        """
        Default model for ioctls: returns constant, launches symex, or delegates to plugin.

        **Arguments**:
        - filename (`str`): File being accessed
        - cmd (`int`): IOCTL command
        - arg: IOCTL argument
        - ioctl_details (`dict`): IOCTL modeling details

        **Returns**:
        - `int`: Return value for the ioctl operation
        """
        # Try to use cmd as our key, but '*' is a fallback
        # is_wildcard = False
        if cmd in ioctl_details:
            cmd_details = ioctl_details[cmd]
        elif "*" in ioctl_details:
            cmd_details = ioctl_details["*"]
            # is_wildcard = True
        else:
            self.log_ioctl_failure(filename, cmd)
            return -25  # -ENOTTY

        model = cmd_details["model"]

        if model == "return_const":
            rv = cmd_details["val"]
            return rv

        elif model == "symex":
            # Symex is tricky and different from normal models.
            # First off, these models need to specify a 'val' just like any other
            # for us to use after (and, to be honest, during) symex.
            # JK: we're gonna always use 0 when doing symex!

            # if self.last_symex:
            # We could be smart and encode info in our retval
            # or do something else. I don't think we want to fully
            # ignore? But we probably could?
            # raise NotImplementedError("Uhhhh nested symex")
            # self.last_symex = filename
            return MAGIC_SYMEX_RETVAL  # We'll detect this on the return and know what to do. I think?
        elif model == "from_plugin":
            plugin_name = cmd_details["plugin"]
            plugin = getattr(plugins, plugin_name)
            func = cmd_details.get("function", "ioctl")
            if hasattr(plugin, func):
                fn = getattr(plugin, func)
            else:
                raise ValueError(f"Hyperfile {filename} depends on plugin {plugin} which does not have function {func}")
            return fn(filename, cmd, arg, cmd_details)
        else:
            # This is an actual error - config is malformed. Bail
            raise ValueError(f"Unsupported ioctl model {model} for cmd {cmd}")
            # return -25 # -ENOTTY

    def dump_results(self):
        """
        Dump all file failures and symex results to disk as YAML.

        **Arguments**:
        - None

        **Returns**:
        - None
        """
        # Dump all file failures to disk as yaml
        with open(pjoin(self.outdir, outfile_missing), "w") as f:
            out = sort_file_failures(self.file_failures)
            yaml.dump(out, f, sort_keys=False)

        if hasattr(self, "symex"):
            # Need to tell symex to export results as well
            self.symex.save_results()

    def uninit(self):
        """
        Called on plugin unload; dumps results to disk.

        **Arguments**:
        - None

        **Returns**:
        - None
        """
        self.dump_results()