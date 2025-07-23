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
    # Directories not in static FS that are added by igloo_init (mostly
    # irrelevant with wrong prefixes)
    "/tmp",
    "/dev/ttyS0",
    "/dev/console",
    "/dev/root",
    "/dev/ram",
    "/dev/ram0"  # We set these up in our init script, common device types
    "/dev/null",
    "/dev/zero",
    "/dev/random",
    "/dev/urandom",  # Standard devices we should see in devtmpfs
    # TODO: pull in devices like how we do during static analysis (e.g.,
    # /resources/proc_sys.txt)
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
    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.proj_dir = self.get_arg("proj_dir")
        self.written_data = {}  # filename -> data that was written to it
        if self.get_arg_bool("penguin_verbose"):
            self.logger.setLevel(logging.DEBUG)
        self.did_mtd_warn = False  # Set if we've warned about misconfigured MTD devices
        # XXX: It has seemed like this should be 1 for some architectures, but
        # that can't be right?
        self.ENOENT = 2
        self.warned = set()  # Syscalls we don't know about that we've seen

        # We track when processes try accessing or IOCTLing on missing files
        # here:
        self.file_failures = (
            {}
        )  # path: {event: {count: X}}. Event is like open/read/ioctl/stat/lstat.

        if self.get_arg(
                "conf") is None or "pseudofiles" not in self.get_arg("conf"):
            raise ValueError(
                "No 'pseudofiles' in config: {self.get_arg('conf')}")

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
        plugins.subscribe(
            plugins.Events,
            "igloo_ioctl",
            self.fail_detect_ioctl)

        # On ioctl return we might want to start symex. We detect failures with
        # a special handler though
        if self.need_ioctl_hooks:
            plugins.syscalls.syscall("on_sys_ioctl_return")(
                self.symex_ioctl_return)

    def gen_hyperfile_function(self, filename, details, ftype):
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
                raise ValueError(
                    f"Hyperfile {filename} depends on plugin {plugin} which does not have function {func}")
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

    def populate_hf_config(self):
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

            # Check if any details with non /dev/mtd names has a 'name'
            # property
            if not filename.startswith("/dev/mtd") and "name" in details:
                raise ValueError(
                    "Pseudofiles: name property can only be set for MTD devices"
                )
            if filename.startswith("/dev/mtd") and "name" not in details:
                raise ValueError(
                    "Pseudofiles: name property must be set for MTD devices"
                )

            for ftype in "read", "write", "ioctl":
                hf_config[filename][hyper(ftype)] = self.gen_hyperfile_function(
                    filename, details, ftype)
                if (
                    ftype == "ioctl"
                    and ftype in details
                    and "model" not in details[ftype]
                    and any([x["model"] == "symex" for x in details[ftype].values()])
                ):
                    # If we have a symex model we'll need to enable some extra
                    # introspection
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
            # Note we don't use our make_rwif closure helper here because these
            # are static
            HYP_READ: self.proc_mtd_check,
            HYP_IOCTL: HyperFile.ioctl_unhandled,
            "size": 0,
        }
        return hf_config

    def symex_ioctl_return(self, regs, proto, syscall, fd, cmd, arg):
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
        # XXX: This is a bit of a hack - we're assuming we only have one symex
        # model
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
        cpu = self.panda.get_cpu()
        # It's time to launch symex!
        self.symex.do_symex(self.panda, cpu, syscall.pc, filename, cmd)

        # We write down the "failure" so we can see that it happened (and know to query symex
        # to get results)
        self.log_ioctl_failure(filename, cmd)

        # set retval to 0 with no error.
        syscall.retval = 0

    def hyp_enoent(self, cpu, file):
        if any(file.startswith(x) for x in ("/dev/", "/proc/", "/sys/")):
            self.centralized_log(file, "syscall")

    #######################################
    def centralized_log(self, path, event, event_details=None):
        # Log a failure to open a given path if it's interesting
        # We just track count
        if not path_interesting(path):
            return

        if path.startswith("/proc/"):
            # replace /proc/<pid> with /proc/<PID> to avoid a ton of different
            # paths
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

    def proc_mtd_check(self, filename, buffer, length, offset, details=None):
        """
        The guest is reading /proc/mtd. We should populate this file
        dynamically based on the /dev/mtd* devices we've set up.

        These devices have a name in addition to other properties:
        /dev/mtd0:
            name: mymtdname
            read:
                model: return_const
                buf: "foo"
        """

        assert filename == "/proc/mtd"

        # For each device in our config that's /dev/mtdX, we'll add a line to the buffer
        # Buffer size is limited to 512 in kernel for now.
        buf = ""
        did_warn = False
        for filename, details in self.config["pseudofiles"].items():
            if not filename.startswith("/dev/mtd"):
                continue

            idx = filename.split("/dev/mtd")[1]
            if idx.startswith("/"):  # i.e., /dev/mtd/0 -> 0
                idx = idx[1:]

            if not idx.isdigit():
                if not self.did_mtd_warn:
                    did_warn = True
                    self.logger.warning(
                        f"Mtd device {filename} is non-numeric. Skipping in /proc/mtd report"
                    )
                continue

            if "name" not in details:
                if not self.did_mtd_warn:
                    did_warn = True
                    self.logger.warning(
                        f"Mtd device {filename} has no name. Skipping in /proc/mtd report"
                    )
                continue

            buf += 'mtd{}: {:08x} {:08x} "{}"\n'.format(
                int(idx), 0x1000000, 0x20000, details["name"]
            )

        if did_warn:
            self.did_mtd_warn = True

        buf = buf[offset: offset + length].encode()

        if len(buf) == 0:
            with open(pjoin(self.outdir, "pseudofiles_proc_mtd.txt"), "w") as f:
                f.write("/proc/mtd was read with no devices in config")

            # The guest read /proc/mtd, but we didn't have anything set up in it! Perhaps
            # it's looking for a device of a specific name - potential failure we can mitigate
            # self.file_failures['/proc/mtd'] = {'read': {'count': 1, 'details': 'special: no mtd devices in pseudofiles'}}

        return (buf, len(buf))

    def fail_detect_ioctl(self, cpu, fname, cmd):
        # A regular (non-dyndev) device was ioctl'd and is returning -ENOTTY so
        # our hypercall triggers
        self.log_ioctl_failure(fname, cmd)

    def fail_detect_opens(self, cpu, fname, fd):
        fd = self.panda.from_unsigned_guest(fd)

        if fd == -self.ENOENT:
            # enoent let's gooooo
            self.centralized_log(fname, "open")

    def log_ioctl_failure(self, path, cmd):
        # This might trigger twice, depending on the -ENOTTY path
        # between our dyndev ioctl handler and do_vfs_ioctl?

        if ignore_ioctl_path(path) or ignore_cmd(cmd):
            # Uninteresting
            return

        if path not in self.file_failures:
            self.file_failures[path] = {}

        if "ioctl" not in self.file_failures[path]:
            self.file_failures[path]["ioctl"] = {}

        first = False
        if cmd not in self.file_failures[path]["ioctl"]:
            self.file_failures[path]["ioctl"][cmd] = {"count": 0}
            first = True

        self.file_failures[path]["ioctl"][cmd]["count"] += 1
        if first:
            # The first time we see an IOCTL update our results on disk
            # This is just relevant if someone's watching the output during a run
            # final results are always written at the end.
            self.dump_results()
            self.logger.debug(f"New ioctl failure observed: {cmd:x} on {path}")

    def read_zero(self, filename, buffer, length, offset, details=None):
        # Simple peripheral model inspired by firmadyne/firmae. Just return 0.
        # If we've seen a write to this device, mix that data in with 0s
        # padding around it
        data = b"0"
        if filename in self.written_data:
            data = self.written_data[filename]

        final_data = data[offset: offset + length]
        # XXX if offset > len(data) should we return an error instead of 0?
        return (final_data, len(final_data))  # data, rv

    def read_one(self, filename, buffer, length, offset, details=None):
        data = b"1"
        if filename in self.written_data:
            data = self.written_data[filename]

        final_data = data[offset: offset + length]
        # XXX if offset > len(data) should we return an error instead of 0?
        return (final_data, len(final_data))  # data, rv

    def read_empty(self, filename, buffer, length, offset, details=None):
        data = b""
        # XXX if offset > len(data) should we return an error instead of 0?
        return (data, 0)  # data, rv

    def read_const_buf(self, filename, buffer, length, offset, details=None):
        data = details["val"].encode() + b"\x00"  # Null terminate?
        final_data = data[offset: offset + length]
        # XXX if offset > len(data) should we return an error instead of 0?
        if offset > len(data):
            return (b"", 0)  # -EINVAL

        return (final_data, len(final_data))  # data, rv

    def _render_file(self, details):
        # Given offset: data mapping plus a pad, we
        # combine to return a buffer
        pad = b"\x00"
        if "pad" in details:
            if isinstance(details["pad"], str):
                pad = details["pad"].encode()
            elif isinstance(details["pad"], int):
                pad = bytes([details["pad"]])
            else:
                raise ValueError("const_map: pad value must be string or int")

        size = details["size"] if "size" in details else 0x10000
        vals = details["vals"]

        # sort vals dict by key, lowest to highest
        vals = {
            k: v for k,
            v in sorted(
                vals.items(),
                key=lambda item: item[0])}

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

                # All shoudl be same type. Could support a list of lists e.g.,
                # ["key=val", [0x41, 0x00, 0x42], ...]?
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
        assert len(
            data) <= size, f"Data is too long: {len(data)} > size {size}"
        data += pad * (size - len(data))
        return data

    def read_const_map(self, filename, buffer, length, offset, details=None):
        data = self._render_file(details)
        final_data = data[offset: offset + length]
        if offset > len(data):
            return (b"", 0)  # No data, no bytes read

        return (final_data, len(final_data))  # data, length

    def read_const_map_file(self, filename, buffer,
                            length, offset, details=None):
        # Create a file on the host using the specified pad, size, vals
        # When we read from the guest, we read from the host file.
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

    def read_from_file(self, filename, buffer, length, offset, details=None):
        self.logger.debug(
            f"Reading {filename} with {length} bytes at {offset}:")
        fname = details["filename"]  # Host file

        if not isabs(fname):
            # Paths are relative to the project directory, unless absolute
            fname = pjoin(self.proj_dir, fname)

        with open(fname, "rb") as f:
            f.seek(offset)
            data = f.read(length)

        return (data, len(data))

    def write_to_file(self, filename, buffer, length,
                      offset, contents, details=None):
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

    def write_discard(self, filename, buffer, length,
                      offset, contents, details=None):
        # TODO: make this actually discard - not sure where it's used right now
        # and default is a better model in general
        return self.write_default(
            filename, buffer, length, offset, contents, details)

    def write_default(self, filename, buffer, length,
                      offset, contents, details=None):
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
    def read_default(self, filename, buffer, length, offset, details=None):
        self.centralized_log(filename, "read")
        return (b"", -22)  # -EINVAL - we don't support reads

    # IOCTL is more complicated than read/write.
    # default is a bit of a misnomer, it's our default ioctl handler which
    # implements default behavior (i.e., error) on issue of unspecified ioctls,
    # but implements what it's told for others
    def ioctl_default(self, filename, cmd, arg, ioctl_details):
        """
        Given a cmd and arg, return a value
        filename is device path
        ioctl_details is a dict of:
            cmd -> {'model': 'return_const'|'symex',
                     'val': X}
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
            # We'll detect this on the return and know what to do. I think?
            return MAGIC_SYMEX_RETVAL
        elif model == "from_plugin":
            plugin_name = cmd_details["plugin"]
            plugin = getattr(plugins, plugin_name)
            func = cmd_details.get("function", "ioctl")
            if hasattr(plugin, func):
                fn = getattr(plugin, func)
            else:
                raise ValueError(
                    f"Hyperfile {filename} depends on plugin {plugin} which does not have function {func}")
            return fn(filename, cmd, arg, cmd_details)
        else:
            # This is an actual error - config is malformed. Bail
            raise ValueError(f"Unsupported ioctl model {model} for cmd {cmd}")
            # return -25 # -ENOTTY

    def dump_results(self):
        # Dump all file failures to disk as yaml
        with open(pjoin(self.outdir, outfile_missing), "w") as f:
            out = sort_file_failures(self.file_failures)
            yaml.dump(out, f, sort_keys=False)

        if hasattr(self, "symex"):
            # Need to tell symex to export results as well
            self.symex.save_results()

    def uninit(self):
        self.dump_results()
