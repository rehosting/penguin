import sys
import re
import math
import logging
import struct
from os.path import dirname, join as pjoin, isfile
from pandare import PyPlugin
from copy import deepcopy
from typing import Dict, Any, List
from collections import Counter
import pycparser

from sys import path
path.append(dirname(__file__))
from symex import PathExpIoctl

KNOWN_PATHS = ["/dev/", "/dev/pts", "/sys", "/proc", "/run", "/tmp",  # Directories not in static FS that are added by igloo_init (mostly irrelevant with wrong prefixes)
               "/dev/ttyS0", "/dev/console", "/dev/root", "/dev/ram", "/dev/ram0" # We set these up in our init script, common device types
               "/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", # Standard devices we should see in devtmpfs
               ]

try:
    from penguin import PenguinAnalysis, yaml
    from penguin.graphs import Failure, Mitigation, Configuration
    from penguin.utils import arch_end
except ImportError:
    # We can still run as a PyPlugin, but we can't do post-run analysis
    PenguinAnalysis = object
    import yaml

# Missing files go into our first log
outfile_missing = "pseudofiles_failures.yaml"
# Files we're modeling go into the second. Particularly useful for defaults
outfile_models = "pseudofiles_modeled.yaml"
MAGIC_SYMEX_RETVAL = 999

def path_interesting(path):
    if '/pipe:[' in path:
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
    '''
    Ignore TTY ioctls, see ioctls.h for T*, TC*, and TIO* ioctls
    '''
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

def make_syscall_info_table():
    """
    Table format: arch -> nr -> (name, arg_names).
    The names do not have a sys_ prefix.
    """

    def parse_c(input):
        input = re.sub(r"\b__user\b", "", input)
        # We don't care about the types. Just replace them with int so parsing succeeds.
        types = [
            'size_t', 'umode_t', 'time_t', 'old_uid_t', 'old_gid_t', 'off_t',
            'pid_t', 'old_sigset_t', 'qid_t', 'loff_t', 'fd_set', 'sigset_t',
            'siginfo_t', 'cap_user_header_t', 'cap_user_data_t', 'uid_t',
            'gid_t', 'timer_t', 'u64', 'u32', 'aio_context_t', 'clockid_t',
            'mqd_t', 'key_t', 'key_serial_t', '__s32', 'old_time32_t',
            '__sighandler_t', 'caddr_t', '__u32', 'rwf_t', 'uint32_t',
        ]
        input = re.sub(rf"\b({'|'.join(types)})\b", "int", input)
        return pycparser.c_parser.CParser().parse(input)

    def parse_protos_file(arch):
        with open(f"/igloo_static/syscalls/linux_{arch}_prototypes.txt") as f:
            lines = [
                line.split(maxsplit=1) for line in f.readlines()
                if not line.startswith("//")
            ]

        return [(int(nr), parse_c(sig)) for nr, sig in lines]

    return {
        arch: {
            nr: (
                ast.ext[0].name.replace("sys_", ""),
                tuple(p.name for p in ast.ext[0].type.args.params),
            ) for nr, ast in parse_protos_file(arch)
        } for arch in ("arm", "mips", "mips64")
    }


class FileFailures(PyPlugin):
    def __init__(self, panda):
        # XXX We need this import in here, otherwise when we load psueodfiles with panda.load_plugin /path/to/pseudofiles.py
        # it sees both FileFailures AND HyperFile. But we only want hyperfile to be loaded by us here, not by our caller.
        from hyperfile import HyperFile, HYPER_READ, HYPER_WRITE, HYPER_IOCTL, hyper

        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.written_data = {} # filename -> data that was written to it

        # XXX: It has seemed like this should be 1 for some architectures, but that can't be right?
        self.ENOENT = 2
        self.warned = set() # Syscalls we don't know about that we've seen

        # We track when processes try accessing or IOCTLing on missing files here:
        self.file_failures = {} # path: {event: {count: X}}. Event is like open/read/ioctl/stat/lstat.

        if self.get_arg("conf") is None or "pseudofiles" not in self.get_arg("conf"):
            raise ValueError("No 'pseudofiles' in config: {self.get_arg('conf')}")

        self.config = self.get_arg("conf")
        # Expect filename: {'read': 'default' OR 'zero' or 'one'
        #                   'write': 'default' OR 'discard',
        #                   'ioctl': {
        #                               '*' OR num: {'model': 'X', 'val': Y}
        #                               }

        self.devfs = []
        self.procfs = []
        self.sysfs = []
        #self.last_symex = None
        self.warned = set()
        need_ioctl_hooks = False

        # Closure so we can pass details through
        def make_rwif(details, fn_ref):
            def rwif(*args):
                return fn_ref(*args, details)
            return rwif

        hf_config = {}
        for filename, details in self.config["pseudofiles"].items():
            hf_config[filename] = {}

            for (targ, prefix) in [(self.devfs, "/dev/"), (self.procfs, "/proc/"), (self.sysfs, "/sys/")]:
                if filename.startswith(prefix):
                    targ.append(filename[len(prefix):])


            # Make sure each key is one of our 3 allowed values, not a junk value
            if any(x not in ['read', 'write', 'ioctl', 'name'] for x in details.keys()):
                raise ValueError("pseudofiles: each file must have a read, write, or ioctl key. No other keys are supported")

            # Check if any details with non /dev/mtd names has a 'name' property
            for fname in details:
                if not fname.startswith("/dev/mtd") and 'name' in details[fname]:
                    raise ValueError("Pseudofiles: name property can only be set for MTD devices")
                if fname.startswith("/dev/mtd") and not 'name' in details[fname]:
                    raise ValueError("Pseudofiles: name property must be set for MTD devices")


            for ftype in "read", "write", "ioctl":
                if ftype not in details or "model" not in details[ftype]:
                    model = "default" # default is default
                else:
                    model = details[ftype]["model"]

                if not hasattr(self, f"{ftype}_{model}"):
                    if ftype == 'ioctl':
                        guess = {"pseudofiles": {filename: {"*": details}}}
                        raise ValueError(f"Invalid ioctl settings. Must specify ioctl number (or '*') within ioctl dictionary, then map each to a model. Did you mean: {guess}")
                    raise ValueError(f"Unsupported hyperfile {ftype}_{model} for {filename}: {details[ftype] if ftype in details else None}")
                # Have a model specified
                fn = getattr(self, f"{ftype}_{model}")

                hf_config[filename][hyper(ftype)] = make_rwif(details[ftype] if ftype in details else {}, fn)

                if ftype == "ioctl" and ftype in details and any([x["model"] == 'symex' for x in details[ftype].values()]):
                    # If we have a symex model we'll need to enable some extra introspection
                    need_ioctl_hooks = True

        if do_netdevs := len(self.get_arg("conf").get("netdevs", [])):
            # We need to add /proc/net/penguin to our procfs list
            self.procfs.append("penguin_net")

        # We'll update hf_config[dyndev.{devnames,procnames,netdevnames,sysfs}] with the list of devices we're shimming
        for f in ["devnames", "procnames", "netdevnames", "sysfs"]:
            hf_config[f"dyndev.{f}"] = {} #XXX: None of these can be empty - we populate all below

        # This is a bit gross - we pull netdevices from core config here so we can pass to hyperfile
        netdev_str = ""
        if 'netdevnames' in self.config['core']:
            netdev_str = self.config['core']['netdevnames'] # It will be a list
        hf_config['dyndev.netdevnames'][hyper("read")] = make_rwif({'val': ",".join(netdev_str)}, self.read_const_buf)

        #if len(self.devfs):
            #self.get_arg("conf")["env"]["dyndev.devnames"] = ",".join(self.devfs)
            #print(f"Configuring dyndev to shim devices: {self.devfs}")
        hf_config["dyndev.devnames"][hyper("read")] = make_rwif({'val': ",".join(self.devfs)}, self.read_const_buf)

        #if len(self.procfs):
        #    #self.get_arg("conf")["env"]["dyndev.procnames"] = ",".join(procfs)
        #    print(f"Configuring dyndev to shim procfiles: {self.procfs}")
        hf_config["dyndev.procnames"][hyper("read")] = make_rwif({'val': ",".join(self.procfs)}, self.read_const_buf)

        #if len(self.sysfs):
        #    #self.get_arg("conf")["env"]["dyndev.sysfs"] = ",".join(sysfs)
        #    print(f"Configuring dyndev to shim sysfs: {self.sysfs}")
        hf_config["dyndev.sysfs"][hyper("read")] = make_rwif({'val': ",".join(self.sysfs)}, self.read_const_buf)


        # If we have netdevs, we want to pass this info to our int shell script dynmaically.
        # We'll do it here throough a file at /proc/penguin_net
        if do_netdevs:
            hf_config['/proc/penguin_net'] = {
                hyper("read"): make_rwif({'val': " ".join(self.get_arg("conf")["netdevs"])}, self.read_const_buf)
            }

        # filename -> {read: model, write: model, ioctls: model}
        # Coordinates with hyperfile for modeling behavior!
        # Can we just pass our config straight over and load both?
        # Need to implement read, write, and IOCTLs
        # IOCTLs with symex gets scary, others are easy though?

        panda.pyplugins.load(HyperFile, {'models': hf_config, 'log_file': pjoin(self.outdir, outfile_models)})
        # Clear results file - we'll update it as we go
        self.dump_results()

        self.syscall_info_table = make_syscall_info_table()

        self.ppp.Core.ppp_reg_cb('igloo_syscall', self.on_syscall)

        # Open/openat is a special case with hypercalls helping us out
        # because openat requires guest introspection to resolve the dfd, but we just
        # did it in the kernel
        self.ppp.Core.ppp_reg_cb('igloo_open', self.fail_detect_opens)
        self.ppp.Core.ppp_reg_cb('igloo_ioctl', self.fail_detect_ioctl)

        self.ppp.Core.ppp_reg_cb('igloo_proc_mtd', self.proc_mtd_check)

        # On ioctl return we might want to start symex. We detect failures with a special handler though
        if need_ioctl_hooks:
            @panda.ppp("syscalls2", "on_sys_ioctl_return")
            def symex_ioctl_return(cpu, pc, fd, cmd, arg):
                # We'll return -999 as a magic placeholder value that indicates we should
                # Start symex. Is this a terrible hack. You betcha!
                rv = panda.arch.get_retval(cpu, convention="syscall")
                rv = panda.from_unsigned_guest(rv) # Unnecessary?

                if rv != MAGIC_SYMEX_RETVAL:
                    return

                if not hasattr(self, 'symex'):
                    # Initialize symex on first use
                    self.symex = PathExpIoctl(self.outdir, self.config['core']['fs'])

                # Look through our config and find the filename with a symex model
                # XXX: This is a bit of a hack - we're assuming we only have one symex model
                filename = None
                for fname, file_model in self.config['pseudofiles'].items():
                    if 'ioctl' in file_model:
                        for cmd, model in file_model['ioctl'].items():
                            if model['model'] == 'symex':
                                filename = fname
                                break

                if filename is None:
                    raise ValueError("No filename with symex model found in config, but we got a symex ioctl. Unexpected")

                # It's time to launch symex!
                self.symex.do_symex(self.panda, cpu, pc, filename, cmd)

                # We write down the "failure" so we can see that it happened (and know to query symex
                # to get results)
                self.log_ioctl_failure(filename, cmd)

                # set retval to 0 with no error.
                panda.arch.set_retval(cpu, 0, convention="syscall", failure=False)

    def on_syscall(self, cpu, buf_addr):
        format_str = f"!i6q{'4096s'*6}q"
        buf_size = struct.calcsize(format_str)
        buf = self.panda.virtual_memory_read(cpu, buf_addr, buf_size, fmt="bytearray")

        # Unpack request with our dynamic format string
        unpacked = struct.unpack_from(format_str, buf)

        nr = unpacked[0]
        args = unpacked[1:1+6]
        strings = unpacked[1+6:1+6+6]
        ret = unpacked[1+6+6]

        if ret != -self.ENOENT:
            # File exists or other error. Not of interest.
            return

        arch, _ = arch_end(self.config["core"]["arch"])
        try:
            name, arg_names = self.syscall_info_table[arch][nr]
        except KeyError:
            if nr not in self.warned:
                self.warned.add(nr)
                print(f"Unknown syscall {nr} on {arch}")
            return

        if name in ('open', 'openat', 'ioctl', 'close'):
            # Handled with other hypercalls
            return

        # Use null terminator and interpret as UTF-8
        strings = [s.split(b'\0', 1)[0].decode() for s in strings]

        fnames = (
            strings[i]
            for i, arg_name in enumerate(arg_names)
            if arg_name in ("filename", "path", "pathname", "fd")
            and any(strings[i].startswith(x) for x in ("/dev/", "/proc/", "/sys/"))
        )
        for fname in fnames:
            self.centralized_log(fname, name)

    #######################################
    def centralized_log(self, path, event, event_details = None):
        # Log a failure to open a given path if it's interesting
        # We just track count
        if not path_interesting(path):
            return

        if path.startswith("/proc/"):
            # replace /proc/<pid> with /proc/<PID> to avoid a ton of different paths
            path = re.sub(r'/proc/\d+', '/proc/PID', path)

        if path not in self.file_failures:
            self.file_failures[path] = {}

        if event not in self.file_failures[path]:
            self.file_failures[path][event] = {'count': 0}

        if 'count' not in self.file_failures[path][event]:
            # If we ioctl'd before opening, we'll have a count-free entry
            self.file_failures[path][event]['count'] = 0

        self.file_failures[path][event]['count'] += 1

        if event_details is not None:
            if not "details" in self.file_failures[path][event]:
                self.file_failures[path][event]['details'] = []
            self.file_failures[path][event]['details'].append(event_details)

    def proc_mtd_check(self, cpu, buffer, buffer_sz):
        '''
        The guest is reading /proc/mtd. We should populate this file
        dynamically based on the /dev/mtd* devices we've set up.

        These devices have a name in addition to other properties:
        /dev/mtd0:
            name: mymtdname
            read:
                model: return_const
                buf: "foo"
        '''
        # For each device in our config that's /dev/mtdX, we'll add a line to the buffer
        # Buffer size is limited to 512 in kernel for now.
        buf = ""
        for filename, details in self.config["pseudofiles"].items():
            if not filename.startswith("/dev/mtd"):
                continue

            idx = filename.split("/dev/mtd")[1]
            if idx.startswith("/"): # i.e., /dev/mtd/0 -> 0
                idx = idx[1:]

            if not idx.isdigit():
                print(f"WARNING: mtd device {filename} is non-numeric. Skipping in /proc/mtd report")
                continue

            if not 'name' in details:
                print(f"WARNING: mtd device {filename} has no name. Skipping in /proc/mtd report")
                continue

            buf += "mtd{}: {:08x} {:08x} \"{}\"\n".format(int(idx), 0x1000000, 0x20000, details['name'])

        if len(buf) > buffer_sz:
            print(f"WARNING truncating mtd buffer from {len(buf)} to {buffer_sz}")
            buf = buf[:buffer_sz]

        try:
            self.panda.virtual_memory_write(cpu, buffer, buf.encode())
            self.panda.arch.set_arg(cpu, 0, 0)  # zero: success
        except ValueError:
            print("Proc mtd write failed - retrying")
            self.panda.arch.set_arg(cpu, 0, 1)  # non-zero = error

        if len(buf) == 0:
            with open(pjoin(self.outdir, 'pseudofiles_proc_mtd.txt'), "w") as f:
                f.write("/proc/mtd was read with no devices in config")

            # The guest read /proc/mtd, but we didn't have anything set up in it! Perhaps
            # it's looking for a device of a specific name - potential failure we can mitigate
            #self.file_failures['/proc/mtd'] = {'read': {'count': 1, 'details': 'special: no mtd devices in pseudofiles'}}


    def fail_detect_ioctl(self, cpu, fname, cmd):
        # A regular (non-dyndev) device was ioctl'd and is returning -ENOTTY so our hypercall triggers
        self.log_ioctl_failure(fname, cmd)

    def fail_detect_opens(self, cpu, fname, fd):
        fd = self.panda.from_unsigned_guest(fd)

        if fd == -self.ENOENT:
            # enoent let's gooooo
            self.centralized_log(fname, 'open')

    def log_ioctl_failure(self, path, cmd):
        # This might trigger twice, depending on the -ENOTTY path
        # between our dyndev ioctl handler and do_vfs_ioctl?

        if ignore_ioctl_path(path) or ignore_cmd(cmd):
            # Uninteresting
            return

        if path not in self.file_failures:
            self.file_failures[path] = {}

        if 'ioctl' not in self.file_failures[path]:
            self.file_failures[path]['ioctl'] = {}

        first = False
        if cmd not in self.file_failures[path]['ioctl']:
            self.file_failures[path]['ioctl'][cmd] = {'count': 0}
            first = True

        self.file_failures[path]['ioctl'][cmd]['count'] += 1
        if first:
            # The first time we see an IOCTL update our results on disk
            # This is just relevant if someone's watching the output during a run
            # final results are always written at the end.
            self.dump_results()

    def read_zero(self, filename, buffer, length, offset, details=None):
        # Simple peripheral model inspired by firmadyne/firmae. Just return 0
        # Extended to support returning data that was written to the file if it was written to previously

        if filename in self.written_data:
            data = self.written_data[filename]
            final_data = data[offset:offset+length]
            return (final_data, len(final_data))

        data = b'0'
        final_data = data[offset:offset+length]
        # XXX if offset > len(data) should we return an error instead of 0?
        return (final_data, len(final_data)) # data, rv

    def read_one(self, filename, buffer, length, offset, details=None):
        data = b'1'
        if filename in self.written_data:
            data = self.written_data[filename]
            final_data = data[offset:offset+length]
            return (final_data, len(final_data))

        final_data = data[offset:offset+length]
        # XXX if offset > len(data) should we return an error instead of 0?
        return (final_data, len(final_data)) # data, rv

    def read_empty(self, filename, buffer, length, offset, details=None):
        data = b''
        # XXX if offset > len(data) should we return an error instead of 0?
        return (data, 0) # data, rv

    def read_const_buf(self, filename, buffer, length, offset, details=None):
        data = details['val'].encode() + b"\x00" # Null terminate?
        final_data = data[offset:offset+length]
        # XXX if offset > len(data) should we return an error instead of 0?
        if offset > len(data):
            return (b'', 0) # -EINVAL

        return (final_data, len(final_data)) # data, rv

    def _render_file(self, details):
        # Given offset: data mapping plus a pad, we
        # combine to return a buffer
        pad  = b'\x00'
        if 'pad' in details:
            if isinstance(details['pad'], str):
                pad = details['pad'].encode()
            elif isinstance(details['pad'], int):
                pad = bytes([details['pad']])
            else:
                raise ValueError("const_map: pad value must be string or int")

        size = details['size'] if 'size' in details else 0x10000
        vals = details['vals']

        # sort vals dict by key, lowest to highest
        vals = {k: v for k, v in sorted(vals.items(), key=lambda item: item[0])}

        # now we flatten. For each offset, val pair
        # Need to grab first offset, then pad to that
        data = b'' #pad * (list(vals.keys())[0] if len(vals.keys()) else 0)

        for off, val in vals.items():
            # We have offset: value where value
            # may be a string, a list of ints (for non-printable chars)
            # or a list of strings to be joined by null terminators

            if isinstance(val, str):
                val = val.encode()

            elif isinstance(val, list):
                if not len(val):
                    continue # Wat?

                # All shoudl be same type. Could support a list of lists e.g., ["key=val", [0x41, 0x00, 0x42], ...]?
                first_val = val[0]
                for this_val in val[1:]:
                    if not isinstance(this_val, type(first_val)):
                        raise ValueError(f"Need matching vals but we have {this_val} and {first_val}")

                if isinstance(first_val, int):
                    # We have a list of ints - these are non-printable chars
                    val = bytes(val)

                elif isinstance(first_val, str):
                    # Join this list with null bytes
                    val = b'\x00'.join([x.encode() for x in val])
            else:
                raise ValueError("_render_file: vals must be strings lists of ints/strings")

            # Pad before this value, then add the value
            data += pad * (off - len(data)) + val

        # Finally pad up to size
        assert len(data) <= size, f"Data is too long: {len(data)} > size {size}"
        data += pad * (size - len(data))
        return data

    def read_const_map(self, filename, buffer, length, offset, details=None):
        data = self._render_file(details)
        final_data = data[offset:offset+length]
        if offset > len(data):
            return (b'', 0) # No data, no bytes read

        return (final_data, len(final_data)) # data, length

    def read_const_map_file(self, filename, buffer, length, offset, details=None):
        # Create a file on the host using the specified pad, size, vals
        # When we read from the guest, we read from the host file.
        hostfile = details['filename']

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

        return (final_data, len(final_data)) # data, length

    def read_from_file(self, filename, buffer, length, offset, details=None):
        #print(f"Reading {filename} with {length} bytes at {offset}:")
        fname = details['filename'] # Host file

        with open(fname, "rb") as f:
            f.seek(offset)
            data = f.read(length)

        return (data, len(data))

    def write_to_file(self, filename, buffer, length, offset, contents, details=None):
        fname = details['filename'] # Host file
        #print(f"Writing {fname} with {length} bytes at {offset}: {contents[:100]}")

        with open(fname, "r+b") as f:
            f.seek(offset)
            f.write(contents)

        return length

    def write_discard(self, filename, buffer, length, offset, contents, details=None):
        # Pretend we wrote everything we were asked to
        return length

    #def write_save(self, filename, buffer, length, offset, contents, details=None):
    def write_default(self, filename, buffer, length, offset, contents, details=None):
        # Store the contents for this file
        if filename not in self.written_data:
            self.written_data[filename] = b""
        # Seek to offset and write contents
        previous = self.written_data[filename][:offset]
        if len(previous) < offset:
            # Pad with null bytes
            previous += b"\x00" * (offset - len(previous))
        self.written_data[filename] = previous + contents + (self.written_data[filename][offset+length:] if len(self.written_data[filename]) > offset+length else b"")
        return length

    # XXX on write we can allow and store by default. Or should we explicitly error and require a model?
    #def write_default(self, filename, buffer, length, offset, contents, details=None):
    #    self.centralized_log(filename, 'write')
    #    return -22 # -EINVAL - we don't support writes


    # default models - log failures
    def read_default(self, filename, buffer, length, offset, details=None):
        self.centralized_log(filename, 'read')
        return (b'', -22) # -EINVAL - we don't support reads


    # IOCTL is more complicated than read/write.
    # default is a bit of a misnomer, it's our default ioctl handler which
    # implements default behavior (i.e., error) on issue of unspecified ioctls,
    # but implements what it's told for others
    def ioctl_default(self, filename, cmd, arg, ioctl_details):
        '''
        Given a cmd and arg, return a value
        filename is device path
        ioctl_details is a dict of:
            cmd -> {'model': 'return_const'|'symex',
                     'val': X}
        '''
        # Try to use cmd as our key, but '*' is a fallback
        is_wildcard = False
        if cmd in ioctl_details:
            cmd_details = ioctl_details[cmd]
        elif '*' in ioctl_details:
            cmd_details = ioctl_details['*']
            is_wildcard = True
        else:
            self.log_ioctl_failure(filename, cmd)
            return -25 # -ENOTTY

        model = cmd_details['model']

        if model == 'return_const':
            rv = cmd_details['val']
            return rv

        elif model == 'symex':
            # Symex is tricky and different from normal models.
            # First off, these models need to specify a 'val' just like any other
            # for us to use after (and, to be honest, during) symex.
            # JK: we're gonna always use 0 when doing symex!

            #if self.last_symex:
                # We could be smart and encode info in our retval
                # or do something else. I don't think we want to fully
                # ignore? But we probably could?
                #raise NotImplementedError("Uhhhh nested symex")
            #self.last_symex = filename
            return MAGIC_SYMEX_RETVAL # We'll detect this on the return and know what to do. I think?
        else:
            # This is an actual error - config is malformed. Bail
            raise ValueError(f"Unsupported ioctl model {model} for cmd {cmd}")
            #return -25 # -ENOTTY

    def dump_results(self):
        # Dump all file failures to disk as yaml
        with open(pjoin(self.outdir, outfile_missing), "w") as f:
            yaml.dump(self.file_failures, f)

        if hasattr(self, 'symex'):
            # Need to tell symex to export results as well
            self.symex.save_results()

    def uninit(self):
        self.dump_results()

class FileFailuresAnalysis(PenguinAnalysis):
    ANALYSIS_TYPE = "pseudofiles"
    VERSION = "1.0.0"

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(self.ANALYSIS_TYPE)
        self.logger.setLevel(logging.DEBUG)

    def is_dev_path(self, path: str) -> bool:
        """Check if the path is a device path."""
        return path.startswith("/dev")

    def parse_failures(self, output_dir) -> List[Failure]:
        '''
        Failures is a list of filename->info.
        Types are any syscall name (e.g., open, ioctl, read, lstat64, etc.)
        Open/stat/access style might be blocking ioctls and other interesting behavior

        IOCTLS are special - if we parse failures for symexing ioctls, we need to know where the symex.pkl
        file lives. To pass this data around we'll encode it inside the ioctl dict in a 'pickle' field

        path -> {type -> {details}}

        Return a structure like:
        {
            { /path/to/failing/file:
                {'open': {'count': 1}}
            },
            { /path/to/failing/file2:
                {'ioctl':
                    {pickle: '/some./path,
                     0x1234: {'count': 1},
                     0x2345: {'count': 3}},
                },
                {'read': {'count': 3}}
            }
        }

        There's a special key in here for /proc/mtd which is a bit of a magic value. If we see this
        it means the guest looked into /proc/mtd and there weren't any values.
        We could (TODO) try to mitigate this by 1) adding an MTD device /dev/mtd100 named "fakemtd
        and doing an an exclusive run where we see if env finds strings that get compared to "fakemtd".

        If any prior ioctls were modeled with symex, we'll ignore everything else to focus on those
        (this is like how in env we only focus on DYNVAL failures when present
        '''

        with open(pjoin(output_dir, 'core_config.yaml')) as f:
            config = yaml.safe_load(f)

            do_symex = False # Should this be per device? I'm gonna say no. At least for now
            symex_path = None
            symex_cmd = None
            for devpath, file_model in config['pseudofiles'].items():
                if 'ioctl' in file_model:
                    for cmd, model in file_model['ioctl'].items():
                        if model['model'] == 'symex':
                            do_symex = True
                            symex_path = devpath
                            symex_cmd = cmd
                            break

            #dynamic_mtd = False
            #for devpath, file_model in config['pseudofiles'].items():
            #    if devpath.startswith("/dev/mtd") and 'name' in file_model:
            #        if file_model['name'] == 'fakemtd':
            #            dynamic_mtd = True
            #            break

        with open(pjoin(output_dir, outfile_missing)) as f:
            file_failures = yaml.safe_load(f)

        with open(pjoin(output_dir, outfile_models)) as f:
            modeled = yaml.safe_load(f)
            # Look through modeled to identify default returnvalues - i.e.,
            # things not specified in our config. We'll add to file_failures
            # Start with ioctls. Look at each device and see if we have a default
            for dev, details in modeled.items():
                if 'ioctl' not in details:
                    continue

                ioctls = {} # cmd -> {'retval': retval, 'count'}

                for result in details['ioctl']:
                    if result['cmd'] not in ioctls:
                        ioctls[result['cmd']] = {'retval': result['retval'], 'count': 0}

                    # Retval must be const
                    if ioctls[result['cmd']]['retval'] != result['retval']:
                        print(f"WARNING modeled ioctl {result['cmd']} on {dev} had different return values {ioctls[result['cmd']]['retval']} and {result['retval']}")
                    ioctls[result['cmd']]['count'] += 1

                # did any ioctls return -ENOTTY and have that not be specified in our config?
                for cmd, data in ioctls.items():
                    retval = data['retval']
                    if retval != -25:
                        # Check config
                        if config.get('pseudofiles', {}).get(dev, {}).get('ioctl', {}).get(cmd, {}).get('model', None):
                            # It was set
                            continue
                        # Must have been a failure - Add into file_failures
                        if dev not in file_failures:
                            file_failures[dev] = {}
                            if 'ioctl' not in file_failures[dev]:
                                file_failures[dev]['ioctl'] = {}
                            if cmd not in file_failures[dev]['ioctl']:
                                file_failures[dev]['ioctl'][cmd] = {'count': data['count']}
                            else:
                                file_failures[dev]['ioctl'][cmd]['count'] += data['count']



        # Let's look at all file_failures with paths that end with numbers to decide if they're excessive (> 5) or not
        # If they're excessive, we'll ignore them
        _prefix_counter = Counter()
        for path in file_failures.keys():
            if not path[-1].isdigit():
                continue
            # Get prefix by stripping number suffix
            while path[-1].isdigit():
                path = path[:-1]
            _prefix_counter[path] += 1

        ignored_prefixes = {k for k, v in _prefix_counter.items() if v > 5}

        #if dynamic_mtd:
        #    # We're running in an exclusive mode where we made up an MTD device name and we're looking for it.
        #    # We should check env_mtd.txt for our names and just use that as our mitigation
        #    if not isfile(pjoin(output_dir, 'env_mtd.txt')):
        #        print(f"Pseudofiles: in dynamic mtd search no env_mtd.txt is present - bailing")
        #        return []

        #    with open(pjoin(output_dir, 'env_mtd.txt')) as f:
        #        env_mtd = [x.strip() for x in f.read().splitlines() if len(x.strip()) > 0]

        #        # Each of these is a device name we should add - I think we can add them *all at once* and see what happens
        #        return [Failure(f"/proc/mtd", self.ANALYSIS_TYPE, {'type': "dynamic_mtd", 'values': env_mtd})]

        fails = []
        for path, info in file_failures.items():
            if path in KNOWN_PATHS:
                continue


            if path.startswith("/sys/"):
                # Everything that failed in sysfs might be interesting. The guest could be creating something though,
                # in which case we want the directory to appear, not the exact file

                for sc, raw_data in info.items():
                    # XXX We generate distinct failures if we have > 1 SC but there's only a single mitigation!
                    # That's probably the source of our duplicate configs later
                    fails.append(Failure(path, self.ANALYSIS_TYPE, {'type': "sys", "path": path, 'sc': sc}))

            elif path.startswith("/proc/"):
                if path == "/proc/mtd":
                    # This is a special case - the guest is reading /proc/mtd and we don't have any devices
                    # presumably it might want a device and for it to be a device of a specific name.
                    fails.append(Failure(f"/proc/mtd", self.ANALYSIS_TYPE, {'type': "mtd_generic"}))
                    continue

                if not proc_interesting(path):
                    continue

                for sc, raw_data in info.items():
                    # XXX We generate distinct failures if we have > 1 SC but there's only a single mitigation!
                    # That's probably the source of our duplicate configs later
                    fails.append(Failure(path, self.ANALYSIS_TYPE, {'type': "proc", "path": path, 'sc': sc}))
                continue

            elif path.startswith("/dev/"):
                # If there are a lot of devices with numeric suffixes, we'll ignore them
                if path[-1].isdigit() and any(path.startswith(x) for x in ignored_prefixes):
                    #self.logger.debug(f"Ignoring /dev path with numeric suffix because there are lots like it {path}")
                    continue

                # If we're doing symex, we only care about "failures" on that one device with that cmd since these
                # are what we'd meaningfully "mitigate" with children. We don't want to mitigate something else and
                # re-symex later.

                if do_symex:
                    # If it's a different device, skip it
                    if symex_path != path:
                        continue

                    # Drop anything except 'ioctl' info
                    info = {k: v for k, v in info.items() if k == 'ioctl'}

                    if not len(info): # There wasn't anything else. Skip this
                        continue

                    # Within IOCTL drop anything except our target cmd
                    info['ioctl'] = {k: v for k, v in info['ioctl'].items() if k == symex_cmd}

                    if not len(info['ioctl']): # There wasn't anything else. Skip this
                        continue

                    # We have a failure for each command we symex'd (probably just one?)
                    for cmd, data in info['ioctl'].items():
                        symex = PathExpIoctl(output_dir, None, read_only=True)
                        models = symex.hypothesize_models(target=path, cmd=cmd, verbose=False)
                        if path not in models or cmd not in models[path]:
                            continue
                        results = [rv for rv in models[path][cmd]]
                        # We want to have symex_results
                        #print(f"Dropping symex data because it's junk, right?: {data}") # data is like {count: '1'}
                        fail_data = {'cmd': cmd, 'sc': 'ioctl', 'path': path, 'symex_results': results}
                        fails.append(Failure(f"{path}_ioctl_{int(cmd):x}_fromsymex", self.ANALYSIS_TYPE, fail_data))
                else:
                    if path.startswith("/dev/mtd"):
                        fails.append(Failure(path, self.ANALYSIS_TYPE, {'type': "mtd"}))
                        continue
                    # Normal case: we saw a syscall fail on a given path and we want to report it
                    for sc, raw_data in info.items():
                        data = raw_data
                        if 'details' in data:
                            # This is some extra info we log to disk, but we shouldn't use it when disambiguating
                            # failures. We'll drop it here.
                            data = deepcopy(raw_data)
                            del data['details']

                        if 'count' in data:
                            data = deepcopy(raw_data)
                            del data['count']

                        # Data will be like {path: /whatever, count: #}
                        if sc != 'ioctl':
                            # Non-IOCTL. Just record the path and syscall
                            data['path'] = path
                            data['sc'] = sc
                            fails.append(Failure(f"pseudofile_{path}_{sc}", self.ANALYSIS_TYPE, data))
                        else:
                            # IOCTL: record path, syscall, and ioctl cmd for each ioctl cmd. Don't update data, just add entries into the failure
                            for cmd in data.keys():
                                assert(cmd != 'pickle'), f'Malformed pseudofile failure: {info}: {sc}: {data}'
                                # data[cmd] just has count - let's *not* use that when building our failure
                                # otherwise we de-duplicate identical failures which completely ruins our search
                                fails.append(Failure(f"{path}_ioctl_{int(cmd):x}", self.ANALYSIS_TYPE, {'cmd': cmd, 'sc': sc, 'path': path}))

        # Final case - if we have a much of failed accesses, we can propose adding ~all~ of them
        # at once! We'll select all
        missing_files = set()
        for f in fails:
            path = f.info.get('path', None)
            if path and path not in config['pseudofiles'] and f.info.get("sc", "") not in ['ioctl', 'read', 'write']:
                missing_files.add(f.info['path'])

        if len(missing_files) > 1:
            file_group = Failure(f"pseudofile_add_group_{len(missing_files)}", self.ANALYSIS_TYPE, {'paths': list(missing_files), 'sc': 'open', 'type': 'multifile'})
            print(f"Adding pseudofile add all group:", missing_files)
            fails.append(file_group)

        return fails

    def get_potential_mitigations(self, config, failure : Failure) -> List[Mitigation]:
        '''
        Called by mgr to get mitigations for a given path with details we returned previously from parse_failures
        '''

        path = failure.info['path'] if 'path' in failure.info else ""

        if path in KNOWN_PATHS:
            return []

        if failure.info.get('type', '') == 'multifile':
            # Before we check if path is invalid, we check if it's a multifile mitigation
            new_paths = [x for x in failure.info['paths'] if x not in config['pseudofiles']]
            return [Mitigation(f"pseudofile_add_group", self.ANALYSIS_TYPE, {'paths': new_paths, 'action': 'add_group', 'weight': 100 + len(new_paths)})]

        if not any(path.startswith(x) for x in ["/dev/", "/proc", "/sys"]):
            return []

        if path.startswith("/proc/") and not proc_interesting(path):
            return []

        if path not in config['pseudofiles']:
            '''
            If the file doesn't exist of course we'll see -EBADF on accesses
            to it. First order of business is adding the device. That's all we do here.
            Caller maps failing path -> this mitigation so we don't need to specify

            There are many syscalls that take a filename and can return -ENOENT - for these we want to make the file
            if it's not in our pseudofiles.

            Syscalls that take in an FD would be different (ignoring for now) - the guest could only get a FD if the file
            already existed - so if we see that case and we're here, that's a non-pseudofile with a regular error
            that we shouldn't change (i.e., we cann't add the file since it already exists)
            '''

            if 'type' in failure.info:
                # MTD failures have a 'type' property
                if failure.info['type'] == 'mtd_generic':
                    # We have a /proc/mtd read failure. Two options
                    return [
                        # 1) we mitigate with exclusive and "fakemtd" which we'll find dynamic comparisons against
                        #Mitigation(f"pseudofile_fake_proc_mtd", self.ANALYSIS_TYPE, {'path': '/dev/mtd0', 'name': 'fakemtd', 'model': 'zero', 'weight': 100}, exclusive=True),
                        # 2) we add a single MTD device with a name and size and hope that's what the guest is looking for
                        Mitigation(f"pseudofile_fixed_mtd", self.ANALYSIS_TYPE, {'path': '/dev/mtd0', 'action': 'add_with_modes', 'name': 'uboot', 'models': ['zero'], 'weight': 100})
                    ]
                elif failure.info['type'] == 'mtd':
                    # We saw a failure opening a specific MTD device, let's make it with a fixed name
                    return [Mitigation(f"pseudofile_fixed_mtd", self.ANALYSIS_TYPE, {'path': path, 'name': 'uboot', 'action': 'add_with_models', 'models': ['zero'], 'weight': 100})]

                elif failure.info['type'] == 'proc':
                    # TODO: If this is a deep directory, we could try making the directory (i.e., by creating dirname of path /foo)
                    # instead of the actual path
                    return [Mitigation(f"pseudofile_add_{path}", self.ANALYSIS_TYPE, {'path': path, 'action': 'add_with_models', 'models': ['zero', 'one'], 'weight': 100})]

                elif failure.info['type'] == 'sys':
                    # TODO: If this is a deep directory, we could try making the directory (i.e., by creating dirname of path /foo)
                    # instead of the actual path
                    return [Mitigation(f"pseudofile_add_{path}", self.ANALYSIS_TYPE, {'path': path, 'action': 'add_with_models', 'models': ['zero', 'one'], 'weight': 100})]

                #elif failure.info['type'] == 'dynamic_mtd':
                #    # We just did a dynamic search for MTD devices and found some names - let's add them all.
                #    # We'll name them /dev/mtdX where X is the index in the list
                #    results = []
                #    for idx, val in enumerate(failure.info['values']):
                #        results.append(Mitigation(f"pseudofile_dynamic_mtd_{val}", self.ANALYSIS_TYPE, {'path': f"/dev/mtd{idx}", 'name': val, 'model': 'zero', 'weight': 100}))
                #    return results

            return [Mitigation(f"pseudofile_add_{path}", self.ANALYSIS_TYPE, {'path': path, 'action': 'add', 'weight': 100})]

        # This path *is* a pseudofile we added. Errors we see are things we might want
        # to handle

        if 'sc' not in failure.info:
            print(f"Missing sc type in failure: {failure.info}. Ignoring")
            return []

        if failure.info['sc'] == 'open':
            #raise ValueError(f"We saw an open failure for {path} but it's added by pseudofiles. This shouldn't happen")
            #print(f"Warning: pseudofiles reported an access failure for {path} but we've (allegedly) added the file already. Ignoring")
            return []

        elif failure.info['sc'] == 'read':
            # Check if there's already a read model for this file
            if 'read' in config['pseudofiles'][path]:
                # TODO: if we had a different read model, we could still propose read_zero, but for now I don't think we'd ever encounter that
                return []
            # We saw a read failure. Let's propose some mitigations. Just one for now: read zero
            return [Mitigation(f"pseudofile_read_zero_{path}", self.ANALYSIS_TYPE, {'path': path, 'action': 'read_model', 'model': 'zero', 'weight': 5})]

        elif failure.info['sc'] == 'write':
            if 'write' in config['pseudofiles'][path]:
                # TODO: if we had a different write model, we could still propose read_zero, but for now I don't think we'd ever encounter that
                return []
            # Saw a write failure. Only thing to do (for now) is discard.
            return [Mitigation(f"pseudofile_write_discard_{path}", self.ANALYSIS_TYPE, {'path': path, 'action': 'write_model', 'model': 'discard', 'weight': 5})]

        elif failure.info['sc'] == 'ioctl':
            # Two options. A) We saw an IOCTL fail and we want to make it try symex. B) We have symex results
            # IOCTL modeling is only a good idea (and will only work) if it's a pseudofiles/dyndev-provided device.
            # Otherwise we won't hit dyndev ioctl handling!
            cmd = failure.info['cmd']

            if 'symex_results' in failure.info:
                if not len(failure.info['symex_results']):
                    self.logger.warning(f"No results from symex for ioctl {cmd:x} on {path}")
                    # TODO: do we want to try adding a default of 0?
                    return []

                # Return a const model for each result
                return [Mitigation(f"{val}", self.ANALYSIS_TYPE, {'path': path, 'cmd': cmd,
                                                                            'action': 'ioctl_model',
                                                                            'model': 'return_const',
                                                                            'weight': 7,
                                                                            'val': val}) \
                        for val in failure.info['symex_results']]

            # We'll mitigate this ioctl by modeling it as symex
            else:
                return [Mitigation(f"symex", self.ANALYSIS_TYPE, {'path': path, 'cmd': cmd, 'weight': 5,
                                                                'action': 'ioctl_model', 'model': 'symex'})]

        elif failure.info['sc'] == 'unlink':
            # It wants to delete a file that's missing - let's not concern ourselves with this
            return []

        # Not sure how to handle other failures. In parse failures we're looking for -EBADF for accesses
        # then failing reads/writes (??) and -ENOTTY ioctls
        # We're probably here because 1) a device exists, but 2) a failure still happened with it.
        # Since we add devices with open permissions (0o777) this might only happen if the guest
        # chmods a device to be less permissive? Or perhaps we're (incorrectly + should be impossible)
        # running on a non-dyndev device.
        self.logger.warning(f"Unexpected failure recorded for {path}: {failure}")
        print(f"Unexpected failure recorded for {path}: {failure}")
        return []

    def implement_mitigation(self, config : Configuration, failure : Failure, mitigation : Mitigation) -> List[Configuration]:
        # Given a mitigation update config to make it happen

        new_config = deepcopy(config.info)
        if 'pseudofiles' not in new_config:
            new_config['pseudofiles'] = {}

        # XXX: When multiple pseudofiles have similar models (i.e., defaults), the yaml loader may use IDs
        # to store a single object that gets referenced multiple times. But when we go to modify this,
        # we **must** make sure we're modifying a unique object. We'll deepcopy the specific pseudofile
        # we're modifying to ensure this.

        path = mitigation.info.get('path')
        if path and path in new_config['pseudofiles']:
            new_config['pseudofiles'][path] = deepcopy(new_config['pseudofiles'][path])

        # Would applying this mitigation to the config be a no-op?
        if mitigation.info['action'] == 'add' and mitigation.info['path'] in new_config['pseudofiles']:
            print(f"Mitigation {mitigation.info['path']} already exists in config - can't add")
            return []

        if mitigation.info['action'] == 'add_with_models':
            results = []
            for model in mitigation.info['models']:
                new_config['pseudofiles'][mitigation.info['path']] = {
                    'read': {
                        'model': model
                    }
                }

                if hasattr(mitigation.info, 'name'):
                    # MTD devices always hit this path when adding, so we'll check for a name and set it if necessary
                    new_config['pseudofiles'][mitigation.info['path']]['name'] = mitigation.info['name']

                results.append(Configuration(mitigation.info['path'], new_config))
            return results

        if mitigation.info['action'] == 'add_group':
            for path in mitigation.info['paths']:
                new_config['pseudofiles'][path] = {}
            return [Configuration(path, new_config)]

        # If this is an add mitigation, we update to pseudofiles[filename]
        if mitigation.info['action'] == 'add':
            # Add file to config. Make sure we have pseudofiles section
            new_config['pseudofiles'][mitigation.info['path']] = {}
            return [Configuration(mitigation.info['path'], new_config)]

        if mitigation.info['action'] == 'read_model':
            # If model is zero we know what to do. Otherwise we don't
            if mitigation.info['model'] != 'zero':
                raise ValueError(f"Unknown read model {mitigation.info['model']}")

            new_config['pseudofiles'][mitigation.info['path']] = {
                'read': {
                    'model': 'zero'
                }
            }
            return [Configuration(f"read_zero", new_config)]

        if mitigation.info['action'] == 'write_model':
            if mitigation.info['model'] != 'discard':
                raise ValueError(f"Unknown write model {mitigation.info['model']}")

            new_config['pseudofiles'][mitigation.info['path']] = {
                'write': {
                    'model': 'discard'
                }
            }
            return [Configuration(f"write_discard", new_config)]

        if mitigation.info['action'] == 'ioctl_model':
            # Model could be symex or return_const
            if mitigation.info['model'] not in ['symex', 'return_const']:
                raise ValueError(f"Unknown ioctl model {mitigation.info['model']}")

            # Make sure we have a pseudofiles section
            if mitigation.info['path'] not in new_config['pseudofiles']:
                new_config['pseudofiles'][mitigation.info['path']] = {}
            if 'ioctl' not in new_config['pseudofiles'][mitigation.info['path']]:
                new_config['pseudofiles'][mitigation.info['path']]['ioctl'] = {}
            if mitigation.info['cmd'] not in new_config['pseudofiles'][mitigation.info['path']]['ioctl']:
                new_config['pseudofiles'][mitigation.info['path']]['ioctl'][mitigation.info['cmd']] = {}

            if mitigation.info['model'] == 'symex':
                # We want to add a symex model for this ioctl
                new_config['pseudofiles'][mitigation.info['path']]['ioctl'][mitigation.info['cmd']] = {
                    'model': 'symex'
                }

                # The symex model is just for us - don't let anyone else try to fix failures
                return [Configuration(f"symex_{mitigation.info['cmd']:x}", new_config, exclusive=self.ANALYSIS_TYPE)]

            # non-symex:
            new_config['pseudofiles'][mitigation.info['path']]['ioctl'][mitigation.info['cmd']] = {
                'model': 'return_const',
                'val': mitigation.info['val']
            }
            return [Configuration(f"const_{mitigation.info['cmd']:x}", new_config)]

        raise ValueError(f"Unknown mitigation action {mitigation.info['action']}")


def main():
    from sys import argv

    if len(argv) < 3:
        raise ValueError(f"Usage {argv[0]} config output_dir")
    config_path = argv[1]
    output_dir = argv[2]

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    analysis = FileFailuresAnalysis()
    failures = analysis.parse_failures(output_dir, None, None)

    idx = 0
    for fail_cause, fail_info in failures.items():
        mitigations = analysis.get_potential_mitigations(config, fail_cause, fail_info) or []
        for m in mitigations or []:
            new_config = analysis.implement_mitigation(config, fail_cause, m)
            #print(f"\t\t[{analysis.ANALYSIS_TYPE}] =", new_config[analysis.ANALYSIS_TYPE])
            with open(f"{output_dir}/config{idx}.yaml", "w") as f:
                yaml.dump(new_config, f)
            idx += 1

if __name__ == '__main__':
    main()
