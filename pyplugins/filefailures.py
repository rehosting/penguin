import sys
import re
import logging
# coloredlogs
import coloredlogs
from os.path import dirname, join as pjoin, isfile
from pandare import PyPlugin
from copy import deepcopy
from typing import Dict, Any, List

from sys import path
path.append(dirname(__file__))
from hyperfile import HyperFile, HYPER_READ, HYPER_WRITE, HYPER_IOCTL, hyper

coloredlogs.install(level='DEBUG', fmt='%(asctime)s %(name)s %(levelname)s %(message)s')

try:
    from penguin import PenguinAnalysis, yaml
except ImportError:
    # We can still run as a PyPlugin, but we can't do post-run analysis
    PenguinAnalysis = object
    import yaml

# XXX you'll see checks for if not >= 0 and >= -2. That's checking if we get -1 or -2 looking for -ENOENT
# ENOENT is 2. Except on mips it seems to be 1. Not sure why?

outfile = "file_failures.yaml"
outfile2 = "file_wildcards.yaml"

def path_interesting(path):
    if path.startswith("/dev/"):
        return True

    if path.startswith("/proc/"):
        return True
    return False

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
        return True
    if path.startswith("pipe:"):
        return True
    return False


class FileFailures(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.file_failures = {} # path: {mode: count}
        self.wildcards = {} # path: {mode: {count: X, rv: Y}}

        if self.get_arg("conf") is None or "files" not in self.get_arg("conf"):
            raise ValueError("No 'files' in config: {self.get_arg('conf')}")

        self.config = self.get_arg("conf")["files"]
        # Expect filename: {'read': 'default' OR 'zero',
        #                   'write': 'default' OR 'discard',
        #                   'ioctl': {
        #                               '*' OR num: {'model': 'X', 'val': Y}
        #                               }

        hf_config = {}
        for filename, details in self.config.items():
            hf_config[filename] = {}

            for ftype in "read", "write", "ioctl":
                if ftype not in details or "model" not in details[ftype]:
                    model = "default" # default is default
                else:
                    model = details[ftype]["model"]

                if not hasattr(self, f"{ftype}_{model}"):
                    raise ValueError(f"Unsupported hyperfile {ftype}_{model} for {filename}: {details[ftype] if ftype in details else None}")
                # Have a model specified

                fn = getattr(self, f"{ftype}_{model}")

                # Closure so we can pass details through
                def make_rwif(details, fn_ref):
                    def rwif(*args):
                        return fn_ref(*args, details)
                    return rwif
                
                hf_config[filename][hyper(ftype)] = make_rwif(details[ftype] if ftype in details else {}, fn)

        # filename -> {read: model, write: model, ioctls: model}
        # XXX TODO: coordinate with hyperfile for modeling behavior!
        # Can we just pass our config straight over and load both?
        # Need to implement read, write, and IOCTLs
        # IOCTLs with symex gets scary, others are easy though?

        panda.pyplugins.load(HyperFile, {'files': hf_config})
        # Clear results file - we'll update it as we go
        self.dump_results()

        @panda.ppp("syscalls2", "on_sys_open_return")
        def fail_detect_open(cpu, pc, fname, mode, flags):
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            if rv >= 0:
                return

            # Grab the filename
            try:
                fname = panda.read_str(cpu, fname)
            except ValueError:
                return
            if rv >= -2: # ENOENT - we only care about files that don't exist
                self.centralized_log(fname, 'open')

        @panda.ppp("syscalls2", "on_sys_openat_return")
        def fail_detect_openat(cpu, pc, fd, fname, mode, flags):
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            if rv >= 0:
                return

            base = ''
            if fd != -100: # CWD
                proc = self.panda.plugins['osi'].get_current_process(cpu)
                if proc == self.panda.ffi.NULL:
                    return
                basename_c = self.panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)
                if basename_c == self.panda.ffi.NULL:
                    return
                base = self.panda.ffi.string(basename_c)
            try:
                path = base + "/" + panda.read_str(cpu, fname)
            except ValueError:
                return

            if rv >= -2: # ENOENT - we only care about files that don't exist
                self.centralized_log(path, 'open')

        @panda.ppp("syscalls2", "on_sys_newlstat_return")
        def faildetect_newlstat(cpu, pc, pathname, statbuf):
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            if rv >= 0:
                return

            if rv >= -2: # ENOENT - we only care about files that don't exist
                self.centralized_log(panda.read_str(cpu, pathname), 'lstat')

        @panda.ppp("syscalls2", "on_sys_lstat64_return")
        def faildetect_lstat64(cpu, pc, pathname, statbuf):
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            if rv >= 0:
                return

            if rv >= -2: # ENOENT - we only care about files that don't exist
                try:
                    pathname = panda.read_str(cpu, pathname)
                except ValueError:
                    print("Failed to read pathname from guest pointer", hex(pathname))
                    return
                self.centralized_log(pathname, 'lstat')

        ################ XXX MIPS ONLY ################3
        if panda.arch_name == "mips":
            # Stat and lstat are only on mips? Not arm at least
            @panda.ppp("syscalls2", "on_sys_stat_return")
            def faildetect_stat(cpu, pc, pathname, statbuf):
                rv = self.panda.arch.get_retval(cpu, convention="syscall")
                if rv >= 0:
                    return

                if rv >= -2: # ENOENT - we only care about files that don't exist
                    self.centralized_log(panda.read_str(cpu, pathname), 'stat')

            @panda.ppp("syscalls2", "on_sys_lstat_return")
            def faildetect_lstat32(cpu, pc, pathname, statbuf):
                rv = self.panda.arch.get_retval(cpu, convention="syscall")
                if rv >= 0:
                    return

                if rv >= -2: # ENOENT - we only care about files that don't exist
                    self.centralized_log(panda.read_str(cpu, pathname), 'lstat')

            @panda.ppp("syscalls2", "on_sys_fstat_return")
            def faildetect_fstat(cpu, pc, fd, statbuf):
                rv = self.panda.arch.get_retval(cpu, convention="syscall")
                if rv >= 0:
                    return

                name = panda.get_file_name(cpu, fd)
                if name == panda.ffi.NULL or name is None:
                    sfd = panda.from_unsigned_guest(fd) 
                    if sfd < 0:
                        print(f"WARN: fstat on invalid FD: {sfd}")
                    elif rv < 0:
                        print(f"WARN: fstat failed with {rv} - but we can't find name for fd {fd}")
                    return

                if rv >= -2: # ENOENT - we only care about files that don't exist
                    self.centralized_log(name, 'fstat')


        ################ XXX ARMEL + MIPS64 ONLY ################3
        # This category is bogus
        if panda.arch_name in ["armel", "mips64"]:
            @panda.ppp("syscalls2", "on_sys_stat64_return")
            def faildetect_stat64(cpu, pc, pathname, statbuf):
                rv = self.panda.arch.get_retval(cpu, convention="syscall")
                if rv >= 0:
                    return

                if rv >= -2: # ENOENT - we only care about files that don't exist
                    self.centralized_log(panda.read_str(cpu, pathname), 'stat')


        # TODO: do we care about lstat?

        # XXX: We detect ioctls, read, writes based on hypercalls
        # for device we add. We just use PANDA to detect failing opens
        # of misisng devices
        '''
        @panda.ppp("syscalls2", "on_sys_ioctl_return")
        def fail_detect_ioctl(cpu, pc, fd, cmd, argp):
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            if rv >= 0:
                return

            name = panda.get_file_name(cpu, fd)
            if name == panda.ffi.NULL or name is None:
                sfd = panda.from_unsigned_guest(fd) 
                if sfd < 0:
                    print(f"WARN: ioctl {cmd:#x} on invalid FD: {sfd}")
                elif rv < 0:
                    print(f"WARN: ioctl {cmd:#x} failed with {rv} - but we can't find name for fd {fd}")
                return
            name = name.decode('utf-8', errors='ignore')

            self.log_ioctl_failure(name, rv, cmd)

        # Failing reads
        @panda.ppp("syscalls2", "on_sys_read_return")
        def fail_detect_read(cpu, pc, fd, buf, count):
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            if rv >= 0:
                return

            name = panda.get_file_name(cpu, fd)
            if name == panda.ffi.NULL or name is None:
                sfd = panda.from_unsigned_guest(fd) 
                if sfd < 0:
                    print(f"WARN: write {cmd:#x} on invalid FD: {sfd}")
                elif rv < 0:
                    print(f"WARN: write {cmd:#x} failed with {rv} - but we can't find name for fd {fd}")
                return
            name = name.decode('utf-8', errors='ignore')

            self.log_read_failure(name, rv, count)

        # Failing writes
        @panda.ppp("syscalls2", "on_sys_read_return")
        def fail_detect_write(cpu, pc, fd, buf, count):
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            if rv >= 0:
                return

            name = panda.get_file_name(cpu, fd)
            if name == panda.ffi.NULL or name is None:
                sfd = panda.from_unsigned_guest(fd) 
                if sfd < 0:
                    print(f"WARN: write {cmd:#x} on invalid FD: {sfd}")
                elif rv < 0:
                    print(f"WARN: write {cmd:#x} failed with {rv} - but we can't find name for fd {fd}")
                return
            name = name.decode('utf-8', errors='ignore')

            self.log_write_failure(name, rv, count)

    def log_read_failure(self, path, rv, count):
        # Should our module returna  specific error we check for?
        self.centralized_log(path, 'read')

    def log_write_failure(self, path, rv, count):
        # Should our module returna  specific error we check for?
        self.centralized_log(path, 'write')
    '''

    def centralized_log(self, path, event):
        if not path_interesting(path):
            return

        if path not in self.file_failures:
            self.file_failures[path] = {}
        
        if event not in self.file_failures[path]:
            self.file_failures[path][event] = {'count': 0}

        self.file_failures[path][event]['count'] += 1

    def log_ioctl_wildcard(self, path, cmd, rv):
        # Log when we model a wildcard ioctl
        # Write down rv and count

        if path not in self.wildcards:
            self.wildcards[path] = {}
        
        if 'ioctl' not in self.wildcards[path]:
            self.wildcards[path]['ioctl'] = {}

        first = False
        if cmd not in self.wildcards[path]['ioctl']:
            first = True
            self.wildcards[path]['ioctl'][cmd] = {"rv": rv, "count": 0}

        # Wildcard should have constant RV, so no need for multi-level here

        if rv != self.wildcards[path]['ioctl'][cmd]["rv"]:
            raise ValueError("How did RV change in wildcard?")

        self.wildcards[path]['ioctl'][cmd]['count'] += 1

        if first:
            self.dump_results()

    def log_ioctl_failure(self, path, cmd):
        #if not path_interesting(path) or ignore_ioctl_path(path):
        #    return
        #if not ignore_cmd(cmd):
        #    return

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
            self.dump_results()

    # Simple peripheral models as seen in firmadyne/firmae
    def read_zero(self, filename, buffer, length, offset, details=None):
        data = b'0'
        final_data = data[offset:offset+length]
        # XXX if offset > len(data) should we return an error isntead of 0?
        return (final_data, len(final_data)) # data, rv

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
        print(f"Reading {filename} with {length} bytes at {offset}")
        fname = details['filename'] # Host file

        with open(fname, "rb") as f:
            f.seek(offset)
            data = f.read(length)

        return (data, len(data))

    def write_from_file(self, filename, buffer, length, offset, contents, details=None):
        fname = details['filename'] # Host file
        #print(f"Writing {fname} with {length} bytes at {offset}: {contents[:100]}")

        with open(fname, "r+b") as f:
            f.seek(offset)
            f.write(contents)

        return length

    def write_discard(self, filename, buffer, length, offset, contents, details=None):
        # Pretend we wrote everything we were asked to
        return length

    # default models - log failures
    def read_default(self, filename, buffer, length, offset, details=None):
        # TODO: log failure
        return (b'', -22) # -EINVAL - we don't support reads

    def write_default(self, filename, buffer, length, offset, contents, details=None):
        # TODO: log failure
        return -22 # -EINVAL - we don't support writes

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
            But no 'val' key for symex?
            If we have no model for a given cmd, that's the same as 'default'
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
            if is_wildcard:
                self.log_ioctl_wildcard(filename, cmd, rv)
            return rv
        elif model == 'symex':
            raise NotImplementedError("Symex is WIP")
        else:
            # This is an actual error - config is malformed. Bail
            raise ValueError(f"Unsupported ioctl model {model} for cmd {cmd}")
            #return -25 # -ENOTTY

    def dump_results(self):
        # Dump all file failures to disk as yaml
        with open(pjoin(self.outdir, outfile), "w") as f:
            yaml.dump(self.file_failures, f)

        # Also dump wildcards. Not sure if we'll use it
        with open(pjoin(self.outdir, outfile2), "w") as f:
            yaml.dump(self.wildcards, f)

    def uninit(self):
        self.dump_results()

class FileFailuresAnalysis(PenguinAnalysis):
    ANALYSIS_TYPE = "files"

    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)

    def is_dev_path(self, path: str) -> bool:
        """Check if the path is a device path."""
        return path.startswith("/dev")
    
    def max_fail_count(self, info: Dict[str, Any]) -> Dict[str, int]:
        """Compute the maximum failure count for each type."""
        max_fails = {}
        for k, details in info.items():
            if k not in max_fails:
                max_fails[k] = 0
            if k == 'ioctl':
                # IOCTLS are special - have an extra level of depth
                for ioctlnum, ioctl_details in details.items():
                    if 'count' not in ioctl_details:
                        self.logger.warning(f"Unexpected count-free ioctl entry in files: {details}")
                        continue
                    max_fails[k] = max(max_fails[k], ioctl_details['count'])
            else:
                if 'count' not in details:
                    self.logger.warning(f"Unexpected count-free entry in files: {details}")
                    continue
                max_fails[k] = max(max_fails[k], details['count'])
        return max_fails

    def parse_failures(self, output_dir):
        '''
        Failures is a list of filename->info.
        Types are open, ioctl, read, write.
        Open is probably blocking other failures

        path -> {type -> {details}}

        Return a structure like:
        {
            { /path/to/failing/file:
                {'open': {'count': 1}}
            },
            { /path/to/failing/file2:
                {'ioctl':
                    {0x1234: {'count': 1},
                     0x2345: {'count': 3}},
                },
                {'read': {'count': 3}}
            }
        }
        '''

        with open(pjoin(output_dir, outfile)) as f:
            file_failures = yaml.safe_load(f)

        fails = {} # path -> info
        for path, info in file_failures.items():
            if path.startswith("/dev") or path.startswith("/proc"):
                # For now let's ignore things that end with a number
                # There are a lot of these in some tests and they seem to be unimportant?
                if path[-1].isdigit():
                    continue
                fails[path] = info

        return fails

    def get_mitigations_from_static(self, path, _):
        # Static pass gives us a path as a string
        # Static analysis doesn't help us figure out what to do though,
        # so just fall back to normal mitigation generation
        #return self.get_potential_mitigations(None, path, None)
        #print("NYI: static mitigations for files")
        return []
    

    @staticmethod
    def get_default_device(weight):
        return {
            'weight': weight, 
            # Default behavior. Error on read/write/ioctl - we'll fix when we see it
            'read': 'default',
            'write': 'default',
            'ioctl': {
                    '*': {
                        'type': 'default',
                    }
                }
            }

    def get_potential_mitigations(self, config: Any, path: str, info: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.is_dev_path(path):
            self.logger.info(f"Ignoring non-dev path {path}")
            return []

        max_fails = self.max_fail_count(info)

        if 'open' in info:
            # If we failed to open a device, we don't care about the other failures
            return [self.get_default_device(info['open']['count'] / (2*max_fails['open']) + 0.5)] # Range from 0.5 for least common to 1.0 for most common

        # Otherwise we can propose ioctls, read model or write models
        results = []
        
        for failtype, failinfo in info.items():
            try:
                weight = info[failtype]['count'] / max_fails[failtype]
            except KeyError:
                weight = None

            if path not in config['files']:
                # We can't change the caller's config so we copy before adding
                config = deepcopy(config)
                config['files'][path] = self.get_default_device(0.5) # 0.5 weight for a non-opened, but read/written/ioctl'd device. Overwritten below

            if failtype == 'read':
                self.logger.info("Adding read-based mitigations")
                # We want to support a read operation. For now we don't support many, in fact it's just zeros
                read_types = ['zeros']
                for read_type in read_types:
                    if read_type == config['files'][path]['read']:
                        continue # Duplicate

                    mitigation = deepcopy(config['files'][path])
                    mitigation['read'] = read_type
                    mitigation['weight'] = weight
                    results.append(mitigation)

            elif failtype == 'write':
                self.logger.info("Adding write-based mitigations")
                # We want to support a write operation. For now we don't support many, in fact it's just discard
                write_types = ['discard']
                for write_type in write_types:
                    if write_type == config['files'][path]['write']:
                        continue # Duplicate

                    mitigation = deepcopy(config['files'][path])
                    mitigation['write'] = write_type
                    mitigation['weight'] = weight
                    results.append(mitigation)

            elif failtype == 'ioctl':
                for cmd, ioctldetails in failinfo.items():
                    weight = ioctldetails['count'] / max_fails[failtype]
                    self.logger.info(f"Adding ioctl-based mitigations for {path}: {cmd:#x}")

                    # We had a failing ioctl. Oh nose.
                    # Whatever shall we do. Let's see:
                    # 1) try 0
                    # 2) symex

                    handler = None
                    if cmd in config['files'][path]['ioctl']:
                        handler = config['files'][path]['ioctl'][cmd]
                        is_default = False
                    elif '*' in config['files'][path]['ioctl']:
                        handler = config['files'][path]['ioctl']['*']
                        is_default = True


                    # Depending on handler and is_default, we propose some new handlers
                    # We might have 'count' IFF it's our first time seeing this - if so we can propose symex

                    if 'type' not in handler:
                        raise ValueError(f"Unexpeced handler {handler} for {path} {cmd:#x}")

                    # Create a mitigation to return 0 - dynamically add it to results!
                    ret0_mitigation = deepcopy(config['files'][path])
                    ret0_mitigation['weight'] = weight
                    ret0_mitigation['ioctl'][cmd] = {
                            'model': 'return_const',
                            'val': 0,
                        }

                    symex_mitigation = deepcopy(config['files'][path])
                    symex_mitigation['weight'] = weight
                    symex_mitigation['ioctl'][cmd] = {
                            'model': 'symbolic_cache',
                            'val': 0,
                        }

                    if handler['type'] == 'default':
                        # We just saw some default ioctls - we can propose both returning 0 and symex
                        # Prioritize symex, we like that more!
                        ret0_mitigation['weight'] -= (0.1 if ret0_mitigation['weight'] > 0.1 else 0.0)
                        results.append(ret0_mitigation)
                        results.append(symex_mitigation)

                    elif handler['type'] == 'symex':
                        # For each identified result we can propose a new config
                        for rv in handler['revs']:
                            mitigation = deepcopy(config['files'][path])
                            mitigation['weight'] = max(1.0, weight + 0.5) # We really like these!
                            mitigation['ioctl'][cmd] = {
                                    'model': 'return_const',
                                    'val': rv,
                                }
                            results.append(mitigation)

                    elif handler['type'] == 'return_const':
                        # If we had a return_const handler, there's no changes we can smartly make
                        # We've previously run symex and made constants from that. Plus we started
                        # with a model returning const 0
                        pass

                    else:
                        raise ValueError(f"Unexpeced handler type: {handler}")

            else:
                raise ValueError(f"Unexpected failure type {failtype}")
            return results

    def implement_mitigation(self, config, failure, mitigation):
        # Given a mitigation, add it to a copy of the config and return
        new_config = deepcopy(config)

        if failure in new_config[self.ANALYSIS_TYPE]:
            print(f"UH OH replacing {failure} in {new_config[self.ANALYSIS_TYPE]}")
            print(new_config[self.ANALYSIS_TYPE][failure])
            print(mitigation)
            print()
            #assert failure not in new_config[self.ANALYSIS_TYPE].keys()

        # fail_cause is our key?
        new_config[self.ANALYSIS_TYPE][failure] = deepcopy(mitigation)
        del new_config[self.ANALYSIS_TYPE][failure]['weight']

        # Ensure the name of the file we're modeling makes it into
        # env['dyndev.devnames'] which is a comma-separated list of
        # devices we want to model
        devs = []
        if 'dyndev.devnames' in config['env']:
            devs = new_config['env']['dyndev.devnames'].split(",")
        
        failure = failure.replace("/dev/", "") # dyndevs doesn't have /dev/ prefix
        if failure not in devs:
            devs.append(failure)
            new_config['env']['dyndev.devnames'] = ",".join(devs)

        return new_config


def main():
    from sys import argv

    if len(argv) < 3:
        raise ValueError(f"Usage {argv[0]} config output_dir")
    config_path = argv[1]
    output_dir = argv[2]

    with open(config_path, "r") as f:
        config = yaml.safe_load(f)

    analysis = FileFailuresAnalysis()
    failures = analysis.parse_failures(output_dir)
    print(f"Got {len(failures)} failures")

    idx = 0
    for fail_cause, fail_info in failures.items():
        print(f"Failure cause: {fail_cause} with info {fail_info}")

        mitigations = analysis.get_potential_mitigations(config, fail_cause, fail_info) or []
        print(f"\tGot {len(mitigations)} mitigations:")
        for m in mitigations or []:
            print(f"\t\t{m}")
            new_config = analysis.implement_mitigation(config, fail_cause, m)
            print("\t\t[env][dyndev] =", new_config['env']['dyndev.devnames'])
            print(f"\t\t[{analysis.ANALYSIS_TYPE}] =", new_config[analysis.ANALYSIS_TYPE])
            with open(f"{output_dir}/config{idx}.yaml", "w") as f:
                yaml.dump(new_config, f)
            idx += 1

if __name__ == '__main__':
    main()