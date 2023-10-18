import sys
import yaml
import tarfile
import re
from os.path import dirname, join as pjoin
from pandare import PyPlugin
from copy import deepcopy

outfile = "file_failures.yaml"

def path_interesting(path):
    # /dev and /proc are interesting, with some exceptions
    if path.startswith("/dev/"):
        return True

    if path.startswith("/proc/"):
        return True

    '''
    # Libraries are boring
    if path.endswith(".so"):
        return False

    if ".so." in path:
        return False

    # XXX default which way?
    return True
    '''

    return False


class FileFailures(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.file_failures = {} # path: {mode: count}

        @panda.ppp("syscalls2", "on_sys_open_return")
        def fail_detect_open(cpu, pc, fname, mode, flags):
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            if rv >= 0:
                return

            # Just get pathname:
            fname = panda.read_str(cpu, fname)
            self.log_open_failure(fname, rv, mode)

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
            path = base + "/" + panda.read_str(cpu, fname)
            self.log_open_failure(path, rv, mode)


    def log_open_failure(self, path, rv, mode):
        if not path_interesting(path):
            return
        
        if rv != -2: # ENOENT - we only care about files that don't exist
            return

        if path not in self.file_failures:
            self.file_failures[path] = {}
        
        if mode not in self.file_failures[path]:
            self.file_failures[path][mode] = 0
        self.file_failures[path][mode] += 1

    def uninit(self):
        # Dump all file failures to disk as yaml
        with open(pjoin(self.outdir, outfile), "w") as f:
            yaml.dump(self.file_failures, f)

def propose_configs(config, result_dir, quiet=False):
    with open(f"{result_dir}/{outfile}") as f:
        file_failures = yaml.safe_load(f)

    # File failures: weight is 2 * count by default
    new_configs = []
    for path, info in file_failures.items():

        if path.startswith("/dev"):
            if not quiet:
                print(f"\tSaw {len(info)} failures trying to open {path}")

            for (weight, devtype, major, minor, mode) in [
                # Adding a dev-file is a high-value add. But adding in a different
                # mode is unlikely to change things. So we prioritize the weight of one
                (99, 'block', 1, 3, 777), # /dev/null - discard all data, return EOF on read
                (1, 'block', 1, 5, 777), # /dev/zero - discard all data, return zeros on read
                    ]:

                new_config = deepcopy(config)
                new_config['files'].append({
                    'type': 'dev',
                    'devtype': devtype,
                    'major': major,
                    'minor': minor,
                    'mode': mode,
                    'path': path
                })

                # And setup a default IOCTL modeler that returns 0 but will propose alternatives
                # based on symex
                new_config['ioctls'].append({
                    'path': path,
                    'type': 'symbolic_cache',
                    'cmd': '*',
                    'val': 0
                })

                new_config['meta']['delta'].append(f"add_device {path}")

                if path[-1].isdigit():
                    weight *= 0.01 # Low priority, think like /dev/ptyX with lots of X's
                new_configs.append((weight, new_config))
        elif path.startswith("/proc"):
            # TODO: do we want to handle these? Fake procfiles? Rebuild kernel, perhaps
            # with LLM assistance?
            #if not quiet:
            #    print(f"\tSaw {len(info)} failures trying to open {path} - ignoring for now")
            pass

    return new_configs