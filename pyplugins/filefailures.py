import sys
import yaml
import tarfile
import re
from os.path import dirname
from pandare import PyPlugin

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
        with open(path.join(self.outdir, outfile), "w") as f:
            yaml.dump(self.file_failures, f)

def propose_mitigations(config, result_dir, quiet=False):
    with open(f"{result_dir}/{outfile}") as f:
        file_failures = yaml.safe_load(f)

    # File failures: weight is 2 * count by default
    mitigations = []
    for path, info in file_failures.items():

        if path.startswith("/dev"):
            score = 2 * len(info)
            if path[-1].isdigit():
                # XXX For now just ignore these. Could also just de-prioritize
                #print("\tIgnoring numeric device for now")
                score = 0.1 # Low priority
                continue
            if not quiet:
                print(f"\tSaw {len(info)} failures trying to open {path}")

            # Device file
            for (devtype, major, minor, mode) in [
                ('block', 1, 3, 777), # /dev/null - discard all data, return EOF on read
                ('block', 1, 5, 777), # /dev/zero - discard all data, return zeros on read
                    ]:
                mitigations.append((('add_file', 'dev', devtype, major, minor, mode, path), score))
        elif path.startswith("/proc"):
            # TODO: do we want to handle these? Fake procfiles? Rebuild kernel (llm assist?)
            #if not quiet:
            #    print(f"\tSaw {len(info)} failures trying to open {path} - ignoring for now")
            pass

    return mitigations