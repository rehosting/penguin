import sys
import tarfile
import re
from os.path import dirname, join as pjoin
from pandare import PyPlugin
from copy import deepcopy

try:
    from penguin import PenguinAnalysis, yaml
except ImportError:
    # We can still run as a PyPlugin, but we can't do post-run analysis
    PenguinAnalysis = object
    import yaml

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

class FileFailuresAnalysis(PenguinAnalysis):
    ANALYSIS_TYPE = "files"

    def parse_failures(self, output_dir):
        with open(pjoin(output_dir, outfile)) as f:
            file_failures = yaml.safe_load(f)

        fails = []
        for path, info in file_failures.items():
            if path.startswith("/dev") or path.startswith("/proc"):
                if self.debug:
                    print(f"\tSaw {len(info)} failures trying to open {path}")
                fails.append(path)
        return {k: {} for k in fails}
    
    def get_potential_mitigations(self, config, path, _):
        # We propose mitigations from state (global or local!)
        results = {} # path -> [details]

        if config is not None and path in config['files']:
            # This config already has a mitigation for this file - can't add again
            # If we're getting potential mitigations for the config that we did
            # parse failures on, this probably never happens?
            return []

        if path.split("/")[1] == 'dev':
            results = []
            for (devtype, major, minor, mode) in [
                ('block', 1, 3, 777), # /dev/null - discard all data, return EOF on read
                ('block', 1, 5, 777), # /dev/zero - discard all data, return zeros on read
                    ]:

                results.append({
                    'type': 'dev',
                    'devtype': devtype,
                    'major': major,
                    'minor': minor,
                    'mode': mode,
                    # XXX: we also want to say this goes with an IOCTL mitigation?
                    # Should we include path in here?
                })

                # And setup a default IOCTL modeler that returns 0 but will
                # propose alternatives based on symex
                #new_config['ioctls'].append({
                #    'path': path,
                #    'type': 'symbolic_cache',
                #    'cmd': '*',
                #    'val': 0
                #})
            return results

        elif path.split("/")[1] == 'proc':
            # TODO: we *should* model these in various ways!
            return []
        else:
            print("WARN: Unexpected file:", path)
            return []

    def implement_mitigation(self, config, failure, mitigation):
        # Given a mitigation, add it to a copy of the config and return
        new_config = deepcopy(config)
        assert failure not in new_config[self.ANALYSIS_TYPE].keys()

        # fail_cause is our key?
        new_config[self.ANALYSIS_TYPE][failure] = mitigation
        return new_config