import sys
import tarfile
import re
import logging
# coloredlogs
import coloredlogs
from os.path import dirname, join as pjoin
from pandare import PyPlugin
from copy import deepcopy
from typing import Dict, Any, List

coloredlogs.install(level='DEBUG', fmt='%(asctime)s %(name)s %(levelname)s %(message)s')

try:
    from penguin import PenguinAnalysis, yaml
except ImportError:
    # We can still run as a PyPlugin, but we can't do post-run analysis
    PenguinAnalysis = object
    import yaml

outfile = "file_failures.yaml"

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

        if self.get_arg("conf") is None or "ioctls" not in self.get_arg("conf"):
            raise ValueError("No ioctls in config: {self.get_arg('conf')}")

        self.configuration = self.get_arg("conf")["files"]

        # filename -> {read: model, write: model, ioctls: model}
        # XXX TODO: coordinate with hyperfile for modeling behavior!
        # Can we just pass our config straight over and load both?
        # Need to implement read, write, and IOCTLs
        # IOCTLs with symex gets scary, others are easy though?

        @panda.ppp("syscalls2", "on_sys_open_return")
        def fail_detect_open(cpu, pc, fname, mode, flags):
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            if rv >= 0:
                return

            # Grab the filename and track iff we care
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

            self.log_write_failure(name, rv, count)

            

    def centralized_log(self, path, event):
        if not path_interesting(path):
            return

        if path not in self.file_failures:
            self.file_failures[path] = {}
        
        if event not in self.file_failures[path]:
            self.file_failures[path][event] = {'count': 0}

        self.file_failures[path][event]['count'] += 1


    def log_open_failure(self, path, rv, mode):
        if rv != -2: # ENOENT - we only care about files that don't exist
            return
        self.centralized_log(path, 'open')

    def log_read_failure(self, path, rv, count):
        # Should our module returna  specific error we check for?
        self.centralized_log(path, 'read')

    def log_write_failure(self, path, rv, count):
        # Should our module returna  specific error we check for?
        self.centralized_log(path, 'write')

    def log_ioctl_failure(self, path, rv, cmd):
        if not path_interesting(path) or ignore_ioctl_path(path):
            return
        if not ignore_cmd(cmd):
            return

        if path not in self.file_failures:
            self.file_failures[path] = {}
        
        if 'ioctl' not in self.file_failures[path]:
            self.file_failures[path]['ioctl'] = {}

        if cmd not in self.file_failures[path]['ioctl']:
            self.file_failures[path]['ioctl'][cmd] = {'count': 0}
        self.file_failures[path]['ioctl'][cmd]['count'] += 1

    def uninit(self):
        # Dump all file failures to disk as yaml
        with open(pjoin(self.outdir, outfile), "w") as f:
            yaml.dump(self.file_failures, f)

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
        print("NYI: static mitigations for files")
        return []
    

    @staticmethod
    def get_default_device(weight):
        return {
            'weight': weight, 
            # Default behavior. Error on read/write/ioctl - we'll fix when we see it
            'read': 'uhandled',
            'write': 'unhandled',
            'ioctl': {
                    '*': {
                        'type': 'unhandled',
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

                    if handler['type'] == 'unhandled':
                        # We just saw some unhandled ioctls - we can propose both returning 0 and symex
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