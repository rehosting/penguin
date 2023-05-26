import sys
from pandare import PyPlugin
import heapq

# Paths we don't care about:
# /firmadyne/libnvram anything - this reveals the nvram values read though
# socket:{RAW,UDP,TCP,...}
# /proc/*/{mounts,stat,cmdline} - boring?

def ignore_ioctl_path(path):
    if path.startswith("/firmadyne/libnvram"):
        return True
    if path.startswith("/proc/"):
        return True
    if path.startswith("socket:"):
        return True
    if path.startswith("pipe:"):
        return True
    return False

def ignore_cmd(ioctl):
    # Ignore TTY ioctls, see ioctls.h for T*, TC*, and TIO* ioctls
    if ioctl >= 0x5400 and ioctl <= 0x54FF:
        return True
    return False

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

class WeightedItem:
    def __init__(self, item, weight):
        self.item = item
        self.weight = weight

    def __lt__(self, other):
        return self.weight < other.weight

class WeightedList:
    def __init__(self):
        self.items = []

    def insert(self, item, weight):
        weighted_item = WeightedItem(item, weight)
        heapq.heappush(self.items, weighted_item)

    def iterweight(self):
        while self.items:
            weighted_item = heapq.heappop(self.items)
            yield weighted_item.item

class FailDetect(PyPlugin):
    def __init__(self, panda):
        self.panda = panda

        self.ioctl_failures = {} # path: {IOCTL: count}
        self.file_failures = {} # path: {mode: count}
        self.did_uninit = False

        @panda.ppp("syscalls2", "on_sys_ioctl_return")
        def fail_detect_on_sys_ioctl_return(cpu, pc, fd, request, arg):
            rv = self.panda.arch.get_retval(cpu, convention="syscall")
            if rv < 0:

                if ignore_cmd(request):
                    return

                # Convert FD to filename with OSI
                proc = self.panda.plugins['osi'].get_current_process(cpu)
                if proc == self.panda.ffi.NULL:
                    return

                filename_c = self.panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)
                if filename_c == self.panda.ffi.NULL:
                    return

                filename = self.panda.ffi.string(filename_c).decode()

                if ignore_ioctl_path(filename):
                    return

                # Check if it's hooked with our ioctl faker (TODO: only if this is loaded?)
                if self.ppp.IoctlFakerC.is_ioctl_hooked(filename, request):
                    # We need to dynamically check this, unlike with files becasue we don't know
                    # the order in which the IoctlFakerC vs faildetect will run
                    return

                if filename not in self.ioctl_failures:
                    self.ioctl_failures[filename] = {}

                if request not in self.ioctl_failures[filename]:
                    self.ioctl_failures[filename][request] = 0

                self.ioctl_failures[filename][request] += 1

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

        if path not in self.file_failures:
            self.file_failures[path] = {}
        
        if mode not in self.file_failures[path]:
            self.file_failures[path][mode] = 0
        self.file_failures[path][mode] += 1


    def propose_mitigation(self, fail_class, *args):
        '''
        For a given failure, propose one or more mitigations
        '''
        if fail_class == 'open':
            path = args[0]
            if path.startswith("/proc"):
                print(f"NYI: handle open failure on /proc: {path}", file=sys.stderr)
                return

            print(f"PROPOSED MITIGATION: create {path}", file=sys.stderr)

        elif fail_class == 'ioctl':
            ioctl, path = args[0], args[1]
            
            # Let's say we can either return 0, 1, or 0xffffffff
            for result in [0, 1, 0xffffffff]:
                print(f"PROPOSED MITIGATION: handle ioctl {ioctl:#x} on {path} to return {result}", file=sys.stderr)

    def uninit(self):
        if self.did_uninit:
            return
        self.did_uninit = True

        mitigations = WeightedList()

        # Here we just calculate failure weights - we *don't* propose mitigations

        # File failures: weight is 2 * count by default
        for path, failures in self.file_failures.items():
            print(f"Saw {len(failures)} failures trying to open {path}", file=sys.stderr)
            mitigations.insert(('open', path), 2*len(failures))
        
        # Ioctl failures: weight is 1 * count
        for path, failures in self.ioctl_failures.items():
            # Iterate through failures, sorted by key (low to high)
            for ioctl, count in sorted(failures.items()):
                print(f"Saw {count} failures trying to run ioctl {ioctl:#x} on {path}", file=sys.stderr)
                mitigations.insert(('ioctl', ioctl, path), len(failures))


        for mitigation in mitigations.iterweight():
            self.propose_mitigation(*mitigation)

    def __del__(self):
        self.uninit()