import sys
import tarfile
import re
from os.path import dirname, join as pjoin, isfile
from pandare import PyPlugin
from copy import deepcopy
from typing import List, Optional
try:
    from penguin import yaml
    from penguin.analyses import PenguinAnalysis
except ImportError:
    PenguinAnalysis = object
    import yaml

mount_log = "mounts.csv"

class MountTracker(PyPlugin):
    '''
    Track when the guest tries mounting filesystems.

    If it's an unsupported type (i.e., mount returns EINVAL), we record
    so we could potentially add kernel support.

    If it's trying to mount a missing device, we record that too.

    For now this is just a passive tracker to inform us if we need to build more analyses or update
    our default kernel options.

    We could support a 'mount shim' option in our config that we'd use to intercept mount calls
    and hide errors and/or mount a different filesystem (i.e., from our static FS extraction).

    I.e., we'd see a mount, report failure, propose mitigation of shimming, then we'd run
    with the mount faked, see what files get opened within the mount path, then try
    finding a good way to make those files appear
    '''
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.mounts = set()

        @self.panda.ppp("syscalls2", "on_sys_mount_return")
        def post_mount(cpu, pc, source, target, fs_type, flags, data):
            retval = panda.arch.get_retval(cpu, convention='syscall')
            results  = {
                "source": source,
                "target": target,
                "fs_type": fs_type,
            }

            for k, v in results.items():
                try:
                    results[k] = self.panda.read_str(cpu, v)
                except:
                    results[k] = "[unknown]"


            #print(f"Mount returns {retval} for: mount -t {results['fs_type']} {results['source']} {results['target']}")
            self.log_mount(retval, results)

            if retval == -16: # EBUSY
                # Already mounted - we could perhaps use this info to drop the mount from our init script?
                # Just pretend it was a success
                panda.arch.set_retval(cpu, 0, failure=False, convention='syscall')

            # Always pretend it was a success?
            #panda.arch.set_retval(cpu, 0, failure=False, convention='syscall')

    def log_mount(self, retval, results):
        src = results['source']
        tgt = results['target']
        fs = results['fs_type']

        if (src, tgt, fs) not in self.mounts:
            self.mounts.add((src, tgt, fs))
            with open(pjoin(self.outdir, mount_log), "a") as f:
                f.write(f"{src},{tgt},{fs},{retval}\n")