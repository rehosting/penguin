import sys
import tarfile
import re
from os.path import dirname, join as pjoin, isfile
from pandare import PyPlugin
from copy import deepcopy
from typing import List, Optional
try:
    from penguin import PenguinAnalysis, yaml
except ImportError:
    PenguinAnalysis = object
    import yaml

mount_types = "mount_types.csv"
mount_fs = "mount_filesystems.csv"

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
        self.mount_types = set()
        self.mount_fs = set()

        @self.panda.ppp("syscalls2", "on_sys_mount_return")
        def post_mount(cpu, pc, source, target, fs_type, flags, data):

            retval = panda.arch.get_retval(cpu, convention='syscall')
            if retval == 0:
                # Successfull mount. Cool
                return
            
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


            # We only care about EINVAL and ENODEV
            if retval == -22:
                # EINVAL - unsupported filesystem type.
                # report the type that was unsupported
                self.log_einval(results['fs_type'])
            elif retval == -19:
                # ENODEV - missing device
                self.log_enodev(results['source'], results['target'])

            elif retval == -16: # EBUSY
                # Already mounted - we could perhaps use this info to drop the mount from our init script?
                pass
            else:
                print(f"Unknown mount error: {retval}: mount -t {results['fs_type']} {results['source']} {results['target']}")

    def log_einval(self, fs):
        if fs not in self.mount_types:
            self.mount_types.add(fs)
            with open(pjoin(self.outdir, mount_types), "a") as f:
                f.write(f"{fs}\n")

    def log_enodev(self, src, tgt):
        if (src, tgt) not in self.mount_fs:
            self.mount_fs.add((src, tgt))
            with open(pjoin(self.outdir, mount_fs), "a") as f:
                f.write(f"{src},{tgt}\n")