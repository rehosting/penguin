#!/usr/bin/env python3

from pandare import Panda
CID = 4
KERN = "4.10"

bindir = "/home/andrew/git/HyDE/fws/"
image = bindir + "stride.raw"
config = { "qemu_machine": "virt",
           "arch":         "arm",
           "rootfs":       "/dev/vda",
           "kconf_group":  "arm",
           "kernel":       bindir + f"zImage{KERN}.arm",
           "drive":        f'if=none,file={image},format=raw,id=rootfs',
           "extra_args":   ['-device', 'virtio-blk-device,drive=rootfs'] + \
                           ["-device", "vhost-vsock-pci,id=vhost-vsock-pci0,guest-cid="+str(CID)]}

# XXX ttyS0 or ttyAMA0 - does firmadyne console hardcode S0, is that the stride problem?
append = f"root={config['rootfs']} console=ttyS0 nandsim.parts=64,64,64,64,64,64,64,64,64,64 \
          rdinit=/firmadyne/preInit.sh rw debug ignore_loglevel print-fatal-signals=1 \
          user_debug=31 firmadyne.syscall=0"
append += " sxid=0190S_8MS-8 "
#append += " init=/firmadyne/utils/busybox -- nc -v -l -p 8000" # DEBUG
#append += " init=/usr/sbin/lighttpd -- -D -f /etc/lighttpd/lighttpd.conf"

args = ['-M',      config['qemu_machine'],
        '-kernel', config['kernel'],
        '-append', append,
        '-drive',  config['drive'],
        '-nographic'] + config['extra_args'] + ['-nographic']

panda = Panda(config['arch'], mem="256", extra_args=args, raw_monitor=True)
panda.set_os_name("linux-32-generic")
panda.load_plugin("syscalls2", {"load-info": True})
panda.load_plugin("osi", {"disable-autoload":True})
panda.load_plugin("osi_linux", {"kconf_file": f"{bindir}{config['kconf_group']}_profile{KERN}.conf",
                                "kconf_group": config['kconf_group']})
#panda.load_plugin("syscalls_logger", {'target': 'lighttpd'})

# Core rehosting @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
from pandarepyplugins import CallTree
panda.pyplugins.load(CallTree)

from pandarepyplugins import LoginForcer, ReadWriteReplace, IoctlFaker
panda.pyplugins.load(LoginForcer)
panda.pyplugins.load(ReadWriteReplace)
panda.pyplugins.ppp.ReadWriteReplace.add_proc("login", ":/bin/false", ":/bin/sh")
panda.pyplugins.load(IoctlFaker)

from pandarepyplugins.FileHallucinator import FileFaker, FakeDiskState, FakeFile
panda.pyplugins.load(FileFaker)
panda.pyplugins.ppp.FileFaker.hallucinate_file("/proc/devices", FakeFile, FakeDiskState(b"4 dsa\n"))
# panda.pyplugins.ppp.FileFaker.rename_file("/dev/mtdblock4", "/dev/mtdblock2")# Unnecessary?

#### End core rehosting

panda.pyplugins.enable_flask(host='127.0.0.1', port=65000)  # XXX could cause issues if guest listens here too?


# Load VSockify
import sys
sys.path.append("../HyDE")
from vsockify import VSockify
panda.pyplugins.load(VSockify, {'cid': CID, 'bridge': False})

# Load PandaWeb + PandaCrawl
#from pandaweb import PandaWeb
#panda.pyplugins.load(PandaWeb)
from pandacrawl import PandaCrawl
panda.pyplugins.load(PandaCrawl, {'cid': CID})

panda.pyplugins.serve()

# TODO: now import and run crawl? Maybe in another thread?
panda.run()
