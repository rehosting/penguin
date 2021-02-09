#!/usr/bin/env python3
import readline # XXX: Workaround for #864
from pandare import Panda
from pandare.extras.file_faker import FileFaker, FakeFile
from pandare.extras.ioctl_faker import IoctlFaker
from subprocess import check_output

 ### REHOSTING
import os
import logging
import coloredlogs
coloredlogs.DEFAULT_LOG_FORMAT = '%(name)s %(levelname)s %(message)s'
coloredlogs.install()
logger = logging.getLogger('panda.rehoster')
logger.setLevel(logging.DEBUG)

# Silence panda internal logs
logger2 = logging.getLogger('panda.hooking')
logger2.setLevel(logging.ERROR)

kernel = "./zImage"
append = "root=/dev/mtdblock0 rw init=/sbin/init rootfstype=jffs2 \
       block2mtd.block2mtd=/dev/vda,0x40000 ip=dhcp sxid=0190_9MG-xx \
       earlyprintk=serial,ttyAMA0 console=ttyAMA0"

# dynamicly mount guest FS ro from qcow (TODO - for now just use binwalked dir)
qcow = "fs1.qcow"
mountpoint = "/home/fasano/git/router-rehosting/_stride-ms5_3_174.fwb.extracted/jffs2-root/fs_1"

panda = Panda("arm", mem="1G",
            #raw_monitor=True,
            extra_args=
            ["-M", "virt", "-kernel", kernel, "-append", append, "-display", "none",
            "-net", "nic,netdev=net0", # NET
            "-netdev", "user,id=net0,hostfwd=tcp::5443-:443,hostfwd=tcp::5580-:80,"\
                       "hostfwd=tcp::2222-:22",
            "-drive", f"if=none,file={qcow},id=vda,format=qcow2",
            "-device", "virtio-blk-device,drive=vda",
	    "-loadvm", "www"
            ])

panda.set_os_name("linux-32-debian.4.9.99")
panda.load_plugin("callstack_instr", {"stack_type": "asid"})
panda.load_plugin("syscalls2", {"load-info": True})

from subprocess import check_output
def find_offset(libname, func_name):
    '''
    Find offset of a symbol in a given executable
    '''
    fs_bin = check_output(f"find {mountpoint} -name {libname}",
                            shell=True).strip().decode('utf8', errors='ignore')
    offset = check_output(f"objdump -T {fs_bin} | grep {func_name}",
                        shell=True).decode('utf8', errors='ignore').split(" ")[0]
    return int("0x"+offset, 16)

@panda.ppp("syscalls2", "on_all_sys_enter")
def first_syscall(cpu, pc, callno):
    panda.disable_ppp("first_syscall")

    # Redundant with crawler's OSI logic but this runs first and must happen before FileFaker init
    panda.load_plugin("osi", {"disable-autoload": True})
    panda.load_plugin("osi_linux",
        {'kconf_file': os.path.dirname(os.path.realpath(__file__))+'/virt.conf',
         'kconf_group': 'linux:virt_4.9.99:64'})

    file_faker  = FileFaker(panda)
    ioctl_faker = IoctlFaker(panda, use_osi_linux=False)
    file_faker.rename_file("/dev/mtdblock4", "/dev/mtdblock2")

    # Pretend we're a different CPU
    file_faker.replace_file("/proc/cpuinfo", FakeFile("cpu : isxni9260\n"))

    # Whatever ID we put in /proc/devices for dsa will be used as the major #
    # when it mknod's the entry in /dev. 4=tty which is relatively inoffensive
    file_faker.replace_file("/proc/devices", FakeFile("4 dsa\n"))

from crawl import Crawler
c = Crawler(panda, "https://localhost:5443", mountpoint)

panda.run()
