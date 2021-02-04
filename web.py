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

panda = Panda("arm", mem="1G", raw_monitor=True, extra_args=
            ["-M", "virt", "-kernel", kernel, "-append", append, "-nographic",
            "-net", "nic,netdev=net0", # NET
            "-netdev", "user,id=net0,hostfwd=tcp::5443-:443,hostfwd=tcp::5580-:80,"\
                       "hostfwd=tcp::2222-:22",
            "-drive", f"if=none,file={qcow},id=vda,format=qcow2",
            "-device", "virtio-blk-device,drive=vda",
	    "-loadvm", "www"
            ])

panda.set_os_name("linux-32-debian.4.9.99")
panda.load_plugin("callstack_instr", {"stack_type": "asid"})
panda.load_plugin("syscalls2")

# Not rehosting - TODO migrate into class

hook_config = {} # pc: retval
def hook_auth(cpu, tb):
    logger.debug("Bypassing auth")
    panda.arch.set_reg(cpu, "r0", hook_config[tb.pc]) # retval
    panda.arch.set_reg(cpu, "ip", panda.arch.get_reg(cpu, "lr"))
    return True

@panda.ppp("syscalls2", "on_all_sys_enter")
def first_syscall(cpu, pc, callno):
    panda.disable_ppp("first_syscall")

    panda.load_plugin("osi", {"disable-autoload": True})
    panda.load_plugin("osi_linux",
	    {'kconf_file': os.path.dirname(os.path.realpath(__file__)) + '/virt.conf',
	     'kconf_group': 'linux:virt_4.9.99:64'})

    file_faker  = FileFaker(panda)
    ioctl_faker = IoctlFaker(panda, use_osi_linux=False)
    file_faker.rename_file("/dev/mtdblock4", "/dev/mtdblock2")

    # Pretend we're a different CPU
    file_faker.replace_file("/proc/cpuinfo", FakeFile("cpu : isxni9260\n"))

    # Whatever ID we put in /proc/devices for dsa will be used as the major #
    # when it mknod's the entry in /dev. 4=tty which is relatively inoffensive
    file_faker.replace_file("/proc/devices", FakeFile("4 dsa\n"))

    panda.enable_callback('asid_www')

@panda.cb_asid_changed(enabled=False)
def asid_www(cpu, old_asid, new_asid):
    '''
    For the first basic block in the WWW process we want to scan its memory
    and setup some hooks - auth bypass + ssl decryption
    '''

    proc = panda.plugins['osi'].get_current_process(cpu) 
    if proc == panda.ffi.NULL:
        return
    proc_name = panda.ffi.string(proc.name).decode("utf8", errors="ignore")

    if proc_name not in ['lighttpd']:
        return 0

    # Scan memory for loaded authentication libraries and hook to always auth valid users
    # Supported auth bypasses:
    #   1) lighttpd 1.4
    #   ... that's it for now. TODO: use dynamic symbol resolution to support across builds/versions

    def _find_offset(libname, func_name):
        fs_bin = check_output(f"find {mountpoint} -name {libname}", shell=True).strip().decode('utf8', errors='ignore')
        offset = check_output(f"objdump -T {fs_bin} | grep {func_name}", shell=True).decode('utf8', errors='ignore').split(" ")[0]
        return int("0x"+offset, 16)

    hook_addr = None
    for mapping in panda.get_mappings(cpu):
        if mapping.name != panda.ffi.NULL:
            name = panda.ffi.string(mapping.name).decode()
            if name == "mod_auth.so":
                offset = _find_offset("mod_auth.so", "http_auth_basic_check")
                hook_addr = mapping.base + offset
                global hook_config
                hook_config[hook_addr] = 1 # Want to return 1
                break

    if hook_addr is None:
        logger.warning("No auth library found to hook")
    else:
        logger.info("Found auth library to hook")
        panda.hook(hook_addr)(hook_auth)



    panda.disable_callback('asid_www')

    return 0

# END Rehosting + Auth bypass

from crawl import Crawler
c = Crawler(panda, "https://localhost:5443", mountpoint)
c.crawl()
