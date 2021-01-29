#!/usr/bin/env python3
from pandare import Panda, ffi
from pandare.extras.file_faker import FileFaker, FakeFile
from pandare.extras.ioctl_faker import IoctlFaker
from time import sleep
from subprocess import check_output
from queue import PriorityQueue
import json

from itertools import product

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from bs4 import BeautifulSoup
import requests
import re

import os
import logging
import coloredlogs
coloredlogs.DEFAULT_LOG_FORMAT = '%(name)s %(levelname)s %(message)s'
coloredlogs.install()
logger = logging.getLogger('panda.crawler')
logger.setLevel(logging.DEBUG)

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
    # If the current process is WWW, find auth library and set up hook
    proc = panda.plugins['osi'].get_current_process(cpu) 
    if proc == ffi.NULL:
        return
    proc_name = ffi.string(proc.name).decode("utf8", errors="ignore")

    if proc_name not in ['lighttpd']:
        return 0

    # Scan memory for loaded authentication libraries and hook to always auth valid users
    # Supported auth bypasses:
    #   1) lighttpd 1.4
    #   ... that's it for now. TODO: use dynamic symbol resolution to support across builds/versions

    def _find_offset(libname, func_name):
        fs_bin = check_output(f"find {mountpoint} -name mod_auth.so", shell=True).strip().decode('utf8', errors='ignore')
        offset = check_output(f"objdump -T {fs_bin} | grep http_auth_basic_check", shell=True).decode('utf8', errors='ignore').split(" ")[0]
        return int("0x"+offset, 16)

    hook_addr = None
    for mapping in panda.get_mappings(cpu):
        if mapping.name != ffi.NULL:
            name = ffi.string(mapping.name).decode()
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

web_files  = set()
crawl_queue = PriorityQueue(1000) # Prioritized queue of items to visit
queued = [] # list of everything ever queued (visited + to visit)
requested = {}  # path: (meth, url, params, result_code)
current_request = None
external_refs = set()
osi_dirs = set() # Set of directories we queued files from with OSI

def do_queue(path, method="GET", args={}):
    global crawl_queue, queued

    if not path: return


    while "//" in path:
        path = path.replace("//", "/")

    if "#" in path:
        path = path.split("#")[0]

    if path in requested.keys():
        return

    # Range from +100 to 0. Higher is less important
    prio = 50

    if path.endswith(".gif") or path.endswith(".jpg"):
        prio += 50

    if path.endswith(".css") or path.endswith(".js"):
        prio += 40

    if "help" in path:
        prio += 10

    if "cgi-bin" in path:
        prio -= 40

    if method != "GET":
        prio = 0 # HIGHEST

    if (method, path, args) not in queued:
        crawl_queue.put_nowait((prio, (method, path, json.dumps(args)))) # May raise exn, better than blocking
        queued.append((method, path, args))


# Find www files
#do_queue("index.html")
#do_queue("cgi-bin/cfgconf.cgi") # TESTING
do_queue("/cgi-bin/quickconf.cgi") # TESTING


# It's not as simple as running find but there's some middle ground to try
'''
webroot = mountpoint+"/var/www" # TODO: genericize
files = check_output(f"find {webroot} -type f ", shell=True).decode("utf8", errors="ignore")
for f in files.split("\n"):
    this_file = f.replace(webroot, "").strip()
    do_queue(this_file)
'''

def analyze(fname):
    if not current_request:
        logger.warning("Can't analyze this request - was it initiated externally?")
        return

    host_path = mountpoint +"/"+fname
    #print(f"WWW opens new {fname}")
    if not os.path.isfile(host_path):
        #print("MISSING FW FILE:", fname) # Notable, but probaly okay? /proc and friends
        return

    host_dir_name = os.path.dirname(host_path)
    dir_name = host_dir_name.replace(mountpoint+"/", "")

    # Current request is for /a/b and we see files /z/a/c, z/a/d - need to build URL: a/c, a/d
    # First identify common path
    # FS: /var/www/dir/page1.html
    # WWW:        /dir/page0.html

    # FS: /var/www/page1.html
    # WWW:        /page0.html

    # Hack: just assume /var/www
    basedir = "/var/www/"

    if dir_name not in osi_dirs:
        osi_dirs.add(dir_name)
        dir_files = os.listdir(host_dir_name)
        #print(f"Read of dir {dir_name} - other files: {dir_files[:4]}...")
        for sibling_files in dir_files: # files or subdirs
            base_dir = os.path.abspath(os.path.dirname("/"+current_request))
            rel_file = base_dir + "/" + sibling_files.replace(basedir, "")

            if rel_file in requested.keys(): # already loaded
                continue
            do_queue(rel_file)

    # TODO: walk parent directories up to webroot and queue up additional files

    if "." in fname:
        ext = fname.split(".")[-1]
        if ext == "cgi":
            print("TODO: Analyze cgi-bin file")


@panda.ppp("syscalls2", "on_sys_execve_enter")
def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
    # Log commands and arguments passed to execve
    try:
        fname = panda.read_str(cpu, fname_ptr)
        argv_buf = panda.virtual_memory_read(cpu, argv_ptr, 100)
        envp_buf = panda.virtual_memory_read(cpu, envp, 100)
    except ValueError: return

    proc = panda.plugins['osi'].get_current_process(cpu) 
    if proc == ffi.NULL:
        return
    proc_name = ffi.string(proc.name).decode("utf8", errors="ignore")

    # Want to filter out background but if lighttpd spawns a shell script which spawns something
    # interesting, we do want to report it
    #if proc_name not in ['lighttpd'] and not ".cgi" in proc_name:
    #    return

    #if current_request is None:
    #    return # Non-crawler request (i.e., find_auth)

    argv = []
    for ptr in ffi.from_buffer("int[]", argv_buf):
        if ptr == 0: break
        try: argv.append(panda.read_str(cpu, ptr))
        except ValueError: argv.append("(error)")

    env = []
    for ptr in ffi.from_buffer("int[]", envp_buf):
        if ptr == 0: break
        try: env.append(panda.read_str(cpu, ptr))
        except ValueError: env.append("(error)=(error)")
    logger.info("Executing: " + ' '.join(argv)) #+ " with args: " + str(env))

    # Keep quiet
    '''
    if ".cgi" in argv[0]:
        for env_pair in env:
            if len(env_pair.split("=")) == 2:
                k,v = env_pair.split("=")
                logger.info(f"\t{k}\t=\t{v}")
            else:
                logger.info(f"\t{env_pair}")
    '''

@panda.ppp("syscalls2", "on_sys_open_enter")
def on_sys_open_enter(cpu, pc, fname_ptr, flags, mode):
    if current_request is None:
        return # Non-crawler request (i.e., find_auth)

    # ID files opened by webserver, pass to analyze() first time we see each file
    try:
        fname = panda.read_str(cpu, fname_ptr)
    except ValueError:
        # Read failed
        return

    proc = panda.plugins['osi'].get_current_process(cpu) 
    if proc == ffi.NULL:
        return
    proc_name = ffi.string(proc.name).decode("utf8", errors="ignore")

    if proc_name not in ['lighttpd']:
        return

    if fname not in web_files:
        web_files.add(fname)
        analyze(fname)

@panda.ppp("syscalls2", "on_sys_read_return")
def read_ret(cpu, pc, fd, buf, cnt):

    if fd != 0: # Assuming standard STDIN on FD 0
        return

    proc = panda.plugins['osi'].get_current_process(cpu) 
    if proc == ffi.NULL:
        return
    proc_name = ffi.string(proc.name).decode("utf8", errors="ignore")

    if ".cgi" not in proc_name: # Only want CGI inputs
        return

    if not cnt == 0:
        return

    try:
        data = panda.read_str(cpu, buf)
    except ValueError:
        # Read failed
        return

    if len(data) == 0:
        return

    logger.info(f"POSTDATA: {repr(data[:cnt])}")

    # Idea: take a snapshot *now* and mutate this buffer to fuzz target CGI bin

@panda.ppp("syscalls2", "on_sys_write_enter")
def write_ent(cpu, pc, fd, buf, cnt):
    if fd not in [1, 2]: # Assuming standard STDOUT/STDERR on FD 1/2
        return

    proc = panda.plugins['osi'].get_current_process(cpu) 
    if proc == ffi.NULL:
        return
    proc_name = ffi.string(proc.name).decode("utf8", errors="ignore")

    if ".cgi" not in proc_name: # Only want CGI inputs
        return

    try:
        data = panda.read_str(cpu, buf)
    except ValueError:
        # Read failed
        return

    #logger.info(f"RESPONSE: {repr(data[:cnt])}")



def make_abs(ref):
    '''
    Given a reference found on a page, resolve relative paths
    '''
    global requested, external_refs

    assert(current_request is not None)

    if ref not in requested.keys():
        if ref.startswith("/"): # Absolute
            abs_ref = ref
        elif "://" in ref:
            if ref not in external_refs:
                external_refs.add(ref)
            return None
        else:
            base_dir = os.path.dirname("/"+current_request)
            abs_ref =  os.path.abspath(base_dir + "/" + ref)
        return abs_ref

def scan_output(html_page):
    # Analyze response from server - look for:
    #   Reference to other pages (possibly with url params?)
    #     - SRC, HREF
    #   Forms
    #   Buttons with actions (need for headless browser?)
    soup = BeautifulSoup(html_page, 'lxml') # XXX using html.parser causes segfaults (threading?)

    # Generic find all SRC and HREF
    for elm in soup.findAll():
        src = elm.get('src')
        if src:
            do_queue(make_abs(src))

        href = elm.get('href')
        if href:
            do_queue(make_abs(href))

    # FORMS
    for form in soup.findAll('form'):
        #print("FORM:", form)
        action = form.get('action')
        method = form.get('method').upper() # Simplify methods by always being caps

        vals = {}
        for field in form.findAll('input'):
            name = field.get('name')
            if not name:
                continue
            in_type = field.get('type')

            fuzz = []
            default = field.get('value')

            if in_type in ['text', 'hidden']:
                #fuzz = "1.2.3.4; sleep 30s; aaaaaaaaaaa ' or '1' ='1'--"
                if default:
                    fuzz.append(default)
                fuzz.append("aaaaaa; sleep 30")

            elif in_type in ["submit"]:
                if default:
                    fuzz.append(default)
                else:
                    fuzz.append("")

            elif in_type in ["checkbox", "button"]:
                fuzz = field.get('value') # checked / clicked(?)  means it submits the 'value' field

            elif in_type == "radio":
                # Multiple inputs, each with one value. Add to list
                # <input type="radio" id="male" name="gender" value="male">
                # <input type="radio" id="female" name="gender" value="female">
                fuzz.append(field.get('value'))

            else:
                print("Unhandled form type:", in_type)
                fuzz = ["1"]

            # Store mapping from name to a list of reasonable values
            vals[name] = fuzz

        # transform {"foo": [1,2], "Zoo": [1], "Moo": [3,4]} into
        # ([foo: 1, zoo:1, moo:3], [foo: 1, zoo:1, moo:4],
        #  [foo: 2, zoo:1, moo:3], [foo: 2, zoo:1, moo:4])

        # XXX: This is too many combinations. Should simplify
        keys, values = zip(*vals.items())
        params_list = [dict(zip(keys, v)) for v in product(*values)]

        abs_act = make_abs(action)
        for idx, params in enumerate(params_list):
            # Form is filled out - use METHOD to ACTION with vals
            logger.warning(f"Queueing form to {action}: {params}")

            do_queue(abs_act, method=method, args=params)

            if idx > 5:
                logger.warning(f"Abandoing subsequent permutations")
                break

        '''
        # For each input, try submitting non default
        # (default, non-def), (default), (default, non-def) should submit:
        # default, default, default
        # default, default, non-def
        # non-def, default, default

        for flip in range(len(vals)+1):
            # Flip the selected value to non-default
            this_vals =  {k:v[-1] for k,v in vals.items()}

            mutate = vals.keys()[flip]
            if len(vals[mutate]) > 1:
                this_vals[mutate] = vals[mutate][0] # Change to non-default

            if len(vals[mutate]) > 1 or flip == len(vals): # last one: all default
                do_queue(abs_act, method=method, args=this_vals)

        break # XXX DEBUG
        '''


#g_auth = (None, None, None) # type, user, pass
g_auth = ("basic", "admin", "foo") # XXX DEBUG ONLY
def find_auth(path):
    '''
    How do we log into this thing? Try a bunch of creds, methods until
    something works. Only partly implemented

    Currently works by hooks (setup on start) to bypass auth function.
    Could also ID creds on rootfs and try offline cracking or patching.
    May be challenging with snapshot-based analysis if webserver has already loaded creds
    '''
    logger.info(f"Attempting authentication bypass...")
    global current_request
    current_request = None

    # Username needs to be valid
    basic_users = ["admin", "user", "cli", "root", "test", "dev"]
    for user in basic_users:
        resp = requests.get(f"https://localhost:5443/{path}", verify=False,
                auth=(user, 'PANDAPASS'))
        if resp.status_code != 401:
            logger.info("Success!")
            global g_auth
            g_auth = ("basic", user, "PANDAPASS")
            return True

    print("Failed to bypass auth")

    return False

bypassed_auth = False
def fetch(meth, path, params):
    # Fetch a page from the webserver. Update current_request so background analyses know what's up
    logger.info(f"{'Fetching' if meth=='GET' else meth} {path} (Queue contains {crawl_queue.qsize()})")

    global current_request, requested
    current_request = path

    if g_auth[0] == None:
        # No auth
        if meth == "GET":
            resp = requests.get(f"https://localhost:5443/{path}", verify=False)
        elif meth == "POST":
            resp = requests.post(f"https://localhost:5443/{path}", data=params, verify=False)
        else:
            raise NotImplementedError("no auth with method="+meth)
    elif g_auth[0] == "basic":
        # Basic auth
        if meth == "GET":
            resp = requests.get(f"https://localhost:5443/{path}", verify=False,
                    auth=(g_auth[1], g_auth[2]))
        elif meth == "POST":
            resp = requests.post(f"https://localhost:5443/{path}", data=params, verify=False,
                    auth=(g_auth[1], g_auth[2]))
        else:
            raise NotImplementedError("basic auth with method=" + meth)
    else:
        raise NotImplementedError("Auth:", g_auth[0])

    fail = False
    if resp.status_code == 401:
        logger.warning(f"Unauthenticated: {path}")
        global bypassed_auth
        if not bypassed_auth and find_auth(path):
            # Only try find_auth once
            bypassed_auth = True
            logger.info(f"Bypassed authentication. Resuming crawl with discovered credentials.")
            # Reset this request now that we know how to auth
            return fetch(meth, path, params)

    elif resp.status_code == 404:
        logger.warning(f"Missing file {path}")
        fail = True
    elif resp.status_code == 500:
        logger.warning(f"Server error: {path}")
        fail = True
    elif resp.status_code == 200:
        fail = False
    else:
        logger.error(f"Unhandled status: {resp.status_code}")

    if path not in requested:
        requested[path] = ((meth, path, params, resp.status_code))

    assert(current_request is not None)
    if not fail:
        scan_output(resp.text)

    current_request = None

@panda.queue_async
def driver():
    global crawl_queue
    while not crawl_queue.empty():
        (prio, (meth, page, params_j))  = crawl_queue.get()
        params = json.loads(params_j)
        fetch(meth, page, params)
    panda.end_analysis()

# RUN
panda.run()


# Print stats

print("\n"*4 + "===========")
statuses = set([x[3] for x in requested.values()])
print(f"Visited {len(requested)} pages")
for status in statuses:
    print(f"Status [{status}]")
    for page_name in sorted(requested.keys()):
        page = requested[page_name] 
        if page[3] == status:
            print(f"\t {page[0]} {page[1]}")

print(f"Saw {len(external_refs)} external references")
for ref in sorted(external_refs):
    print(ref)
