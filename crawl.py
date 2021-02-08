import json
import logging
import os
import re
import random
#from queue import PriorityQueue
from collections import deque
from time import sleep
from subprocess import check_output
import urllib3
import requests
from bs4 import BeautifulSoup
import coloredlogs

from StateTreeFilter import StateTreeFilter, StateAdapter

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
coloredlogs.DEFAULT_LOG_FORMAT = '%(name)s %(levelname)s %(message)s'
coloredlogs.install()

def make_abs(base, ref):
    '''
    REF is a relative/absolute path valid when at base.
    Transform into a full absolute path
    '''

    if ref.startswith("/"): # absolute
        abs_ref = ref
    elif "://" in ref:
        return None
    else:
        base_dir = os.path.dirname("/"+base)
        delim = "/"
        if base_dir.endswith("/") or ref.startswith("/"):
            delim = ""
        abs_ref =  os.path.abspath(base_dir + delim + ref)
    return abs_ref

def longestSubstringFinder(string1, string2):
	# From https://stackoverflow.com/a/42882629
    answer = ""
    len1, len2 = len(string1), len(string2)
    for i in range(len1):
        for j in range(len2):
            lcs_temp=0
            match=''
            while ((i+lcs_temp < len1) and (j+lcs_temp<len2) and string1[i+lcs_temp] == string2[j+lcs_temp]):
                match += string2[j+lcs_temp]
                lcs_temp+=1
            if (len(match) > len(answer)):
                answer = match
    return answer

def get_calltree(panda, cpu):
    # Print the calltree to the current process

    proc = panda.plugins['osi'].get_current_process(cpu)
    if proc == panda.ffi.NULL:
        print("Error determining current process")
        return
    procs = panda.get_processes_dict(cpu)
    chain = [{'name': panda.ffi.string(proc.name).decode('utf8', 'ignore'),
              'pid': proc.pid, 'parent_pid': proc.ppid}]
    while chain[-1]['pid'] > 1 and chain[-1]['parent_pid'] in procs.keys():
        chain.append(procs[chain[-1]['parent_pid']])
    return " -> ".join(f"{item['name']} ({item['pid']})" for item in chain[::-1])

def is_child_of(panda, cpu, parent_names):
    # Return true IFF current_proc is or has a parent in parent_names

    proc = panda.plugins['osi'].get_current_process(cpu)
    if proc == panda.ffi.NULL:
        print("Error determining current process")
        return
    procs = panda.get_processes_dict(cpu)
    chain = [{'name': panda.ffi.string(proc.name).decode('utf8', 'ignore'),
              'pid': proc.pid, 'parent_pid': proc.ppid}]
    while chain[-1]['pid'] > 1 and chain[-1]['parent_pid'] in procs.keys():
        chain.append(procs[chain[-1]['parent_pid']])

    for item in chain:
        if item['name'] in parent_names:
            return True
    return False

def _strip_url(url):
    '''
    Remove any redundant properties from URLs

    Remove duplicate /s and anything after #
    '''

    if "://" in url:
        meth, body = url.split("://")
    else:
        meth = None
        body = url

    while "//" in body:
        body = body.replace("//", "/")

    if "#" in body:
        body = body.split("#")[0]

    if meth:
        return meth + "://" + body
    else:
        return body

class Crawler():
    '''
    A PANDA-powered web crawler. Analyzes syscalls and guest filesystem to identify attack surface
    '''

    def __init__(self, panda, domain, mountpoint, start_url="index.html"):
        self.panda = panda
        self.mountpoint = mountpoint # Host path to guest rootfs
        self.domain = domain # proto+domain+port to connect to. E.g. https://localhost:5443
        if not self.domain.endswith("/"):
            self.domain += "/"

        self.hook_config = {} # pc: retval

        # State management
        # States:
        # crawl: Crawling active (TODO more detailed sub-states)
        # findauth: Analyzing authentication on a 401-protected page (TODO: sub-states?)

        # formfuzz.analyze: Fuzzing a form - analyzing
        # formfuzz.send: Request sent to guest, but not yet parsed by webserver
        # formfuzz.decrypt: Guest is decrypting connection
        # formfuzz.introspection: Guest is responding to request - deep analysis enabled

        # maybe:
        # formfuzz.introspection.on_tree: Active process created by webserver or children

        self.s = StateTreeFilter('crawl')

        # Queue management
        self.crawl_queue = deque() # push right with append(), pop left with popleft()
        self.queued = [] # list of everything ever queued (tuples)
        self.queued_paths = [] # list of everything ever queued (url, method)

        self.form_queue = deque()
        self.queued_forms = [] # list of forms we've ever queued (action, method)

        self.crawl_results = {}  # path: (meth, url, params, result_code)

        self.current_request = None # None or path we are currently requesting

        # When WWW tries to open a file we analyze it and queue up other files with
        # analyze_www_open. Only want to do once per file and directory
        self.observed_file_opens  = set()
        self.observed_dir_accesses = set()

        self.bypassed_auth = False

        self.www_auth = (None, None, None) # type, user, pass
        self.start_url = start_url
        self.www_procs = ['lighttpd']

        local_log = logging.getLogger('panda.crawler')
        self.logger = StateAdapter(local_log, {'state': self.s})
        self.introspect_children = []

        # Debugging ONLY
        # DEBUG: analyze forms
        self.s.change_state('formfuzz.analyze')
        import pickle
        with open("form.pickle", "rb") as f:
            self.form_queue = pickle.loads(f.read())
        self.logger.error("Have %d targets in form_queue", len(self.form_queue))
        for (meth, page, params) in self.form_queue:
            params_dec = json.loads(params)
            self.logger.info("Form: %s with %d params", page, len(params_dec))
            #print(params_dec)
            #for param in params_dec.keys():
            #    print(param)
            #    print(params_dec[param])
            #    print(params_dec[param]['defaults'])

        # DEBUG: creds and basedir
        self.www_auth = ("basic", "admin", "foo")
        self.basedir = "/var/www/" # TODO: dynamically figure this out


        # PANDA callbacks registered within init so they can access self
        # without it being an argument

        @self.panda.queue_blocking
        def driver():
            # Do a task depending on current mode

            while len(self.crawl_queue) > 0 or len(self.form_queue) > 0:
                if self.s.state_matches('crawl'):
                    if len(self.crawl_queue):
                        (meth, page)  = self.crawl_queue.popleft()
                        self.logger.info("Fetching %s (%d in queue)", page, len(self.crawl_queue))
                        self.crawl_fetch(meth, page)
                    else:
                        # Exhaused crawl queue, switch to form fuzzing
                        # (if both queues are empty, loop terminates)
                        self.s.change_state('formfuzz.analyze')
                        self.logger.info("Switching to form fuzzing")
                        """
                        # DEBUG SAVE QUEUE
                        import pickle
                        try:
                            with open("form.pickle", "wb") as f:
                                pickle.dump(self.form_queue, f)
                        except Exception as e:
                            print("ERROR PICKLING:", e)
                        """

                elif self.s.state_matches('formfuzz.analyze'):
                    if len(self.form_queue):
                        #(meth, page, params_j)  = self.form_queue.popleft()
                        (meth, page, params_j)  = self.form_queue.pop()
                        params = json.loads(params_j)
                        self.fuzz_form(meth, page, params)
                    else:
                        self.logger.error("DEBUG - abort after end of formfuzz")
                        break # XXX
                        # Exhaused form fuzz queue, switch to crawling
                        # (if both queues are empty, loop terminates)
                        self.s.change_state('crawl')
                        self.logger.info("Switching to crawling")
                else:
                    # Driver is passive - a target analysis is ongoing (i.e., findauth)
                    sleep(1)
                    return None

            self.logger.info("END")
            self.logger.info("Driver finished both queues")
            self.panda.end_analysis()

        @self.panda.ppp("syscalls2", "on_sys_open_enter")
        @self.s.state_filter("crawl")
        def on_sys_open_enter(cpu, pc, fname_ptr, flags, mode):
            '''
            Identify files opened by WWW during crawl
            '''

            try: fname = self.panda.read_str(cpu, fname_ptr)
            except ValueError: return

            if self._active_proc_name(cpu) not in self.www_procs:
                return

            if fname in self.observed_file_opens:
                return

            '''
            This is a file we're opening for the first time. Here
            explore the directory being opened for other files to queue.
            Somewhere else we identify forms
            '''
            #self.logger.info(f"Observed first open of: {fname} by guest www")

            self.observed_file_opens.add(fname)

            if fname.startswith("/etc/"): # Not a webserver
                self.logger.warning(f"Ignoring WWW load of non-served(?) file {fname}")
                return

            # Need to resolve mountpoint/fname
            if fname.startswith("/"):
                fname = fname[1:]
            host_path = os.path.join(self.mountpoint, fname)

            if not os.path.isfile(host_path):
                self.logger.warning(f"File doesn't exist in FS at {host_path}")
                return

            # Current request is for /a/b and we see files /z/a/c, z/a/d - need to build URL: a/c, a/d
            # First identify common path - e.g.,
            # FS: /var/www/dir/page1.html       # FS: /var/www/page1.html
            # WWW:        /dir/page0.html        # WWW:        /page0.html

            host_dir_name = os.path.dirname(host_path)
            guest_dir_name = host_dir_name.replace(self.mountpoint+"/", "")

            if guest_dir_name not in self.observed_dir_accesses:
                self.observed_dir_accesses.add(guest_dir_name)
                dir_files = os.listdir(host_dir_name)

                for sibling_file in dir_files: # files or subdirs
                    base_dir = os.path.abspath(os.path.dirname("/"+self.current_request))
                    host_file = host_dir_name + "/" + sibling_file
                    rel_file = base_dir + "/" + sibling_file.replace(self.basedir, "")
                    rel_file = _strip_url(rel_file)

                    if os.path.isfile(host_file):
                        # sibling files - queue them all up
                        if rel_file not in self.queued_paths:
                            self.do_queue(rel_file)
                    elif os.path.isdir(host_file):
                        # Directory - queue up all files in the directory
                        # Could go deeper and queue up in dir/sub/sub2/.../file
                        subfiles = [x for x in os.listdir(host_file)
                                       if os.path.isfile(host_file + "/" + x)]
                        for subfile in subfiles:
                            rel_subdir_file = rel_file +"/" + subfile
                            self.do_queue(rel_subdir_file)

                    else:
                        self.logger.warn(f"Not a file not dir: {host_file}")
                        pass


            # TODO: walk parent directories up to webroot and queue up additional files

        ##### FORMFUZZ State machine in syscalls
        # When we're in formfuzz.send and we see a sys_accept + sys_read
        # on the FD and it contains our data, switch to formfuzz.introspect
        # UGH does it do weird stuff like dup the FD directly to a cgi-bin binary?
        self.formfuzz_fds = [] # Only supports exactly 1 FD for now

        @self.panda.ppp("syscalls2", "on_sys_accept4_return")
        @self.s.state_filter("formfuzz.send")
        def ffs_accept4(cpu, pc, sockfd, addr, addrlen, flags):
            returned_fd = self.panda.plugins['syscalls2'].get_syscall_retval(cpu)
            if returned_fd > 0:
                self.formfuzz_fds.append(returned_fd)
                self.logger.info("Fuzzform ACCEPT4ED on socket. File descriptor %d",
                                    returned_fd)



        @self.panda.ppp("syscalls2", "on_sys_accept_return")
        @self.s.state_filter("formfuzz.send")
        def ffs_accept(cpu, pc, sockfd, addr, addrlen):
            returned_fd = self.panda.plugins['syscalls2'].get_syscall_retval(cpu)
            if returned_fd > 0:
                self.formfuzz_fds.append(returned_fd)
                self.logger.debug("Fuzzform accepted on socket. File descriptor %d",
                                    returned_fd)

        # FD manipulation - unlikely to actually be used?
        '''
        @self.panda.ppp("syscalls2", "on_all_sys_return")
        @self.s.state_filter("formfuzz.send")
        def ffs_debug_all(cpu, pc, no):
            proc_name = self._active_proc_name(cpu)
            if proc_name == "lighttpd":
                print(f"{proc_name}: {no}")

            if no == 221: # FNCTL64
                proc_name = self._active_proc_name(cpu)
                if proc_name == "lighttpd" or proc_name.endswith(".cgi"):
                    # TODO use Luke's cleaner version of this from dynamic_symbols PR
                    fd      = panda.arch.get_reg(cpu, "r0")
                    cmd     = panda.arch.get_reg(cpu, "r1")
                    opt_arg = panda.arch.get_reg(cpu, "r2")
                    print(f"{proc_name}: fnctl64: fd={fd} cmd={cmd} arg={opt_arg}")

                    if fd in self.formfuzz_fds:
                        print("FNCTL HIT")
                        """
                        #define F_DUPFD     0   /* dup */
                        #define F_GETFD     1   /* get close_on_exec */
                        #define F_SETFD     2   /* set/clear close_on_exec */
                        #define F_GETFL     3   /* get file->f_flags */
                        #define F_SETFL     4   /* set file->f_flags */
                        #ifndef F_GETLK
                        #define F_GETLK     5
                        #define F_SETLK     6
                        #define F_SETLKW    7
                        #endif
                        #ifndef F_SETOWN
                        #define F_SETOWN    8   /* for sockets. */
                        #define F_GETOWN    9   /* for sockets. */
                        #endif
                        #ifndef F_SETSIG
                        #define F_SETSIG    10  /* for sockets. */
                        #define F_GETSIG    11  /* for sockets. */
                        """

                        if cmd == 0: # dup
                            print("DUP")
                        else:
                            print("Unhandled fnctl", cmd)

        @self.panda.ppp("syscalls2", "on_sys_dup_return")
        @self.s.state_filter("formfuzz.send")
        def ffs_dup(cpu, pc, src):
            if src in self.formfuzz_fds:
                dst = self.panda.plugins['syscalls2'].get_syscall_retval(cpu)
                print("DUP TO", dst)
                self.formfuzz_fds.append(dst)

        @self.panda.ppp("syscalls2", "on_sys_dup2_return")
        @self.s.state_filter("formfuzz.send")
        def ffs_dup2(cpu, pc, src, dst):
            if src in self.formfuzz_fds:
                print("DUP TO", dst)
                self.formfuzz_fds.append(dst)

        @self.panda.ppp("syscalls2", "on_sys_dup3_return")
        @self.s.state_filter("formfuzz.send")
        def ffs_dup3(cpu, pc, src, dst, flags):
            if src in self.formfuzz_fds:
                print("DUP TO", dst)
                self.formfuzz_fds.append(dst)
        '''

        # Decryption hooks - in two parts - on start and on ret
        @self.s.state_filter("formfuzz.decrypt", default_ret=0)
        def decrypt_hook(cpu, tb):
            # SSL_read(Encrypted, char* decrypted, int num)
            ret_addr = self.panda.arch.get_reg(cpu, "lr")

            # If first SSL_read for this request - reset buffers
            if not hasattr(self, 'decrypting') or not self.decrypting:
                self.decrypting = True
                self.decrypting_buf = self.panda.arch.get_reg(cpu, "r1")
                self.decrypting_cnt = self.panda.arch.get_reg(cpu, "r2")

            # XXX: Gets registered multiple times? Should use names and update if exists
            # each time ret hook is triggered it should disable itself
            self.panda.hook(ret_addr)(decrypt_ret_hook)

            return 0

        @self.s.state_filter("formfuzz.decrypt", default_ret=0)
        def decrypt_ret_hook(cpu, tb):
            if not hasattr(self, 'decrypting') or not self.decrypting:
                # Need to disable this hook better
                return 0

            if self.decrypting_cnt == 0:
                return 0

            try:
                data = panda.read_str(cpu, self.decrypting_buf)[:self.decrypting_cnt]
            except ValueError:
                self.logger.debug("Could not read buffer from 0x%x", self.decrypting_buf)
                return 0

            if self._parse_request(data):
                # IDEA: Right as we enter formfuzz.introspect would be a good place
                # to snapshot for fuzzing since we now have a plaintext buffer
                # about to be parsed
                self.s.change_state("formfuzz.introspect")
                self.decrypting = False
            return 0

        @self.panda.ppp("syscalls2", "on_sys_read_return")
        @self.s.state_filter("formfuzz.send")
        def introspect_read(cpu, pc, fd, buf, cnt):
            '''
            When accepted FD is read from check if its our data

            Note date may be encrypted (HTTPS) if so we move to that state
            '''

            if fd not in self.formfuzz_fds:
                return

            #assert len(self.formfuzz_fds)==1, "Unsupported: multiple accepted FDs"

            proc_name = self._active_proc_name(cpu)

            try:
                data = panda.read_str(cpu, buf)[:cnt]
            except ValueError:
                self.logger.warn("Could not read buffer from fd%d read()", fd)
                return

            # When we see reads it's either encrypted or not.
            # If it's encrypted, we push our parsing logic ahead to run
            # upon decryption (entering state formfuzz.decrypt)
            # otherwise we can run it here using this FD.

            if 'HTTP' in data: # Unencrypted - go right to introspect
                self.logger.info(f"{proc_name} reading unencrypted data")
                self.logger.error("TODO: handle plaintext")
                print("Plaintext request:", repr(data))
                # TODO HANLDE THIS

                self.s.change_state(".introspect")
            #else:

            if True: # Assume always encrypted...
                # Encrypted - wait for decryption to happen before introspecting
                self.logger.debug(f"{proc_name} potentially reading encrypted traffic from FD{fd} - attempting decryption")
                if not hasattr(self, 'decrypting_crypto'):
                    # Dynamically find crypto library + hook if we haven't previously
                    decrypt_addr = self.find_crypto_offset(cpu)
                    assert(decrypt_addr is not None), "Failed to find decryptor"
                    self.decrypting_crypto = True
                    self.panda.hook(decrypt_addr)(decrypt_hook)

                self.s.change_state(".decrypt")

        ### formfuzz.introspect state
        # Here we analyze calls to execve (interesting),
        # stdin/err/out from www and child processes, and
        # close syscalls (to identify end)

        @self.panda.ppp("syscalls2", "on_sys_execve_enter")
        @self.s.state_filter("formfuzz.introspect")
        def introspect_execve(cpu, pc, fname_ptr, argv_ptr, envp):
            '''
            When WWW responds to request, capture all execs.
            TODO: Store child PIDs so we can simplify is_child_of(www) later
            '''
            try:
                fname = panda.read_str(cpu, fname_ptr)
            except ValueError:
                return

            if is_child_of(self.panda, cpu, self.www_procs):
                proc = panda.plugins['osi'].get_current_process(cpu)
                pname = self.panda.ffi.string(proc.name).decode()

                args = self._read_str_buf(cpu, argv_ptr)
                cmd = " ".join(args)
                #callers = get_calltree(self.panda, cpu)
                #self.logger.warn("EXEC from %s %d: %s [%s]", pname, proc.pid, callers, cmd)
                # Maybe raise level, it's interesting
                self.logger.debug("WWW execs from %s: [%s]", pname, cmd)
                self.introspect_children.append(proc.pid)

                # Check if exec contains attacker-controlled data.
                # This should really be done on each arg - not the " ".join'd version
                # because execve ("/bin/ls" "attacker data") is very different from
                # execve("/bin/ls", "attacker", "data")
                for attacker_key, attacker_data in self.formfuzz_data.items():
                    # Are there any 6 bytes of attacker-controlled data
                    # that made it to the syscall arg string (anywhere?)
                    if len(attacker_data) <= 6 or len(cmd) <= 6:
                        continue

                    # slow :(
                    common_str = longestSubstringFinder(attacker_data, cmd)

                    if len(common_str) >= 6:
                        self.logger.error(f"Potential attacker controlled data `{common_str}` (from `{attacker_key}={attacker_data}` page=`{self.formfuzz_url}`) in execve: {args}")


            '''
            else:
                # DEBUG - off tree
                proc = panda.plugins['osi'].get_current_process(cpu)
                pname = self.panda.ffi.string(proc.name).decode()

                args = self._read_str_buf(cpu, argv_ptr)
                cmd = "  ".join(args)
                callers = get_calltree(self.panda, cpu)
                self.logger.info("Off-tree EXEC from %s: %s [%s]", pname, callers, cmd)
            '''

        @self.panda.ppp("syscalls2", "on_all_sys_enter2")
        @self.s.state_filter("formfuzz")
        def on_tree_syscall(cpu, pc, call, rp):
            '''
            Look at all string args to syscalls for www children during request
            processing. If any contain attacker-controlled data, alert user -
            this will highlight potential path-traversal and command injection
            vulnerabilities
            '''

            if call == self.panda.ffi.NULL:
                self.logger.debug("Unsupported syscall") # No additional info :(
                # Happens often, but for syscalls we probably don't care about?
                return
            if rp == self.panda.ffi.NULL:
                self.logger.warn("Syscall info (RP) null") # Unlikely
                return

            proc = self.panda.plugins['osi'].get_current_process(cpu)
            # Note - we might not care about syscalls issued by WWW itself
            # because children are more interesting (i.e., custom scripts)
            # if so, disable the second part of this check and move pname down
            pname = self.panda.ffi.string(proc.name).decode()
            if proc.pid not in self.introspect_children and pname not in self.www_procs:
                return

            #pname = self.panda.ffi.string(proc.name).decode()
            #cname = self.panda.ffi.string(call.name).decode()
            #self.logger.warn(f"Process {pname} issued syscall {cname}")

            for arg_idx in range(call.nargs):
                arg_type = call.argt[arg_idx]
                if arg_type == self.panda.libpanda.SYSCALL_ARG_STR_PTR:
                    arg_val = rp.args[arg_idx]

                    # arg is actually a mess. We have a guest pointer
                    # stored in a uint8_t array. Cast it to guest-ptr-size
                    # then we actually read it
                    argsz = call.argsz[arg_idx]
                    if argsz == 4:
                        cast_type = 'uint32_t'
                    elif argsz == 8:
                        cast_type = 'uint64_t'
                    else:
                        raise ValueError(f"Unhandled case for arg size {argsz}")

                    str_ptr = self.panda.ffi.cast(f'{cast_type}[{arg_idx+1}]',
                                                    arg_val)[arg_idx]

                    try:
                        str_val = self.panda.read_str(cpu, str_ptr)
                    except ValueError:
                        return

                    # Mostly duplicated with execve syscall
                    for attacker_key, attacker_data in self.formfuzz_data.items():
                        # Are there any 6 bytes of attacker-controlled data
                        # that made it to the syscall arg string (anywhere?)
                        if len(attacker_data) <= 6 or len(str_val) <= 6:
                            continue

                        # slow :(
                        common_str = longestSubstringFinder(attacker_data, str_val)

                        if len(common_str) >= 6:
                            cname = self.panda.ffi.string(call.name).decode()
                            arg_name = self.panda.ffi.string(call.argn[arg_idx]).decode()
                            self.logger.error(f"Potential attacker controlled data `{common_str}` (from `{attacker_key}={attacker_data}` page=`{self.formfuzz_url}`) in {cname} syscall's arg {arg_name}: `{str_val}`")


        @self.panda.ppp("syscalls2", "on_sys_write_enter")
        @self.s.state_filter("formfuzz")
        def write_ent(cpu, pc, fd, buf, cnt):
            '''
            Data written by child processes
            '''
            proc_name = self._active_proc_name(cpu)

            if proc_name not in self.www_procs:
                # TODO: check if pid or ppid matches www

                callers = get_calltree(self.panda, cpu)


            if ".cgi" not in proc_name: # only want cgi inputs
                return

            try:
                data = self.panda.read_str(cpu, buf)
            except ValueError:
                return

            out = [None, "STDOUT", "STDERR"][fd] if fd <= 2 else str(fd)
            self.logger.info(f"{proc_name}:{out}: {repr(data[:cnt])}")

        @self.panda.ppp("syscalls2", "on_sys_close_enter")
        @self.s.state_filter("formfuzz.introspect")
        def close_fd(cpu, pc, fd):
            '''
            WWW closes connection  - done with formfuzz.introspection
            But sometimes there's more processing in the background
            so let's leave our introspection running a little longer,
            until we get the response back in fuzz_form()
            '''

            if fd not in self.formfuzz_fds:
                return

            proc_name = self._active_proc_name(cpu)

            if proc_name in self.www_procs:
                self.logger.debug(f"{proc_name} closed network socket")
                self.formfuzz_fds = [x for x in self.formfuzz_fds if x != fd]
                #self.s.change_state(".analyze")

        def hook_return(cpu, tb):
            '''
            Registered as a hook to bypass auth by changing return value
            See call to panda.hook(...)(hook_return)
            '''
            if tb.pc not in self.hook_config:
                # Outdated hook
                return False
            #self.logger.info(f"Bypassing auth at 0x{tb.pc:x}")
            self.panda.arch.set_reg(cpu, "r0", self.hook_config[tb.pc]) # ret val
            self.panda.arch.set_reg(cpu, "ip", self.panda.arch.get_reg(cpu, "lr"))
            return True

        @self.panda.cb_asid_changed(enabled=False)
        @self.s.state_filter("findauth", default_ret=0)
        def findauth_hook(cpu, old_asid, new_asid):
            '''
            When WWW is next running, scan memory and find auth fn to hook
            '''

            proc_name = self._active_proc_name(cpu)

            if proc_name not in self.www_procs:
                return 0

            # Scan memory for loaded authentication libraries and hook
            # to always auth valid users

            # Supported auth bypasses:
            #   1) lighttpd 1.4
            #   ... that's it for now.

            hook_addr = None
            for mapping in panda.get_mappings(cpu):
                if mapping.name != panda.ffi.NULL:
                    name = panda.ffi.string(mapping.name).decode()
                    if name == "mod_auth.so":
                        offset = self._find_offset("mod_auth.so", "http_auth_basic_check")
                        hook_addr = mapping.base + offset
                        self.hook_config[hook_addr] = 1 # Want to return 1
                        self.logger.debug("Auth hook at 0x%x", hook_addr)
                        break

            if hook_addr is None:
                self.logger.warning("No auth library found to hook")
            else:
                self.logger.debug("Found auth library to hook")
                self.panda.hook(hook_addr)(hook_return)

            self.panda.disable_callback('findauth_hook')

            return 0




    ################################## / end of init


    # Helpers
    def _active_proc_name(self, cpu):
        proc = self.panda.plugins['osi'].get_current_process(cpu)
        if proc == self.panda.ffi.NULL: return ""
        return self.panda.ffi.string(proc.name).decode("utf8", errors="ignore")

    def _read_str_buf(self, cpu, ptr, length=100):
        '''
        Given a pointer to a char** (e.g., argv, envp), read
        and return as an array of strings.
        Returns [] on failure
        '''

        try:
            ptr_buf = self.panda.virtual_memory_read(cpu, ptr, length)
        except ValueError:
            return []

        results = []
        for read_ptr in self.panda.ffi.from_buffer("int[]", ptr_buf):
            if read_ptr == 0: break
            try:
                results.append(self.panda.read_str(cpu, read_ptr))
            except ValueError:
                results.append(None)

        return results

    def _parse_request(self, data):
        '''
        A request may be read in multiple bytes. Assuming only one is ever processed
        at a time, this will manage that read and combine into a single buffer.
        Returns `True` if request is finished or `False` if additional data is expected
        '''
        if not hasattr(self, "parse_req") or not self.parse_req:
            self.parse_req = True
            self.parse_req_buf         = ""   # Full buffer
            self.parse_req_in_headers  = True # before \r\n\r\n
            self.parse_req_headers     = ""   # up to  \r\n\r\n
            self.parse_req_postdata    = ""   # after  \r\n\r\n
            self.parse_req_content_len = None

        done = False
        if self.parse_req_in_headers:
            if "Content-Length: " in data:
                cl = data.split("Content-Length: ")[1].split("\n")[0]
                self.parse_req_content_len = int(cl)

            self.parse_req_buf += data
            self.parse_req_headers += data

            if "\r\n\r\n" in self.parse_req_headers:
                # end of headers
                self.parse_req_in_headers = False

                # Make sure we don't have any postdata in headers
                if "\r\n\r\n" in self.parse_req_headers:
                    self.parse_req_headers = self.parse_req_headers.\
                                                split("\r\n\r\n")[0]

                if self.parse_req_content_len is not None:
                    # Expecting postdata
                    self.logger.debug("Recv'd headers: %s", self.parse_req_headers)
                    pass
                else:
                    # Not expecting postdata, all done
                    self.logger.debug("Recv'd request: %s", self.parse_req_headers)
                    done = True

        if not self.parse_req_in_headers:
            # Now we're in postdata - however data may overlap so clean it first
            if "\r\n\r\n" in data:
                data = data.split("\r\n\r\n")[1]
            self.parse_req_postdata += data

            if len(self.parse_req_postdata) >= self.parse_req_content_len:
                self.logger.debug("Recv'd POSTDATA: %s", self.parse_req_postdata)
                done = True

        if done:
            # Have all expected data from request, cleanup state
            self.parse_req = False

        return done

    def _find_offset(self, libname, func_name):
        '''
        Find offset of a symbol in a given executable
        '''
        fs_bin = check_output(f"find {self.mountpoint} -name {libname}",
                                shell=True).strip().decode('utf8', errors='ignore')
        offset = check_output(f"objdump -T {fs_bin} | grep {func_name}",
                            shell=True).decode('utf8', errors='ignore').split(" ")[0]
        return int("0x"+offset, 16)


    def find_crypto_offset(self, cpu):
        '''
        Search currently loaded libraries for crypto (TODO parameterize for other libs)
        '''

        for mapping in self.panda.get_mappings(cpu):
            if mapping.name != self.panda.ffi.NULL:
                name = self.panda.ffi.string(mapping.name).decode()
                if name.startswith("libssl.so"):
                    offset = self._find_offset("libssl.so", "SSL_read")
                    self.logger.debug("Found SSL_read at: 0x%x", mapping.base+offset)
                    return mapping.base + offset
        return None

    ############## / end of helpers

    def reset_snap(self):
        '''
        Revert snapshot and ensure WWW is up. Reset hooks

        Should be called in blocking thread
        '''
        # TODO: Can we directly interact with monitor through a new panda api fn?
        # or is the issue here not snapshots?

        # ISSUE IS OSI not working post revert! - Fixed now?

        # TODO: Why do hooks need to be reset on restore?
        if len(self.hook_config):
            #self.logger.warn("Clearing hooks")
            self.bypassed_auth = False # No longer have hook
            self.hook_config = {}
        
        '''
        # Maybe just re-hooking same addrs will work faster? - Doesn't work
        if len(self.hook_config):
            for hook_addr in self.hook_config.keys():
                self.panda.hook(hook_addr)(hook_return)
        '''

        # Do revert
        self.panda.revert_sync("www")

        # Ensure after reset loading index works
        valid_page = self._fetch("GET", self.start_url, retry=False)

        if valid_page is None:
            raise RuntimeError(f"Failed to connect to {self.start_url} even after revert")

        valid_page.raise_for_status() # Should have 200
        return valid_page

        # This is a bad hack - we can't disable and then re-enable PPP callbacks so
        # we just re-register it here

    def fuzz_form(self, meth, page, params):
        # state == formfuzz.analyze
        '''
        Given a method / path / parameters, fuzz a form by throwing junk
        into each parameter once and combine with defaults for all others

        Goals:
            Find bugs - params sent to system()
            Hints of bugs - params sent to syscalls
            Measure coverage of parsing script
            Obtain high coverage

            params = {name: {type: foo, defaults: [1,2]}, ...}
        '''

        #if 'quickcommit' not in page:
        #    return

        if not len(params):
            self.logger.warning(f"No parameters on form to {page}")
            return

        # Values we try in every parameter - check for CLI injection and XSS
        for fuzz_val in ["PANDA1PANDA ; `PANDA2PANDA`", "<pandascript>"]:
            request_params = [] # [{param:value, ...}, ...]

            for fuzz_target in params.keys():
                # Mutate param[fuzz_target]
                #these_params = {fuzz_target: "PANDA1PANDA ; `PANDA2PANDA` && $(PANDA3PANDA); PANDA4PANDA ' PANDA5PANDA \"PANDA6PANDA"}
                these_params = {fuzz_target: fuzz_val}

                # If param is a checkbox don't fuzz, just select at random
                #print("Fuzzing:", params[fuzz_target]['type'])

                for normal_target in params.keys():
                    if normal_target == fuzz_target:
                        continue
                    #if 'defaults' not in params[normal_target]:
                        #print("AHHHH ERROR")
                        #print(normal_target)

                    if 'defaults' not in params[normal_target]:
                        defaults = ['bbbb']
                    else:
                        defaults = [x for x in params[normal_target]['defaults'] if x is not None]

                    if len(defaults) == 0:
                        elm_typ = params[normal_target]['type']
                        if elm_typ == 'text':
                            these_params[normal_target] = "aaa"
                        elif elm_typ == 'file':
                            these_params[normal_target] = "AAAAAA"
                        elif elm_typ == 'hidden':
                            these_params[normal_target] = "" # Hidden attr will be unset until fuzzed
                        else:
                            raise RuntimeError(f"Unsupported default gen for {elm_typ}")

                    elif len(defaults) == 1:
                        these_params[normal_target] = defaults[0]

                    elif len(defaults) > 1:
                        #self.logger.warning("Multiple defaults TODO: %s = %s", normal_target, str(defaults))
                        '''
                        # Just take longest string
                        longest_len = max([len(x) for x in defaults])
                        longest = [x for x in defaults if len(x) == longest_len][0]
                        these_params[normal_target] = longest
                        '''
                        # Select at random
                        these_params[normal_target] = random.choice(defaults)


                request_params.append(these_params)

            self.logger.warn("Fuzzing form %s with %d permutations (%d forms remain)",
                                page, len(request_params), len(self.form_queue))
            for params in request_params:
                # Send request -> change to formfuzz.send
                # Another thread will transition from .send->.introspect
                self.introspect_children = []
                self.formfuzz_data = params
                self.formfuzz_url = page
                self.s.change_state('.send')
                base = self._fetch(meth, page, params)

                self.s.change_state('.analyze')

                # Unlikely that we'd be here without bypassing auth previously, but just in case
                if base is not None and base.status_code == 401:
                    #self.logger.warning(f"Unauthenticated: {page}")
                    if not self.bypassed_auth:
                        self.bypassed_auth = True # True indicates we attempted
                        if self.find_auth(page, meth, params):
                            self.logger.debug("Bypassed authentication. Resuming formfuzz with discovered credentials.")
                            # Retry with auth
                            base = self._fetch(meth, page, params, retry=False)
                            
                if base is None:
                    self.logger.warn("Request failed")
                    continue

                for name, param in params.items():
                    if len(param) < 4:
                        # False positives
                        continue
                    if param in base.text: # XSS test
                        self.logger.warn(f"Reflected parameter value {name}: {param}")


                # Request finished. Should have reached .introspect
                # No longer true - we stay in .introspect after socket closes until
                # we come back here to handle any (immediate) post-request processing
                if not self.s.state_matches('formfuzz.analyze'):
                    #self.logger.warning("Failed to introspect on parsing")
                    self.s.change_state('.analyze')

                # Now switch back to formfuzz.analyze until we send next request
                #print("\nREQUEST RESPONSE:", repr(base.text))
    def analyze_www_open(self, fname):
        '''
        Called after filter in on_sys_open_enter. If there's a current_request and
        the webserver is opening a file, let's analyze the path and file contents.

        Affects:
            1) Identify new files to add to crawl queue
            2) Mine files for parameters (TODO)
        '''


    def do_queue(self, path, method="GET"):
        '''
        Given a path/method/params, standardize the format
        and add it to the crawl queue - unless it was already queued previously

        Updates self.crawl_queue, self.queued, self.queued_paths

        '''
        #self.logger.warn("DEBUG NOP in do_queue")
        #return

        if not path:
            return

        path = _strip_url(path)

        if path in self.crawl_results.keys():
            #self.logger.warning(f"Skipping duplicate(?) request to {path}")
            return
        else:
            self.logger.debug(f"Queue {path}")

        # Priority ranges from +100 to 0. Higher is less important
        prio = 50

        if path.endswith(".gif") or path.endswith(".jpg"): prio += 50
        if path.endswith(".css") or path.endswith(".js"): prio += 40

        if "help" in path: prio += 10
        if "cgi-bin" in path: prio -= 40
        if method != "GET": prio = 0 # Highest

        if (method, path) not in self.queued:
            self.crawl_queue.append((method, path)) # Raises exn if queue is full
            self.queued.append((method, path))
            self.queued_paths.append(path)

    def do_form_queue(self, path, form):
        '''
        A form object must capture method and params.

        We'll submit a bunch of junk to it later
        '''
        for k in ["method", "params"]: # No need for action, we have path
            if k not in form.keys():
                raise ValueError(f"Forms to be queued must have {k}")

        method = form['method']
        path = _strip_url(path)

        # More parameters = more exciting
        prio = 100 - len(form['params'].keys())

        if (path, method) not in self.queued_forms:
            # TODO: What if we find additional fields later? Should merge if exists
            # but params are different
            self.form_queue.append((method, path, json.dumps(form['params'])))
            self.queued_forms.append((path, method))

    def parse_form(self, bs_form):
        '''
        Given a bs4.form, generate permutations of submitting it and add to queue

        Generates a simple dict to represent the form

        TODO: combine with some static analysis to identify additional params
        '''
        form = {
                "action": _strip_url(bs_form.get('action')), # Destination URL
                "method": bs_form.get('method').upper(), # always caps
                "params": {}
        }

        for field in bs_form.findAll('input'):
            name = field.get('name')
            if not name: continue

            if name not in form['params']:
                form['params'][name] = {
                        'type':    field.get('type'),
                        'defaults': [field.get('value')]
                        }
            else:
                # Duplicate name - e.g., a set of radio buttons. Add to defaults
                form['params'][name]['defaults'].append(field.get('value'))

        abs_act = make_abs(self.current_request, _strip_url(bs_form.get('action')))
        self.logger.info(f"Recording form that {form['method']}s to {abs_act}")
        self.do_form_queue(abs_act, form)

    def scan_output(self, raw_html, path=None):
        '''
        Analyze response from server (called by crawl_fetch).
        Look for:
          Reference to other pages (possibly with url params?)
            - src, href, url
          Forms
          Buttons with actions (need for headless browser?)
        '''

        if path and "." in path:
            _, ext = os.path.splitext(path)
        else:
            ext = ""

        # First check if it's not HTML - note extension might not match
        # but if it contains <html> it's probably HTML. Probably...
        if "<html>" not in raw_html and ext != ".html":

            if ext == ".js":
                # Look for xhr.send('get/post' 'url', ...)
                # Could also pull params from here but they're more likely to be js vars
                xhr_re = re.compile(r"send\(\s*(?:'|\")(?:GET|POST)(?:'|\"),\s*(?:'|\")([-a-zA-Z0-9_/]*)(?:'|\")")
                for match in xhr_re.findall(raw_html):
                    # If we find any, queue them up. Could improve by grabbing params
                    self.do_queue(make_abs(self.current_request, match))
            else:
                #self.logger.warning(f"Parsing unsupported for non-HTML/JS ({ext}).")
                pass
            return

        # It's HTML - parse with BS4
        self.logger.debug("Searching HTML for references...")
        soup = BeautifulSoup(raw_html, 'lxml') # XXX using html.parser causes segfaults (threading?)
        # Find all SRCs and HREFs
        for elm in soup.findAll():
            for attr in ['src', 'href']:
                if elm.get(attr):
                    self.logger.debug(f"Found {attr} ref: {elm.get(attr)}")
                    self.do_queue(make_abs(self.current_request, elm.get(attr)))


        # FORM, send to helper
        for form in soup.findAll('form'):
            self.parse_form(form)

    def find_auth(self, path, meth='GET', params={}):
        '''
        How do we log into this thing? Try a bunch of creds, methods until
        something works.

        Change mode to findauth restore old mode at end

        Currently works using hooks (setup on start) to bypass auth function.
        Could also ID creds on rootfs and try offline cracking or patching.
        May be challenging with snapshot-based analysis if webserver has already loaded creds
        '''

        old_state = self.s.state()
        self.s.change_state('findauth')
        #self.logger.info("Attempting authentication bypass...")

        if len(self.hook_config.keys()) == 0:
            #self.logger.info("Enable findauth hook")
            self.panda.enable_callback('findauth_hook')

        # Username needs to be valid, try a bunch of common ones
        # Could parse /etc/passwd for more names to test
        basic_users = ["admin", "user", "cli", "root", "test", "dev"]
        for user in basic_users:
            if meth == 'GET':
                resp = requests.get(self.domain+path, verify=False,
                        params=params, auth=(user, 'PANDAPASS'))
            elif meth == 'POST':
                resp = requests.post(self.domain+path, verify=False,
                        params=params, auth=(user, 'PANDAPASS'))
            else:
                raise ValueError(f"Unsupported method {meth}")

            if resp.status_code != 401:
                #self.logger.info("Successfully bypassed authentication")
                self.www_auth = ("basic", user, "PANDAPASS")
                self.s.change_state(old_state)
                return True

        self.logger.error("Failed to bypass auth")
        self.s.change_state(old_state)
        return False

    def _fetch(self, meth, path, params={}, retry=True):
        '''
        GET/POST with our auth tokens. Returns Requests object
        If the connection fails and retry is set, we'll revert the guest
        with self.reset_snap() and then retry

        Note we explicitly send Connection: close to ensure sockets aren't reused(?)
        '''

        url = _strip_url(self.domain + path)

        #self.logger.info("Fetching (%s) %s", meth, url)
        if self.www_auth[0] is None:
            auth = None
        elif self.www_auth[0] == "basic":
            auth = (self.www_auth[1], self.www_auth[2])
        else:
            raise NotImplementedError("Unsupported auth:"+ self.www_auth[0])

        try:
            if meth == "GET":
                resp = requests.get( url, verify=False, auth=auth,
                                    timeout=20, headers={'Connection':'close'})
            elif meth == "POST":
                resp = requests.post(url, verify=False, auth=auth, data=params,
                                    timeout=20, headers={'Connection':'close'})
            else:
                raise NotImplementedError("Unsupported method:"+ meth)
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout) as e:

            # Something went wrong. Just revert guest and retry
            # If that fails, log and return None
            if not retry:
                # We reset the guest so it's probably not an issue with guest state,
                # the page is probably just broken
                self.logger.error(f"Fetch failed to load {path} and retries exhausted")
                return None

            #self.logger.warning(f"Attempting revert & retry to confirm failure reaching {path} {e}")
            self.reset_snap()

            return self._fetch(meth, path, params, retry=False) # Don't retry agian
        return resp

    def crawl_fetch(self, meth, path, params={}):
        '''
        Fetch a page from the webserver.
        Responsible for managing current_request to match the page being requested
        '''

        #self.logger.info(f"{meth} {path} (Queue contains {self.crawl_queue.qsize()})")

        self.current_request = path
        fail = False

        resp = self._fetch(meth, path, params)

        if resp is None:
            fail = True
            status = 408 # HTTP Timeout
        else:
            status = resp.status_code

            if status == 401:
                self.logger.warning(f"Unauthenticated: {path}")
                if not self.bypassed_auth:
                    this_req = self.current_request # Save current request in case we can't auth
                    self.current_request = None
                    self.bypassed_auth = True # True indicates we attempted
                    if self.find_auth(path):
                        self.logger.debug("Bypassed authentication. Resuming crawl with discovered credentials.")
                        # Reset this request now that we know how to auth
                        self.crawl_fetch(meth, path, params)
                        return
                    self.current_request = this_req # Restore

                # find_auth failed or was previously setup and didn't work
                fail = True

            elif status == 404:
                self.logger.warning(f"Missing file {path}")
                fail = True
            elif status == 500:
                self.logger.warning(f"Server error: {path}")
                fail = True
            elif status == 200:
                fail = False
            else:
                self.logger.error(f"Unhandled status: {status}")

        if path not in self.crawl_results:
            self.crawl_results[path] = ((meth, path, params, status))
        else:
            print("Crawled path twice?", path)

        # Must have current_reuqest when we go into scan_output
        assert self.current_request is not None
        if not fail:
            self.scan_output(resp.text, path)
        self.current_request = None

    def crawl(self):
        '''
        Emulate guest, and explore all pages found
        '''
        self.do_queue(self.start_url)

        # Start emulation in main thread
        self.panda.run()

        # Emulation finished - print stats
        print("\n"*4 + "===========")
        statuses = {x[3] for x in self.crawl_results.values()}
        print(f"Visited {len(self.crawl_results)} pages")
        for status in statuses:
            print(f"Status [{status}]")
            for page_name in sorted(self.crawl_results.keys()):
                page = self.crawl_results[page_name]
                if page[3] == status:
                    print(f"\t {page[0]} {page[1]}")
