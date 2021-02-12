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
from pathlib import Path

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

def longest_substr(string1, string2):
    '''
    Find longest substring between two strings.
    From https://stackoverflow.com/a/42882629
    '''
    answer = ""
    len1, len2 = len(string1), len(string2)
    for i in range(len1):
        for j in range(len2):
            lcs_temp=0
            match=''
            while ((i+lcs_temp < len1) and (j+lcs_temp<len2) and
                    string1[i+lcs_temp] == string2[j+lcs_temp]):
                match += string2[j+lcs_temp]
                lcs_temp+=1
            if len(match) > len(answer):
                answer = match
    return answer

def is_child_of(panda, cpu, parent_names):
    '''
    Return true IFF current_proc is or has a parent in parent_names
    '''

    proc = panda.plugins['osi'].get_current_process(cpu)
    if proc == panda.ffi.NULL:
        print("Error determining current process")
        return False
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

    Also remove anything after ? - TODO: get params might be part of form attack surface we want to fuzz
    so maybe we should add these to the fuzz queue
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

    if "?" in body:
        # TODO: maybe add to fuzz queue as a GET target?
        body = body.split("?")[0]

    if meth:
        return meth + "://" + body
    return body

class Crawler():
    '''
    A PANDA-powered web crawler. Analyzes syscalls and guest filesystem to identify attack surface
    '''

    def __init__(self, panda, domain, mountpoint, start_url="index.html", timeout=60):
        self.panda = panda
        self.mountpoint = mountpoint # Host path to guest rootfs
        self.domain = domain # proto+domain+port to connect to. E.g. https://localhost:5443
        self.timeout = timeout
        if not self.domain.endswith("/"):
            self.domain += "/"

        self.auth_hook = None

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

        self.s = StateTreeFilter('crawl', debug=True) #enable to get state changes logged

        # Queue management
        self.crawl_queue = deque() # push right with append(), pop left with popleft()
        self.queued = [] # list of everything ever queued (tuples)
        self.queued_paths = [] # list of everything ever queued (url, method)

        self.form_queue = deque()
        self.queued_forms = [] # list of forms we've ever queued (action, method)

        self.crawl_results = {}  # path: (meth, url, params, result_code)

        self.current_request = None # None or path we are currently requesting

        # When WWW tries to open a file we analyze it and queue up other files
        self.observed_file_opens  = set()
        self.observed_dir_accesses = set()

        self.bypassed_auth = False
        self.decrypting = (None, None)

        self.www_auth = (None, None, None) # type, user, pass
        self.start_url = start_url
        self.www_procs = ['lighttpd', 'phpcgi', 'httpd'] # maybe httpd?

        local_log = logging.getLogger('panda.crawler')
        self.logger = StateAdapter(local_log, {'state': self.s})

        self.introspect_children = []
        self.formfuzz_fds = []
        self.formfuzz_data = {}
        self.formfuzz_url = ""
        self.parse_req = False

        # Debugging ONLY
        '''
        # DEBUG: analyze forms
        #panda.load_plugin("speedtest")
        self.s.change_state('formfuzz.analyze')
        #self.s.change_state('debug')
        import pickle
        with open("form.pickle", "rb") as f:
            #self.form_queue = pickle.loads(f.read())
            fq = pickle.loads(f.read())

        # Biggest to smallest
        for x in sorted(fq, key=lambda k: len(k[2]), reverse=True):
            self.form_queue.append(x)

        self.logger.error("Have %d targets in form_queue", len(self.form_queue))
        for (meth, page, params) in self.form_queue:
            params_dec = json.loads(params)
            self.logger.info("Form: %s with %d params", page, len(params_dec))
            #print(params_dec)
            #for param in params_dec.keys():
            #    print(param)
            #    print(params_dec[param])
            #    print(params_dec[param]['defaults'])
        '''

        # DEBUG: creds and basedir
        self.www_auth = ("basic", "admin", "foo")
        #self.basedir = "/var/www/" # TODO: dynamically figure this out - LIGHTTPD test
        self.basedir = "" # TODO: dynamically figure this out - PHP test


        # PANDA callbacks registered within init so they can access self
        # without it being an argument

        #@self.panda.queue_blocking
        def driver():

            while len(self.crawl_queue) > 0 or len(self.form_queue) > 0:
                if self.s.state_matches('crawl'):
                    if self.crawl_queue:
                        (meth, page)  = self.crawl_queue.popleft()
                        self.logger.info("Fetching %s (%d in queue)", page, len(self.crawl_queue))
                        self.crawl_one(meth, page)
                    else:
                        # Exhaused crawl queue, switch to form fuzzing
                        # (if both queues are empty, loop terminates)
                        self.s.change_state('formfuzz.analyze')
                        self.logger.info("Switching to form fuzzing")
                        # DEBUG SAVE QUEUE
                        import pickle
                        try:
                            with open("form2.pickle", "wb") as f:
                                pickle.dump(self.form_queue, f)
                        except Exception as e:
                            print("ERROR PICKLING:", e)

                elif self.s.state_matches('formfuzz.analyze'):
                    if self.form_queue:
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

            if self.current_request is None:
                return # Shouldn't be here

            try:
                fname = self.panda.read_str(cpu, fname_ptr)
            except ValueError:
                return

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

            #Bad logic - wanted for lighttpd, but not PHP
            '''
            if fname.startswith("/etc/"): # Not a webserver
                self.logger.warning(f"Ignoring WWW load of non-served(?) file {fname}")
                return
            '''

            # Find common host root path between self.current_reuqest and the file we saw opened
            # I.e., if requests is /a/b/c/d and fs request is root/c/d common path is root/c/d
            path = _strip_url(self.current_request) # trim ?...#...

            www_components = self.current_request.split("/")[::-1] # /b/c -> [c,b]
            fs_components = fname.replace(self.mountpoint, "").split("/")[::-1] # mountpoint/a/b/c -> [c,b,a]

            common = []
            for (www, fs) in zip(www_components, fs_components):
                if www == fs:
                    common.append(www)
                else:
                    break

            common = "/".join(common[::-1])
            # Now we have /b/c

            if not len(common):
                # No overlap - assume it's an unrelated request - i.e., we open /index.html guest opened /foo
                return

            # Subtract common from mountpoint to get common root
            assert(fname.endswith(common)), f"Common path is {common} but {fname} doesn't end with it"
            common_root = Path(self.mountpoint + "/" +  common.join(fname.split(common)[:-1]))
            # Now we have mountpoint/a/ in common_root

            for discovered_file in self._fs_crawl(common_root):
                web_file = str(discovered_file).replace(str(common_root), "")
                if web_file not in self.queued_paths:
                    self.do_queue(web_file)


        ##### FORMFUZZ State machine in syscalls
        # When we're in formfuzz.send and we see a sys_accept + sys_read
        # on the FD and it contains our data, switch to formfuzz.introspect
        # UGH does it do weird stuff like dup the FD directly to a cgi-bin binary?

        @self.panda.ppp("syscalls2", "on_sys_accept4_return")
        @self.s.state_filter("formfuzz.send")
        def ffs_accept4(cpu, pc, sockfd, addr, addrlen, flags):
            # TODO: should filter for WWW proc
            returned_fd = self.panda.plugins['syscalls2'].get_syscall_retval(cpu)
            if returned_fd > 0:
                self.formfuzz_fds.append(returned_fd)
                self.logger.info("Fuzzform ACCEPT4ED on socket. File descriptor %d",
                                    returned_fd)



        @self.panda.ppp("syscalls2", "on_sys_accept_return")
        @self.s.state_filter("formfuzz.send")
        def ffs_accept(cpu, pc, sockfd, addr, addrlen):
            # TODO: should filter for WWW proc
            returned_fd = self.panda.plugins['syscalls2'].get_syscall_retval(cpu)
            if returned_fd > 0:
                self.formfuzz_fds.append(returned_fd)
                self.logger.debug("Fuzzform accepted on socket. File descriptor %d",
                                    returned_fd)

        # TODO: somehow lighttpd closes the network FD and then writes to it and closes it again
        # I can't find any syscalls explaining how it holds on to the FD or gets it again
        # Is there a bug in syscalls?
        '''
        @self.panda.ppp("syscalls2", "on_all_sys_return2")
        @self.s.state_filter("formfuzz")
        def on_sc(cpu, pc, call, rp):
            if call == self.panda.ffi.NULL or rp == self.panda.ffi.NULL:
                return
            if call.name == self.panda.ffi.NULL:
                return
            pname = self._active_proc_name(cpu)
            #if pname != "lighttpd":
            #    return

            cname = self.panda.ffi.string(call.name).decode()
            rv_raw = self.panda.arch.get_reg(cpu, 'r0')
            rv = int(self.panda.ffi.cast(f'int', rv_raw))
            self.logger.info(f"{pname} syscall: {cname} => {rv}")
            for idx in range(call.nargs):
                arg_name = call.argn[idx]
                if arg_name == self.panda.ffi.NULL:
                    continue
                arg_s = self.panda.ffi.string(arg_name).decode()
                if arg_s == 'fd':
                    argsz = call.argsz[idx]
                    if argsz == 4:
                        cast_type = 'uint32_t'
                    elif argsz == 8:
                        cast_type = 'uint64_t'
                    else:
                        raise ValueError(f"Unhandled case for arg size {argsz}")

                    arg_val = rp.args[idx]
                    val = self.panda.ffi.cast(f'{cast_type}[{idx+1}]', arg_val)[idx]
                    self.logger.info(f"\t arg {idx} fd = {val}")
        '''


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
        @self.s.state_filter("formfuzz")
        def ffs_dup(cpu, pc, src):
            if src in self.formfuzz_fds:
                dst = self.panda.plugins['syscalls2'].get_syscall_retval(cpu)
                print("DUP TO", dst)
                self.formfuzz_fds.append(dst)

        @self.panda.ppp("syscalls2", "on_sys_dup2_return")
        @self.s.state_filter("formfuzz")
        def ffs_dup2(cpu, pc, src, dst):
            if src in self.formfuzz_fds:
                print("DUP TO", dst)
                self.formfuzz_fds.append(dst)

        @self.panda.ppp("syscalls2", "on_sys_dup3_return")
        @self.s.state_filter("formfuzz")
        def ffs_dup3(cpu, pc, src, dst, flags):
            if src in self.formfuzz_fds:
                print("DUP TO", dst)
                self.formfuzz_fds.append(dst)
        '''



        # Decryption hooks - in two parts - on start and on ret
        @self.s.state_filter("formfuzz.decrypt")
        def decrypt_hook(cpu, tb, hook):
            # SSL_read(Encrypted, char* decrypted, int num)
            self.logger.debug("Hit decrypt hook")
            ret_addr = self.panda.arch.get_reg(cpu, "lr")

            # If first SSL_read for this request - reset buffers
            self.decrypting = (self.panda.arch.get_reg(cpu, "r1"), self.panda.arch.get_reg(cpu, "r2"))

            self.panda.hook(ret_addr, kernel=False, asid=panda.current_asid(cpu))(self.decrypt_hook_ret)

        # forgive me for this terrible hack
        self.decrypt_hook = decrypt_hook

        #@self.s.state_filter("formfuzz.decrypt")
        def decrypt_hook_ret(cpu, tb, hook):
            hook.enabled = False # Disable

            if not self.s.state_matches('formfuzz.decrypt'):
                # Not sure why we're here, but it's faster to disable+bail
                # than to filter
                self.logger.warn("Entered decrypt_hook when in wrong state %s", self.s.state())
                return

            (buf, cnt) = self.decrypting
            self.decrypting = (None, None)

            if not cnt or not buf: # cnt may be 0 or None. Either way, bail
                return

            try:
                data = panda.read_str(cpu, buf)[:cnt]
            except ValueError:
                self.logger.warn("Could not read 0x%x bytes from buffer from 0x%x", cnt, buf)
                return

            if self._parse_request(data):
                # IDEA: Right as we enter formfuzz.introspect would be a good place
                # to snapshot for fuzzing since we now have a plaintext buffer
                # about to be parsed
                self.s.change_state("formfuzz.introspect")
                # Should disable decrypt_hook somehow

            # if _parse_request returned false, we need to keep hooking to get more of this request
            # so we don't change states

        # forgive me for this terrible hack
        self.decrypt_hook_ret = decrypt_hook_ret

        '''
        def httpd_auth(cpu, tb, hook):
            # XXX all these registers are arch-specific, need to genericize
            ret_addr = self.panda.arch.get_reg(cpu, "ra")
            self.panda.arch.set_reg(cpu, "v0", 1)
            self.panda.arch.set_pc(cpu, ret_addr)
            self.logger.error("Hit HTTPD auth check, ret at 0x%x, return immediately with rv=1", ret_addr)
            return True # invalidate

            #self.panda.hook(ret_addr, kernel=False, asid=panda.current_asid(cpu))(self.auth_hook_ret)
        # forgive me for this terrible hack
        self.httpd_auth = httpd_auth
        '''

        def auth_hook_ret(cpu, tb, hook):
            hook.enabled = False
            old = self.panda.arch.get_reg(cpu, "v0")
            self.logger.error("HTTPD auth check returns: %d", old)
            self.panda.arch.set_reg(cpu, "v0", 1)
            return True # Invalidate

        self.auth_hook_ret = auth_hook_ret

        '''
        def test(cpu, tb, hook):
            print("TESTING")
            self.logger.error("TEST\n")
        self.test = test
        '''



        @self.panda.ppp("syscalls2", "on_all_sys_enter")
        def crawl_first_syscall(cpu, pc, callno):
            '''
            XXX: This is gross. Can't use dynamic_symbols until after OSI is loaded.
            Need a better way to defer this
            '''
            panda.disable_ppp("crawl_first_syscall")
            self.panda.load_plugin("hooks")
            self.panda.hook_symbol("libssl", "SSL_read")(self.decrypt_hook)
            #self.panda.hook_symbol("mod_auth", "http_auth_basic_check", kernel=False,
            #            cb_type="before_block_exec_invalidate_opt")(self.hook_auth_check)

            #XXX: cb_type is ignored for hook_symbol - plugin currently changed to register as bbe_io
            
            # HTTPD
            # TODO why doesn't hook_symbol work here? Bc non lib?
            #self.panda.hook_symbol("httpd", "webuserok")(self.testing)
            # Address from ghidra, but we have symbols so it was easy
            # Could add asid filter
            #self.panda.hook(0x401e30, enabled=True, kernel=False,
            #        cb_type="before_block_exec_invalidate_opt")(self.httpd_auth)

            #self.panda.hook_symbol("libc", "strcmp")(self.test)
            
            #XXX TODO: the non 401-based auth login needs to actually fil out forms, not just send Basic


        @self.panda.ppp("syscalls2", "on_sys_read_return")
        @self.s.state_filter("formfuzz.send")
        def read_after_send(cpu, pc, fd, buf, cnt):
            '''
            When accepted FD is read from check if its our data

            Note date may be encrypted (HTTPS) if so we move to that state
            '''

            if fd not in self.formfuzz_fds:
                return

            proc_name = self._active_proc_name(cpu)
            if proc_name not in self.www_procs:
                return

            try:
                data = panda.read_str(cpu, buf)[:cnt]
            except ValueError:
                self.logger.warn("Could not read buffer from fd%d read()", fd)
                return

            # When we see reads it's either encrypted or not.
            # If it's encrypted, we push our parsing logic ahead to run
            # upon decryption (entering state formfuzz.decrypt)
            # otherwise we can run it here using this FD.

            if 'HTTP/1.1\r\n' in data: # Unencrypted - Just ignore it for now
                self.logger.warning(f"{proc_name} may be reading unencrypted"
                                      " data - ignoring: %s", repr(data))
                #self.s.change_state(".introspect")
                #else: ...

            # Assume always encrypted for now.
            # Encrypted - wait for decryption to happen before introspecting
            #self.logger.info(f"{proc_name} potentially reading encrypted traffic from FD{fd} - attempting decryption")

            self.s.change_state(".decrypt")

        ### formfuzz.introspect state
        # Here we analyze calls to execve (interesting),
        # stdin/err/out from www and child processes, and
        # close syscalls (to identify end)

        @self.panda.ppp("syscalls2", "on_sys_execve_enter")
        #@self.s.state_filter("formfuzz.introspect")
        def introspect_execve(cpu, pc, fname_ptr, argv_ptr, envp):
            '''
            When WWW responds to request, capture all execs.
            TODO: Store child PIDs so we can simplify is_child_of(www) later
            '''
            try:
                fname = panda.read_str(cpu, fname_ptr)
            except ValueError:
                return

            if True or is_child_of(self.panda, cpu, self.www_procs): # XXX DEBUG
                proc = panda.plugins['osi'].get_current_process(cpu)
                pname = self.panda.ffi.string(proc.name).decode()

                args = self._read_str_buf(cpu, argv_ptr)
                cmd = " ".join(args)
                #self.logger.warn("EXEC from %s %d: %s [%s]", pname, proc.pid, callers, cmd)

                # This is interesting, may want to bump priority level
                #self.logger.info("WWW execs from %s: [%s]", pname, cmd)
                self.logger.info("XXX execs from %s: [%s]", pname, cmd)

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
                    common_str = longest_substr(attacker_data, cmd)

                    if len(common_str) >= 6:
                        self.logger.error(f"Potential attacker controlled data `{common_str}` (from `{attacker_key}={attacker_data}` page=`{self.formfuzz_url}`) in execve: {args}")

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

            # Log all syscalls issued by all child processes by uncommenting:
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
                        common_str = longest_substr(attacker_data, str_val)

                        if len(common_str) >= 6:
                            cname = self.panda.ffi.string(call.name).decode()
                            arg_name = self.panda.ffi.string(call.argn[arg_idx]).decode()
                            self.logger.error(f"Potential attacker controlled data `{common_str}` (from `{attacker_key}={attacker_data}` page=`{self.formfuzz_url}`) in {cname} syscall's arg {arg_name}: `{str_val}`")


        @self.panda.ppp("syscalls2", "on_sys_write_enter")
        @self.s.state_filter("formfuzz.introspect")
        def write_ent(cpu, pc, fd, buf, cnt):
            '''
            Data written by www & children processes
            '''

            '''
            proc_name = self._active_proc_name(cpu)
            if proc_name not in self.www_procs:
                # TODO: check if pid or ppid matches www

                callers = get_calltree(self.panda, cpu)
            '''

            # TODO: Test this - log for www + all children, not just CGIs

            proc = self.panda.plugins['osi'].get_current_process(cpu)
            pname = self.panda.ffi.string(proc.name).decode()
            if proc.pid not in self.introspect_children and pname not in self.www_procs:
                return

            try:
                data = self.panda.read_str(cpu, buf)
            except ValueError:
                return

            if pname in self.www_procs and fd in self.formfuzz_fds:
                # Webserver is reading encrypted request, we already logged this before
                return

            out = [None, "STDOUT", "STDERR"][fd] if fd <= 2 else f"FD:{fd}"
            out_name_ptr = self.panda.plugins['osi_linux'].osi_linux_fd_to_filename(cpu, proc, fd)
            out_name_s = self.panda.ffi.string(out_name_ptr).decode(errors="ignore") if out_name_ptr != self.panda.ffi.NULL else "error"

            # This is informative and useful for RE, but a pain for debugging
            #self.logger.info(f"{pname} write to {out} ({out_name_s}): {repr(data[:cnt])}")

        def hook_auth_check(cpu, tb, hook):
            '''
            Registered as a hook to bypass auth by changing return value
            '''
            ret = self.panda.arch.get_reg(cpu, "lr")
            self.logger.debug("Change auth at 0x%x and ret to 0x%x", tb.pc, ret)
            self.panda.arch.set_reg(cpu, "r0", 1) # TODO: parameterize this return value
            self.panda.arch.set_reg(cpu, "ip", ret)

            return True # invalidate bb

        # forgive me for this terrible hack
        self.hook_auth_check = hook_auth_check

        self.dbg_procs = set()

        self.dbg_ctr = 0

        @self.panda.cb_before_block_exec(enabled=False)
        def dump_maps(cpu, *args):
            # Debug helper - print process mapping for WWW during findauth

            name = self._active_proc_name(cpu)
            if name not in self.www_procs:
                return

            for mapping in self.panda.get_mappings(cpu):
                if mapping.name != self.panda.ffi.NULL:
                    mapname = self.panda.ffi.string(mapping.name).decode()
                    self.logger.error("Proc %s library %s at 0x%x", name, mapname, mapping.base)
            self.panda.disable_callback("dump_maps")
        


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
            ptr_buf = self.panda.virtual_memory_read(cpu, ptr, length, fmt='ptrlist')
        except ValueError:
            return []

        results = []
        for read_ptr in ptr_buf:
            if read_ptr == 0: break
            try:
                results.append(self.panda.read_str(cpu, read_ptr))
            except ValueError:
                results.append("Error")

        return results

    def _parse_request(self, data):
        '''
        A request may be read in multiple bytes. Assuming only one is ever processed
        at a time, this will manage that read and combine into a single buffer.
        Returns `True` if request is finished or `False` if additional data is expected
        '''
        if not self.parse_req:
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
                else:
                    # Not expecting postdata, all done
                    self.logger.debug("Recv'd request: %s", self.parse_req_headers)
                    done = True

        if not done and not self.parse_req_in_headers:
            # Now we're in postdata - however data may overlap so clean it first
            if "\r\n\r\n" in data:
                data = data.split("\r\n\r\n")[1]
            self.parse_req_postdata += data

            if self.parse_req_content_len is not None and len(self.parse_req_postdata) >= self.parse_req_content_len:
                self.logger.info("Recv'd POSTDATA: %s", repr(self.parse_req_postdata))
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


    def _fs_crawl(self, root):
        '''
        Given a directory (pathlib.Path), find all child files.
        return a list Path objects
        '''

        # base case, it's a file
        if os.path.isfile(root):
            return [root]

        if root.is_dir():
            subdir_results = []
            for subdir in os.listdir(root):
                subdir_results.extend(self._fs_crawl(root / subdir))
            return subdir_results

        if root.is_symlink():
            # Symlink - Note this is probably broken on the hostfs, it should be a link
            # relative to the rootfs

            # If we don't make the 2nd path relative (to /) it's absolute and pathlib just ignores
            # the first mountpoint path
            resolved = Path(self.mountpoint)  / (Path(root).resolve()).relative_to('/')
            return self._fs_crawl(resolved)

        if root.exists():
            # File exists but we didn't handle it. Oops
            self.logger.warn("Unhandled filetype: {host_file}")

        #self.logger.warn("No exists %s", root)
        # File doesn't exist or is unhandled type
        return []
    ############## / end of helpers


    def reset_snap(self):
        '''
        Revert snapshot and ensure WWW is up. Reset hooks

        Should be called in blocking thread
        '''
        # Do revert
        self.panda.revert_sync("www")

        # Ensure after reset loading index works - don't recurse back into reset if it fails
        valid_page = self._fetch("GET", self.start_url, retries=-1)

        if valid_page is None:
            # Try one more time with an increased timeout
            self.timeout = self.timeout*2
            valid_page = self._fetch("GET", self.start_url, retries=-1)
            if valid_page is None:
                raise RuntimeError(f"Failed to connect to {self.start_url} even after revert")

        valid_page.raise_for_status() # Should have 200
        return valid_page

        # This is a bad hack - we can't disable and then re-enable PPP callbacks so
        # we just re-register it here

    def _fuzz_one(self, meth, page, params):
        '''
        Send a request to a single form with a single set of "fuzzed" params

        Kicks off state machine for panda-based analysis

        return True if OK, false if page failed to load
        '''
        # Send request -> change to formfuzz.send
        # Another thread will transition from .send->.introspect
        self.introspect_children = []
        self.formfuzz_fds = []
        self.formfuzz_data = params
        self.formfuzz_url = page

        # Switch to sending. Async activity will happen in various callbacks
        self.s.change_state('.send')
        base = self._fetch(meth, page, params)

        # Request finished. Should be in .introspect unless something went wrong. Move back to .analyze
        if not self.s.state_matches('formfuzz.introspect'):
            self.logger.warning(f"Failed to introspect on parsing - requested ended in state {self.s.state()}")
        self.s.change_state('.analyze')

        # Unlikely that we'd be here without bypassing auth previously, but just in case (and for debugging)
        if base is not None and base.status_code == 401:
            self.logger.warning(f"Unauthenticated: {page}")
            if not self.bypassed_auth:
                self.bypassed_auth = True # True indicates we attempted
                if self.find_auth(page, meth, params):
                    self.logger.info("Bypassed authentication. Resuming formfuzz with discovered credentials.")
                    # Retry with auth
                    return self._fuzz_one(meth, page, params)

        if base is None:
            self.logger.warn("Request failed")
            return False

        for name, param in params.items():
            if len(param) < 4:
                # False positives
                continue
            if param in base.text: # XSS test
                self.logger.warn(f"Reflected parameter value {name}: {param}")

        # Now switch back to formfuzz.analyze until we send next request
        #print("\nREQUEST RESPONSE:", repr(base.text))
        return True

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

        '''
        if 'rmtcommit' not in page:
            self.logger.warn("Debug: skip %s", page)
            return
        '''

        if len(params) == 0:
            self.logger.warning(f"No parameters on form to {page}")
            return

        page_fails = 0
        page_oks = 0
        # Values we try in every parameter - check for CLI injection and XSS
        for input_idx, fuzz_val in enumerate(["PANDA1PANDA ; `PANDA2PANDA`", "<panda3pand>"]):
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
                        defaults = []
                    else:
                        defaults = [x for x in params[normal_target]['defaults'] if x is not None]

                    # Create reasonable default depending on type
                    if len(defaults) == 0:
                        elm_typ = params[normal_target]['type']
                        if elm_typ == 'text':
                            these_params[normal_target] = "BBBB"
                        elif elm_typ == 'file':
                            these_params[normal_target] = "AAAAAA"
                        elif elm_typ == 'hidden':
                            these_params[normal_target] = "" # Hidden attr will be unset until it's fuzz_target
                        else:
                            self.logger.warning(f"Unsupported default gen for {elm_typ}")
                            these_params[normal_target] = "1"
                            #raise RuntimeError(f"Unsupported default gen for {elm_typ}")

                    elif len(defaults) == 1:
                        these_params[normal_target] = defaults[0]

                    elif len(defaults) > 1:
                        # Multiple defaults - select at random
                        these_params[normal_target] = random.choice(defaults)

                request_params.append(these_params)

            for idx, param_dict in enumerate(request_params):
                # XXX: Message is confusing, need to include fuzz_val loop
                this_idx   = len(request_params)*input_idx + idx
                total_idx = len(request_params)*(input_idx+1)
                self.logger.warn("Fuzzing form at %s: request %d of %d. (%d forms remain)", page, this_idx, total_idx, len(self.form_queue))
                if self._fuzz_one(meth, page, param_dict):
                    page_oks += 1
                else:
                    # page has failed. If we've made more than 5 requests and more than half have failed, bail
                    page_fails += 1
                    if (page_oks + page_fails) > 5 and (page_fails > page_oks):
                        self.logger.warn("Form at %s fails for majority of initial inputs. Skipping fuzzing", page)
                        return

            # DEBUG: skip 2nd input
            continue


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

        if (method, path) not in self.queued:
            self.logger.debug(f"Queue {path}")
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
        raw_act = bs_form.get('action') # may be none if it should post to current page
        abs_act = make_abs(self.current_request, _strip_url(raw_act) if raw_act else "")

        raw_meth = bs_form.get('method')
        meth = raw_meth.upper() if raw_meth else 'GET'
        form = {
                "action": abs_act,
                "method": meth, # always caps
                "params": {}
        }

        for field in bs_form.findAll('input'):
            name = field.get('name')
            if not name:
                continue

            if name not in form['params']:
                form['params'][name] = {
                        'type':    field.get('type'),
                        'defaults': [field.get('value')]
                        }
            else:
                # Duplicate name - e.g., a set of radio buttons. Add to defaults
                form['params'][name]['defaults'].append(field.get('value'))

        self.logger.info(f"Recording form that {form['method']}s to {abs_act}")
        self.do_form_queue(abs_act, form)

    def scan_output(self, raw_html, path=None):
        '''
        Analyze response from server (called by crawl_one).
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

    def find_auth(self, path, meth='GET', params=None):
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
        if params is None:
            params = {}

        # Username needs to be valid, try a bunch of common ones
        # Could parse /etc/passwd for more names to test
        basic_users = ["admin", "user", "cli", "root", "test", "dev"]
        for user in basic_users:
            try:
                if meth == 'GET':
                    resp = requests.get(self.domain+path, verify=False,
                            params=params, timeout=self.timeout, auth=(user, 'PANDAPASS'))
                elif meth == 'POST':
                    resp = requests.post(self.domain+path, verify=False,
                            params=params, timeout=self.timeout, auth=(user, 'PANDAPASS'))
                else:
                    raise ValueError(f"Unsupported method {meth}")
            except (requests.exceptions.ConnectionError,
                    requests.exceptions.ConnectTimeout,
                    requests.exceptions.ReadTimeout) as e:
                resp = None
                # Note that a timeout is OK - it used to 401, now it timed out - we probably just send a bad input to it
                # but we did figure out auth
                self.logger.warn(f"Exception in find_auth: {e}")
            #self.panda.enable_callback("dump_maps")

            if resp is None or (resp.status_code not in [401, 404] and "login" not in resp.text):
                self.logger.info("Successfully bypassed authentication")
                self.www_auth = ("basic", user, "PANDAPASS")
                self.s.change_state(old_state)
                return True

        self.logger.error("Failed to bypass auth")
        self.s.change_state(old_state)
        return False

    def _fetch(self, meth, path, params=None, retries=1):
        '''
        GET/POST with our auth tokens. Returns Requests object
        If the connection fails and retryies is set, we'll revert the guest
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

        if params is None:
            params = {}

        try:
            if meth == "GET":
                resp = requests.get( url, verify=False, auth=auth,
                                    timeout=self.timeout, headers={'Connection':'close'})
            elif meth == "POST":
                resp = requests.post(url, verify=False, auth=auth, data=params,
                                    timeout=self.timeout, headers={'Connection':'close'})
            else:
                raise NotImplementedError("Unsupported method:"+ meth)
        except (requests.exceptions.ConnectionError,
                requests.exceptions.ConnectTimeout,
                requests.exceptions.ReadTimeout) as e:

            #self.logger.error("DEBUG QUIT")
            #self.panda.end_analysis()

            # Something went wrong. Just revert guest and retry
            # If that fails, log and return None
            if retries == 0:
                # We reset the guest so it's probably not an issue with guest state,
                # the page is probably just broken
                self.logger.error(f"Fetch failed to load {path} and retries exhausted")

                # If the request we just submitted *broke* the whole thing, we have now sent it
                # twice and broken the server twice. Need to reset a second time so subsequent requests are OK
                self.reset_snap()

            if retries <= 0:
                # Retries -1 indicates we shouldn't retry
                return None

            self.logger.warning(f"_fetch timed out: attempting revert & retry to confirm failure reaching {path} {e}")
            self.reset_snap()

            return self._fetch(meth, path, params, retries=0) # Don't retry agian

        self.logger.info(f"{meth} resp from {path} took {resp.elapsed.total_seconds()}s {resp.status_code}")
        return resp

    def crawl_one(self, meth, path, params=None):
        '''
        Crawl a single from the webserver.
        Responsible for managing current_request to match the page being requested
        '''

        self.logger.info(f"{meth} {path} (Queue contains {len(self.crawl_queue)})")

        self.current_request = path
        fail = False

        if params is None:
            params = {}

        resp = self._fetch(meth, path, params)

        login_form = False
        # did we request a page that replied with 200 but a login form? If so,
        # we want to bypass auth!
        if "login" not in path and "index" not in path and "Login" in resp.text: # XXX how to handle false positives?
            # not a login url, but we're getting a login prompt - real content may be hidden
            login_form = True

        if resp is None:
            fail = True
            status = 408 # HTTP Timeout
        else:
            status = resp.status_code

            if status == 401 or login_form:
                self.logger.warning(f"Unauthenticated: {path}")
                if not self.bypassed_auth:
                    this_req = self.current_request # Save current request in case we can't auth
                    self.current_request = None
                    self.bypassed_auth = True # True indicates we attempted
                    if self.find_auth(path):
                        self.logger.debug("Bypassed authentication. Resuming crawl with discovered credentials.")
                        # Reset this request now that we know how to auth
                        self.crawl_one(meth, path, params)
                        return
                    else:
                        self.logger.debug("Bypassed authentication. Resuming crawl with discovered credentials.")
                    self.current_request = this_req # Restore
                else:
                    self.logger.warn("Unauthenticated and auth technique failed. Bail")
                    self.panda.end_analysis()

                # find_auth failed or was previously setup and didn't work
                fail = True

            elif status == 404:
                self.logger.warning(f"Missing file {path} (maybe a directory)")
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
            self.logger.warning("Crawled path twice?", path)

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

        '''
        # Shut up a bunch of the error messages
        from pandare.extras.ioctl_faker import IoctlFaker
        IoctlFaker(self.panda)
        '''

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
        #print("\nRequest:")
        #print(url, auth, params)
