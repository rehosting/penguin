'''
TODOs:
    Save state after crawling
    Fuzz form queue
'''

import json
import logging
import os
from queue import PriorityQueue
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
        abs_ref =  os.path.abspath(base_dir + "/" + ref)
    return abs_ref

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

        # State management
        # States:
        # crawl: Crawling active (TODO more detailed sub-states)
        # findauth: Analyzing authentication on a 401-protected page (TODO: sub-states?)

        # formfuzz.analyze: Fuzzing a form - analyzing
        # formfuzz.send: Request sent to guest, but not yet parsed by webserver
        # formfuzz.introspection: Analyzing guest behavior
        # formfuzz.introspection.on_tree: Active process created by webserver or children

        self.s = StateTreeFilter('formfuzz.analyze') # DEBUG
        #self.s = StateTreeFilter('crawl')

        # Queue management
        self.crawl_queue = PriorityQueue(1000) # Prioritized queue of items to visit
        self.queued = [] # list of everything ever queued (tuples)
        self.queued_paths = [] # list of everything ever queued (url, method)

        self.form_queue = PriorityQueue(1000) # Prioritized queue of forms to fuzz
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



        # Debugging ONLY
        self.www_auth = ("basic", "admin", "foo")
        self.start_url = "/cgi-bin/quickcommit.cgi"
        self.basedir = "/var/www/" # TODO: dynamically figure this out

        # DEBUG FORM
        self.recording_coverage = False
        self.form_queue.put_nowait((40, ('POST', '/cgi-bin/alarmcommit.cgi', json.dumps({"commit_changes": {"type": "submit", "defaults": [""]}, "power_alarm": {"type": "checkbox", "defaults": ["1"]}, "ring_alarm_local": {"type": "checkbox", "defaults": ["1"]}, "ring_alarm_any": {"type": "checkbox", "defaults": ["1"]}, "link_1_": {"type": "checkbox", "defaults": ["1"]}, "link_2_": {"type": "checkbox", "defaults": ["1"]}, "link_3_": {"type": "checkbox", "defaults": ["1"]}, "link_4_": {"type": "checkbox", "defaults": ["1"]}, "link_5_": {"type": "checkbox", "defaults": ["1"]}, "link_6_": {"type": "checkbox", "defaults": ["1"]}, "link_7_": {"type": "checkbox", "defaults": ["1"]}, "link_8_": {"type": "checkbox", "defaults": ["1"]}, "link_9_": {"type": "checkbox", "defaults": ["1"]}, "NUMPORTS": {"type": "hidden", "defaults": ["10"]}}))))

        # PANDA callbacks registered within init using self.panda

        @self.panda.queue_blocking
        def driver():
            '''
            Do a task depending on current mode
            '''

            while not self.crawl_queue.empty() or not self.form_queue.empty():
                if self.s.state_matches('crawl'):
                    if not self.crawl_queue.empty():
                        (_, (meth, page))  = self.crawl_queue.get()
                        self.fetch(meth, page)
                    else:
                        # Exhaused crawl queue, switch to form fuzzing
                        # (if both queues are empty, loop terminates)
                        #self.set_mode('formfuzz')
                        pass
                elif self.s.state_matches('formfuzz.analyze'):
                    if not self.form_queue.empty():
                        self.logger.error("Formfuzz sending")
                        (_, (meth, page, params_j))  = self.form_queue.get()
                        params = json.loads(params_j)
                        self.fuzz_form(meth, page, params)
                        self.logger.error("QUIT EARLY - debug")
                        break
                    else:
                        # Exhaused form fuzz queue, switch to crawling
                        # (if both queues are empty, loop terminates)
                        #self.set_mode('crawl')
                        pass
                else:
                    # Driver is passive - a target analysis is ongoing (i.e., findauth)
                    sleep(1)
                    return None # Maybe need a sleep?

            self.logger.info("Driver finished both queues")
            self.panda.end_analysis()

        @self.s.state_filter("crawl")
        @self.panda.ppp("syscalls2", "on_sys_open_enter")
        def on_sys_open_enter(cpu, pc, fname_ptr, flags, mode):
            '''
            Identify files opened by WWW during crawl
            '''
            if self.current_request is None:
                return # Non-crawler request (i.e., find_auth)

            try: fname = self.panda.read_str(cpu, fname_ptr)
            except ValueError: return

            if self._active_proc_name(cpu) not in self.www_procs:
                return

            if fname not in self.observed_file_opens:
                self.analyze_www_open(fname)

        @self.s.state_filter("crawl")
        @self.panda.ppp("syscalls2", "on_sys_execve_enter")
        def on_sys_execve_enter(cpu, pc, fname_ptr, argv_ptr, envp):
            # Log commands and arguments passed to execve
            try:
                fname = panda.read_str(cpu, fname_ptr)
            except ValueError: return

            # Other processes are interesting too...
            if self._active_proc_name(cpu) not in self.www_procs:
                return

            argv = self._read_str_buf(cpu, argv_ptr)
            env  = self._read_str_buf(cpu, envp)
            self.logger.info("Executing: " + ' '.join(argv)) #+ " with args: " + str(env))
            # Could print environment data too?

        ##### FORMFUZZ State machine in syscalls
        # When we're in fuzzform.send and we see a sys_accept + sys_read
        # on the FD and it contains our data, switch to fuzzform.introspect
        # UGH does it do weird stuff like dup the FD directly to a cgi-bin binary?
        self.fuzzform_fds = []

        @self.s.state_filter("formfuzz.send")
        @self.panda.ppp("syscalls2", "on_sys_accept4_return")
        def ffs_accept(cpu, pc, sockfd, addr, addrlen, flags):
            returned_fd = self.panda.plugins['syscalls2'].get_syscall_retval(cpu)
            if returned_fd > 0:
                self.fuzzform_fds.append(returned_fd)
                self.logger.info("Fuzzform ACCEPT4ED on socket. File descriptor %d",
                                    returned_fd)
            else:
                self.logger.info("Fuzzform ACCEPT4 returned error %d", returned_fd)



        @self.s.state_filter("formfuzz.send")
        @self.panda.ppp("syscalls2", "on_sys_accept_return")
        def ffs_accept(cpu, pc, sockfd, addr, addrlen):
            returned_fd = self.panda.plugins['syscalls2'].get_syscall_retval(cpu)
            if returned_fd > 0:
                self.fuzzform_fds.append(returned_fd)
                self.logger.info("Fuzzform ACCEPTED on socket. File descriptor %d",
                                    returned_fd)
            else:
                self.logger.info("Fuzzform ACCEPT returned error %d", returned_fd)

        # FD manipulation - unlikely to actually be used?
        '''
        @self.s.state_filter("formfuzz.send")
        @self.panda.ppp("syscalls2", "on_all_sys_return")
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

                    if fd in self.fuzzform_fds:
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

        @self.s.state_filter("formfuzz.send")
        @self.panda.ppp("syscalls2", "on_sys_dup_return")
        def ffs_dup(cpu, pc, src):
            if src in self.fuzzform_fds:
                dst = self.panda.plugins['syscalls2'].get_syscall_retval(cpu)
                print("DUP TO", dst)
                self.fuzzform_fds.append(dst)

        @self.s.state_filter("formfuzz.send")
        @self.panda.ppp("syscalls2", "on_sys_dup2_return")
        def ffs_dup2(cpu, pc, src, dst):
            if src in self.fuzzform_fds:
                print("DUP TO", dst)
                self.fuzzform_fds.append(dst)

        @self.s.state_filter("formfuzz.send")
        @self.panda.ppp("syscalls2", "on_sys_dup3_return")
        def ffs_dup3(cpu, pc, src, dst, flags):
            if src in self.fuzzform_fds:
                print("DUP TO", dst)
                self.fuzzform_fds.append(dst)
        '''

        # Decrypt
        @self.s.state_filter("formfuzz.send.decrypt", default_ret=0)
        def decrypt_hook(cpu, tb):
            # SSL_read(Encrypted, char* decrypted, int num)
            ret_addr = self.panda.arch.get_reg(cpu, "lr")

            # XXX: Gets registered multiple times? Should use names and update if exists
            self.panda.hook(ret_addr)(decrypt_ret_hook)

            # If first SSL_read for this request - setup buffers
            # XXX: must clear when request is finished!
            if not hasattr(self, 'decrypted_buf'):
                self.decrypted_buf = self.panda.arch.get_reg(cpu, "r1")
                self.decrypted_cnt = self.panda.arch.get_reg(cpu, "r2")
                self.decrypted_msg = "" # Full buffer

                self.decrypted_in_headers = True # before \r\n\r\n
                self.decrypted_headers = "" # up to \r\n\r\n
                self.decrypted_postdata = "" # after \r\n\r\n

                self.decrypted_content_len = None
            return 0

        @self.s.state_filter("formfuzz.send.decrypt", default_ret=0)
        def decrypt_ret_hook(cpu, tb):
            if not hasattr(self, 'decrypted_buf'):
                # Need to disable this hook better
                return 0

            if self.decrypted_cnt == 0:
                return 0

            try:
                data = panda.read_str(cpu, self.decrypted_buf)[:self.decrypted_cnt]
            except ValueError:
                self.logger.warn("Could not read buffer from 0x%x", self.decrypted_buf)
                return 0

            done = False
            if self.decrypted_in_headers:
                if "Content-Length: " in data:
                    cl = data.split("Content-Length: ")[1].split("\n")[0]
                    self.decrypted_content_len = int(cl)

                self.decrypted_msg += data
                self.decrypted_headers += data

                if "\r\n\r\n" in self.decrypted_headers:
                    # end of headers
                    self.decrypted_in_headers = False

                    # Make sure we don't have any postdata in decrypted_headers
                    if "\r\n\r\n" in self.decrypted_headers:
                        self.decrypted_headers = self.decrypted_headers.\
                                                    split("\r\n\r\n")[0]

                    if self.decrypted_content_len is not None:
                        # Expecting postdata
                        self.logger.info("Decrypted headers: %s", self.decrypted_headers)
                    else:
                        # Not expecting postdata, all done
                        self.logger.info("Decrypted Request: %s", self.decrypted_msg)
                        done = True

            if not self.decrypted_in_headers:
                # Now we're in postdata - however data may overlap so clean it first
                if "\r\n\r\n" in data:
                    data = data.split("\r\n\r\n")[1]
                self.decrypted_postdata += data

                if len(self.decrypted_postdata) >= self.decrypted_content_len:
                    self.logger.info("Decrypted POSTDATA: %s", self.decrypted_postdata)
                    done = True

            if done:
                # IDEA: This would be a great place to snapshot for fuzzing
                # since we now have a plaintext buffer about to be parsed
                self.s.change_state("fuzzform.introspect")
                del self.decrypted_buf
            return 0

        @self.s.state_filter("formfuzz.send")
        @self.panda.ppp("syscalls2", "on_sys_read_return")
        def introspect_read(cpu, pc, fd, buf, cnt):
            '''
            When accepted FD is read from check if its our data

            Note date may be encrypted (HTTPS) if so we move to that state
            '''

            if fd not in self.fuzzform_fds:
                return

            proc_name = self._active_proc_name(cpu)
            print(f"{proc_name} READ fd {fd} up to {cnt} bytes")

            try:
                data = panda.read_str(cpu, buf)[:cnt]
            except ValueError:
                self.logger.warn("Could not read buffer from fd%d read()", fd)
                return

            # TODO: is there just one read from the FD? Should we wait until it closes
            # Probably want to wait for the close?

            if 'HTTP' in data: # Unencrypted - go right to introspect
                self.logger.warn("Unencrypted")
                print("Plaintext request:", repr(data))
                self.s.change_state(".introspect")
            else:
                # Encrypted - wait for decryption to happen before introspecting
                self.logger.warn("Guest is reading encrypted traffic - decrypting")
                if not hasattr(self, 'decrypting_crypto'):
                    # Dynamically find crypto library + hook if we haven't previously
                    decrypt_addr = self.find_crypto_offset(cpu)
                    assert(decrypt_addr is not None), "Failed to find decryptor"
                    self.decrypting_crypto = True
                    self.panda.hook(decrypt_addr)(decrypt_hook)

                self.s.change_state("formfuzz.send.decrypt")

        @self.s.state_filter("formfuzz")
        @self.panda.ppp("syscalls2", "on_sys_read_return")
        def dbg_read(cpu, pc, fd, buf, cnt):
            try:
                data = panda.read_str(cpu, buf)[:cnt]
            except ValueError:
                return
            if 'HTTP' in data:
                print("HIT ON READ")

        #@self.s.state_filter("formfuzz.introspect")
        #@self.panda.ppp("syscalls2", "on_sys_read_return")
        # ### DISABLED
        def read_ret(cpu, pc, fd, buf, cnt):
            '''
            Searching for data fed into cgi-bin scripts via STDIN
            '''
            if fd != 0: # Assuming standard STDIN on FD 0
                return

            proc_name = self._active_proc_name(cpu)

            if ".cgi" not in proc_name: # Only want CGI inputs
                return

            try: data = panda.read_str(cpu, buf)
            except ValueError: return

            if len(data) == 0:
                return

            self.logger.info(f"POSTDATA: {repr(data[:cnt])}")

            # Idea: take a snapshot *now* and mutate this buffer to fuzz target CGI bin

            # Load coverage plugin to analyze process
            pn_b = proc_name.encode()
            
            # only do if first time
            '''
            print("SETUP COVERAGE")
            self.panda.load_plugin("coverage", {"filename": "out_"+proc_name, 
                "mode": "osi-block","privilege": "user"})
            self.panda.enable_callback("cov")
            '''

        @self.s.state_filter("formfuzz")
        @self.panda.ppp("syscalls2", "on_sys_write_enter")
        def write_ent(cpu, pc, fd, buf, cnt):
            '''
            Report data written by cgi-bin processes to stdout/stderr
            '''
            if fd not in [1, 2]: # assuming standard stdout/stderr on fd 1/2
                return

            proc_name = self._active_proc_name(cpu)

            if ".cgi" not in proc_name: # only want cgi inputs
                return

            try: data = panda.read_str(cpu, buf)
            except ValueError: return

            out = "STDOUT" if fd == 1 else "STDERR"
            self.logger.info(f"{proc_name}:{out}: {repr(data[:cnt])}")

        @self.s.state_filter("formfuzz")
        @self.panda.ppp("syscalls2", "on_sys_close_enter")
        def close_fd(cpu, pc, fd):
            '''
            STDOUT (response to request) is closed - end of request processing by binary
            '''
            if fd != 1: # Stdout only
                return

            proc_name = self._active_proc_name(cpu)

            if ".cgi" not in proc_name: # only want cgi inputs
                return

            #self.panda.disable_callback("cov")
            self.logger.info(f"{proc_name} finished")
            self.panda.end_analysis()

            '''
            for name, bbs in self.cov.items():
                for bb in sorted(bbs):
                    print(name, hex(bb))
            '''



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
                    self.logger.info("Found SSL_read at: 0x%x", mapping.base+offset)
                    return mapping.base + offset
        return None

    ############## / end of helpers

    def fuzz_form(self, meth, page, params):
        # state == formfuzz.analyze
        '''
        Given a method / path / parameters, fuzz a form!

        Goals:
            Find bugs - params sent to system()
            Hints of bugs - params sent to syscalls 
            Measure coverage of parsing script
            Obtain high coverage

            params = {name: {type: foo, defaults: [1,2]}, ...}
        '''
        self.logger.error("DEBUG: fuzzin' %s", page)
        for param_name, param_detail in params.items():
            print(f"{param_name}: {param_detail['defaults']}")

        # Throw junk in each parameter once and combine with defaults for all others

        request_params = [] # [{param:value, ...}, ...]

        for fuzz_target in params.keys():
            # Mutate param[fuzz_target]
            these_params = {fuzz_target: "aaaa ; sleep 30s; kill -9 1;"}

            for normal_target in params.keys():
                if normal_target == fuzz_target:
                    continue
                defaults = params[normal_target]['defaults']

                if len(defaults) == 1:
                    these_params[normal_target] = defaults[0]
                else:
                    self.logger.warning("Multiple defaults TODO")
                    these_params[normal_target] = defaults[0]

            request_params.append(these_params)

        for params in request_params:
            print("\n\n")
            print(params)

            # Send request -> change to fuzzform.send
            # Another thread will transition from .send->.introspect
            self.s.change_state('.send')
            base = self._fetch(meth, page, params)
            # Request finished. Should have reached .introspect
            if self.s.state_matches('fuzzform.introspect'):
                self.logger.warning("Failed to reach introspection state")
            # Now switch back to fuzzform.analyze until we send next request
            self.s.change_state('.analyze')
            print("\nREQUEST RESPONSE:", repr(base))


    def analyze_www_open(self, fname):
        '''
        Called after filter in on_sys_open_enter. If there's a current_request and
        the webserver is opening a file, let's analyze the path and file contents.

        Affects:
            1) Identify new files to add to crawl queue
            2) Mine files for parameters (TODO)
        '''

        self.logger.info(f"Observed open of: {fname} by guest www")

        assert self.current_request # ensured by caller
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

            for sibling_files in dir_files: # files or subdirs
                base_dir = os.path.abspath(os.path.dirname("/"+self.current_request))
                rel_file = base_dir + "/" + sibling_files.replace(self.basedir, "")

                if rel_file not in self.queued_paths:
                    self.do_queue(rel_file)

        # TODO: walk parent directories up to webroot and queue up additional files

        if "." in fname and fname.split(".") == "cgi":
            self.logger.debug(f"TODO: Should statically analyze {fname}")

    def do_queue(self, path, method="GET"):
        '''
        Given a path/method/params, standardize the format
        and add it to the crawl queue - unless it was already queued previously

        Updates self.crawl_queue, self.queued, self.queued_paths

        '''
        if not path:
            return

        while "//" in path:
            path = path.replace("//", "/")

        if "#" in path:
            path = path.split("#")[0]

        if path in self.crawl_results.keys(): # Already visited (TODO this is dumb, we want to request some pages more than once)
            self.logger.warning(f"Skipping duplicate(?) request to {path}")
            return

        # Priority ranges from +100 to 0. Higher is less important
        prio = 50

        if path.endswith(".gif") or path.endswith(".jpg"): prio += 50
        if path.endswith(".css") or path.endswith(".js"): prio += 40
        if "help" in path: prio += 10
        if "cgi-bin" in path: prio -= 40
        if method != "GET": prio = 0 # Highest

        if (method, path) not in self.queued:
            self.crawl_queue.put_nowait((prio, (method, path))) # Raises exn if queue is full
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

        # More parameters = more exciting
        prio = 100 - len(form['params'].keys())

        if (path, method) not in self.queued_forms: # What if we get additional fields later?
            self.logger.warning("FORM QUEUE: %s", path)
            self.form_queue.put_nowait((prio, (method, path, json.dumps(form['params'])))) # Raises exn if queue is full
            self.queued_forms.append((path, method))

            self.logger.error("DEBUG- end after queueing")
            self.panda.end_analysis()



    def parse_form(self, bs_form):
        '''
        Given a bs4.form, generate permutations of submitting it and add to queue

        Generates a simple dict to represent the form

        TODO: combine with some static analysis to identify additional params
        '''
        form = {
                "action": bs_form.get('action'), # Destination URL
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

        abs_act = make_abs(self.current_request, bs_form.get('action'))
        self.do_form_queue(abs_act, form)

    def scan_output(self, raw_html):
        '''
        Analyze response from server (called by fetch).
        Look for:
          Reference to other pages (possibly with url params?)
            - src, href
          Forms
          Buttons with actions (need for headless browser?)
        '''
        soup = BeautifulSoup(raw_html, 'lxml') # XXX using html.parser causes segfaults (threading?)

        # Find all SRC and HREF
        for elm in soup.findAll():
            if elm.get('src'):   self.do_queue(make_abs(self.current_request, elm.get('src')))
            if elm.get('href'):  self.do_queue(make_abs(self.current_request, elm.get('href')))

        # FORM, send to helper
        for form in soup.findAll('form'):
            self.parse_form(form)

    def find_auth(self, path):
        '''
        How do we log into this thing? Try a bunch of creds, methods until
        something works. Only partly implemented

        Currently works by hooks (setup on start) to bypass auth function.
        Could also ID creds on rootfs and try offline cracking or patching.
        May be challenging with snapshot-based analysis if webserver has already loaded creds

        TODO: split into another class?
        '''
        self.logger.info("Attempting authentication bypass...")
        self.current_request = None

        # Username needs to be valid
        basic_users = ["admin", "user", "cli", "root", "test", "dev"]
        for user in basic_users:
            resp = requests.get(self.domain+path, verify=False,
                    auth=(user, 'PANDAPASS'))
            if resp.status_code != 401:
                self.logger.info("Success!")
                self.www_auth = ("basic", user, "PANDAPASS")
                return True

        self.logger.warning("Failed to bypass auth")
        return False

    def _fetch(self, meth, path, params={}):
        '''
        GET/POST with our auth tokens. Returns Requests object
        '''

        url = self.domain + path
        self.logger.warn("Fetching %s in mode %s", url, self.s.state())
        if self.www_auth[0] is None:
            auth = None
        elif self.www_auth[0] == "basic":
            auth = (self.www_auth[1], self.www_auth[2])
        else:
            raise NotImplementedError("Unsupported auth:"+ self.www_auth[0])

        if meth == "GET":
            resp = requests.get( url, verify=False, auth=auth)
        elif meth == "POST":
            resp = requests.post(url, verify=False, auth=auth, data=params)
        else:
            raise NotImplementedError("Unsupported method:"+ meth)
        return resp 

    def fetch(self, meth, path, params={}):
        '''
        Fetch a page from the webserver.
        Responsible for managing current_request to match the page being requested
        '''

        self.logger.info(f"{meth} {path} (Queue contains {self.crawl_queue.qsize()})")

        self.current_request = path
        resp = self._fetch(meth, path, params)

        fail = False
        if resp.status_code == 401:
            self.logger.warning(f"Unauthenticated: {path}")
            if not self.bypassed_auth:
                this_req = self.current_request # Save current request in case we can't auth
                self.current_request = None
                self.bypassed_auth = True
                if self.find_auth(path):
                    self.logger.info("Bypassed authentication. Resuming crawl with discovered credentials.")
                    # Reset this request now that we know how to auth
                    self.fetch(meth, path, params)
                    return
                self.current_request = this_req # Restore

        elif resp.status_code == 404:
            self.logger.warning(f"Missing file {path}")
            fail = True
        elif resp.status_code == 500:
            self.logger.warning(f"Server error: {path}")
            fail = True
        elif resp.status_code == 200:
            fail = False
        else:
            self.logger.error(f"Unhandled status: {resp.status_code}")

        if path not in self.crawl_results:
            self.crawl_results[path] = ((meth, path, params, resp.status_code))

        assert self.current_request is not None
        if not fail:
            self.scan_output(resp.text)

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
