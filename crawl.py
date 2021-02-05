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
        logger.warning("Error determining current process")
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
        logger.warning("Error determining current process")
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
        # formfuzz.decrypt: Guest is decrypting connection
        # formfuzz.introspection: Guest is responding to request - deep analysis enabled

        # maybe:
        # formfuzz.introspection.on_tree: Active process created by webserver or children

        #self.s = StateTreeFilter('formfuzz.analyze') # enable to debug
        self.s = StateTreeFilter('crawl')

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
        #self.www_auth = ("basic", "admin", "foo")
        #self.start_url = "/cgi-bin/quickcommit.cgi"
        self.basedir = "/var/www/" # TODO: dynamically figure this out

        # DEBUG FORM
        #self.form_queue.put_nowait((40, ('POST', '/cgi-bin/alarmcommit.cgi', json.dumps({"commit_changes": {"type": "submit", "defaults": [""]}, "power_alarm": {"type": "checkbox", "defaults": ["1"]}, "ring_alarm_local": {"type": "checkbox", "defaults": ["1"]}, "ring_alarm_any": {"type": "checkbox", "defaults": ["1"]}, "link_1_": {"type": "checkbox", "defaults": ["1"]}, "link_2_": {"type": "checkbox", "defaults": ["1"]}, "link_3_": {"type": "checkbox", "defaults": ["1"]}, "link_4_": {"type": "checkbox", "defaults": ["1"]}, "link_5_": {"type": "checkbox", "defaults": ["1"]}, "link_6_": {"type": "checkbox", "defaults": ["1"]}, "link_7_": {"type": "checkbox", "defaults": ["1"]}, "link_8_": {"type": "checkbox", "defaults": ["1"]}, "link_9_": {"type": "checkbox", "defaults": ["1"]}, "NUMPORTS": {"type": "hidden", "defaults": ["10"]}}))))
        '''
        self.form_queue.put_nowait((40, ('POST', '/cgi-bin/quickcommit.cgi',
            json.dumps({"gateway": {"type": "text", "defaults": ["none"]},
                        "use_dhcp": {"type": "checkbox", "defaults": ["0"]},
                        "ip_address": {"type": "text", "defaults": ["192.168.0.1/24"]},
                        "netmask": {"type": "text", "defaults": ["255.255.255.0"]},
                        }))))
        '''

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
                        self.set_mode('formfuzz.analyze')
                        self.logger.info("Switching to form fuzzing")

                elif self.s.state_matches('formfuzz.analyze'):
                    if not self.form_queue.empty():
                        (_, (meth, page, params_j))  = self.form_queue.get()
                        params = json.loads(params_j)
                        self.fuzz_form(meth, page, params)
                    else:
                        # Exhaused form fuzz queue, switch to crawling
                        # (if both queues are empty, loop terminates)
                        self.set_mode('crawl')
                        self.logger.info("Switching to crawling")
                else:
                    # Driver is passive - a target analysis is ongoing (i.e., findauth)
                    sleep(1)
                    return None

            self.logger.info("Driver finished both queues")
            self.panda.end_analysis()

        @self.panda.ppp("syscalls2", "on_sys_open_enter")
        @self.s.state_filter("crawl")
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

        @self.panda.ppp("syscalls2", "on_sys_execve_enter")
        @self.s.state_filter("crawl")
        def crawl_execve(cpu, pc, fname_ptr, argv_ptr, envp):
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
        # When we're in formfuzz.send and we see a sys_accept + sys_read
        # on the FD and it contains our data, switch to formfuzz.introspect
        # UGH does it do weird stuff like dup the FD directly to a cgi-bin binary?
        self.fuzzform_fds = [] # Only supports exactly 1 FD for now

        @self.panda.ppp("syscalls2", "on_sys_accept4_return")
        @self.s.state_filter("formfuzz.send")
        def ffs_accept4(cpu, pc, sockfd, addr, addrlen, flags):
            returned_fd = self.panda.plugins['syscalls2'].get_syscall_retval(cpu)
            if returned_fd > 0:
                self.fuzzform_fds.append(returned_fd)
                self.logger.info("Fuzzform ACCEPT4ED on socket. File descriptor %d",
                                    returned_fd)



        @self.panda.ppp("syscalls2", "on_sys_accept_return")
        @self.s.state_filter("formfuzz.send")
        def ffs_accept(cpu, pc, sockfd, addr, addrlen):
            returned_fd = self.panda.plugins['syscalls2'].get_syscall_retval(cpu)
            if returned_fd > 0:
                self.fuzzform_fds.append(returned_fd)
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

        @self.panda.ppp("syscalls2", "on_sys_dup_return")
        @self.s.state_filter("formfuzz.send")
        def ffs_dup(cpu, pc, src):
            if src in self.fuzzform_fds:
                dst = self.panda.plugins['syscalls2'].get_syscall_retval(cpu)
                print("DUP TO", dst)
                self.fuzzform_fds.append(dst)

        @self.panda.ppp("syscalls2", "on_sys_dup2_return")
        @self.s.state_filter("formfuzz.send")
        def ffs_dup2(cpu, pc, src, dst):
            if src in self.fuzzform_fds:
                print("DUP TO", dst)
                self.fuzzform_fds.append(dst)

        @self.panda.ppp("syscalls2", "on_sys_dup3_return")
        @self.s.state_filter("formfuzz.send")
        def ffs_dup3(cpu, pc, src, dst, flags):
            if src in self.fuzzform_fds:
                print("DUP TO", dst)
                self.fuzzform_fds.append(dst)
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
                self.logger.warn("Could not read buffer from 0x%x", self.decrypting_buf)
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

            if fd not in self.fuzzform_fds:
                return

            assert len(self.fuzzform_fds)==1, "Unsupported: multiple accepted FDs"

            proc_name = self._active_proc_name(cpu)

            try:
                data = panda.read_str(cpu, buf)[:cnt]
            except ValueError:
                self.logger.warn("Could not read buffer from fd%d read()", fd)
                return

            # When we see reads it's either encrypted or not.
            # If it's encrypted, we push our parsing logic ahead to run
            # upon decryption (entering state formfuzz.introspect.decrypt)
            # otherwise we can run it here using this FD.

            if 'HTTP' in data: # Unencrypted - go right to introspect
                self.logger.info(f"{proc_name} reading unencrypted data")
                self.logger.error("TODO: handle plaintext")
                print("Plaintext request:", repr(data))
                # TODO HANLDE THIS

                self.s.change_state(".introspect")
            else:
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
            When WWW responds to request, capture all execs. Add PIDs
            to self.www_children
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
                for attacker_key, attacker_data in self.fuzzform_data.items():
                    # Are there any 6 bytes of attacker-controlled data
                    # that made it to the syscall arg string (anywhere?)
                    if len(attacker_data) <= 6 or len(cmd) <= 6:
                        continue

                    # slow :(
                    common_str = longestSubstringFinder(attacker_data, cmd)

                    if len(common_str) >= 6:
                        self.logger.error(f"Potential attacker controlled data `{common_str}` (from `{attacker_key}={attacker_data}` page=`{self.fuzzform_url}`) in execve: {args}")


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
                #self.logger.warn("Unsupported syscall") # No additional info :(
                # Happens often, but for syscalls we probably don't care about?
                return
            if rp == self.panda.ffi.NULL:
                self.logger.warn("Syscall info (RP) null") # Unlikely
                return

            proc = self.panda.plugins['osi'].get_current_process(cpu)
            if proc.pid not in self.introspect_children:
                return

            pname = self.panda.ffi.string(proc.name).decode()
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
                    for attacker_key, attacker_data in self.fuzzform_data.items():
                        # Are there any 6 bytes of attacker-controlled data
                        # that made it to the syscall arg string (anywhere?)
                        if len(attacker_data) <= 6 or len(str_val) <= 6:
                            continue

                        # slow :(
                        common_str = longestSubstringFinder(attacker_data, str_val)

                        if len(common_str) >= 6:
                            cname = self.panda.ffi.string(call.name).decode()
                            arg_name = self.panda.ffi.string(call.argn[arg_idx]).decode()
                            self.logger.error(f"Potential attacker controlled data `{common_str}` (from `{attacker_key}={attacker_data}` page=`{self.fuzzform_url}`) in {cname} syscall's arg {arg_name}: `{str_val}`")


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

            if fd not in self.fuzzform_fds:
                return

            proc_name = self._active_proc_name(cpu)

            if proc_name in self.www_procs:
                self.logger.debug(f"{proc_name} closed network socket")
                #self.s.change_state(".analyze")



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
        self.logger.info("Fuzzing form at %s", page)
        #for param_name, param_detail in params.items():
        #    print(f"{param_name}: {param_detail['defaults']}")

        # Throw junk in each parameter once and combine with defaults for all others

        request_params = [] # [{param:value, ...}, ...]

        for fuzz_target in params.keys():
            # Mutate param[fuzz_target]
            #these_params = {fuzz_target: "PANDA1PANDA ; `PANDA2PANDA` && $(PANDA3PANDA); PANDA4PANDA ' PANDA5PANDA \"PANDA6PANDA"}
            these_params = {fuzz_target: "PANDA1PANDA ; `PANDA2PANDA`"}

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
            # Send request -> change to formfuzz.send
            # Another thread will transition from .send->.introspect
            self.introspect_children = []
            self.fuzzform_data = params
            self.fuzzform_url = page
            self.s.change_state('.send')
            base = self._fetch(meth, page, params)
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
                self.logger.info("Successfully bypassed authentication")
                self.www_auth = ("basic", user, "PANDAPASS")
                return True

        self.logger.warning("Failed to bypass auth")
        return False

    def _fetch(self, meth, path, params={}):
        '''
        GET/POST with our auth tokens. Returns Requests object

        Note we explicitly close the connection to ensure sockets aren't reused(?)
        '''

        # Normalize path. Domain ends with /
        while "//" in path:
            path = path.replace("//", "/")

        if path.startswith("/"):
            path = path[1:]

        url = self.domain + path

        self.logger.warn("Fetching %s", url)
        if self.www_auth[0] is None:
            auth = None
        elif self.www_auth[0] == "basic":
            auth = (self.www_auth[1], self.www_auth[2])
        else:
            raise NotImplementedError("Unsupported auth:"+ self.www_auth[0])

        if meth == "GET":
            resp = requests.get( url, verify=False, auth=auth,
                                headers={'Connection':'close'})
        elif meth == "POST":
            resp = requests.post(url, verify=False, auth=auth, data=params,
                                headers={'Connection':'close'})
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
