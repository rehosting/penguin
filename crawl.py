# It's not as simple as running find but there's some middle ground to try
'''
webroot = mountpoint+"/var/www" # TODO: genericize
files = check_output(f"find {webroot} -type f ", shell=True).decode("utf8", errors="ignore")
for f in files.split("\n"):
    this_file = f.replace(webroot, "").strip()
    do_queue(this_file)
'''

import json
import logging
import os
from queue import PriorityQueue
import urllib3
import requests
from bs4 import BeautifulSoup
import coloredlogs

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


class Crawler:
    '''
    A PANDA-powered web crawler

    '''
    def __init__(self, panda, mountpoint, start_url="/index.html"):
        self.panda = panda
        self.mountpoint = mountpoint # Host path to guest rootfs

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

        self.logger = logging.getLogger('panda.crawler')
        self.logger.setLevel(logging.DEBUG) # Not helpful

        # Debugging ONLY
        self.www_auth = ("basic", "admin", "foo")
        self.start_url = "/cgi-bin/quickcommit.cgi"
        self.basedir = "/var/www/" # TODO: dynamically figure this out

        # PANDA callbacks registered within init using self.panda

        @self.panda.queue_async
        def driver():
            # TODO: add form_queue
            while not self.crawl_queue.empty():
                (_, (meth, page))  = self.crawl_queue.get()
                self.fetch(meth, page)

            self.panda.end_analysis()

        @self.panda.ppp("syscalls2", "on_sys_open_enter")
        def on_sys_open_enter(cpu, pc, fname_ptr, flags, mode):
            '''
            Identify files opened by WWW
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

        @self.panda.ppp("syscalls2", "on_sys_read_return")
        def read_ret(cpu, pc, fd, buf, cnt):
            '''
            Searching for data fed into cgi-bin scripts via STDIN
            '''

            if self.current_request is None:
                return # Non-crawler request (i.e., find_auth)

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
    ############## / end of helpers

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
            self.form_queue.put_nowait((prio, (method, path, json.dumps(form)))) # Raises exn if queue is full
            self.queued_forms.append((path, method))



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
            resp = requests.get(f"https://localhost:5443/{path}", verify=False,
                    auth=(user, 'PANDAPASS'))
            if resp.status_code != 401:
                self.logger.info("Success!")
                self.www_auth = ("basic", user, "PANDAPASS")
                return True

        self.logger.warning("Failed to bypass auth")
        return False

    def fetch(self, meth, path, params={}):
        '''
        Fetch a page from the webserver.
        Responsible for managing current_request to match the page being requested
        '''

        self.logger.info(f"{meth} {path} (Queue contains {self.crawl_queue.qsize()})")

        self.current_request = path

        url = f"https://localhost:5443/{path}"
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
        statuses = {[x[3] for x in self.crawl_results.values()]}
        print(f"Visited {len(self.crawl_results)} pages")
        for status in statuses:
            print(f"Status [{status}]")
            for page_name in sorted(self.crawl_results.keys()):
                page = self.crawl_results[page_name]
                if page[3] == status:
                    print(f"\t {page[0]} {page[1]}")
