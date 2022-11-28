import json
import logging
import os
import re
import random
from collections import deque
from bs4 import BeautifulSoup
import coloredlogs
import hashlib

import pickle
import glob
import threading
import json
from queue import Queue
from threading import Lock
import requests
from urllib.parse import urlparse
from time import sleep

from sys import path
path.append("/igloo/")
path.append("/pandata/")
from qemuPython import QemuPyplugin

from crawl_utils import make_abs, make_rel, _strip_domain, _strip_url, _build_url
from crawl_fs import FsHelper

coloredlogs.install(level='INFO')
TIMEOUT=30

class PageDetails(object):
    '''
    Given a URL and method, store info in a standardized format
    '''

    def __init__(self, full_url, method="GET"):
        '''
        Provides details of URL:
         self.info.{hostname,port,path,query,fragement}
         self.method
        '''
        self.info = urlparse(full_url)
        self.method = method

    def __eq__(self, other):
        # TODO: does comparison of .info work?
        return self.method == other.method and self.info == other.info

    def __str__(self):
        return f"{self.info}: {self.method}"

    def __hash__(self):
        return hash(str(self))

class TargetInfo(object):
    '''
    For a given service, track details of observed pages
    and details of yet-to-be-visited pages.

    Maybe needs to be thread-safe
    '''

    def __init__(self, family, ip, port, host_port, service_name=None):
        self.results = {} # PageDetails -> Response
        self.logger = logging.getLogger(f'CrawlTarget_{id(self)}')

        self.session = None # Session object for requests to use
        self.guest_port = port
        self.host_port = host_port

        # List of pages to be visited and that have been visited. Neither should start with /es
        self.pending = ["", "index.php", "robots.txt"]
        self.visited = []

        # List of forms to fuzz and that have been fuzzed (data format TBD)
        self.forms = {} # (path, method) -> Form details (Json? Ugh)
        self.forms_pending = []
        self.forms_visited = []

    def get_base_url(self):
        base_url = f"localhost:{self.host_port}/"
        if self.guest_port == 443:
            base_url = 'https://' + base_url
        else:
            base_url = 'http://' + base_url
        return base_url

    def has_next_form(self):
        return len(self.forms_pending) > 0

    def get_next_form(self):
        '''
        Get the next form to fuzz
        '''
        assert(self.has_next_form())

        # Pop path from pending
        return self.forms_pending.pop(0)

    def has_next_url(self):
        return len(self.pending) > 0

    def get_next_url(self):
        '''
        Get the next page to visit.
        '''
        assert(self.has_next_url())

        # Pop path from pending
        return self.pending.pop(0)

    def _add_ref(self, url, match, params=None):
        '''
        When analyzing `url` we found page `match` with `params` - make absolute and queue if necessary. Match can be null if it's just a resbumission of the current url
        '''

        targ_url = make_abs(url, match)

        if targ_url is None:
            return

        assert("http://" not in targ_url), f"Bad target: {targ_url}"

        if "javascript:" in targ_url: # We don't want to go to /javascript:void(0)
            return

        if targ_url.startswith("javascript:"):
            return

        if targ_url.endswith(".png") or targ_url.endswith(".jpg") or targ_url.endswith(".gif"):
            return

        if targ_url.startswith("./"):
            targ_url = targ_url[2:]

        while targ_url.startswith("/"):
            targ_url = targ_url[1:]

        # Hacky: add URL with variations on get get params if we have any
        urls = [targ_url]

        if params is None:
            params = []

        param_base = targ_url
        param_append = ('?' in param_base)
        for p in params:
            suffix = '&' if param_append else '?'
            suffix += p +'='

            for payload in ['PANDA1PANDA', 'aaaaaaaaaaaaaaaaaaaaaaa', '../', '0', '1', 'true']:
                urls.append(targ_url + suffix + payload)

        for url in urls:
            if url not in self.visited and url not in self.pending:
                self.logger.debug(f"Add url to pending: {url}") # Must be just a path, no leading / - we have the slash in the base URL
                self.pending.append(url)

    def record_visited(self, url):
        u = make_rel(url)
        self.logger.debug(f"Recording that we visited {u}")
        self.visited.append(u)

    def log_failure(self, url):
        '''
        We were unable to connect to URL (time out, redirect loop, 500 error, etc)

        TODO: can we detect a base url is failing and drop it from the queue?
        If we hit a redirect loop page that looks like it maps the whole rootfs, we get stuck
        retrying pointless requests for a long time...
        '''
        self.record_visited(url)

        pd_url = PageDetails(url)
        if pd_url not in self.results:
            self.results[pd_url] = []
        self.results[pd_url].append(None)

    def parse_response(self, url, response):
        '''
        Given a request+response pair for a given url,
        parse it to find more URLs to visit and store the results.

        Return list of form_texts (i.e., text of html forms) discovered
        '''

        discovered_forms = []
        self.record_visited(url)

        # Store raw response
        pd_url = PageDetails(url)
        if pd_url not in self.results:
            self.results[pd_url] = []

        if response not in self.results[pd_url]:
            # If we (accidentally?) make the same request twice, only record if the response is the same
            self.results[pd_url].append(response)

        # Analysis will depend on content type
        if any([url.endswith(x) for x in [".png", ".jpg"]]):
            # Binary data, ignore
            pass

        elif url.endswith(".js"):
            # Javascript, manually scrape for src=
            for match in re.findall(f'src=(?:["\']?)([a-zA-Z0-9+._/]*)(?:["\']?)', response.text):
                self._add_ref(url, match)

        else:
            # Fallback, assume HTML
            soup = BeautifulSoup(response.content, 'html5lib') # XXX: Other options: html5lib, lxml, or html.parser.  html.parser segfaults?

            # Simple extraction: src, href, and url properties
            for elm in soup.findAll():
                for attr in ['src', 'href', 'url']:
                    if elm.get(attr):
                        self._add_ref(url, elm.get(attr))

            # meta tag for redirect is a bit annoying
            for meta in soup.find_all("meta"):
                if redir := meta.get("content"):
                    if "url=" in redir:
                        dest = redir.split("url=")[1]
                        self._add_ref(url, dest)

            # Also record forms - useful for dynamic data
            for form in soup.findAll('form'):
                discovered_forms.append(form)
        return discovered_forms

    def dump_stats(self):
        # Print health details
        codes = {} # code: count, None = unreachable
        print(f"Have {len(self.results)} items for {self}:")
        for page, details in self.results.items():
            print(page)
            for response in details:
                code = None
                sz = None

                if response is not None:
                    code = response.status_code
                    sz = len(response.text)
                if code not in codes:
                    codes[code] = 0
                codes[code] += 1
                print(f"\t\tSTATUS: {code}\t\tSIZE:{sz}")

        for code, count in codes.items():
            print(f"{count} responses with code {code}")
            if code != 200 and code != 404:
                for page, details in self.results.items():
                    for response in details:
                        if (response is not None and response.status_code == code) or (response is None and code is None):
                            print(page)
                print()
            # Status None: /cgi-bin/sysinfo.cgi, stpstat.cgi, ringstat.cgi

        # Hash every result, store hashes in a set
        # Note we might want to do something more fuzzy, some pages will probably
        # include a date string or something kind of useless like that
        page_hashes = set()
        for page, details in self.results.items():
            for response in details:
                if response is None:
                    continue
                page_hashes.add(hashlib.sha1(response.text.encode('utf8')))
        print(f"Saw a total of {len(page_hashes)} distinct responses")

class PandaCrawl(QemuPyplugin):
    '''
    Track vsockify listening services in a guest. Identify services
    and crawl appropriately.
    '''
    def __init__(self, arch, args, CID, fw, outdir):
        self.logger = logging.getLogger('PandaCrawl')
        logging.getLogger("urllib3").setLevel("INFO")
        self.outdir = outdir
        self.fwdir = os.path.dirname(fw) # has image.tar

        self.FSH = FsHelper(self.fwdir + "/image.tar")

        self.targets = {} # (service_name, family, ip, port): Target()
        self.have_targets = Lock()
        self.have_targets.acquire() # Lock it immediately
        self.pending_file_queue = Queue()

        self.pending_execve = False
        self.execve_runner = []
        self.execve_args = []
        self.execve_env = []

        self.sc_line_re = re.compile(r'([a-z0-9_]*) \[PID: (\d*) \(([a-zA-Z0-9/\-:_\. ]*)\)], file: (.*)')

        self.reset_seen()
        self.seen_cov_set = set()
        self.php_post_re = re.compile(r"""\$_POST\[['"]([a-zA-Z0-9_]*)['"]""")
        self.php_get_re = re.compile(r"""\$_GET\[['"]([a-zA-Z0-9_]*)['"]""")
        self.php_request_re = re.compile(r"""\$_REQUEST\[['"]([a-zA-Z0-9_]*)['"]""")


        self.crawl_thread = threading.Thread(target=self.crawl_manager)
        self.crawl_thread.daemon = True
        self.crawl_thread.name = "crawler"
        self.crawl_thread.start()

    def reset_seen(self):
        self.seen_files = []
        self.seen_execs = []
        self.seen_covs = []

    def on_get_param(self, request, target, param):
        self.logger.info(f"Informed of GET param by coverage analysis: {param}")
        target._add_ref(request.url, None, params=[param])

    def on_post_param(self, request, target, param):
        path = _strip_domain(_strip_url(request.url))
        self.logger.info(f"POST PARAM for {path}")
        method = 'POST'
        form_key = (path, method)
        if request.method == 'POST':
            if form_key in target.forms:
                params_j = target.forms[form_key]
                params = json.loads(params_j)
                if param in params:
                    pass # Already knew about this one
                else:
                    params[param] = {'type': 'text', 'defaults': []}
                    if form_key not in self.forms_pending: # already visited, before we found this - re-visit
                        self.forms_pending.append(form_key)
            else:
                # New form, probably want to reuse existing logic but that assumes it has a form so let's just make it up
                form = {
                    "method": 'POST',
                    "action": path,
                    "params": {param: {'type': 'text', 'defaults': []}}
                }
                # form key can't already be in there since we're in the else
                target.forms[form_key] = json.dumps(form['params'])
                target.forms_pending.append(form_key)
        else:
            # Add POST to queue
            form = {
                "method": 'POST',
                "action": path,
                "params": {param: {'type': 'text', 'defaults': []}}
            }
            if form_key not in target.forms:
                target.forms[form_key] = json.dumps(form['params'])
                target.forms_pending.append(form_key)
            else:
                params_j = target.forms[form_key]
                params = json.loads(params_j)
                if param in params:
                    # (For now): If we get here we just learned the name and we already
                    # knew it - nothing better to add.
                    self.logger.info(f"Rediscovered param {param} that we already had in {form_key}: {params}")
                else:
                    # We knew about the form, but not this value.
                    self.logger.warning(f"Updating form for {form_key} to add {param}")
                    params[param] = {'type': 'text', 'defaults': []}
                    target.forms[form_key] = json.dumps(params)
                    if form_key not in target.forms_pending:
                        target.forms_pending.append(form_key)

    def on_output(self, line):
        '''
        Non-blocking function to process a line of guest output via dedicated serial.
        Called automatically by qemuPython. Blocks output parsing while running.

        Three things to watch for:
            1) File-based syscalls
            2) Execves
            3) Coverage

        We store these in:
            self.seen_files,
            self.seen_execs,
            self.seen_covs

        then parse after each request
        '''

        if line.startswith('COV: '):
            lang, file, line, code = line[5:].split(",", 3)
            self.seen_covs.append((lang, file, line, code))
            return

        if self.pending_execve:
            # If it's a syscall and we're parsing an execve, consume
            # and combine details until we get a non-execve output
            if line.startswith('execve ARG'):
                if 'execve ARG ' in line:
                    self.execve_args.append(line.split('execve ARG ')[1])
                else:
                    self.execve_args.append("")
            elif line.startswith('execve ENV: '):
                self.execve_env.append(line.split('execve ENV: ')[1])
                return
            elif line == 'execve END':
                # Execves are always a little interesting
                self.logger.info(f"execve: {self.execve_runner} args={self.execve_args} env={self.execve_env}")
                self.seen_execs.append((self.pending_execve, self.execve_args, self.execve_env))

                self.execve_runner = []
                self.execve_args = []
                self.execve_env = []
                self.pending_execve = False
                return
            else:
                self.logger.warning(f"Unexpected: in execve got other log message: {line}")

        if m := self.sc_line_re.match(line):
            (sc_name , pid, procname, filename) = m.groups()
            #self.logger.info(f"{procname} ({pid}) does {sc_name} on {filename}")
            # TODO process syscall (sync?)
            #QemuPython.on_sc(pending_files, pending_cbs, sc_name, pid, procname, tail)
            if sc_name == 'execve':
                self.execve_runner = (procname, pid)
                self.pending_execve = True

            self.seen_files.append((sc_name, pid, procname, filename))

    def check_syscalls(self, request, target, params=None):
        '''
        We issued and finished the provided request. Now check the syscalls that were run during it
        Check: seen_files, seen_execs, and seen_covs

        TODO: to avoid race conditions, this should block emulation until log reader is all caught up
        then parse log output. Otherwise we could be missing later syscalls that were run during
        processing request, but not yet captured while processing serial output.

        TODO: handle params
        '''

        for seen_file in self.seen_files:
            # each seen_file is (sc_name, pid, procname, filename)
            self.check_file_access(request, target, *seen_file)

        for seen_exec in self.seen_execs:
            # each seen_execs is parent, args, env
            self.check_execve(request, target, *seen_exec)

        for seen_cov in self.seen_covs:
            # each seen_covs is lang, file, line, source code
            self.check_cov(request, target, *seen_cov)

    def check_cov(self, request, target, lang, file, line, code):
        #self.logger.info(f"Coverage {lang} {file}:{line}")
        if (lang, file, line) in self.seen_cov_set:
            # Don't re-analyze duplicates
            return

        self.seen_cov_set.add((lang, file, line))

        if "IGLOOIZED" in line:
            # Artifact from our introspection, ignore these lines
            return

        if hasattr(self, f'on_{lang}_coverage'): # on_php_coverage
            getattr(self, f'on_{lang}_coverage')(request, target, file, line, code)
        else:
            self.logger.error(f'No parser for {lang} coverage')

    def on_php_coverage(self, request, target, file, line_no, code):
        for param in self.php_post_re.findall(code):
            #self.logger.info("POST:", param)
            self.on_post_param(request, target, param)

        for param in self.php_request_re.findall(code):
            # REQUEST pulls data from GET and POST, for now just assume post?
            #self.logger.info("REQUEST:", param)
            self.on_post_param(request, target, param)

        for param in self.php_get_re.findall(code):
            #self.logger.info("GET:", param)
            self.on_get_param(request, target, param)

    def check_execve(self, request, target, parent_proc, argv, envp):
        '''
        Bug finding: command injection
        '''
        url = urlparse(request.url)
        self.logger.info(f"Execve {argv} {envp} when fetching/posting {url}")

        # Do we want to record thse?
        #self.all_progs.add(str(argsv[0]))
        #self.all_execs.add(tuple([str(x) for x in argv]))

        def _check_get(tok, sc_file):
            if "=" not in tok:
                if tok in sc_file and len(tok) > 4:
                    print("QUERY MATCH:", tok)
            else:
                k, v = tok.split("=")
                if k in sc_file and len(k) > 4:
                    print("QUERY KEY:", k)
                if v in sc_file and len(v) > 4:
                    print("QUERY VAL:", v)

        def _check_post(key, val, sc_file):
            if key in sc_file and len(key) > 4:
                print(f"POST: key: {key}")
            if val in sc_file and len(val) > 4:
                print(f"POST: key[{key}]'s value: {val}")

        # Is URL in exec/env?
        for arg in argv:
            for comp in str(url).split("/"):
                if comp in arg:
                    print("URL MATCH:", comp, arg)

        # Are any get params in exec / env?
        for tok in url.query.split("&"):
            for arg in argv:
                _check_get(tok, arg)
            for env in envp:
                _check_get(tok, env)

        # Are any postdata in exec / evn
        if request.method == 'POST':
            for arg in argv:
                for k, v in request.params.items():
                    _check_post(k, v, arg)
            for env in envp:
                for k, v in request.params.items():
                    _check_post(k, v, env)


    def check_file_access(self, request, target, sysname, pid, procname, sysc_string):
        '''
        A file was accessed during a request. Check and see if this file access could be attacker-controlled.
        If so, identify other promising paths in the filesystem and form requests that might reach those.
        '''
        for path in self.FSH.check(request, target, sysname, pid, procname, sysc_string):
            # XXX: what if these paths are all broken, then we'd queue up a ton of bad ones
            target._add_ref(request.url, path)



    def on_bind(self, proto, guest_ip, guest_port, host_port, procname):
        '''
        Called directly by qvpn when it sees a bind 5s after it tells the vpn to bridge it.
        Blocking in here blocks qvpn as well so we don't block
        '''

        self.logger.info(f"Saw bind from {procname} {proto} to {guest_ip}:{guest_port}, mapped to host port {host_port}")

        if guest_port != 80 or proto != 'tcp':
            self.logger.info(f"\tIgnoring non tcp:80 (actual {proto}:{guest_port})")
            return

        key = (procname, proto, host_port, guest_ip, guest_port)
        if key not in self.targets:
            self.targets[key] = TargetInfo(proto, guest_ip, guest_port, host_port, service_name=procname)

            if len(self.targets) == 1 and self.have_targets.locked():
                # First item was just added, release the lock
                self.have_targets.release()

    def generate_form_fuzz_requests(self, target, path, method):
        params_j = target.forms[(path, method)]
        params = json.loads(params_j)
        self.logger.info(f"Crawling a form:{method} {path}: {params}")

        requests = {(method, path): []}

        for fuzz_target in params.keys():
            # Mutate param[fuzz_target]
            #these_params = {fuzz_target: "PANDA1PANDA ; `PANDA2PANDA` && $(PANDA3PANDA); PANDA4PANDA ' PANDA5PANDA \"PANDA6PANDA"}
            these_params = {fuzz_target: "PANDA1PANDA ; `PANDA2PANDA`"}

            for normal_target in params.keys():
                if normal_target == fuzz_target:
                    continue
                defaults = params[normal_target]['defaults']

                if len(defaults) == 0:
                    these_params[normal_target] = "PANDA3PANDA" # XXX should we fuzz this? We don't know the expected value

                elif len(defaults) == 1:
                    these_params[normal_target] = defaults[0]
                else:
                    self.logger.warning("Multiple defaults TODO")
                    these_params[normal_target] = defaults[0]

            requests[(method, path)].append(these_params)
        return requests


    def crawl_manager(self):
        '''
        Wait until we have at least one target, then crawl pages
        as necessary from our targets.
        '''

        self.have_targets.acquire() # Wait until first entry

        while True:
            for (procname, proto, host_port, guest_ip, guest_port), target in self.targets.items():
                if target.has_next_url() or target.has_next_form():
                    # We have stuff pending on this target - great!
                    break
            else:
                self.logger.warning("No targets left - finished in crawl_manager")
                break

            #url = _build_url(sock_family, sock_ip, sock_port, path)
            base_url = target.get_base_url()

            # Get a URL to crawl - Is this just paths, should we explore params?

            # pending_requests = {(method, path): [[param_set1], [param_set2]]}
            if target.has_next_form():
                # Next up is a form, let's generate a bunch of requests for it
                pending_requests = self.generate_form_fuzz_requests(target, *target.get_next_form())
            elif target.has_next_url():
                # Just a URL, generate one or more requests for it
                path = target.get_next_url()
                pending_requests = {('GET', path): [{}] } # One request within this GET+path, and it has no params
            else:
                break

            # Now we should have some data in requests, let's crawl those page(s)
            if target.session is None:
                target.session = requests.Session()

            for (method, path), params in pending_requests.items():
                url = base_url + path

                for req_params in params:
                    # Clear any pending syscall info we've seen
                    self.reset_seen()
                    try:
                        r = requests.Request(method, url, data=req_params, headers={'Connection':'close'})
                        response = target.session.send(r.prepare(), timeout=TIMEOUT)
                    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
                        target.log_failure(url)
                        self.logger.warning(f"Failed to visit from at {url} with {params} => {e}")
                        continue
                    except (requests.exceptions.TooManyRedirects) as e:
                        target.log_failure(url)
                        self.logger.warning(f"Guest url {url} hits redirect loop with {params} => {e}")
                        continue
                    finally:
                        self.check_syscalls(r, target, params=params)

                    if response.status_code == 401:
                        self.logger.error(f"UNAUTHORIZED {url} - retrying with admin/admin") # TODO: do better
                        # Auth denied - need to log in. Hmph - can we persist this or do it with library hooking?
                        try:
                            response = target.session.get(url, auth=('admin', 'admin'), timeout=TIMEOUT)
                        except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
                            target.log_failure(url)
                            self.logger.warning(f"Failed to visit {url}")
                            continue

                    if response.status_code != 404:
                        try:
                            response.raise_for_status()
                        except Exception as e:
                            self.logger.warning(f"Request error for {url}: {e}")

                    for form_text in target.parse_response(url, response):
                        self.parse_form(form_text, url, (procname, proto, host_port, guest_ip, guest_port))


        self.logger.info("Finished crawling")

        #for t in self.targets.values():
        #    t.dump_stats()

    def parse_form(self, bs_form, url, target_key):
        '''
        Given a bs4.form, generate permutations of submitting it and add to queue

        Generates a simple dict to represent the form

        TODO: combine with some static analysis to identify additional params
        '''
        if (raw_act := bs_form.get('action')):
             form_target = _strip_url(raw_act)
        else:
            form_target = ""

        abs_act = make_abs(url, form_target)
        if not abs_act:
            self.logger.warning(f"Parsing form at {url} gave us a raw_act of {raw_act} then an abs_url of None - is it out of scope?")
            return

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

        self.logger.debug(f"Recording form that {form['method']}s to {abs_act}")
        self.do_form_queue(abs_act, form, target_key)

    def do_form_queue(self, path, form, target_key):
        '''
        A form object must capture method and params.

        We'll submit a bunch of junk to it later
        '''

        for k in ["method", "params"]: # No need for action, we have path
            if k not in form.keys():
                raise ValueError(f"Forms to be queued must have {k}")

        method = form['method']
        path = _strip_url(path)

        form_key = (path, method)
        if form_key not in self.targets[target_key].forms:
            self.targets[target_key].forms[form_key] = json.dumps(form['params'])
            self.targets[target_key].forms_pending.append(form_key)
        elif json.dumps(form['params']) != self.targets[target_key].forms[form_key]:
            # TODO: What if we find additional fields later? Should merge if exists
            # but params are different
            print("TODO ran into a form with new params")
            print("\tHAD:", self.targets[target_key].forms[form_key])
            print("\tNEW:", form['params'])
        else:
            # Nothing new to do with this form
            return
