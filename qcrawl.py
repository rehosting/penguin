import json
import logging
import os
import re
import random
from collections import deque
from bs4 import BeautifulSoup
import coloredlogs
import subprocess
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
from qemuPython import QemuPyplugin

coloredlogs.install(level='INFO')

TIMEOUT=30

def make_abs(url, ref):
    '''
    REF is a relative/absolute path valid when at url
    Transform into an absolute path relative to the root of the domain
    e.g., if we're at http://foo.com/zoo and we see a ref to ./boo, we should
    return "/zoo/boo"

    Must Not include http://foo.com
    '''

    if ref is None:
        return url

    if ref.startswith("/"): # absolute url - easy mode
        abs_ref = ref[1:]
    elif "://" in ref: # External URL?
        return None
    else:
        # Relative path. if we have /foo/zoo.html we want to make the ref relative to /foo
        #                if we have /zoo.html we want to make the ref relative to /
        full = url + "/../" + ref
        base_url = "/".join(url.split("/")[:3])
        abs_ref = os.path.abspath(full.replace(base_url, ""))
        if abs_ref.startswith("/"):
            abs_ref = abs_ref[1:]

    return abs_ref

def make_rel(url):
    '''
    Given a url we just visited, turn it into a relative path on from the host:
    http://example.com:1234/asdf/basdf should turn into asdf/basdf
    '''
    path = urlparse(url).path
    while '//' in path:
        path = path.replace('//', '/')

    # Drop leading / in path
    while path.startswith("/"):
        path = path[1:]

    return path

def _strip_domain(url):
    '''
    Remove domain (doesn't handle http://user:pass@domain/)
    should handle http/https://domain:port/path
    '''
    #'http://asdf:port/"
    url = url.replace("http://", "").replace("https://", "")
    if '/' in url and url != '/':
        url = url[url.index('/')+1:]
    else:
        url = ''
    return url

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

    if body.startswith("/"):
        body = body[1:]

    if meth:
        return meth + "://" + body
    return body

def _build_url(sock_family, sock_ip, sock_port, path):
    if sock_family == 10:
        sock_ip = f"[{sock_ip}]"

    if not sock_ip.endswith("/"):
        sock_ip += "/"

    url = sock_ip + path # Do we need proto?
    if sock_port == 443:
        url = "https://" + url
    else:
        url = "http://" + url
    return url



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

    def __init__(self, family, ip, port, service_name=None):
        self.results = {} # PageDetails -> Response
        self.logger = logging.getLogger(f'CrawlTarget_{id(self)}')

        self.session = None # Session object for requests to use

        # List of pages to be visited and that have been visited. Neither should start with /es
        self.pending = ["", "index.php", "robots.txt"]
        self.visited = []

        # List of forms to fuzz and that have been fuzzed (data format TBD)
        self.forms = {} # (path, method) -> Form details (Json? Ugh)
        self.forms_pending = []
        self.forms_visited = []

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
        We were unable to connect to URL (time out)
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
    and crawl aproperiately.
    '''
    def __init__(self, arch, args, CID, fw, outdir):
        self.logger = logging.getLogger('PandaCrawl')
        logging.getLogger("urllib3").setLevel("INFO")
        self.outdir = outdir
        self.fwdir = os.path.dirname(fw) # has image.tar

        '''
        try:
            panda.pyplugins.ppp.CollectCoverage.ppp_reg_cb('on_get_param',
                                                        self.on_get_param)
            panda.pyplugins.ppp.CollectCoverage.ppp_reg_cb('on_post_param',
                                                        self.on_post_param)
        except AttributeError as e:
            self.logger.warning("Crawling without on_{get,post}_param callbacks from CollectCoverage")
        '''

        self.targets = {} # (service_name, family, ip, port): Target()
        self.have_targets = Lock()
        self.have_targets.acquire() # Lock it immediately
        self.pending_file_queue = Queue()

        self.all_progs = set() # All distinct programs run in guest (argv[0])
        self.all_execs = set() # All distinct commands run in guest (full argv)

        self.pending_execve = False
        self.execve_args = []
        self.execve_env = []

        self.sc_line_re = re.compile(r'([a-z0-9_]*) \[PID: (\d*) \(([a-zA-Z0-9/\-:_\. ]*)\)], file: (.*)')

        self.reset_seen()

        self.crawl_thread = threading.Thread(target=self.crawl_manager)
        self.crawl_thread.daemon = True
        self.crawl_thread.name = "crawler"
        self.crawl_thread.start()

    def reset_seen(self):
        self.seen_files = []
        self.seen_execs = []
        self.seen_covs = []

    '''
    def on_get_param(self, param):
        if self.active_request is None:
            self.logger.warning(f"Told of GET param {param} with no active request")
            return

        self.logger.info(f"Informed of GET param by coverage analysis: {param}")
        active_target = self.active_request[0]
        active_req = self.active_request[1]

        active_target._add_ref(active_req.url, None, params=[param])

    def on_post_param(self, param):
        if self.active_request is None:
            self.logger.warning(f"Told of POST param {param} with no active request")
            return

        active_target = self.active_request[0]
        active_req = self.active_request[1]
        path = _strip_domain(_strip_url(active_req.url))
        self.logger.info(f"POST PARAM for {path}")
        method = 'POST'
        form_key = (path, method)
        if active_req.method == 'POST':
            if form_key in active_target.forms:
                params_j = active_target.forms[form_key]
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
                active_target.forms[form_key] = json.dumps(form['params'])
                active_target.forms_pending.append(form_key)
        else:
            # Add POST to queue
            form = {
                "method": 'POST',
                "action": path,
                "params": {param: {'type': 'text', 'defaults': []}}
            }
            if form_key not in active_target.forms:
                active_target.forms[form_key] = json.dumps(form['params'])
                active_target.forms_pending.append(form_key)
            else:
                params_j = active_target.forms[form_key]
                params = json.loads(params_j)
                if param in params:
                    # (For now): If we get here we just learned the name and we already
                    # knew it - nothing better to add.
                    self.logger.info(f"Rediscovered param {param} that we already had in {form_key}: {params}")
                else:
                    # We knew about the form, but not this value.
                    self.logger.warning(f"Updating form for {form_key} to add {param}")
                    params[param] = {'type': 'text', 'defaults': []}
                    active_target.forms[form_key] = json.dumps(params)
                    if form_key not in active_target.forms_pending:
                        active_target.forms_pending.append(form_key)
    '''

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
            # TODO QUEUE?
            #self.logger.info(f"coverage: {lang} {file}:{line}")
            self.seen_covs.append((lang, file, line, code))

        if self.pending_execve:
            # If it's a syscall and we're parsing an execve, consume
            # and combine details until we get a non-execve output
            if line.startswith('execve ARG '):
                self.execve_args.append(line.split('execve ARG ')[1])
                return
            elif line.startswith('execve ENV: '):
                self.execve_env.append(line.split('execve ENV: ')[1])
                return
            else:
                # We were in an execve output, but now we're not
                # Note we could also patch the kernel to log 'execve END' after env.

                #QemuPython.on_sc(pending_files, pending_cbs, self.pending_execve[0],
                #                 self.pending_execve[1], self.pending_execve[2], None,
                #                 args=self.execve_args, env=self.execve_env)
                self.logger.info(f"execve: {self.execve_args} env={self.execve_env}")

                self.seen_execs.append((self.execve_args, self.execve_env))

                self.execve_args = []
                self.execve_env = []
                self.pending_execve = False

        # Note we won't get here if self.pending_execve is still True
        if m := self.sc_line_re.match(line):
            (sc_name , pid, procname, filename) = m.groups()
            #self.logger.info(f"{procname} ({pid}) does {sc_name} on {filename}")
            # TODO process syscall (sync?)
            #QemuPython.on_sc(pending_files, pending_cbs, sc_name, pid, procname, tail)
            self.seen_files.append((sc_name, pid, procname, filename))

    def ls_filesystem(self, path):
        '''
        Get the files form a directory out of the tarfs, if we can. This should be run in another
        thread from the main emulation loop because it's slow!
        '''

        # Prevviously we'd just extract files on demand, but we were running into deadlocks, so let's just do this once and store results
        #lines = subprocess.check_output(f"tar -tf '{self.fwdir}/image.tar' {path}", shell=True).decode()
        #return [l.strip() for l in lines.splitlines()]

        if not hasattr(self, 'filesystem_contents'):
            self.filesystem_contents = subprocess.check_output(f"tar -tf '{self.fwdir}/image.tar'", shell=True).decode().splitlines()

        if not hasattr(self, 'tarbase'):
            self.tarbase = subprocess.check_output(f"tar -tf '{self.fwdir}/image.tar' | head -n1", shell=True).decode().strip()

        # Tarbase is either / or ./ then path might be foo or /foo. Make sure we don't have .//foo
        if self.tarbase.endswith("/") and path.startswith("/"):
            path = self.tarbase + path[1:]
        elif not self.tarbase.endswith("/") and not path.startswith("/"):
            path = self.tarbase + "/" + path
        else:
            path = self.tarbase + path

        return [x for x in self.filesystem_contents if x.startswith(path)]

    def analyze_fs(self, target, match_type, path, sysc_string):
        if match_type == "full_url_match":
            '''
            Imagine a get of /dir/file that opens /var/www/dir/file
            We calculate fs_base of /var/www. Then we ls /var/www/dir/file
            in the filesystem. Drop /var/www from each and those are the URLs to visit
            '''
            sysc_dir  = os.path.dirname(sysc_string)    # /var/www/dir
            files = self.ls_filesystem(sysc_dir)        # /var/www/dir/other_file
            fs_base = sysc_string.replace(path, "")     # /var/www/

            for f in files:
                new_url = f.replace(fs_base, "")        # dir/other_file
                if f == "./":
                    continue
                if f.startswith("./"):
                    f = f[1:] # make ./foo /foo. It will become relative later?
                #print(f"Possible sibling. Browsing to {url.path} accessed {sysc_string}. So we should be able to hit {f} if we browse to {new_url}?")
                if not new_url.startswith("/"):
                    new_url = "/" + new_url
                target._add_ref(path, new_url)
        else:
            raise ValueError(f"Unexpected match type: {match_type}")

    def check_syscalls(self, active_request):
        '''
        We issued and finished the provided request. Now check the syscalls that were run during it
        Check: seen_files, seen_execs, and seen_covs
        '''

        for seen_file in self.seen_files:
            self.check_file_access(active_request, *seen_file)

        for seen_exec in self.seen_execs:
            self.check_execve(active_request, *seen_exec)

        for seen_cov in self.seen_covs:
            self.check_cov(active_request, *seen_cov)

    def check_cov(self, active_request, lang, file, line, code):
        self.logger.info(f"Coverage {lang} {file}:{line}")

    def check_execve(self, active_request, argv, envp):
        active_target = active_request[0]
        active_req = active_request[1]
        url = urlparse(active_req.url)
        self.logger.info(f"Execve {argv} {envp} when fetching/posting {url}")

    def check_file_access(self, active_request, sysname, pid, procname, sysc_string):
        assert(active_request is not None)
        assert(sysc_string is not None) # This is the contents of the syscall

        # Ignore when our infrastructure is writing results
        if sysc_string.startswith('/tmp/igloo') or sysc_string.startswith('/igloo/utils'):
            print("Ignoring:", sysc_string) # Should filter these in userspace helper
            return

        active_target = active_request[0]
        active_req = active_request[1]
        url = urlparse(active_req.url)

        #if '/proc' not in sysc_string and '/lib' not in sysc_string:
        #    print(f"While requesting {active_req} ({url.path}) we saw a {sysname} with {sysc_string}")

        if url.path in sysc_string and len(url.path) > 4:
            # Note this can be block now
            self.analyze_fs(active_target, "full_url_match", url.path, sysc_string)

        else:
            return # XXX TODO: handle these other cases

            # TODO: when should partial path matches be a cause for searching the filesystem?
            for tok in url.path.split("/"):
                if tok in sysc_string and len(tok) > 4:
                    print("URL token match:", tok, url.path)
                    # TODO: can we figure out if this is a directory we should search for siblings?

        for tok in url.query.split("&"):
            if "=" not in tok:
                if tok in sysc_string and len(tok) > 4:
                    print("QUERY MATCH:", tok)
            else:
                k, v = tok.split("=")
                if k in sysc_string and len(k) > 4:
                    print("QUERY KEY:", k)
                if v in sysc_string and len(v) > 4:
                    print("QUERY VAL:", v)

        if active_req.method == 'POST':
            for p in active_req.params:
                print("POST has param", p) # TODO


    """
    def on_call(self, cpu, args):
        '''
        On every exec, log arguments, check if any might be from an active request
        '''

        #if self.active_request is not None:
        #    # This mirrors the check_syscall logic, but simplified and just for debugigng
        #    self.logger.info(f"During request saw execution of: {repr(args)}")

        # Do we care about these?
        self.all_progs.add(str(args[0]))
        self.all_execs.add(tuple([str(x) for x in args]))

        if self.panda_introspection_enabled:
            s = ", ".join([x for x in args if x is not None])
            for x in [x for x in args if x is not None]:
                self.check_syscall(x, 'exec', context=s)
    """

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
            self.targets[key] = TargetInfo(proto, guest_ip, guest_port, procname)

            if len(self.targets) == 1 and self.have_targets.locked():
                # First item was just added, release the lock
                self.have_targets.release()

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
            base_url = f"localhost:{host_port}/"
            if guest_port == 443:
                base_url = 'https://' + base_url
            else:
                base_url = 'http://' + base_url

            # Get a URL to crawl - Is this just paths, should we explore params?
            if target.has_next_form():
                # Have forms
                (path, method) = target.get_next_form()
                params_j = target.forms[(path, method)]
                params = json.loads(params_j)
                url = base_url + path
                self.logger.info(f"Crawling a form:{method} {path}: {params}")


                request_params = [] # [{param:value, ...}, ...]
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

                    request_params.append(these_params)

                if target.session is None:
                    target.session = requests.Session()

                # Now we have a list of dicts to request
                for params in request_params:
                    try:
                        # TODO generate data based off params_j and submit with request
                        self.logger.info(f"FORM fetch {url} with {params}")
                        self.reset_seen()
                        #print(f"Dropped {len(dropped_files)} file accesses prior to request")

                        active_request = (target, requests.Request(method, url, data=params, headers={'Connection':'close'}), params)
                        response = target.session.send(active_request[1].prepare(), timeout=TIMEOUT)
                    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
                        target.log_failure(url)
                        self.logger.warning(f"Failed to visit from at {url} with {params} => {e}")
                        continue
                    finally:
                        self.check_syscalls(active_request)

                    #if response.status_code == 401: # 500, ...
                    try:
                        response.raise_for_status()
                    except Exception as e:
                        self.logger.warning(f"Request error for {url}: {e}")

                    for form_text in target.parse_response(url, response):
                        self.parse_form(form_text, url, (procname, proto, host_port, guest_ip, guest_port))

            elif target.has_next_url():
                # No forms - crawl more pages

                path = target.get_next_url()
                url = base_url + path

                # Set up session if necessary
                if target.session is None:
                    target.session = requests.Session()

                self.logger.debug(f"Visiting {url}")

                # Crawl it. TODO: support params / non-get methods for non-forms
                try:
                    active_request = (target, requests.Request('GET', url))

                    self.reset_seen() # Drop any old files accessed

                    response = target.session.send(active_request[1].prepare(), timeout=TIMEOUT)
                    #print(f"Dropped {len(dropped_files)} file accesses prior to request")
                except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
                    target.log_failure(url)
                    self.logger.warning(f"Failed to visit {url} => {e}")
                    continue
                finally:
                    self.check_syscalls(active_request)


                if response.status_code == 401:
                    self.logger.error(f"UNAUTHORIZED {url} - retrying with admin/admin") # TODO: do better
                    # Auth denied - need to log in. Hmph - can we persist this or do it with library hooking?
                    try:
                        response = target.session.get(url, auth=('admin', 'admin'), timeout=TIMEOUT)
                    except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
                        target.log_failure(url)
                        self.logger.warning(f"Failed to visit {url}")
                        continue

                try:
                    response.raise_for_status()
                except Exception as e:
                    self.logger.warning(f"Request error for {url}: {e}")

                for form_text in target.parse_response(url, response):
                    self.parse_form(form_text, url, (procname, proto, host_port, guest_ip, guest_port))


        self.logger.info("Finished crawling")

        for t in self.targets.values():
            t.dump_stats()

        print(f"Saw a total of {len(self.all_progs)} unique programs run during analysis. Saved to {self.outdir}/progs.txt")
        print(f"Saw a total of {len(self.all_execs)} unique program executions during analysis. Saved to {self.outdir}/execs.txt")

        with open(self.outdir + "/progs.txt", "w") as f:
            for x in self.all_progs:
                f.write(str(x)+"\n")

        with open(self.outdir + "/execs.txt", "w") as f:
            for x in self.all_execs:
                f.write(str(x)+"\n")

        print("PANDA Crawl finished")
        #self.panda.end_analysis()

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

        self.logger.info(f"Recording form that {form['method']}s to {abs_act}")
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
