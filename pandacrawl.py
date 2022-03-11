#!/usr/bin/env python3

import json
import logging
import os
import re
import random
from collections import deque
from time import sleep
from bs4 import BeautifulSoup
import coloredlogs

import pickle
import glob
import threading
import json
from queue import Queue
from threading import Lock
import requests
from vsockadapter import VSockAdapter
from urllib.parse import urlparse

from pandare import PyPlugin
from pandarepyplugins import CallTree

TIMEOUT=10

def make_abs(url, ref):
    '''
    REF is a relative/absolute path valid when at url
    Transform into an absolute path relative to the root of the domain
    e.g., if we're at http://foo.com/zoo and we see a ref to ./boo, we should
    return "/zoo/boo"
    '''

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

'''
if __name__ == '__main__':
    v1 = make_abs("http://example.com/foo/zoo.html", "boo.html")
    assert (v1 == "foo/boo.html"), v1
'''

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

        self.session = None # Session object for requests to use

        # List of pages to be visited and that have been visited
        self.pending = ["/"]
        self.visited = []

        # List of forms to fuzz and that have been fuzzed (data format TBD)
        self.forms_pending = []
        self.forms_visited = []

    def has_next_url(self):
        return len(self.pending) > 0

    def get_next_url(self):
        '''
        Get the next page to visit.
        '''
        assert(self.has_next_url())

        # Pop path from pending
        return self.pending.pop(0)

    def _add_ref(self, url, match):
        '''
        When analyzing `url` we found page `match` - make absolute and queue if necessary
        '''

        targ_url = make_abs(url, match)

        if targ_url is None:
            return

        if targ_url not in self.visited and targ_url not in self.pending:
            self.pending.append(targ_url)

    def log_failure(self, url):
        '''
        We were unable to connect to URL (time out)
        '''
        self.visited.append(url)

        pd_url = PageDetails(url)
        if pd_url not in self.results:
            self.results[pd_url] = []
        self.results[pd_url].append(None)

    def parse_response(self, url, response):
        '''
        Given a request+response pair for a given url,
        parse it to find more URLs to visit and store the results
        '''
        
        self.visited.append(url)

        # Store raw response
        pd_url = PageDetails(url)
        if pd_url not in self.results:
            self.results[pd_url] = []
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
            soup = BeautifulSoup(response.content, 'lxml') # XXX: lxml or html.parser. Latter segfaults?

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
                print(f"TODO: parse form {repr(form)[:100]}")
                #self.parse_form(form, url, target_key)

    def dump_stats(self):
        # Print health details
        codes = {} # code: count, None = unreachable
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

                print(f"\tSTATUS: {code}\t\tSIZE:{sz}")

        for code, count in codes.items():
            print(f"{count} responses with code {code}")

class PandaCrawl(PyPlugin):
    '''
    Track vsockify listening services in a guest. Identify services
    and crawl aproperiately.
    '''
    def __init__(self, panda):
        self.panda = panda
        self.logger = logging.getLogger('PandaCrawl')
        self.cid = int(self.get_arg("cid"))

        self.targets = {} # (service_name, family, ip, port): Target()
        self.have_targets = Lock()
        self.have_targets.acquire() # Lock it immediately

        self.crawl_thread = threading.Thread(target=self.crawl_manager)
        self.crawl_thread.daemon = True
        self.crawl_thread.name = "crawler"
        self.crawl_thread.start()

        self.ppp.VSockify.ppp_reg_cb('on_bind', self.on_bind)

    def on_bind(self, vport, name, sock_family, sock_ip, sock_port):
        self.logger.info(f"Saw bind from {name} {sock_family} {sock_ip}:{sock_port} which is on vhost {self.cid}:{vport}")

        if sock_port != 80 or sock_ip != '0.0.0.0':
            self.logger.info("\tDEBUG: ignoring")
            return

        key = (name, vport, sock_family, sock_ip, sock_port)
        if key not in self.targets:
            self.targets[key] = TargetInfo(sock_family, sock_ip, sock_port, name)

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
            for (name, vport, sock_family, sock_ip, sock_port), target in self.targets.items():
                if target.has_next_url():
                    # We have stuff pending on this target - great!
                    break
            else:
                self.logger.warning("No targets left - finished in crawl_manager")
                break

            # Get a URL to crawl
            path = target.get_next_url()
            url = _build_url(sock_family, sock_ip, sock_port, path)

            # Set up session if necessary
            if target.session is None:
                target.session = requests.Session()
                vmsa = VSockAdapter(self.cid, vport)
                target.session.mount('http://', vmsa)
                target.session.mount('https://', vmsa)

            # Crawl it. TODO: support params / non-get methods
            try:
                response = target.session.get(url, timeout=TIMEOUT)
            except (requests.exceptions.ConnectionError, requests.exceptions.ReadTimeout) as e:
                target.log_failure(url)
                self.logger.warning(f"Failed to visit {url} => {e}")
                continue


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

            target.parse_response(url, response)

        self.logger.info("Finished crawling")

        for t in self.targets.values():
            t.dump_stats()

        self.panda.end_analysis()
        # TODO: pickle state?
        import sys
        sys.exit()

    """
    def parse_form(self, bs_form, url, target_key):
        '''
        Given a bs4.form, generate permutations of submitting it and add to queue

        Generates a simple dict to represent the form

        TODO: combine with some static analysis to identify additional params
        '''
        raw_act = bs_form.get('action') # may be none if it should post to current page
        abs_act = make_abs(url, _strip_url(raw_act) if raw_act else "")

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

        if (path, method) not in self.targets[target_key]['forms']:
            # TODO: What if we find additional fields later? Should merge if exists
            # but params are different
            self.targets[target_key]['pending_forms'].add((path, method, json.dumps(form['params'])))
            self.targets[target_key]['forms'].add((path, method))
    """
