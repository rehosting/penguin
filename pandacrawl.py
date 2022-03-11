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
from urlparse import urlparse

from pandare import PyPlugin
from pandarepyplugins import CallTree

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

    def __eq__(self, other)
        # TODO: does comparison of .info work?
        return self.method == other.method and self.info == other.info

class TargetInfo(object):
    '''
    For a given service, track details of observed pages
    and details of yet-to-be-visited pages.

    Maybe needs to be thread-safe
    '''

    def __init__(self, family, ip, port, service_name=None):
        self.results = {} # PageDetails -> Response

        self.session = None # Session object for requests to use

        # Queue of pages to be visited
        self.pending = Queue()

        # List of pages that have been visited
        self.visited = []

        # Set of known pages
        self.pages = set()

        # Queue of forms to 
        self.pending_forms = Queue()
        self.froms = set()

    def get_next_page(self):
        '''
        Get the next page to visit.
        '''
        pass

    def store_and_parse_response(self, request, response):
        '''
        Store the response for the given request
        and parse it for more URLs to queue up
        '''
        pass


class PandaCrawl(PyPlugin):
    '''
    Track vsockify listening services in a guest. Identify services
    and crawl aproperiately.
    '''
    def __init__(self, panda):
        self.panda = panda
        self.logger = logging.getLogger('PandaCrawl')
        self.cid = int(self.get_arg("cid"))

        self.targets = {} # (service_name, family, ip, port): {
                          #     pending: {},        
                          #     visited: {},
                          #     pages: set(),
                          #     pending_forms: {} (path, method, json(params))
                          #     forms: set() => (path, method)
                          #}
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
            self.targets[key] = {'pending': Queue(),
                    'visited': [], 'pages': set(),
                    'pending_forms': set(), 'forms': set(),
                    'session': None}

            # Read all target_X.pickle files to see if any match this
            # if so, seed state with that
            for possible_pickle in glob.glob("./target_*.pickle"):
                with open(possible_pickle, "rb") as f:
                    (targ_info, pending_q, pages, visited, pending_forms, forms) = pickle.load(f)

                if targ_info == key:
                    self.logger.warning("Loading data from cache")
                    [self.targets[key]["pending"].put(x) for x in pending_q]
                    self.targets[key]["pages"] = pages
                    self.targets[key]["visited"] = visited
                    self.targets[key]["pending_forms"] = pending_forms
                    self.targets[key]["forms"] = forms
                    break
            else:
                # Didn't break
                self.targets[key]['pending'].put("/")

            if len(self.targets) == 1 and self.have_targets.locked():
                print("unlock have_targets")
                # First item was just added, release the lock
                self.have_targets.release()

    def crawl_manager(self):
        '''
        Select a target from self.targets. If none, wait.

        With a given target, make a request based off pending. Update visited, pages, forms
        then update pending to add newly-discovered pages
        '''

        self.have_targets.acquire() # Wait until first entry

        while True:
            for target_key, details in self.targets.items():
                if details['pending'].qsize() > 0:
                    # We have stuff pending on this target - great!
                    break
            else:
                self.logger.warning("No targets left - finished in crawl_manager")
                break
                return

            # Get details of target
            (name, vport, sock_family, sock_ip, sock_port) = target_key

            # Get target path to build URL
            path = details['pending'].get()

            if not path:
                self.logger.warning(f"No path?: {path}")
                continue

            if sock_family == 10:
                sock_ip = f"[{sock_ip}]"

            if not sock_ip.endswith("/"):
                sock_ip += "/"

            url = sock_ip + path # Do we need proto?
            if sock_port == 443:
                url = "https://" + url
            else:
                url = "http://" + url

            # Set up session
            if details['session'] is None:
                s = requests.Session()
                vmsa = VSockAdapter(self.cid, vport)
                s.mount('http://', vmsa)
                s.mount('https://', vmsa)
                details['session'] = s

            session = details['session']
            #self.logger.info(f"Targeting {target_key}: {url} (path={path}) with session {session}")

            self.crawl_one(session, url, target_key)
            #break # XXX DEBUG

        self.logger.info("Finished crawling")
        for idx, targ_info in enumerate(self.targets.keys()):
            details = self.targets[targ_info]
            try:
                with open(f"target_{idx}.pickle", "wb") as f:
                    pending_q = []
                    while not details['pending'].empty():
                        pending_q.append(details['pending'].get())

                    pickle.dump((targ_info,
                        pending_q, details['pages'], details['visited'],
                        details['pending_forms'], details['forms']), f)
            except Exception as e:
                print("ERROR PICKLING:", e)
                raise

        print("\n\nDONE")
        import sys
        sys.exit()

    def crawl_one(self, session, url, target_key):
        '''
        Crawl a page. Select a target from self.targets or stall if none available.

        Once a target is selected, get requests, and populate details
        '''
        req = session.get(url)
        self.analyze_response(target_key, url, req)

    def add_ref(self, target_key, url, new_elm):
        targ_url = make_abs(url, new_elm)
        self.logger.info(f"At {url} found ref to: {new_elm} -> {targ_url}")

        this_target = self.targets[target_key]
        # Add targ_url if not in this_target['visited']
        if targ_url and targ_url not in this_target['visited'] and targ_url not in this_target['pages']:
            self.logger.warning(f"ADDING TARGET {targ_url}. Already know about: {this_target['pages']}")
            this_target['pages'].add(targ_url)
            this_target['pending'].put(targ_url)

    def analyze_response(self, target_key, url, request):
        self.logger.info(f"Analyzing {url} ({len(self.targets[target_key]['pages'])}of {self.targets[target_key]['pending'].qsize()} => {repr(request.text[:500])}")

        if request.status_code == 401:
            self.logger.error("UNAUTHORIZED - retrying with admin/admin") # TODO: better
            # Auth denied - need to log in. Hmph
            request = self.targets[target_key]['session'].get(url, auth=('admin', 'admin'))
            try:
                request.raise_for_status()
            except Exception as e:
                self.logger.warning(f"FAIL: {e}")
            self.logger.info(f"AUTH'd: {request.text}")


        if request.status_code != 200:
            print("TODO code", request.status_code)
            return

        this_target = self.targets[target_key]
        if url.endswith(".js"):
            for match in re.findall(f'src=.([a-zA-Z0-9._/]*).', request.text):
                self.add_ref(target_key, url, match)

        if url.endswith(".png") or url.endswith(".jpg"):
            pass
        else:
            # Fallthrough: HTML
            raw_html = request.text
            soup = BeautifulSoup(raw_html, 'lxml') # XXX using html.parser causes segfaults (threading?)

            for elm in soup.findAll():
                for attr in ['src', 'href', 'url']:
                    if elm.get(attr):
                        self.add_ref(target_key, url, elm.get(attr))

            for meta in soup.find_all("meta"):
                if redir := meta.get("content"):
                    if "url=" in redir:
                        dest = redir.split("url=")[1]
                        self.add_ref(target_key, url, dest)

            for form in soup.findAll('form'):
                print(f"TODO: parse form {repr(form)}")
                self.parse_form(form, url, target_key)

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
