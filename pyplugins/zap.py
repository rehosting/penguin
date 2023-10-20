import requests
import subprocess
import time
import socket
import random
import threading
import os

from zapv2 import ZAPv2
from contextlib import closing
from pandare import PyPlugin
from requests.exceptions import ProxyError

class Zap(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")

        self.api_key = str(random.randint(0, 2**32))
        self.output_file = open(self.outdir + "/zap.log", "w")

        self.url_queue = []
        self.url_queue_lock = threading.Lock()
        self.log_files = []

        # Run zap, listening with random API key and free port
        self.port = self.find_free_port()
        self.process = subprocess.Popen(["/zap/zap.sh",
                                         "-dir", f"/root/.ZAP/{self.api_key}", # This is terrible, but we need something unique
                                         "-daemon",
                                         "-config", f"api.key={self.api_key}",
                                         "-port", str(self.port),
                                         "-Xmx1024m", # Default is EIGHT! Is 1G okay?
                                         ],
                                           stdout=self.output_file, stderr=self.output_file)

        self.api_base = f"http://127.0.0.1:{self.port}/JSON/"
        print("Launching ZAP with proxy on port", self.port)

        # XXX here we block main thread - should be okay? Up to 30s
        for i in range(10):
            try:
                requests.get(f"http://127.0.0.1:{self.port}")
                break
            except Exception as e:
                time.sleep(3)
                print("Waiting for zap to start...")

        self.ppp.VsockVPN.ppp_reg_cb('on_bind', self.zap_on_bind)
        #self.ppp.SyscallProxy.ppp_reg_cb('on_pbind', self.zap_on_bind)
        #self.ppp.SyscallProxy2.ppp_reg_cb('on_pbind', self.zap_on_bind)

    @staticmethod
    def find_free_port():
        '''
        https://stackoverflow.com/a/45690594
        '''
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(('localhost', 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]

    def zap_on_bind(self, proto, guest_ip, guest_port, host_port, procname):
        '''
        There was a bind - spider and active scan. Note we now go through SyscallProxy
        so we can analyze syscall behavior during each zap-generated requestd
        '''

        #if guest_port not in [80, 443] or proto != 'tcp':
        if guest_port not in [80] or proto != 'tcp':
            # Ignore
            return

        f = open(self.outdir + f"/zap_{proto}_{guest_port}.log", "w")
        self.log_files.append(f)

        # Launch a thread to analyze this request
        t = threading.Thread(target=self.crawl_thread, args=(host_port,f))
        t.daemon = True
        t.start()

    def add_url(self, url):
        # Add a relative url to our target. Should NOT start with a /

        if url.startswith("/"):
            raise ValueError("URL should not start with /, but got " + url)

        if self.url_queue_lock.locked():
            print("ERROR ignoring request to add url", url, "while locked", file=self.output_file)
            #raise ValueError("Cannot add url while locked")
            return

        with self.url_queue_lock:
            self.url_queue.append(url)

    def crawl_thread(self, host_port, log_file):
        '''
        self.spider(f"http://localhost:{host_port}/", recurse=True)

        # XXX: this is a hack to wait for the spider to finish
        time.sleep(5)
        self.dump_spider_results()

        self.active_scan(f"http://localhost:{host_port}/")
        '''

        # Make sure syscall proxy is up. Not in main thread so this is okay?
        time.sleep(5)

        # proxies are zap's proxies - yep
        localProxy = {'http': f'http://127.0.0.1:{self.port}',
                      'https': f'https://127.0.0.1:{self.port}'}

        zap = ZAPv2(proxies=localProxy, apikey=self.api_key)

        target = f"http://127.0.0.1:{host_port}/"
        #self.ppp.Introspect.set_zap(host_port, self)

        # Do we block the guest here?
        # Open our URL, through ZAP proxy?
        try:
            r = requests.get(f"http://127.0.0.1:{self.port}", verify=False)
        except Exception as e:
            print(e, file=log_file)
            #self.panda.end_analysis()
            raise

        # Now try talking to target
        try:
            r = requests.get(target, proxies=localProxy, verify=False)
            #r = requests.get(target, proxies=localProxy, verify=False, headers={'Host': 'http://127.0.0.1:80'})
            r.raise_for_status()
        except Exception as e:
            print(e, file=log_file)
            #self.panda.end_analysis()
            raise

        # First we just browse to the main URL to update the sites tree
        #print(zap.core.access_url(url=target, followredirects=True))
        try:
            print(zap.urlopen(target), file=log_file)
        except Exception as e:
            print(f"EXCEPTION connecting to {target}: {e}", file=log_file)
            #self.panda.end_analysis()
            raise
        time.sleep(2) # Give the sites tree a chance to get updated

        # Next we passively scan
        print(f"Spidering target: {target}", file=log_file)
        #scanids = set([zap.spider.scan(target)]) # Set of all scans we're running - I think the scan is called 'no_implementor' ?? We get a status for that?
        zap.spider.scan(target) 
        
        # Wait up to 10s for the spider to start
        for idx in range(10):
            try:
                zap.spider.status()
            except Exception as e:
                if idx == 9:
                    print(f"Failed to start spider: {e}", file=log_file)
                    return
                time.sleep(1)

        # Wait for both spider to finish AND for the queue to be empty
        # not sure what's up with the no_implementor - hopefully it's an init thing?
        try:
            while len(self.url_queue) > 0 or int(zap.spider.status()) < 100: # Are any scans pending?
                url = None
                with self.url_queue_lock:
                    if len(self.url_queue) > 0:
                        url = target + self.url_queue.pop(0)
                if url:
                    zap.spider.scan(url)
                    print(f"Adding url from introspect to spider: {url}", file=log_file)
                    #print("SCANIDS now:", scanids)

                # Only sleep when queue is empty
                if len(self.url_queue) == 0:
                    print(f"Spider progress: {zap.spider.status()}", file=log_file)
                    time.sleep(2)
        except ProxyError:
            print("ERROR: ProxyError while spidering")
            return

        print('Spider completed', file=log_file)
        time.sleep(5) # Give the passive scanner a chance to finish

        # Now we actively scan
        print(f"Scanning target: {target}", file=log_file)
        zap.ascan.scan(target)
        # Wait for both scan to finish AND for the queue to be empty
        while len(self.url_queue) > 0 or int(zap.ascan.status()) < 100:
            # Pop any new URLs off the queue and queue them for scanning
            url = None
            with self.url_queue_lock:
                if len(self.url_queue) > 0:
                    url = target + self.url_queue.pop(0)
            if url:
               zap.ascan.scan(url)
               print(f"Adding url from introspect to scan {url}", file=log_file)

            # Only sleep when queue is empty
            if len(self.url_queue) == 0:
                print(f"Scan progress: {zap.ascan.status()}", file=log_file)
                time.sleep(5)

        print('Scan completed', file=log_file)

        # Now print scan results
        print('\nHosts: ' + ', '.join(zap.core.hosts), file=log_file) 

        print('\nAlerts: ', file=log_file)
        # Get all unique URLs that raised alerts.
        # This is about as good as we can do for finding all valid URLs since zap
        # doesn't expose status codes to us
        alert_urls = set()
        for x in zap.core.alerts():
            print(x, file=log_file)
            alert_urls.add(x.get('url'))

        print('\nAlerts URLs: ', file=log_file)
        print('\n'.join(alert_urls), file=log_file)

        # Print each URL we visited
        print('\nAll URLs visited:', file=log_file)
        for url in zap.core.urls():
            print(url, file=log_file)

        # Shut down PANDA -- XXX NO, that would be bad!
        #self.panda.end_analysis()

    def uninit(self):
        if self.output_file:
            self.output_file.close()
        if hasattr(self, 'process'):
            self.process.terminate()

            ctr = 0
            while self.process.poll() is None:
                time.sleep(1)
                ctr+=1
                if ctr > 10:
                    print("ERROR - could not terminate process")
                    self.process.kill()
            self.process.wait()

        for f in self.log_files:
            f.close()
