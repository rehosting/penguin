import requests
import subprocess
import time
import socket
import random
import threading

from zapv2 import ZAPv2
from contextlib import closing
from pandare import PyPlugin

class Zap(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")

        self.api_key = str(random.randint(0, 2**32))
        self.output_file = open(self.outdir + "/zap.log", "w")

        # Run zap, listening with random API key and free port
        self.port = self.find_free_port()
        self.process = subprocess.Popen(["/zap/zap.sh", "-daemon", "-config", f"api.key={self.api_key}", "-port", str(self.port)], stdout=self.output_file, stderr=self.output_file)

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

        #self.ppp.VsockVPN.ppp_reg_cb('on_bind', self.zap_on_bind)
        self.ppp.SyscallProxy.ppp_reg_cb('on_pbind', self.zap_on_bind)

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

        # Launch a thread to analyze this request
        t = threading.Thread(target=self.crawl_thread, args=(host_port,))
        t.daemon = True
        t.start()

    def crawl_thread(self, host_port):
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
        self.ppp.Introspect.set_zap(host_port, self)
        print(f"Connecting to syscall proxy on {target}")

        # Do we block the guest here?
        # Open our URL, through ZAP proxy?
        try:
            print(f"DIRECT TEST: Can we talk to ZAP?")
            r = requests.get(f"http://127.0.0.1:{self.port}", verify=False)
            print(r.text)
        except Exception as e:
            print(e)
            print("BAIL FOR DEBUG")
            return

        # Now try talking to target
        try:
            print(f"DIRECT TEST: Can we talk to target?")
            r = requests.get(target, proxies=localProxy, verify=False)
            print(r.text)
        except Exception as e:
            print(e)
            print("BAIL2 FOR DEBUG")
            return

        #zap.core.access_url(url=target, followredirects=True)
        try:
            zap.urlopen(target)
        except Exception as e:
            print()
            print(f"EXCEPTION connecting to {target}: {e}")
            #self.panda.end_analysis()
            return

        # Give the sites tree a chance to get updated
        time.sleep(2)

        print(f"Spidering target: {target}")
        scanid = zap.spider.scan(target)

        # Give the Spider a chance to start
        time.sleep(2)
        while (int(zap.spider.status(scanid)) < 100):
            print(f"Spider progress: {zap.spider.status(scanid)}")
            time.sleep(2)

        print('Spider completed')
        # Give the passive scanner a chance to finish
        time.sleep(5)

        print(f"Scanning target: {target}")
        scanid = zap.ascan.scan(target)
        while (int(zap.ascan.status(scanid)) < 100):
            print(f"Scan progress: {zap.ascan.status(scanid)}")
            time.sleep(5)

        print('Scan completed')

        # Now print scan results
        print('Hosts: ' + ', '.join(zap.core.hosts))
        #print('Alerts: ')
        #print(zap.core.alerts())

        # Print each URL we visited
        print('All URLs:')
        for url in zap.core.urls():
            print(url)

    def uninit(self):
        if self.output_file:
            self.output_file.close()
        if hasattr(self, 'process'):
            self.process.terminate()
