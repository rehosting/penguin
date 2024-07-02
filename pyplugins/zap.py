import logging
import os
import random
import socket
import subprocess
import tarfile
import threading
import time
from contextlib import closing
from sys import stdout
from time import sleep

import requests
from pandare import PyPlugin
from python_hosts import Hosts, HostsEntry
from zapv2 import ZAPv2

# Simple wordlist of common usernames and passwords
usernames = ["admin", "user", "root"]
passwords = ["admin", "user", "password", ""]

# Generate a list of tuples where each tuple is a pair of username and password
credentials = [(user, passwd) for user in usernames for passwd in passwords]

HOSTS_FILE = "/etc/hosts"


def find_potential_urls(fs_tar_path):
    urls = set()
    # Filetypes a webserver might be serving:
    file_extensions = [
        ".php",
        ".html",
        ".js",
        ".cgi",
        ".xml",
        ".css",
        ".asp",
        ".aspx",
        ".jsp",
        ".json",
        ".txt",
        ".htm",
        ".xhtml",
    ]

    matches = set()
    with tarfile.open(fs_tar_path, "r") as tar:
        for member in tar.getmembers():
            if not member.isfile():
                continue
            path = member.name

            if any(path.endswith(ext) for ext in file_extensions):
                # Add various permutations of the path
                path_parts = path.strip("/").replace("./", "").split("/")
                for i in range(len(path_parts)):
                    perm_path = "/".join(path_parts[i:])
                    matches.add(perm_path)

                """
                # Read the file content
                file_content = tar.extractfile(member.name).read().decode(errors='ignore')

                # Simple heuristic to find URLs
                urls.update(re.findall(r'https?://[^\s"]+', file_content))
                
                # Heuristic to find paths
                paths = re.findall(r'/(?:[a-zA-Z0-9_-]+/)*[a-zA-Z0-9_-]+', file_content)
                urls.update(paths)
                """

    # Combine the matches and urls sets
    all_urls = matches.union(urls)
    return list(all_urls)


class Zap(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.fs_tar = self.get_arg("fs")
        self.target_host = self.get_arg("target_host")
        self.logger = logging.getLogger("zap")

        if self.target_host:
            h = Hosts(HOSTS_FILE)
            h.add([HostsEntry("ipv4", "127.0.0.1", None, [self.target_host])])
            h.write()
        else:
            self.target_host = "127.0.0.1"

        self.api_key = str(random.randint(0, 2**32))
        self._output_file = open(self.outdir + "/zap.log", "w")

        self.url_queue = []
        self.url_queue_lock = threading.Lock()
        self.log_files = []

        # Run zap, listening with random API key and free port
        self.port = self.find_free_port()
        # Create /tmp/zap
        os.makedirs(f"/tmp/zap/{self.api_key}", exist_ok=True)
        self.process = subprocess.Popen(
            [
                "/zap/zap.sh",
                "-dir",
                f"/tmp/zap/{self.api_key}",  # This is terrible, but we need something unique
                "-host",
                "127.0.0.1",
                "-daemon",
                "-silent",  # XXX: this is the only way to prevent zap from installing updates on every launch
                "-config",
                f"api.key={self.api_key}",
                "-port",
                str(self.port),
                "-Xmx1024m",  # Default is EIGHT! Is 1G okay?
            ],
            stdout=self._output_file,
            stderr=self._output_file,
        )

        self.api_base = f"http://127.0.0.1:{self.port}/JSON/"
        # XXX here we block main thread - should be okay? Up to 30s
        for i in range(6):
            try:
                requests.get(f"http://127.0.0.1:{self.port}")
                break
            except Exception as e:
                time.sleep(5)
        else:
            # Failed to start zap
            self.logger.error("Failed to start zap. Not scanning web apps.")
            return

        self.ppp.VsockVPN.ppp_reg_cb("on_bind", self.zap_on_bind)
        # self.ppp.SyscallProxy.ppp_reg_cb('on_pbind', self.zap_on_bind)
        # self.ppp.SyscallProxy2.ppp_reg_cb('on_pbind', self.zap_on_bind)

    @property
    def output_file(self):
        if hasattr(self, "_output_file"):
            if not self._output_file.closed:
                return self._output_file
        return stdout

    @property
    def running(self):
        if hasattr(self, "panda"):
            return True if self.panda.running.is_set() else False
        else:
            return False

    @staticmethod
    def find_free_port():
        """
        https://stackoverflow.com/a/45690594
        """
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(("localhost", 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]

    def open_connection_through_proxy(self, target, proxy):
        try:
            response = requests.get(target, proxies=proxy, verify=False)
            response.raise_for_status()
            return True
        except requests.RequestException as e:
            print(
                f"Failed to open connection through proxy: {e}", file=self.output_file
            )
            return False

    def update_sites_tree(self, zap, target):
        try:
            print(zap.urlopen(target), file=self.output_file)
            time.sleep(2)  # Give the sites tree a chance to get updated
            return True
        except Exception as e:
            print(f"Exception updating sites tree: {e}", file=self.output_file)
            return False

    def queue_filesystem(self, zap, target):
        self.fs_urls = find_potential_urls(self.fs_tar)
        # print(f"Found FS urls: {self.fs_urls}", file=self.output_file)

        for url in self.fs_urls:
            if not self.running:
                break
            try:
                print(f"Opening {target+url}", file=self.output_file)
                zap.urlopen(target + url)
            except Exception as e:
                print(f"Failed to open potential URL {url}", file=self.output_file)
                if self.output_file == stdout:
                    return
            sleep(1)
        return True

    def perform_spidering(self, zap, target):
        print(f"Spidering target: {target}", file=self.output_file)
        zap.spider.scan(target)

        # Check for spider to start and then wait for completion
        if self.wait_for_spider_to_start(zap):
            return self.wait_for_spider_to_finish(zap)
        else:
            return False

    def perform_ajaxSpidering(self, zap, target):
        print(f"Ajax Spidering target: {target}", file=self.output_file)

        # Give the Ajax spider a chance to start
        time.sleep(10)
        while zap.ajaxSpider.status != "stopped":
            print(
                "zap.ajaxSpider Spider is " + zap.ajaxSpider.status(),
                file=self.output_file,
            )
            time.sleep(5)
        for url in self.fs_urls:
            if not self.running:
                break
            url = target + url
            # zap.ajaxSpider Spider every url configured
            print(
                "zap.ajaxSpider Spider the URL: "
                + url
                + zap.ajaxSpider.scan(url=url, inscope=None)
            )
            # Give the zap.ajaxSpider spider a chance to start
            time.sleep(10)
            while zap.ajaxSpider.status != "stopped":
                print(
                    "zap.ajaxSpider Spider is " + zap.ajaxSpider.status,
                    file=self.output_file,
                )
                time.sleep(5)
        return True

        zap.ajaxSpider.scan(target)
        # Check for spider to start and then wait for completion
        if self.wait_for_ajaxSpider_to_start(
            zap
        ):  # XXX Pylint says this method doesn't exist
            return self.wait_for_ajaxSpider_to_finish(zap)
        else:
            return False

    def perform_active_scan(self, zap, target):
        print(f"Scanning target: {target}", file=self.output_file)
        zap.ascan.scan(target)
        return self.wait_for_active_scan_to_finish(zap)

    def wait_for_spider_to_start(self, zap):
        for idx in range(10):
            if not self.running:
                break
            try:
                if int(zap.spider.status()) >= 0:
                    return True
            except Exception as e:
                if idx == 9:
                    print(f"Failed to start spider: {e}", file=self.output_file)
                    return False
                time.sleep(1)
        return False

    def wait_for_spider_to_finish(self, zap):
        while int(zap.spider.status()) < 100:
            time.sleep(2)
        return True

    def wait_for_ajaxSpider_to_finish(self, zap):
        while int(zap.ajaxSpider.status()) < 100:
            time.sleep(2)
        return True

    def wait_for_active_scan_to_finish(self, zap):
        while int(zap.ascan.status()) < 100:
            time.sleep(5)
        return True

    def process_scan_results(self, zap, log_file):
        print("\nHosts: " + ", ".join(zap.core.hosts), file=log_file)

        print("\nAlerts: ", file=log_file)
        alert_urls = set()
        for x in zap.core.alerts():
            print(x, file=log_file)
            alert_urls.add(x.get("url"))

        print("\nAlert URLs:", file=log_file)
        print("\n".join(alert_urls), file=log_file)

        print("\nAll URLs visited:", file=log_file)
        for url in zap.core.urls():
            print(url, file=log_file)

    def zap_on_bind(self, proto, guest_ip, guest_port, host_port, procname):
        """
        There was a bind - spider and active scan. Note we now go through SyscallProxy
        so we can analyze syscall behavior during each zap-generated requestd
        """
        if guest_port not in [80] or proto != "tcp":
            # Ignore
            return

        f = open(self.outdir + f"/zap_{proto}_{guest_ip}_{guest_port}.log", "w")
        self.log_files.append(f)

        # Launch a thread to analyze this request
        t = threading.Thread(target=self.crawl_thread_exn, args=(host_port, f))
        t.daemon = True
        t.start()

    def add_url(self, url):
        # Add a relative url to our target. Should NOT start with a /

        if url.startswith("/"):
            raise ValueError("URL should not start with /, but got " + url)

        if self.url_queue_lock.locked():
            print(
                "ERROR ignoring request to add url",
                url,
                "while locked",
                file=self.output_file,
            )
            # raise ValueError("Cannot add url while locked")
            return

        with self.url_queue_lock:
            self.url_queue.append(url)

    def crawl_thread_exn(self, host_port, log_file):
        try:
            self.crawl_thread(host_port, log_file)
        except Exception as e:
            # on shutdown we get errors trying to print
            if not self.running:
                return
            print("Exception in crawl thread:", e)
            # Print line number of exception
            import traceback

            traceback.print_exc()
            if not log_file.closed:
                print("Exception in crawl thread:", e, file=log_file)
            # raise

    def crawl_thread(self, host_port, log_file):
        # Setup and initial checks
        localProxy = {
            "http": f"http://127.0.0.1:{self.port}",
            "https": f"https://127.0.0.1:{self.port}",
        }
        zap = ZAPv2(proxies=localProxy, apikey=self.api_key)
        if host_port == 80:
            target = f"http://{self.target_host}/"
        else:
            target = f"http://{self.target_host}:{host_port}/"

        # Setup some default credentials!
        # Define a context for the target URL
        context_name = f"AuthContext:{target}"
        context_id = zap.context.new_context(
            contextname=context_name, apikey=self.api_key
        )

        # Set up the authentication method for the context
        auth_method_name = "httpAuthentication"
        auth_method_config_params = f"hostname={self.target_host}&port=80&realm="
        zap.authentication.set_authentication_method(
            contextid=context_id,
            authmethodname=auth_method_name,
            authmethodconfigparams=auth_method_config_params,
            apikey=self.api_key,
        )

        # Set up the users for the context
        for username, password in credentials:
            user_id = zap.users.new_user(context_id, username)
            user_auth_config_params = f"username={username}&password={password}"
            zap.users.set_authentication_credentials(
                context_id, user_id, user_auth_config_params
            )
            zap.users.set_user_enabled(context_id, user_id, True)

        # Process sequence
        if not self.open_connection_through_proxy(target, localProxy):
            return
        if not self.update_sites_tree(zap, target):
            return
        if not self.queue_filesystem(zap, target):
            return
        if not self.perform_spidering(zap, target):
            return
        if not self.perform_ajaxSpidering(zap, target):
            return
        if not self.perform_active_scan(zap, target):
            return
        self.process_scan_results(zap, log_file)

    def uninit(self):
        if hasattr(self, "process"):
            self.process.terminate()

            ctr = 0
            while self.process.poll() is None:
                time.sleep(1)
                ctr += 1
                if ctr > 10:
                    print("ERROR - could not terminate process")
                    self.process.kill()
            self.process.wait()

        for f in self.log_files:
            f.close()

        if self.output_file:
            self.output_file.close()

        # remove the entry from /etc/hosts
        if self.target_host != "127.0.0.1":
            h = Hosts(HOSTS_FILE)
            h.remove_all_matching("127.0.0.1", self.target_host)
            h.write()
