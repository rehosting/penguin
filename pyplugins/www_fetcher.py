from pandare import PyPlugin
from penguin import getColoredLogger
import requests
import threading
import time
import os
from copy import deepcopy

class WWWFetcher(PyPlugin):
    def __init__(self, panda, shutdown_dict=None):
        self.panda = panda
        self.ppp_cb_boilerplate("on_bridge")

        self.outdir = self.get_arg("outdir")
        self.ppp.VsockVPN.ppp_reg_cb("on_bind", self.www_on_bind)
        self.lock = threading.Lock()
        self.logger = getColoredLogger("plugins.WWWFetcher")

        if shutdown_dict:
            self.shutdown_dict = deepcopy(shutdown_dict)

    def www_on_bind(self, proto, guest_ip, guest_port, host_port, host_ip, procname):
        if not (proto == "tcp" and guest_port in [80, 443]):
            return

        f = self.outdir + f"/www_fetcher_{guest_port}_{host_port}"

        t = threading.Thread(target=self.fetch_thread, args=(host_ip, guest_port, host_port, f))
        t.daemon = True
        t.start()

    def fetch_thread(self, host_ip, guest_port, host_port, outfile):
        time.sleep(10) # Give the webserver a chance to start up
        #Might happen if webserver dies and comes back up?
        if guest_port == 80:
            url = "http://"
        else:
            url = "https://"
        url += f"{host_ip}:{host_port}"
        if os.path.isfile(outfile):
            self.logger.warn(f"Already fetched {url}, overwriting...")
        try:
            response = requests.get(url, verify=False)
            resp_len = len(response.content)
            self.logger.info(f"Got response w/status {response.status_code} of {resp_len} bytes from {url}")
            with self.lock:
                with open(outfile, "w") as f:
                    f.write(str(resp_len))
                if self.shutdown_dict and guest_port in self.shutdown_dict:
                    self.shutdown_dict[guest_port] -= 1
                if all(value == 0 for value in shutdown_dict.values()):
                    self.logger.warn(f"We've seen the requested number of non-zero responses, shutting down")
                    self.panda.end_analysis()
        except requests.ConnectionError:
            self.logger.error(f"Failed to connect to {url}")
