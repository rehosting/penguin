import logging
import subprocess
import coloredlogs

from sys import path
path.append("/igloo/")
from qemuPython import QemuPyplugin

coloredlogs.install(level='INFO')

class ReprCrawl(QemuPyplugin):
    '''
    Launch witcher's Repr crawler on our FW

    Called directly by qvpn when it sees a bind 5s after it tells the vpn to bridge it.
    '''
    def __init__(self, arch, args, CID, fw, outdir):
        self.logger = logging.getLogger('ReqrCrawl')
        self.logger.info("loaded")

    def on_bind(self, proto, guest_ip, guest_port, host_port, procname):
        self.logger.info(f"Bind from {procname} {proto} to {guest_ip}:{guest_port}, mapped to host port {host_port}")
        if guest_port != 80 or proto != 'tcp':
            self.logger.info(f"\tIgnoring non tcp:80 (actual {proto}:{guest_port})")
            return

        self.queue.put((procname, guest_port, host_port))

    def after_output(self, procname, guest_port, host_port):
        self.logger.info("Starting crawler for {procname}:{guest_port} bridged via host port {host_port}")
        r = subprocess.Popen(["/root/.nvm/versions/node/v14.17.6/bin/node", # gross
                              "/reqr/request_crawler/main.js",
                              "foo", # TODO: what is this argument?
                             f"http://localhost:{host_port}",
                              "/reqr"])

