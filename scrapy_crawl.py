import logging
import coloredlogs
import subprocess
from scrapy.crawler import CrawlerRunner
from twisted.internet import reactor


from sys import path
path.append("/igloo/")
path.append("/pandata/")
from qemuPython import QemuPyplugin

from fw_spider import FwSpider
coloredlogs.install(level='INFO')

class PandaCrawl2(QemuPyplugin):
    '''
    Launch and manage scrapy crawler

    Called directly by qvpn when it sees a bind 5s after it tells the vpn to bridge it.
    '''
    def __init__(self, arch, args, CID, fw, outdir):
        self.logger = logging.getLogger('PandaCrawl')


    def on_bind(self, proto, guest_ip, guest_port, host_port, procname):
        self.logger.info(f"Bind from {procname} {proto} to {guest_ip}:{guest_port}, mapped to host port {host_port}")
        if guest_port != 80 or proto != 'tcp':
            self.logger.info(f"\tIgnoring non tcp:80 (actual {proto}:{guest_port})")
            return

        start = f'http://localhost:{host_port}'
        subprocess.check_output(f"scrapy runspider /pandata/fw_spider.py -a start_url={start}", shell=True)

