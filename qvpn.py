import tempfile
import subprocess
import socket
import re
from contextlib import closing
from time import sleep

import logging
import coloredlogs

from sys import path
path.append("/igloo/")
from qemuPython import QemuPyplugin

coloredlogs.install(level='INFO')

asid_socket_map = {}
active_listeners = set() # (proto, port)

class VsockVPNQ(QemuPyplugin):
    def __init__(self, arch, args, CID, fw, outdir):
        self.logger = logging.getLogger(f'QVPN')

        if 'vhost-vsock' not in str(args) and 'vhost-user-vsock' not in str(args):
            self.logger.error("VsockVPN error: QEMU running without vsock/vhost-user-vsock")
            return

        self.SOCK_DGRAM = 2 if arch == 'arm' else 1 # It's always 2 except for mips

        assert(CID is not None)

        # Launch VPN on host as panda starts. Init in the guest will launch the VPN in the guest
        self.event_file = tempfile.NamedTemporaryFile(prefix=f'/tmp/vpn_events_{CID}_')

        self.logger.info(f"QVPN running with CID {CID}, outdir {outdir}, logging to {self.event_file.name} and running vpn process in background")

        self.host_vpn = subprocess.Popen(["/igloo/vpn/vpn.x86_64-unknown-linux-musl", "host", "-e", self.event_file.name, "-c", str(CID)], stdout=subprocess.DEVNULL)

        #self.host_vpn = subprocess.Popen(["/igloo/vsock_vpn2", "host", "-e", self.event_file.name, "-c", str(CID)], stdout=subprocess.DEVNULL)

        #open [PID: 157 (find)], bind %s:%s:%d IP=%pI4
        self.sc_line_re = re.compile(r'([a-z0-9_]*) \[PID: (\d*) \(([a-zA-Z0-9/\-:_\. ]*)\)], bind: (SOCK_[A-Z]*):(AF_INET6?):([0-9]*) IP=([0-9a-f:\.]*)')

    @staticmethod
    def find_free_port():
        '''
        https://stackoverflow.com/a/45690594
        '''
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(('localhost', 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]

    def on_output(self, line):
        '''
        Non-blocking function to process a line of guest output via dedicated serial.

        Identify binds, queue up after_output fn for each.
        '''
        if m := self.sc_line_re.match(line):
            (sc_name, pid, procname, sock_type, family, port, ip) = m.groups()
            port = int(port)
            self.queue.put((procname, pid, family, sock_type, ip, port))

    def after_output(self, procname, pid, family, sock_type, ip, port):
        '''
        This function is allowed to block
        '''
        # sock_type aka DOMAIN: SOCK_STREAM, etc, translate this into proto: tcp or udp
        # family: AF_INET, AF_INET6, etc.

        host_port = self.find_free_port()

        try:
            proto = {'SOCK_STREAM': 'tcp',
                      'SOCK_DGRAM':  'udp'}[sock_type]
        except KeyError:
            self.logger.warning(f"Unsupported protocol: {protocol}")
            return

        if port == 0:
            return

        if family != 'AF_INET':
            self.logger.warning(f"Unsupported domain: {family}")
            return

        self.logger.info(f"Mapping guest {family} {proto} {ip}:{port} to host 0.0.0.0:{host_port}")

        with open(self.event_file.name, "a") as f:
            f.write(f"bind {proto} {ip}:{port} 0.0.0.0:{host_port}\n")

        # inform PandaCrawl if it's loaded (TODO: should this be in pandacrawl?)
        sleep(5)
        call_count = 0
        for plugin in self.qp.plugins.keys():
            if f := getattr(self.qp.plugins[plugin], 'on_bind', None):
                self.logger.info(f"Notifying {plugin} of bind")
                f(proto, ip, port, host_port, procname)
                call_count += 1

        if call_count == 0:
            self.logger.warning("No on_bind consumers for qvpn")

    def uninit(self):
        self.host_vpn.kill()
        self.event_file.close()
