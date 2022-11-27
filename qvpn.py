import tempfile
import subprocess
import socket
from contextlib import closing
from time import sleep
from sys import path
path.append("/igloo/")
from qemuPython import QemuPyplugin

asid_socket_map = {}
active_listeners = set() # (proto, port)

class VsockVPNQ(QemuPyplugin):
    def __init__(self, arch, args, CID, fw, outdir):
        if 'vhost-vsock' not in str(args) and 'vhost-user-vsock' not in str(args):
            print("VsockVPN error: QEMU running without vsock/vhost-user-vsock")
            return

        self.SOCK_DGRAM = 2 if arch == 'arm' else 1 # It's always 2 except for mips

        print(f"VPN running with CID {CID}, outdir {outdir}")
        assert(CID is not None)

        # Launch VPN on host as panda starts. Init in the guest will launch the VPN in the guest
        self.event_file = tempfile.NamedTemporaryFile(prefix=f'/tmp/vpn_events_{CID}_')

        self.host_vpn = subprocess.Popen(["/igloo/vpn/vpn.x86_64-unknown-linux-musl", "host", "-e", self.event_file.name, "-c", str(CID)], stdout=subprocess.DEVNULL)
        #self.host_vpn = subprocess.Popen(["/igloo/vsock_vpn2", "host", "-e", self.event_file.name, "-c", str(CID)], stdout=subprocess.DEVNULL)


        self.qp.register_bind_cb(self.vpn_on_bind)

    @staticmethod
    def find_free_port():
        '''
        https://stackoverflow.com/a/45690594
        '''
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(('localhost', 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]


    def vpn_on_bind(self, procname, pid, protocol, domain, ip, port_no):
        host_portno = self.find_free_port()
        fams = {'SOCK_STREAM': 'tcp',
                'SOCK_DGRAM':  'udp'}
        if protocol not in fams:
            print("Unsupported protocol:", protocol)
            return
        if port_no == 0:
            return

        fam = fams[protocol]

        if domain != 'AF_INET':
            print("Unsupported domain:", domain)
            return

        print(f"Mapping guest {domain} {fam} {ip}:{port_no} to host 0.0.0.0:{host_portno}")

        with open(self.event_file.name, "a") as f:
            f.write(f"bind {fam} {ip}:{port_no} 0.0.0.0:{host_portno}\n")

        if 'PandaCrawl' in self.qp.plugins:
            sleep(5)
            self.qp.plugins['PandaCrawl'].on_bind(fam, ip, port_no, host_portno, procname)
        #self.ppp_run_cb('on_bind', domain, ip, port_int, host_portno, procname)

    def uninit(self):
        self.host_vpn.kill()
        self.event_file.close()
