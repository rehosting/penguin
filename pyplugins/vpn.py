from pandare import PyPlugin
import tempfile
import subprocess
import socket
from contextlib import closing
import atexit
import re

from penguin import getColoredLogger
from os import environ as env
from os.path import join
from os import geteuid

static_dir = "/igloo_static/"

running_vpns = []
def kill_vpn():
    for p in running_vpns:
        p.kill()
        p.wait()

atexit.register(kill_vpn)

BRIDGE_FILE="vpn_bridges.csv"

#Port maps built from an optional environment variable
#e.g., IGLOO_VPN_PORT_MAPS="TCP:80:192.168.0.1:80,udp:20002:192.168.0.1:20002"

class VsockVPN(PyPlugin):
    def __init__(self, panda):
        if 'vhost-vsock' not in str(panda.panda_args) and 'vhost-user-vsock' not in str(panda.panda_args):
            raise ValueError("VsockVPN error: PANDA running without vsock")

        self.ppp_cb_boilerplate('on_bind')

        self.outdir = self.get_arg("outdir")
        vhost_socket = self.get_arg("vhost_socket")
        CID = self.get_arg("CID")
        port_maps = self.get_arg("IGLOO_VPN_PORT_MAPS")
        self.seen_ips = set() # IPs we've seen
        self.wild_ips = set() # (sock_type, port, procname) tuples
        self.mapped_ports = set() # Ports we've mapped
        self.active_listeners = set() # (proto, port)
        assert(CID is not None)

        self.logger = getColoredLogger("plugins.VPN")

        # Check if we have CONTAINER_{IP,NAME} in env
        self.exposed_ip = env.get("CONTAINER_IP", None)
        self.container_name = env.get("CONTAINER_NAME", None)

        self.has_perms = geteuid() == 0
        if not self.has_perms:
            # Non-root, but do we have CAP_NET_BIND_SERVICE?
            with open("/proc/self/status") as f:
                status = f.read()
                self.has_perms = "CapInh:.*cap_net_bind_service" in status

        '''
        Fixed maps:
            Map[(sock_type, guest_ip, guest_port)] = host_port
        '''
        self.fixed_maps = {} 

        # We prioritize the value in our config value over the environment 
        # variable
        if not port_maps and "IGLOO_VPN_PORT_MAPS" in env:
            port_maps = env["IGLOO_VPN_PORT_MAPS"]
            
        if port_maps:
            #port mappings as a comma-separated list tcp:80:192.168.0.1:80
            for arg in port_maps.split(','):
                if m := re.search(r"(tcp|udp):(\d+):(.*):(\d+)",arg,re.IGNORECASE):
                    sock_type = m[1].lower()
                    host_port = int(m[2])
                    guest_ip = m[3]
                    guest_port = int(m[4])
                    self.seen_ips.add(guest_ip)
                    self.fixed_maps[(sock_type, guest_ip, guest_port)] = host_port
                else:
                    raise ValueError(f"Couldn't parse port map: {arg}")
            self.logger.info(f"VPN loaded fixed port assingments: {self.fixed_maps}")

        # Launch VPN on host as panda starts. Init in the guest will launch the VPN in the guest
        self.event_file = tempfile.NamedTemporaryFile(prefix=f'/tmp/vpn_events_{CID}_')
        self.host_vpn = subprocess.Popen([join(static_dir, "vpn/vpn.x86_64"), "host", "-e", self.event_file.name, "-c", str(CID), '-u', vhost_socket], stdout=subprocess.DEVNULL)
        running_vpns.append(self.host_vpn)

        with open(join(self.outdir, BRIDGE_FILE), 'w') as f:
            f.write("procname,ipvn,domain,guest_ip,guest_port,host_port\n")

        # Whenever NetLog detects a bind, we'll set up bridges
        self.ppp.NetBinds.ppp_reg_cb('on_bind', self.on_bind)

    def on_bind(self, sock_type, ipvn, ip, port, procname):
        if port == 0:
            # Empherial ports - not sure how to handle these
            return

        listener_key = (sock_type, port)
        if listener_key in self.active_listeners:
            # Already forwarding this proto+port
            return

        self.active_listeners.add(listener_key)

        if ipvn == 4: # Only handling IPv4 wildcards like this for now
            if ip == '0.0.0.0':
                # Add wild_ips
                self.wild_ips.add((sock_type, port, procname))

                # Bridge for each previously seen ip
                for seen_ip in self.seen_ips:
                    host_port = self.bridge(sock_type, seen_ip, port, procname, ipvn)
                    self.ppp_run_cb('on_bind', sock_type, seen_ip, port, host_port, procname)

            elif ip not in self.seen_ips:
                # Find all wild_ips, log this IP
                self.seen_ips.add(ip)

                # For any previously-wild_ip service, bridge it with this new IP
                for (sock_type, seen_port, seen_procname) in self.wild_ips:
                    host_port = self.bridge(sock_type, ip, seen_port, seen_procname, ipvn)
                    self.ppp_run_cb('on_bind', sock_type, ip, seen_port, host_port, procname)

        host_port = self.bridge(sock_type, ip, port, procname, ipvn)
        self.ppp_run_cb('on_bind', sock_type, ip, port, host_port, procname)
    
    def map_bound_socket(self, sock_type, ip, guest_port, procname):
        host_port = guest_port
        # procname, listening, port, reason
        reason = ""
        if mapped_host_port := self.fixed_maps.get((sock_type,ip,guest_port), None):
            host_port = mapped_host_port
            if not self.is_port_open(host_port):
                raise RuntimeError(f"User requested to map host port {host_port} but it is not free")
            reason = "(via fixed mapping)"
        elif guest_port < 1024 and self.has_perms:
            host_port = self.find_free_port()
            reason = f"({guest_port} is privileged and user cannot bind)"
        elif guest_port in self.mapped_ports or not self.is_port_open(guest_port):
            host_port = self.find_free_port()
            reason = f"({guest_port} is already in use)"

        if self.exposed_ip:
            connect_to = f"{self.exposed_ip}:{host_port}"
        elif self.container_name:
            connect_to = f"container {self.container_name}:{host_port}"
        else:
            connect_to = f"container on port {host_port}"

        listen_on = f"{sock_type} {ip}:{guest_port}"

        self.logger.info(f"{procname: >10} binds {listen_on: <20} reach it at {connect_to: <20} {reason}")

        return host_port

    def bridge(self, sock_type, ip, guest_port, procname, ipvn):
        host_port = self.map_bound_socket(sock_type, ip, guest_port, procname)
        self.mapped_ports.add(host_port)
        with open(self.event_file.name, "a") as f:
            f.write(f"{sock_type},{ip}:{guest_port},0.0.0.0:{host_port}\n")

        with open(join(self.outdir, BRIDGE_FILE), 'a') as f:
            f.write(f"{procname},ipv{ipvn},{sock_type},{ip},{guest_port},{host_port}\n")

        return host_port

    @staticmethod
    def find_free_port():
        '''
        https://stackoverflow.com/a/45690594
        '''
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.bind(('localhost', 0))
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            return s.getsockname()[1]

    @staticmethod
    def is_port_open(port):
        '''
        https://stackoverflow.com/a/35370008
        '''
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            return sock.connect_ex(('localhost', port))

    def uninit(self):
        if hasattr(self, 'host_vpn'):
            self.logger.debug("Killing VPN")
            self.host_vpn.terminate()
            self.host_vpn.kill()
            running_vpns[:] = [x for x in running_vpns if x != self.host_vpn]
            self.logger.debug("Killed VPN")
