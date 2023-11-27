from pandare import PyPlugin
import tempfile
import subprocess
import socket
from contextlib import closing
import atexit
import re
from os import environ as env
from os.path import join
from os import geteuid
from igloo import static_dir
from socket import AF_INET, AF_INET6
running_vpns = []
def kill_vpn():
    for p in running_vpns:
        p.kill()

atexit.register(kill_vpn)

# Two outfiles: netbinds.txt, bridges.txt
BINDS_FILE="vpn_netbinds.csv"
BRIDGE_FILE="vpn_bridges.csv"
#Port maps built from an optional environment variable
#e.g., IGLOO_VPN_PORT_MAPS="TCP:80:192.168.0.1:80,udp:20002:192.168.0.1:20002"

class VsockVPN(PyPlugin):
    def __init__(self, panda):
        if 'vhost-vsock' not in str(panda.panda_args):
            raise ValueError("VsockVPN error: PANDA running without vsock")

        self.ppp_cb_boilerplate('on_bind')

        self.outdir = self.get_arg("outdir")
        CID = self.get_arg("CID")
        port_maps = self.get_arg("IGLOO_VPN_PORT_MAPS")
        self.seen_ips = set() # IPs we've seen
        self.wild_ips = set() # (sock_type, port, procname) tuples
        self.mapped_ports = set() # Ports we've mapped
        self.active_listeners = set() # (proto, port)

        self.SOCK_DGRAM = 2

        print(f"VPN running with CID {CID}, outdir {self.outdir}")
        assert(CID is not None)
        
        
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
            print(f"VPN loaded fixed port assingments: {self.fixed_maps}")

        # Launch VPN on host as panda starts. Init in the guest will launch the VPN in the guest
        self.event_file = tempfile.NamedTemporaryFile(prefix=f'/tmp/vpn_events_{CID}_')

        self.host_vpn = subprocess.Popen([join(static_dir, "vpn/vpn.x86_64"), "host", "-e", self.event_file.name, "-c", str(CID)], stdout=subprocess.DEVNULL)
        running_vpns.append(self.host_vpn)

        with open(join(self.outdir, BRIDGE_FILE), 'w') as f:
            f.write("procname,ipvn,domain,guest_ip,guest_port,host_port\n")

        with open(join(self.outdir, BINDS_FILE), 'w') as f:
            f.write(f"procname,ipvn,domain,guest_ip,guest_port\n")
        
        def get_bind_type(cpu, sockfd):
            fname_type_map = {
                b'socket:UDP': ('udp', AF_INET),
                b'socket:TCP': ('tcp', AF_INET),
                b'socket:UDPv6': ('udp', AF_INET6),
                b'socket:TCPv6': ('tcp', AF_INET6),
            }
            if sockname := panda.get_file_name(cpu, sockfd):
                if type_ := fname_type_map.get(sockname, None):
                    return type_
                else:
                    return False
                
        def get_bind_port(cpu, sockaddrin_addr):
            try: # port is 2 bytes starting 2 bytes into the struct for both v4/v6
                sin_port = panda.virtual_memory_read(cpu, sockaddrin_addr+2, 2, fmt='int')
                sin_port = int.from_bytes(int.to_bytes(sin_port, 2, panda.endianness), 'little')
                port  = int(socket.htons(sin_port))
                return port
            except ValueError:
                return
        
        def get_bind_ipv4_addr(cpu, sockaddrin_addr):
            ip = '0.0.0.0'
            #struct sockaddr_in {
            #    sa_family_t    sin_family; /* address family: AF_INET */
            #    in_port_t      sin_port;   /* port in network byte order */
            #    struct in_addr sin_addr;   /* internet address */
            #};

            try:
                sin_addr =  panda.virtual_memory_read(cpu, sockaddrin_addr+4, 4)
            except ValueError:
                return
            if sin_addr != 0:
                ip = socket.inet_ntop(socket.AF_INET, sin_addr)
            return ip

        def get_bind_ipv6_addr(cpu, sockaddrin_addr):   
            ip = '::1'
            #struct sockaddr_in6 {
            #    sa_family_t     sin6_family;   /* AF_INET6 */
            #    in_port_t       sin6_port;     /* port number */
            #    uint32_t        sin6_flowinfo; /* IPv6 flow information */
            #    struct in6_addr sin6_addr;     /* IPv6 address */
            #    uint32_t        sin6_scope_id; /* Scope ID (new in 2.4) */
            #};

            #struct in6_addr {
            #    unsigned char   s6_addr[16];   /* IPv6 address */
            #};
            try:
                sin6_addr =  panda.virtual_memory_read(cpu, sockaddrin_addr+8, 16)
            except ValueError:
                return
            if sin6_addr != 0:
                ip = f"[{socket.inet_ntop(socket.AF_INET6, sin6_addr)}]"
            return ip
        
        def get_bind_ip(cpu, sockaddrin_addr, domain):
            if domain == AF_INET:
                return get_bind_ipv4_addr(cpu, sockaddrin_addr)        
            elif domain == AF_INET6:
                return get_bind_ipv6_addr(cpu, sockaddrin_addr)
        
        # Returns False if we don't support this kind of bind
        def get_bind_info(cpu, sockfd, sockaddrin_addr):
            type_ = get_bind_type(cpu, sockfd)
            if type_ is False:
                return "Unsupported"
            if type_:
                sock_type, family = type_
                if port := get_bind_port(cpu, sockaddrin_addr):
                    if ip := get_bind_ip(cpu, sockaddrin_addr, family):
                        return (sock_type, family, port, ip)

        recent_binds = {}
        @panda.ppp("syscalls2", "on_sys_bind_enter")
        def on_bind_enter(cpu, pc, sockfd, sockaddrin_addr, addrlen):
            if info := get_bind_info(cpu, sockfd, sockaddrin_addr):
                if info == "Unsupported":
                    return
                key = (panda.get_process_name(cpu),sockfd)
                recent_binds[key] = info
                
        @panda.ppp("syscalls2", "on_sys_bind_return")
        def on_bind(cpu, pc, sockfd, sockaddrin_addr, addrlen):
            retval = panda.arch.get_return_value(cpu)
            if retval != 0:
                return
            
            procname = panda.get_process_name(cpu)
            key = (procname,sockfd)
            if key in recent_binds:
                sock_type,family,port,ip = recent_binds[key]
            elif info := get_bind_info(cpu, sockfd, sockaddrin_addr):
                if info == "Unsupported":
                    return
                sock_type,family,port,ip = info
            else:
                print(f"Could not resolve bind info in {procname}")
                return
            
            ipvn = 4 if family == AF_INET else 6
            with open(join(self.outdir, BINDS_FILE), 'a') as f:
                f.write(f"{procname},{ipvn},{sock_type},{ip},{port}\n")

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
        if mapped_host_port := self.fixed_maps.get((sock_type,ip,guest_port), None):
            host_port = mapped_host_port
            assert self.is_port_open(host_port), f"User requested to map host port {host_port} but it is not free!"
            print(f"VPN started for {procname} listening on {sock_type} {ip}:{guest_port}, connect to container port {host_port} (via fixed mapping)")
        elif guest_port < 1024 and geteuid() != 0:
            host_port = self.find_free_port()
            print(f"VPN started for {procname} listening on {sock_type} {ip}:{guest_port}, connect to container port {host_port} ({guest_port} is privileged and user is not root)")
        elif guest_port in self.mapped_ports or not self.is_port_open(guest_port):
            host_port = self.find_free_port()
            print(f"VPN started for {procname} listening on {sock_type} {ip}:{guest_port}, connect to container port {host_port} ({guest_port} unavailable)")
        else:
            print(f"VPN started for {procname} listening on {sock_type} {ip}:{guest_port}, connect to container port {host_port}")
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
            print("Killing VPN")
            self.host_vpn.terminate()
            self.host_vpn.kill()
            running_vpns[:] = [x for x in running_vpns if x != running_vpns]
            print("Killed VPN")
