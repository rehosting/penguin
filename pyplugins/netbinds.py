import socket
from pandare import PyPlugin
from os.path import join

BINDS_FILE="netbinds.csv"

class NetBinds(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")

        # The NetBinds.on_bind PPP callback happens on every bind.
        # Don't be confused by the vpn on_bind callback that happens
        # after the VPN bridges a connection. This one has the better name
        # but that one is more of a pain to change.
        self.ppp_cb_boilerplate('on_bind')
        
        with open(join(self.outdir, BINDS_FILE), 'w') as f:
            f.write(f"procname,ipvn,domain,guest_ip,guest_port\n")
        
        def get_bind_type(cpu, sockfd):
            fname_type_map = {
                b'socket:UDP': ('udp', socket.AF_INET),
                b'socket:TCP': ('tcp', socket.AF_INET),
                b'socket:UDPv6': ('udp', socket.AF_INET6),
                b'socket:TCPv6': ('tcp', socket.AF_INET6),
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
            if domain == socket.AF_INET:
                return get_bind_ipv4_addr(cpu, sockaddrin_addr)        
            elif domain == socket.AF_INET6:
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
                sock_type, family, port, ip = recent_binds[key]
                del recent_binds[key] # Only expect to see one return per enter

            elif info := get_bind_info(cpu, sockfd, sockaddrin_addr):
                if info == "Unsupported":
                    return
                sock_type, family, port, ip = info
            else:
                print(f"Could not resolve bind info in {procname}")
                return
            
            ipvn = 4 if family == socket.AF_INET else 6

            # Report the bind's info
            with open(join(self.outdir, BINDS_FILE), 'a') as f:
                f.write(f"{procname},{ipvn},{sock_type},{ip},{port}\n")

            # Trigger our callback
            self.ppp_run_cb('on_bind', sock_type, ipvn, ip, port, procname)