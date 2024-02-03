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

        self.ppp.Core.ppp_reg_cb('igloo_bind', self.on_bind)


    def on_bind(self, cpu, procname, is_ipv4, is_stream, port, sin_addr):
        ipvn = 4 if is_ipv4 else 6
        sock_type = 'tcp' if is_stream else 'udp'

        if ipvn == 4:
            ip = '0.0.0.0'
            if sin_addr != 0:
                ip = socket.inet_ntop(socket.AF_INET, sin_addr)
        else:
            ip = '::1'
            if sin_addr != 0:
                ip = f"[{socket.inet_ntop(socket.AF_INET6, sin_addr)}]"

        # Report the bind's info
        with open(join(self.outdir, BINDS_FILE), 'a') as f:
            f.write(f"{procname},{ipvn},{sock_type},{ip},{port}\n")

        # Trigger our callback
        self.ppp_run_cb('on_bind', sock_type, ipvn, ip, port, procname)