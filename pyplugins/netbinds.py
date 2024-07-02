import socket
import struct
import time
from os.path import join

from pandare import PyPlugin

BINDS_FILE = "netbinds.csv"


class NetBinds(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.panda = panda
        self.seen_binds = set()
        self.start_time = time.time()

        # The NetBinds.on_bind PPP callback happens on every bind.
        # Don't be confused by the vpn on_bind callback that happens
        # after the VPN bridges a connection. This one has the better name
        # but that one is more of a pain to change.
        self.ppp_cb_boilerplate("on_bind")

        with open(join(self.outdir, BINDS_FILE), "w") as f:
            f.write(f"procname,ipvn,domain,guest_ip,guest_port,time\n")

        self.ppp.Core.ppp_reg_cb("igloo_bind", self.on_bind)

    def on_bind(self, cpu, procname, is_ipv4, is_stream, port, sin_addr):
        now = time.time()
        ipvn = 4 if is_ipv4 else 6
        sock_type = "tcp" if is_stream else "udp"
        is_le = self.panda.endianness == "little"
        time_delta = now - self.start_time

        # Convert to little endian if necessary and ensure it's only 16 bits
        port = port & 0xFFFF
        if is_le:
            port = socket.ntohs(port)

        if ipvn == 4:
            ip = "0.0.0.0"
            if sin_addr != 0:
                if not is_le:
                    sin_addr = struct.pack("<I", struct.unpack(">I", sin_addr)[0])
                ip = socket.inet_ntop(socket.AF_INET, sin_addr)
        else:
            ip = "::1"
            if sin_addr != 0:
                if not is_le:
                    sin_addr = struct.pack("<IIII", *(struct.unpack(">IIII", sin_addr)))
                ip = f"[{socket.inet_ntop(socket.AF_INET6, sin_addr)}]"

        # Only report each bind once, if it's identical
        # VPN / stats will just get confused if we report the same bind twice
        if (procname, ipvn, sock_type, ip, port) in self.seen_binds:
            return
        self.seen_binds.add((procname, ipvn, sock_type, ip, port))

        # Report the bind's info
        with open(join(self.outdir, BINDS_FILE), "a") as f:
            f.write(f"{procname},{ipvn},{sock_type},{ip},{port},{time_delta:.3f}\n")

        # Trigger our callback
        self.ppp_run_cb("on_bind", sock_type, ipvn, ip, port, procname)
