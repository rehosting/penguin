import socket
import struct
import time
from os.path import join, dirname

from pandare import PyPlugin

from penguin import getColoredLogger

BINDS_FILE = "netbinds.csv"
SUMMARY_BINDS_FILE = "netbinds_summary.csv"

class NetBinds(PyPlugin):
    def __init__(self, panda):
        self.outdir = self.get_arg("outdir")
        self.panda = panda
        self.seen_binds = set()
        self.start_time = time.time()
        self.logger = getColoredLogger("plugins.netbinds")
        self.shutdown_on_www = self.get_arg_bool("shutdown_on_www")

        # The NetBinds.on_bind PPP callback happens on every bind.
        # Don't be confused by the vpn on_bind callback that happens
        # after the VPN bridges a connection. This one has the better name
        # but that one is more of a pain to change.
        self.ppp_cb_boilerplate("on_bind")

        with open(join(self.outdir, BINDS_FILE), "w") as f:
            f.write("procname,ipvn,domain,guest_ip,guest_port,time\n")

        with open(join(self.outdir, SUMMARY_BINDS_FILE), "w") as f:
            f.write("n_procs,n_sockets,bound_www,time\n")

        self.ppp.Events.listen("igloo_ipv4_bind", self.on_ipv4_bind)
        self.ppp.Events.listen("igloo_ipv6_bind", self.on_ipv6_bind)
        self.ppp.Events.listen("igloo_ipv4_setup", self.on_ipv4_setup)
        self.ppp.Events.listen("igloo_ipv6_setup", self.on_ipv6_setup)
        self.pending_procname = None
        self.pending_sinaddr = None

    def on_ipv4_setup(self, cpu, procname, sin_addr):
        if self.pending_procname is not None:
            self.logger.error(f"Pending bind not cleared before new bind for ipv6: {self.pending_procname} vs {procname}")
        self.pending_procname = procname
        self.pending_sinaddr = int.to_bytes(sin_addr, 4, "little")

    def on_ipv6_setup(self, cpu, procname, sinaddr_addr):
        if self.pending_procname is not None:
            self.logger.error(f"Pending bind not cleared before new bind for ipv6: {self.pending_procname} vs {procname}")
        self.pending_procname = procname
        self.pending_sinaddr = self.panda.virtual_memory_read(cpu, sinaddr_addr, 16)

    def on_ipv4_bind(self, cpu, port, is_steam):
        self.on_bind(
            cpu, self.pending_procname, True, is_steam, port, self.pending_sinaddr
        )
        self.pending_procname = None
        self.pending_sinaddr = None

    def on_ipv6_bind(self, cpu, port, is_steam):
        self.on_bind(
            cpu, self.pending_procname, False, is_steam, port, self.pending_sinaddr
        )
        self.pending_procname = None
        self.pending_sinaddr = None

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

		# Log details to disk
        self.report_bind_info(time_delta, procname, ipvn, sock_type, ip, port)

        # Trigger our callback
        self.ppp_run_cb("on_bind", sock_type, ipvn, ip, port, procname)

        # If bind is 80 and we have shutdown_www option, end the emulation
        if port == 80 and self.shutdown_on_www:
            self.logger.info("Shutting down emulation due to bind on port 80")
            self.panda.end_analysis()

    def report_bind_info(self, time_delta, procname, ipvn, sock_type, ip, port):
		# Collect summary stats at this time (unique processes, total binds, bound_www, time)
        n_sockets = 0
        procs = set()
        bound_www = False

        # Report this specific bind
        with open(join(self.outdir, BINDS_FILE), "a") as f:
            f.write(f"{procname},{ipvn},{sock_type},{ip},{port},{time_delta:.3f}\n")

        # Look through self.seen_binds, count unique procnames, total binds, and bound_www
        for data in self.seen_binds:
            name = data[0]
            port = data[4]
            procs.add(name)
            n_sockets += 1
            if port == 80:
                bound_www = True
        n_procs = len(procs)

		# Report summary stats
        with open(join(self.outdir, SUMMARY_BINDS_FILE), "a") as f:
            f.write(f"{n_procs},{n_sockets},{bound_www},{time_delta:.3f}\n")