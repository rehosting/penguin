"""
netbinds.py - NetBinds Plugin for Penguin

This module provides the NetBinds plugin, which monitors and records all network bind events
within the guest during emulation. It tracks both IPv4 and IPv6 binds, logs detailed information
about each bind, and publishes 'on_bind' events for other plugins to react to new network services.
The plugin is responsible for:

- Subscribing to low-level bind/setup/release events for IPv4 and IPv6 sockets.
- Tracking and deduplicating all bind events, including process name, IP version, socket type, IP, and port.
- Logging bind details and summary statistics to CSV files in the output directory.
- Publishing 'on_bind' events for other plugins (such as VPN, Nmap, FetchWeb) to consume.
- Optionally shutting down emulation when a web service (port 80) is bound, if configured.

Arguments:
    - shutdown_on_www (bool, optional): If True, shut down emulation when a bind occurs on port 80.

Plugin Interface:
    - Publishes 'on_bind' events with (sock_type, ipvn, ip, port, procname) for other plugins to consume.
    - Does not subscribe to other plugin events, but listens to low-level system events.
    - Writes bind logs and summaries to files in the output directory.

Overall Purpose:
    The NetBinds plugin provides a comprehensive record of all network services started by the guest,
    enabling automation, analysis, and integration with other actuation plugins.
"""

import socket
import struct
import time
from os.path import join

from penguin import plugins, Plugin

BINDS_FILE = "netbinds.csv"
SUMMARY_BINDS_FILE = "netbinds_summary.csv"


class NetBinds(Plugin):
    def __init__(self) -> None:
        """
        Initialize the NetBinds plugin, set up event subscriptions, and prepare log files.
        """
        self.outdir = self.get_arg("outdir")
        self.seen_binds = set()
        self.start_time = time.time()
        self.bind_list = []
        self.shutdown_on_www = self.get_arg_bool("shutdown_on_www")

        # The NetBinds.on_bind PPP callback happens on every bind.
        # Don't be confused by the vpn on_bind callback that happens
        # after the VPN bridges a connection. This one has the better name
        # but that one is more of a pain to change.

        plugins.register(self, "on_bind")

        with open(join(self.outdir, BINDS_FILE), "w") as f:
            f.write("procname,ipvn,domain,guest_ip,guest_port,time\n")

        with open(join(self.outdir, SUMMARY_BINDS_FILE), "w") as f:
            f.write("n_procs,n_sockets,bound_www,time\n")

        plugins.subscribe(plugins.Events, "igloo_ipv4_bind", self.on_ipv4_bind)
        plugins.subscribe(plugins.Events, "igloo_ipv6_bind", self.on_ipv6_bind)
        plugins.subscribe(plugins.Events, "igloo_ipv4_setup", self.on_ipv4_setup)
        plugins.subscribe(plugins.Events, "igloo_ipv6_setup", self.on_ipv6_setup)
        plugins.subscribe(plugins.Events, "igloo_ipv4_release", self.on_ipv4_release)
        plugins.subscribe(plugins.Events, "igloo_ipv6_release", self.on_ipv6_release)
        self.pending_procname = None
        self.pending_sinaddr = None

    def on_ipv4_setup(self, cpu, procname, sin_addr) -> None:
        """
        Handle IPv4 socket setup event, record pending bind state.

        Args:
            cpu: The CPU core where the event occurred.
            procname: The name of the process attempting the bind.
            sin_addr: The IPv4 address being bound, in network byte order.
        """
        if self.pending_procname is not None:
            self.logger.error(f"Pending bind not cleared before new bind for ipv6: {self.pending_procname} vs {procname}")
        self.pending_procname = procname
        self.pending_sinaddr = int.to_bytes(sin_addr, 4, "little")

    def on_ipv6_setup(self, cpu, procname, sinaddr_addr) -> None:
        """
        Handle IPv6 socket setup event, record pending bind state.

        Args:
            cpu: The CPU core where the event occurred.
            procname: The name of the process attempting the bind.
            sinaddr_addr: The memory address where the IPv6 address is stored.
        """
        if self.pending_procname is not None:
            self.logger.error(f"Pending bind not cleared before new bind for ipv6: {self.pending_procname} vs {procname}")
        self.pending_procname = procname
        self.pending_sinaddr = self.panda.virtual_memory_read(cpu, sinaddr_addr, 16)

    def on_ipv4_bind(self, cpu, port, is_steam) -> None:
        """
        Handle IPv4 bind event, trigger on_bind and clear pending state.

        Args:
            cpu: The CPU core where the event occurred.
            port: The port number being bound, in host byte order.
            is_steam: Boolean indicating if this is a stream (TCP) bind.
        """
        self.on_bind(
            cpu, self.pending_procname, True, is_steam, port, self.pending_sinaddr
        )
        self.pending_procname = None
        self.pending_sinaddr = None

    def on_ipv6_bind(self, cpu, port, is_steam) -> None:
        """
        Handle IPv6 bind event, trigger on_bind and clear pending state.

        Args:
            cpu: The CPU core where the event occurred.
            port: The port number being bound, in host byte order.
            is_steam: Boolean indicating if this is a stream (TCP) bind.
        """
        self.on_bind(
            cpu, self.pending_procname, False, is_steam, port, self.pending_sinaddr
        )
        self.pending_procname = None
        self.pending_sinaddr = None

    def on_ipv4_release(self, cpu, ip_port, is_stream) -> None:
        """
        Handle IPv4 socket release event, remove bind from tracking.

        Args:
            cpu: The CPU core where the event occurred.
            ip_port: The IP:port string of the released socket.
            is_stream: Boolean indicating if this was a stream (TCP) socket.
        """
        sock_type = "tcp" if is_stream else "udp"
        ip, port = ip_port.split(':')
        if int(port) != 0:
            self.remove_bind(ip, port, sock_type)

    def on_ipv6_release(self, cpu, ip_port, is_stream) -> None:
        """
        Handle IPv6 socket release event, remove bind from tracking.

        Args:
            cpu: The CPU core where the event occurred.
            ip_port: The IP:port string of the released socket.
            is_stream: Boolean indicating if this was a stream (TCP) socket.
        """
        sock_type = "tcp" if is_stream else "udp"
        ip_part, port = ip_port.rsplit(']:')
        if int(port) != 0:
            ip = ip_part.lstrip('[')
            self.remove_bind(ip, port, sock_type)

    def on_bind(self, cpu, procname, is_ipv4, is_stream, port, sin_addr) -> None:
        """
        Handle a completed bind event, log details, publish event, and optionally shut down.

        Args:
            cpu: The CPU core where the event occurred.
            procname: The name of the process that performed the bind.
            is_ipv4: Boolean indicating if this is an IPv4 bind.
            is_stream: Boolean indicating if this is a stream (TCP) bind.
            port: The port number being bound, in host byte order.
            sin_addr: The IP address being bound, in network byte order.
        """
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

        self.track_bind(procname, ipvn, sock_type, ip, port, time_delta)

        # Trigger our callback
        plugins.publish(self, "on_bind", sock_type, ipvn, ip, port, procname)

        # If bind is 80 and we have shutdown_www option, end the emulation
        if port == 80 and self.shutdown_on_www:
            self.logger.info("Shutting down emulation due to bind on port 80")
            self.panda.end_analysis()

    def track_bind(self, procname, ipvn, sock_type, ip, port, time) -> None:
        """
        Track a bind event in the internal list for later analysis.

        Args:
            procname: The name of the process that performed the bind.
            ipvn: The IP version (4 or 6) of the bind.
            sock_type: The type of socket (TCP or UDP).
            ip: The IP address being bound.
            port: The port number being bound.
            time: The time since emulation start when the bind occurred.
        """
        add_dict = {
            "Process Name": procname,
            "IPvN": ipvn,
            "Socket Type": sock_type,
            "IP": ip,
            "Port": port,
            "Time": time
        }
        self.bind_list.append(add_dict)

    def remove_bind(self, ip, port, sock_type) -> None:
        """
        Remove a bind from the internal tracking list.

        Args:
            ip: The IP address of the bind to remove.
            port: The port number of the bind to remove.
            sock_type: The type of socket (TCP or UDP) of the bind to remove.
        """
        self.bind_list[:] = [bind for bind in self.bind_list if not (bind["IP"] == ip and bind["Port"] == int(port) and bind["Socket Type"] == sock_type)]

    def give_list(self):
        """
        Return the current list of tracked binds.

        Returns:
            list: A list of dictionaries, each representing a tracked bind.
        """
        return self.bind_list

    def report_bind_info(self, time_delta, procname, ipvn, sock_type, ip, port) -> None:
        """
        Log bind details and summary statistics to disk.

        Args:
            time_delta: The time since emulation start when the bind occurred.
            procname: The name of the process that performed the bind.
            ipvn: The IP version (4 or 6) of the bind.
            sock_type: The type of socket (TCP or UDP).
            ip: The IP address being bound.
            port: The port number being bound.
        """
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
