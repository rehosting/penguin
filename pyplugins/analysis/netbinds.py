"""
NetBinds Plugin (netbinds.py) for Penguin
=========================================

This module provides the NetBinds plugin, which monitors and records the full
lifecycle of network services within the guest during emulation. It tracks both
IPv4 and IPv6 sockets, recording when they are *bound* (opened) and when they
are *released* (closed), and publishes 'on_bind' events for other plugins to
react to new network services.

Lifecycle tracking
-------------------

Services frequently flap: a process may bind, close, and re-bind the same
address in rapid succession (e.g. supervisord restarting a daemon, or a server
that briefly rebinds during startup). To avoid treating every flap as a genuine
close, NetBinds applies a *debounce period*:

- When a socket is released, the close is held as *pending* rather than being
  finalized immediately.
- If the same socket is re-bound within ``debounce_period`` seconds, the close
  is cancelled and the event is recorded as a *flap* (the service is considered
  to have stayed up continuously).
- A pending close older than ``debounce_period`` is *finalized* into a real
  close. Finalization happens opportunistically when later events arrive, and
  unconditionally when the plugin unloads.

A socket that flaps ``transient_threshold`` or more times during the run is
labelled *transient* in the lifecycle summary, marking it as an unstable
service worth attention.

Features
--------

- Subscribes to low-level bind/setup/release events for IPv4 and IPv6 sockets.
- Tracks and deduplicates first-seen binds (process name, IP version, socket
  type, IP, port), as before.
- Logs first-seen binds and summary statistics to CSV files in the output
  directory (``netbinds.csv``, ``netbinds_summary.csv``) -- unchanged format.
- Logs every open/flap/transient/close transition to ``netbind_events.csv`` and
  writes a per-socket lifecycle summary to ``netbinds_lifecycle.csv`` on unload.
- Publishes 'on_bind' events for other plugins (such as VPN, Nmap, FetchWeb).
- Optionally shuts down emulation when a web service (port 80) is bound.

Arguments
---------

- shutdown_on_www (bool, optional): If True, shut down emulation when a bind
  occurs on port 80.
- debounce_period (float, optional): Seconds a close is held pending before
  being treated as a real close. A re-bind within this window is a flap.
  Default: 2.0.
- transient_threshold (int, optional): Number of flaps at which a socket is
  labelled transient. Default: 3.

Plugin Interface
----------------

- Publishes 'on_bind' events with (sock_type, ipvn, ip, port, procname) for
  other plugins to consume. (Semantics unchanged: fired once per first-seen
  unique bind.)
- Listens to low-level system bind/setup/release events.
- Writes bind logs, a lifecycle event log, and summaries to the output dir.

Overall Purpose
---------------

The NetBinds plugin provides a comprehensive record of the network services
started -- and stopped -- by the guest, enabling automation, analysis, and
integration with other actuation plugins.
"""

import socket
import struct
import time
from os.path import join

from pydantic import Field
from penguin import plugins, Plugin, PluginArgs

BINDS_FILE = "netbinds.csv"
SUMMARY_BINDS_FILE = "netbinds_summary.csv"
EVENTS_FILE = "netbind_events.csv"
LIFECYCLE_FILE = "netbinds_lifecycle.csv"

DEFAULT_DEBOUNCE_PERIOD = 2.0
DEFAULT_TRANSIENT_THRESHOLD = 3


class NetBinds(Plugin):
    class Args(PluginArgs):
        shutdown_on_www: bool = Field(
            default=False, description="If true, shut down emulation when a bind occurs on port 80."
        )
        debounce_period: float = Field(
            default=DEFAULT_DEBOUNCE_PERIOD,
            description="Seconds a close is held pending before being treated as a real close. "
            "A re-bind within this window is recorded as a flap, not a close.",
        )
        transient_threshold: int = Field(
            default=DEFAULT_TRANSIENT_THRESHOLD,
            description="Number of flaps at which a socket is labelled transient.",
        )

    def __init__(self) -> None:
        """
        Initialize the NetBinds plugin, set up event subscriptions, and prepare log files.
        """
        self.outdir = self.get_arg("outdir")
        self.seen_binds = set()
        self.start_time = time.time()
        self.shutdown_on_www = self.get_arg_bool("shutdown_on_www")

        debounce = self.get_arg("debounce_period")
        self.debounce_period = float(debounce) if debounce is not None else DEFAULT_DEBOUNCE_PERIOD
        threshold = self.get_arg("transient_threshold")
        self.transient_threshold = int(threshold) if threshold is not None else DEFAULT_TRANSIENT_THRESHOLD

        # Per-socket lifecycle state, keyed by (ipvn, sock_type, normalized_ip, port).
        # This is the source of truth for currently-active binds (see give_list).
        self.sockets = {}

        # The NetBinds.on_bind PPP callback happens on every first-seen bind.
        # Don't be confused by the vpn on_bind callback that happens
        # after the VPN bridges a connection. This one has the better name
        # but that one is more of a pain to change.

        plugins.register(self, "on_bind")

        with open(join(self.outdir, BINDS_FILE), "w") as f:
            f.write("procname,ipvn,domain,guest_ip,guest_port,pid,time\n")

        with open(join(self.outdir, SUMMARY_BINDS_FILE), "w") as f:
            f.write("n_procs,n_sockets,bound_www,time\n")

        with open(join(self.outdir, EVENTS_FILE), "w") as f:
            f.write("event,procname,ipvn,domain,guest_ip,guest_port,pid,time\n")

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
        self.pending_sinaddr = plugins.mem.read_bytes_panda(cpu, sinaddr_addr, 16)

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
        Handle IPv4 socket release event, record a (debounced) close.

        Args:
            cpu: The CPU core where the event occurred.
            ip_port: The IP:port string of the released socket.
            is_stream: Boolean indicating if this was a stream (TCP) socket.
        """
        sock_type = "tcp" if is_stream else "udp"
        ip, port = ip_port.rsplit(':', 1)
        if int(port) != 0:
            self.record_close(4, sock_type, ip, int(port))

    def on_ipv6_release(self, cpu, ip_port, is_stream) -> None:
        """
        Handle IPv6 socket release event, record a (debounced) close.

        Args:
            cpu: The CPU core where the event occurred.
            ip_port: The IP:port string of the released socket, e.g. "[::1]:80".
            is_stream: Boolean indicating if this was a stream (TCP) socket.
        """
        sock_type = "tcp" if is_stream else "udp"
        ip_part, port = ip_port.rsplit(']:', 1)
        if int(port) != 0:
            ip = ip_part.lstrip('[')
            self.record_close(6, sock_type, ip, int(port))

    def on_bind(self, cpu, procname, is_ipv4, is_stream, port_pid, sin_addr) -> None:
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

        try:
            port_str, pid_str = port_pid.split(":")
            # Ensure port is only 16 bits
            port = int(port_str) & 0xFFFF
            pid = int(pid_str)
        except ValueError:
            raise ValueError(f"Invalid port_pid format: {port_pid}. Expected format 'port:pid'.")

        # Convert to little endian if necessary
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

        # Update the socket lifecycle on every bind, including repeats, so we
        # can observe (and debounce) flapping services. This runs before the
        # seen_binds dedup gate below, which only governs the legacy CSV/event.
        self.record_open(now, time_delta, procname, ipvn, sock_type, ip, port, pid)

        # Only report each bind once, if it's identical
        # VPN / stats will just get confused if we report the same bind twice
        if (procname, ipvn, sock_type, ip, port) in self.seen_binds:
            return
        self.seen_binds.add((procname, ipvn, sock_type, ip, port))

        # Log details to disk
        self.report_bind_info(time_delta, procname, ipvn, sock_type, ip, port, pid)

        # Trigger our callback
        plugins.publish(self, "on_bind", sock_type, ipvn, ip, port, procname)

        # If bind is 80 and we have shutdown_www option, end the emulation
        if port == 80 and self.shutdown_on_www:
            self.logger.info("Shutting down emulation due to bind on port 80")
            self.panda.end_analysis()

    @staticmethod
    def _norm_ip(ip) -> str:
        """Normalize an IP for keying: strip IPv6 brackets so bind ('[::1]')
        and release ('::1') refer to the same socket."""
        return ip.strip("[]")

    def _socket_key(self, ipvn, sock_type, ip, port):
        """Build the lifecycle dict key for a socket."""
        return (ipvn, sock_type, self._norm_ip(ip), int(port))

    def _log_event(self, event, rec, time_delta) -> None:
        """Append one lifecycle transition to the event log."""
        with open(join(self.outdir, EVENTS_FILE), "a") as f:
            f.write(
                f"{event},{rec['procname']},{rec['ipvn']},{rec['sock_type']},"
                f"{rec['ip']},{rec['port']},{rec['pid']},{time_delta:.3f}\n"
            )

    def _sweep_pending_closes(self, now) -> None:
        """Finalize any pending closes that have outlived the debounce period."""
        for rec in self.sockets.values():
            if rec["pending_close"] is not None and (now - rec["pending_close"]) > self.debounce_period:
                self._finalize_close(rec)

    def _finalize_close(self, rec) -> None:
        """Turn a pending close into a real close, accounting for uptime."""
        close_delta = rec["pending_close_delta"]
        rec["state"] = "closed"
        rec["close_count"] += 1
        rec["last_close"] = close_delta
        if rec["last_open"] is not None:
            rec["total_uptime"] += max(0.0, close_delta - rec["last_open"])
        rec["pending_close"] = None
        rec["pending_close_delta"] = None
        self._log_event("close", rec, close_delta)

    def record_open(self, now, time_delta, procname, ipvn, sock_type, ip, port, pid) -> None:
        """
        Record a bind (open) in the socket lifecycle, applying debounce so a
        re-bind shortly after a close is treated as a flap rather than a new
        service.
        """
        self._sweep_pending_closes(now)
        key = self._socket_key(ipvn, sock_type, ip, port)
        rec = self.sockets.get(key)

        if rec is None:
            self.sockets[key] = {
                "procname": procname,
                "pid": pid,
                "ipvn": ipvn,
                "sock_type": sock_type,
                "ip": ip,
                "port": port,
                "state": "open",
                "open_count": 1,
                "close_count": 0,
                "flap_count": 0,
                "first_open": time_delta,
                "last_open": time_delta,
                "last_close": None,
                "pending_close": None,
                "pending_close_delta": None,
                "total_uptime": 0.0,
                "transient": False,
            }
            self._log_event("open", self.sockets[key], time_delta)
            return

        # Refresh identity from the latest binder.
        rec["procname"] = procname
        rec["pid"] = pid
        rec["ip"] = ip

        if rec["pending_close"] is not None:
            # Re-bound within the debounce window -> a flap. The close never
            # really happened; the service is considered continuously up.
            rec["pending_close"] = None
            rec["pending_close_delta"] = None
            rec["flap_count"] += 1
            rec["open_count"] += 1
            rec["state"] = "open"
            self._log_event("flap", rec, time_delta)
            if rec["flap_count"] >= self.transient_threshold and not rec["transient"]:
                rec["transient"] = True
                self.logger.info(
                    f"Service {sock_type}/{ip}:{port} ({procname}) marked transient "
                    f"after {rec['flap_count']} flaps"
                )
                # Record the transition to transient as its own lifecycle event so
                # it is observable incrementally (the per-socket summary is only
                # written at unload).
                self._log_event("transient", rec, time_delta)
        elif rec["state"] == "closed":
            # Genuine re-open after a finalized close (outside the debounce
            # window) -- a spaced restart, not rapid flapping.
            rec["open_count"] += 1
            rec["last_open"] = time_delta
            rec["state"] = "open"
            self._log_event("open", rec, time_delta)
        # else: already open and not pending close -> duplicate bind, no change.

    def record_close(self, ipvn, sock_type, ip, port) -> None:
        """
        Record a release (close) in the socket lifecycle. The close is held
        pending until the debounce period elapses (see _sweep_pending_closes
        and uninit), so a quick re-bind can cancel it as a flap.
        """
        now = time.time()
        time_delta = now - self.start_time
        self._sweep_pending_closes(now)

        key = self._socket_key(ipvn, sock_type, ip, port)
        rec = self.sockets.get(key)
        if rec is None or rec["state"] != "open":
            # Release for a socket we never saw bound, or already closed/pending.
            return
        rec["pending_close"] = now
        rec["pending_close_delta"] = time_delta

    def give_list(self):
        """
        Return the list of currently-active binds (open, or closed-but-pending
        within the debounce window).

        Returns:
            list: A list of dictionaries, each representing an active bind.
        """
        active = []
        for rec in self.sockets.values():
            if rec["state"] == "open":
                active.append({
                    "Process Name": rec["procname"],
                    "IPvN": rec["ipvn"],
                    "Socket Type": rec["sock_type"],
                    "IP": rec["ip"],
                    "Port": rec["port"],
                    "PID": rec["pid"],
                    "Time": rec["first_open"],
                    "State": "transient" if rec["transient"] else "open",
                    "Flaps": rec["flap_count"],
                })
        return active

    def report_bind_info(self, time_delta, procname, ipvn, sock_type, ip, port, pid) -> None:
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
            f.write(f"{procname},{ipvn},{sock_type},{ip},{port},{pid},{time_delta:.3f}\n")

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

    def uninit(self) -> None:
        """
        Finalize the socket lifecycle on unload and write the lifecycle summary.

        Any pending closes are finalized at their real (pending) close time, and
        any sockets still open at shutdown have their uptime closed out at the
        end of the run.
        """
        now = time.time()
        final_delta = now - self.start_time

        for rec in self.sockets.values():
            if rec["pending_close"] is not None:
                # A close that never got a re-bind: it was real.
                self._finalize_close(rec)
            elif rec["state"] == "open" and rec["last_open"] is not None:
                # Still up at shutdown: count uptime through end of run.
                rec["total_uptime"] += max(0.0, final_delta - rec["last_open"])

        with open(join(self.outdir, LIFECYCLE_FILE), "w") as f:
            f.write(
                "procname,ipvn,domain,guest_ip,guest_port,pid,state,transient,"
                "open_count,close_count,flap_count,first_open,last_close,total_uptime\n"
            )
            for rec in self.sockets.values():
                last_close = "" if rec["last_close"] is None else f"{rec['last_close']:.3f}"
                f.write(
                    f"{rec['procname']},{rec['ipvn']},{rec['sock_type']},{rec['ip']},"
                    f"{rec['port']},{rec['pid']},{rec['state']},{rec['transient']},"
                    f"{rec['open_count']},{rec['close_count']},{rec['flap_count']},"
                    f"{rec['first_open']:.3f},{last_close},{rec['total_uptime']:.3f}\n"
                )
