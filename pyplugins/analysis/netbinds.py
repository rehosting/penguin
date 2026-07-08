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

Each socket (keyed by IP version, socket type, address, and port) moves through
a small state machine:

- ``pending`` -- bound, but not yet announced. A new bind is held for
  ``announce_debounce_s`` seconds before 'on_bind' is published, so
  short-lived binds never reach downstream actuation (VPN bridging, nmap,
  fetchweb, ...). A socket still pending when the run ends keeps this state
  in the final CSVs: it was bound at shutdown but never confirmed as a
  listener, so consumers should not count it as a working service.
- ``listening`` -- bound and announced: the bind survived the announce window.
- ``transient`` -- bound and released *within* the announce window. Transient
  binds are never announced; they appear in ``netbinds.csv`` (state
  ``transient``) so analyses can see them without treating them as working
  services.
- ``closed`` -- was listening, later released for good.

Both debounce windows are measured in **host wall-clock time** (like every
other timestamp this plugin records): guest/emulation time is not exposed to
pyplugins, so the transient-vs-listening classification of a short-lived bind
depends on emulation speed and is not exactly reproducible across hosts. The
in-guest test fixtures set ``announce_debounce_s: 0`` for this reason; the
debounce machinery itself is covered by host-side unit tests.

Announced services frequently flap: a process may close and re-bind the same
address in rapid succession (e.g. supervisord restarting a daemon, or a server
that briefly rebinds during startup). To avoid treating every flap as a genuine
close, NetBinds also applies a *close debounce*:

- When a listening socket is released, the close is held as *pending* rather
  than being finalized immediately.
- If the same socket is re-bound within ``debounce_period`` seconds, the close
  is cancelled and the event is recorded as a *flap* (the service is considered
  to have stayed up continuously).
- A pending close older than ``debounce_period`` is *finalized* into a real
  close. Finalization happens opportunistically when later events arrive, and
  unconditionally when the plugin unloads.

A socket that flaps ``transient_threshold`` or more times during the run is
also flagged transient in the lifecycle summary, marking it as an unstable
service worth attention.

Known limitation: the guest kernel only reports TCP releases for sockets in
the LISTEN state (accepted connections share the listener's local port, so
their teardown must not be reported). A TCP socket that binds but closes
without ever listening therefore never emits a release and remains
``listening``/``pending`` until the end of the run.

Snapshot / restore
------------------

A restored VM is already past its binds, so it never re-issues the bind
hypercalls this plugin watches. NetBinds therefore participates in the
snapshot host-state protocol (``save_state`` / ``load_state`` / ``on_restore``):
the socket lifecycle is bundled with the snapshot and rebuilt on restore, so
``netbinds.csv``, the lifecycle summary, and ``give_list`` stay accurate across
a (possibly cross-process) restore. Already-announced services are rebuilt
silently -- downstream consumers such as the VPN bridge replay their own saved
state, so re-announcing would double-actuate -- while a service still within
its announce window at snapshot time is a ground-truth listener in the restored
guest and is announced on restore.

Features
--------

- Subscribes to low-level bind/setup/release events for IPv4 and IPv6 sockets.
- Tracks and deduplicates first-seen binds (process name, IP version, socket
  type, IP, port), as before.
- Logs announced binds and summary statistics to CSV files in the output
  directory (``netbinds.csv``, ``netbinds_summary.csv``). ``netbinds.csv``
  carries ``state`` and ``closed_time`` columns and is rewritten on unload with
  each socket's final state (including never-announced transient binds).
- Logs every open/flap/transient/close transition to ``netbind_events.csv`` and
  writes a per-socket lifecycle summary to ``netbinds_lifecycle.csv`` on unload.
- Publishes 'on_bind' events for other plugins (such as VPN, Nmap, FetchWeb)
  after the announce debounce.
- Optionally shuts down emulation when a web service (port 80) is announced.

Arguments
---------

- shutdown_on_www (bool, optional): If True, shut down emulation when a bind
  on port 80 is announced (i.e. survives the announce debounce).
- announce_debounce_s (float, optional): Seconds a new bind is held before
  being announced via 'on_bind'. A release within this window marks the bind
  transient and suppresses the announcement. <= 0 announces immediately.
  Default: 2.0.
- debounce_period (float, optional): Seconds a close is held pending before
  being treated as a real close. A re-bind within this window is a flap.
  Default: 2.0.
- transient_threshold (int, optional): Number of flaps at which a socket is
  labelled transient. Default: 3.

Plugin Interface
----------------

- Publishes 'on_bind' events with (sock_type, ipvn, ip, port, procname) for
  other plugins to consume. (Semantics unchanged apart from the announce
  debounce: fired once per first-seen unique bind that survives the window.)
- Listens to low-level system bind/setup/release events.
- Writes bind logs, a lifecycle event log, and summaries to the output dir.

Overall Purpose
---------------

The NetBinds plugin provides a comprehensive record of the network services
started -- and stopped -- by the guest, enabling automation, analysis, and
integration with other actuation plugins.
"""

import os
import socket
import struct
import threading
import time
from os.path import join

from pydantic import Field
from penguin import plugins, Plugin, PluginArgs

BINDS_FILE = "netbinds.csv"
SUMMARY_BINDS_FILE = "netbinds_summary.csv"
EVENTS_FILE = "netbind_events.csv"
LIFECYCLE_FILE = "netbinds_lifecycle.csv"

BINDS_HEADER = "procname,ipvn,domain,guest_ip,guest_port,pid,time,state,closed_time\n"

DEFAULT_ANNOUNCE_DEBOUNCE_S = 2.0
DEFAULT_DEBOUNCE_PERIOD = 2.0
DEFAULT_TRANSIENT_THRESHOLD = 3


class NetBinds(Plugin):
    class Args(PluginArgs):
        shutdown_on_www: bool = Field(
            default=False, description="If true, shut down emulation when a bind on port 80 is announced."
        )
        announce_debounce_s: float = Field(
            default=DEFAULT_ANNOUNCE_DEBOUNCE_S,
            description="Seconds a new bind is held before being announced via 'on_bind'. "
            "A release within this window marks the bind transient and suppresses the "
            "announcement (so e.g. the VPN never bridges it). <= 0 announces immediately.",
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

        announce = self.get_arg("announce_debounce_s")
        self.announce_debounce_s = float(announce) if announce is not None else DEFAULT_ANNOUNCE_DEBOUNCE_S
        debounce = self.get_arg("debounce_period")
        self.debounce_period = float(debounce) if debounce is not None else DEFAULT_DEBOUNCE_PERIOD
        threshold = self.get_arg("transient_threshold")
        self.transient_threshold = int(threshold) if threshold is not None else DEFAULT_TRANSIENT_THRESHOLD

        # Per-socket lifecycle state, keyed by (ipvn, sock_type, normalized_ip, port).
        # This is the source of truth for currently-active binds (see give_list).
        self.sockets = {}
        # Rows appended to netbinds.csv during the run (announced binds), kept
        # so the file can be rewritten with final states on unload.
        self.bind_rows = []
        # Guards sockets/seen_binds/bind_rows and the CSV files: bind/release
        # events arrive on the hypercall path while announce timers fire on
        # timer threads.
        self._lock = threading.Lock()
        # Lifecycle state stashed by load_state() on a snapshot restore, applied
        # in on_restore() once every plugin has loaded. None when not restoring.
        self._restore_data = None

        # The NetBinds.on_bind PPP callback happens once per first-seen bind
        # that survives the announce debounce.
        # Don't be confused by the vpn on_bind callback that happens
        # after the VPN bridges a connection. This one has the better name
        # but that one is more of a pain to change.

        plugins.register(self, "on_bind")

        with open(join(self.outdir, BINDS_FILE), "w") as f:
            f.write(BINDS_HEADER)

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
            self.logger.error(f"Pending bind not cleared before new bind for ipv4: {self.pending_procname} vs {procname}")
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
        Handle a completed bind event: decode it and feed the socket lifecycle.
        Announcement (CSV row, 'on_bind' publication, shutdown_on_www) happens
        after the announce debounce -- see record_open.

        Args:
            cpu: The CPU core where the event occurred.
            procname: The name of the process that performed the bind.
            is_ipv4: Boolean indicating if this is an IPv4 bind.
            is_stream: Boolean indicating if this is a stream (TCP) bind.
            port_pid: "port:pid" string, port in network byte order.
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

        self.record_open(now, time_delta, procname, ipvn, sock_type, ip, port, pid)

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

    def _schedule_announce(self, key, rec, now, time_delta):
        """Hold the socket in 'pending' for the announce window. A release that
        arrives first cancels the announcement (transient bind); otherwise the
        socket is promoted to 'listening' and announced.

        Promotion happens on whichever comes first: the announce sweep run on
        the hypercall path by later bind/release events, or this backup timer.
        The timer alone is not enough -- under heavy instrumentation the vCPU
        thread spends nearly all its time in Python callbacks and background
        threads can be GIL-starved for many seconds -- while the sweep alone
        would never announce a quiet guest's only service. Together they
        cover both cases.

        Returns the announcement payload when announcing inline
        (announce_debounce_s <= 0), else None."""
        if self.announce_debounce_s <= 0:
            return self._promote_to_listening(rec, time_delta)
        rec["pending_since"] = now
        timer = threading.Timer(self.announce_debounce_s, self._announce_cb, args=(key,))
        timer.daemon = True
        rec["announce_timer"] = timer
        timer.start()
        return None

    def _sweep_pending_announces(self, now):
        """Promote any pending sockets whose announce window has elapsed.
        Runs on the hypercall path (see _schedule_announce). Caller holds
        _lock. Returns the announcement payloads to publish."""
        time_delta = now - self.start_time
        announcements = []
        for rec in list(self.sockets.values()):
            if rec["state"] != "pending" or rec["pending_since"] is None:
                continue
            if (now - rec["pending_since"]) >= self.announce_debounce_s:
                if rec["announce_timer"] is not None:
                    rec["announce_timer"].cancel()
                    rec["announce_timer"] = None
                announcement = self._promote_to_listening(rec, time_delta)
                if announcement is not None:
                    announcements.append(announcement)
        return announcements

    def _announce_cb(self, key) -> None:
        """Timer callback: the bind survived the announce window."""
        now = time.time()
        time_delta = now - self.start_time
        with self._lock:
            rec = self.sockets.get(key)
            if rec is None or rec["state"] != "pending":
                return
            rec["announce_timer"] = None
            announcement = self._promote_to_listening(rec, time_delta)
        if announcement is not None:
            self._publish_announcements([announcement])

    def _promote_to_listening(self, rec, time_delta):
        """Mark a pending socket listening and record its announcement.
        Caller holds _lock. Returns the announcement payload to publish
        (after releasing _lock -- see _publish_announcements), or None for a
        duplicate."""
        rec["state"] = "listening"
        rec["pending_since"] = None
        return self._record_announcement(rec, time_delta)

    def _record_announcement(self, rec, time_delta):
        """Record an announced bind: netbinds.csv row, summary stats, and the
        bind_rows bookkeeping for the final rewrite. Deduplicated per unique
        (procname, ipvn, sock_type, ip, port) as before. Caller holds _lock.
        Returns the 'on_bind' payload to publish, or None for a duplicate."""
        rec["announced"] = True

        # Only report each bind once, if it's identical
        # VPN / stats will just get confused if we report the same bind twice
        ident = (rec["procname"], rec["ipvn"], rec["sock_type"], rec["ip"], rec["port"])
        if ident in self.seen_binds:
            return None
        self.seen_binds.add(ident)

        # Log details to disk
        self.report_bind_info(time_delta, rec["procname"], rec["ipvn"],
                              rec["sock_type"], rec["ip"], rec["port"], rec["pid"])
        self.bind_rows.append({
            "procname": rec["procname"], "ipvn": rec["ipvn"], "sock_type": rec["sock_type"],
            "ip": rec["ip"], "port": rec["port"], "pid": rec["pid"], "time": time_delta,
            "key": self._socket_key(rec["ipvn"], rec["sock_type"], rec["ip"], rec["port"]),
        })
        return (rec["sock_type"], rec["ipvn"], rec["ip"], rec["port"], rec["procname"])

    def _publish_announcements(self, announcements) -> None:
        """Publish 'on_bind' for recorded announcements and handle
        shutdown_on_www. Must be called WITHOUT _lock held: subscribers run
        arbitrary code (VPN bridging, probes) and must be able to call back
        into this plugin (e.g. give_list) without deadlocking."""
        for sock_type, ipvn, ip, port, procname in announcements:
            plugins.publish(self, "on_bind", sock_type, ipvn, ip, port, procname)

            # If an announced bind is on 80 and we have the shutdown_www
            # option, end the emulation. Announce-debounced on purpose: a
            # transient www bind should not end the run before the real
            # service comes up.
            if port == 80 and self.shutdown_on_www:
                self.logger.info("Shutting down emulation due to bind on port 80")
                self.panda.end_analysis()

    def record_open(self, now, time_delta, procname, ipvn, sock_type, ip, port, pid) -> None:
        """
        Record a bind (open) in the socket lifecycle. New sockets are held in
        'pending' for the announce debounce; re-binds shortly after a close are
        treated as flaps rather than new services.
        """
        with self._lock:
            announcements = self._record_open_locked(
                now, time_delta, procname, ipvn, sock_type, ip, port, pid)
        self._publish_announcements(announcements)

    def _record_open_locked(self, now, time_delta, procname, ipvn, sock_type, ip, port, pid):
        """State-machine half of record_open; caller holds _lock. Returns the
        announcement payloads to publish once the lock is released."""
        self._sweep_pending_closes(now)
        announcements = self._sweep_pending_announces(now)
        key = self._socket_key(ipvn, sock_type, ip, port)
        rec = self.sockets.get(key)

        if rec is None:
            rec = {
                "procname": procname,
                "pid": pid,
                "ipvn": ipvn,
                "sock_type": sock_type,
                "ip": ip,
                "port": port,
                "state": "pending",
                "announced": False,
                "announce_timer": None,
                "pending_since": None,
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
            self.sockets[key] = rec
            self._log_event("open", rec, time_delta)
            announcement = self._schedule_announce(key, rec, now, time_delta)
            if announcement is not None:
                announcements.append(announcement)
            return announcements

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
            rec["state"] = "listening"
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
        elif rec["state"] in ("closed", "transient"):
            # Genuine re-open after a finalized close or a transient bind
            # (outside any debounce window) -- a spaced restart.
            rec["open_count"] += 1
            rec["last_open"] = time_delta
            self._log_event("open", rec, time_delta)
            if rec["announced"]:
                # Already survived the announce window once; no need to
                # debounce the restart. (A new procname on an announced
                # socket still publishes, via the seen_binds dedup.)
                rec["state"] = "listening"
                announcement = self._record_announcement(rec, time_delta)
                if announcement is not None:
                    announcements.append(announcement)
            else:
                rec["state"] = "pending"
                announcement = self._schedule_announce(key, rec, now, time_delta)
                if announcement is not None:
                    announcements.append(announcement)
        # else: pending or listening and not pending close -> duplicate
        # bind, no change.
        return announcements

    def record_close(self, ipvn, sock_type, ip, port) -> None:
        """
        Record a release (close) in the socket lifecycle. A release within the
        announce window marks the bind transient (never announced); a release
        of a listening socket is held pending until the close debounce elapses
        (see _sweep_pending_closes and uninit), so a quick re-bind can cancel
        it as a flap.
        """
        now = time.time()
        time_delta = now - self.start_time
        with self._lock:
            self._sweep_pending_closes(now)
            announcements = self._sweep_pending_announces(now)

            key = self._socket_key(ipvn, sock_type, ip, port)
            rec = self.sockets.get(key)
            if rec is None or rec["state"] in ("closed", "transient"):
                # Release for a socket we never saw bound, or already closed.
                pass
            elif rec["state"] == "pending":
                # Released before the announce window elapsed: a transient
                # bind. Cancel the announcement -- downstream plugins (VPN,
                # nmap, ...) never hear about it.
                if rec["announce_timer"] is not None:
                    rec["announce_timer"].cancel()
                    rec["announce_timer"] = None
                rec["pending_since"] = None
                rec["state"] = "transient"
                rec["transient"] = True
                rec["close_count"] += 1
                rec["last_close"] = time_delta
                if rec["last_open"] is not None:
                    rec["total_uptime"] += max(0.0, time_delta - rec["last_open"])
                self._log_event("transient", rec, time_delta)
            else:
                # Listening: hold the close pending for the debounce window.
                rec["pending_close"] = now
                rec["pending_close_delta"] = time_delta
        self._publish_announcements(announcements)

    def give_list(self):
        """
        Return the list of currently-active binds: listening, pending
        announcement, or closed-but-pending within the close debounce window.

        Returns:
            list: A list of dictionaries, each representing an active bind.
        """
        with self._lock:
            active = []
            for rec in self.sockets.values():
                if rec["state"] in ("pending", "listening"):
                    active.append({
                        "Process Name": rec["procname"],
                        "IPvN": rec["ipvn"],
                        "Socket Type": rec["sock_type"],
                        "IP": rec["ip"],
                        "Port": rec["port"],
                        "PID": rec["pid"],
                        "Time": rec["first_open"],
                        "State": "transient" if rec["transient"] else rec["state"],
                        "Flaps": rec["flap_count"],
                    })
            return active

    def save_state(self):
        """Capture the socket lifecycle so a cross-process snapshot restore can
        reproduce netbinds.csv, the lifecycle summary, and give_list().

        A VM snapshot restores the *guest*, which is then already past its
        binds, so it never re-issues the bind hypercalls NetBinds reacts to.
        Without this, a restored run would start blank and every pre-snapshot
        service would vanish from the record. Non-serialisable / host-clock
        fields (the announce timer thread and the absolute pending_since /
        pending_close instants) are dropped -- they cannot survive a
        cross-process, possibly cross-host restore; see on_restore.
        """
        with self._lock:
            if not self.sockets:
                return None
            drop = ("announce_timer", "pending_since",
                    "pending_close", "pending_close_delta")
            sockets = [
                {k: v for k, v in rec.items() if k not in drop}
                for rec in self.sockets.values()
            ]
            return {
                "sockets": sockets,
                "seen_binds": [list(b) for b in self.seen_binds],
                "bind_rows": [{**r, "key": list(r["key"])} for r in self.bind_rows],
            }

    def load_state(self, data) -> None:
        """Stash lifecycle state captured at snapshot time. Applied in
        on_restore(), which runs after every plugin has loaded."""
        self._restore_data = data or None

    def on_restore(self, tag: str) -> None:
        """Rehydrate the socket lifecycle after a snapshot restore.

        Already-announced sockets (listening/closed) are restored *silently*:
        downstream consumers such as the VPN bridge replay their own saved
        state on restore, so re-publishing 'on_bind' for them would
        double-actuate. Sockets still 'pending' (bound but never announced)
        at snapshot time are ground-truth listeners in the restored guest that
        no downstream plugin saved, so they are promoted to 'listening' and
        announced now.
        """
        data = self._restore_data
        self._restore_data = None
        if not data:
            return
        time_delta = time.time() - self.start_time
        with self._lock:
            announcements = self._rehydrate_locked(data, time_delta)
        self._publish_announcements(announcements)

    def _rehydrate_locked(self, data, time_delta):
        """Rebuild sockets/seen_binds/bind_rows from saved state and rewrite
        netbinds.csv. Caller holds _lock. Returns announcements to publish for
        pending sockets promoted to listening on restore."""
        self.seen_binds = {tuple(b) for b in data.get("seen_binds", [])}
        self.bind_rows = [{**r, "key": tuple(r["key"])} for r in data.get("bind_rows", [])]
        self.sockets = {}
        announcements = []
        for saved in data.get("sockets", []):
            rec = dict(saved)
            rec["announce_timer"] = None
            rec["pending_since"] = None
            rec["pending_close"] = None
            rec["pending_close_delta"] = None
            key = self._socket_key(rec["ipvn"], rec["sock_type"], rec["ip"], rec["port"])
            self.sockets[key] = rec
            if rec["state"] == "pending" and not rec.get("announced"):
                announcement = self._promote_to_listening(rec, time_delta)
                if announcement is not None:
                    announcements.append(announcement)
        self._rewrite_binds_file()
        return announcements

    def report_bind_info(self, time_delta, procname, ipvn, sock_type, ip, port, pid) -> None:
        """
        Log bind details and summary statistics to disk. Called at announce
        time, so the row is written with state 'listening'; final states are
        filled in when the file is rewritten on unload.

        Args:
            time_delta: The time since emulation start when the bind was announced.
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
            f.write(f"{procname},{ipvn},{sock_type},{ip},{port},{pid},{time_delta:.3f},listening,\n")

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

    def _rewrite_binds_file(self) -> None:
        """Rewrite netbinds.csv with final lifecycle states.

        Rows appended during the run always carry state 'listening' (only
        announced binds get rows); on unload the file is rewritten so each row
        shows its final state and closed_time, plus one row per socket that
        was never announced (transient binds, and still-pending binds younger
        than the announce window at shutdown). Written to a temp file and
        renamed so a crash mid-rewrite cannot destroy the data accumulated
        during the run.
        """
        tmp_path = join(self.outdir, BINDS_FILE + ".tmp")
        with open(tmp_path, "w") as f:
            f.write(BINDS_HEADER)
            for row in self.bind_rows:
                rec = self.sockets.get(row["key"])
                state = rec["state"] if rec is not None else "listening"
                closed_time = ""
                if rec is not None and state == "closed" and rec["last_close"] is not None:
                    closed_time = f"{rec['last_close']:.3f}"
                f.write(
                    f"{row['procname']},{row['ipvn']},{row['sock_type']},{row['ip']},"
                    f"{row['port']},{row['pid']},{row['time']:.3f},{state},{closed_time}\n"
                )
            for rec in self.sockets.values():
                if rec["announced"]:
                    continue
                closed_time = "" if rec["last_close"] is None else f"{rec['last_close']:.3f}"
                f.write(
                    f"{rec['procname']},{rec['ipvn']},{rec['sock_type']},{rec['ip']},"
                    f"{rec['port']},{rec['pid']},{rec['first_open']:.3f},{rec['state']},{closed_time}\n"
                )
        os.replace(tmp_path, join(self.outdir, BINDS_FILE))

    def uninit(self) -> None:
        """
        Finalize the socket lifecycle on unload and write the lifecycle summary.

        Announce timers are cancelled; sockets still pending announcement keep
        the 'pending' state in the final CSVs -- they were bound when the run
        ended but never confirmed as listeners (and never published).
        Any pending closes are finalized at their real (pending) close time,
        and any sockets still open at shutdown have their uptime closed out at
        the end of the run.
        """
        now = time.time()
        final_delta = now - self.start_time

        with self._lock:
            for rec in self.sockets.values():
                if rec["announce_timer"] is not None:
                    rec["announce_timer"].cancel()
                    rec["announce_timer"] = None
                if rec["pending_close"] is not None:
                    # A close that never got a re-bind: it was real.
                    self._finalize_close(rec)
                elif rec["state"] == "pending":
                    # Still bound at shutdown but younger than the announce
                    # window: never confirmed as a listener. Keep the honest
                    # 'pending' state rather than promoting -- promoting would
                    # also affirmatively mislabel a socket whose release was
                    # missed (TCP bind-without-listen; see module docstring).
                    # A pid-exit fallback was considered and rejected:
                    # daemonizing services bind in a parent that exits while a
                    # child keeps the socket, so pid-exit would mark real
                    # listeners closed.
                    rec["pending_since"] = None
                    if rec["last_open"] is not None:
                        rec["total_uptime"] += max(0.0, final_delta - rec["last_open"])
                elif rec["state"] == "listening" and rec["last_open"] is not None:
                    # Still up at shutdown: count uptime through end of run.
                    rec["total_uptime"] += max(0.0, final_delta - rec["last_open"])

            self._rewrite_binds_file()

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
