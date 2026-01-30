"""
VPN Plugin (vpn.py) for Penguin
===============================

This module provides the VPN plugin, which enables vsock-based VPN bridging between the emulated guest
and the host. It manages port mappings, source IP spoofing, and dynamic forwarding of guest network
services to the host.

Features
--------

- Launches and manages host-side VPN and vsock bridge processes.
- Handles port mappings from guest to host, including privileged ports and user-defined mappings.
- Supports source IP spoofing for guest services.
- Dynamically bridges guest network binds to the host and exposes them.
- Logs and tracks active network bridges and listeners.
- Cleans up VPN processes on exit.

Arguments
---------

- log (bool, optional): Enable logging of VPN traffic.
- pcap (bool, optional): Enable PCAP capture of VPN traffic.
- verbose (bool, optional): Enable verbose logging.
- IGLOO_VPN_PORT_MAPS (str, optional): Comma-separated port mapping rules.
    This variable allows explicit mapping of guest services to host ports. The format is:
        <proto>:<host_port>:<guest_ip>:<guest_port>
    For example:
        IGLOO_VPN_PORT_MAPS="TCP:80:192.168.0.1:80,udp:20002:192.168.0.1:20002"
    This maps TCP port 80 on the host to TCP port 80 on the guest at 192.168.0.1, and UDP port 20002 on the host to UDP port 20002 on the guest at 192.168.0.1.
    If not provided as an argument, the plugin will look for it in the environment variables. If neither is set, default port mapping logic is used.
- spoof (dict, optional): Source IP spoofing configuration.
- conf (dict): Configuration dictionary for the emulation environment.

Plugin Interface
----------------

- Registers for the "on_bind" event to dynamically bridge guest network binds.
- Publishes "on_bind" events for other plugins to react to new host-exposed services.
- Writes bridge information to a CSV file in the output directory.

Overall Purpose
---------------

The VPN plugin enables flexible, dynamic, and secure exposure of guest network services to the host,
supporting advanced features like port mapping and source IP spoofing, and integrates with the
Penguin plugin system for event-driven networking.
"""

import atexit
import re
import socket
import subprocess
import tempfile
import jc
import threading
from contextlib import closing
from os import environ as env
from os import geteuid
from os.path import join

from penguin import Plugin, plugins
from penguin.defaults import static_dir

running_vpns = []


def kill_vpn() -> None:
    """
    Kill all running VPN processes registered in running_vpns.
    """
    for p in running_vpns:
        p.kill()
        p.wait()


def guest_cmd(cmd: str) -> subprocess.CompletedProcess:
    """
    Run a command in the guest using guesthopper.

    Args:
        cmd (str): Command to run in the guest.
    Returns:
        subprocess.CompletedProcess: Result of the command execution.
    """
    result = subprocess.run(["python3", "/igloo_static/guesthopper/guest_cmd.py", cmd],
                            capture_output=True)
    return result


atexit.register(kill_vpn)

BRIDGE_FILE = "vpn_bridges.csv"

# Port maps built from an optional environment variable
# e.g., IGLOO_VPN_PORT_MAPS="TCP:80:192.168.0.1:80,udp:20002:192.168.0.1:20002"


class VPN(Plugin):
    def __init__(self, panda) -> None:
        """
        Initialize the VPN plugin, set up vsock bridge, VPN process, and port mappings.

        Args:
            panda: The Panda emulation object.
        Raises:
            ValueError: If PANDA is not running with vsock support or port map parsing fails.
        """
        if "vhost-vsock" not in str(panda.panda_args) and "vhost-user-vsock" not in str(
            panda.panda_args
        ):
            raise ValueError("VsockVPN error: PANDA running without vsock")

        plugins.register(self, "on_bind")

        self.outdir = self.get_arg("outdir")

        if self.get_arg_bool("verbose"):
            self.logger.setLevel("DEBUG")

        # TODO: add option on whether or not to pass -o to host vpn
        self.launch_host_vpn(self.get_arg("CID"),
                             self.get_arg("socket_path"),
                             self.get_arg("uds_path"),
                             self.get_arg_bool("log"),
                             self.get_arg_bool("pcap"))

        port_maps = self.get_arg("IGLOO_VPN_PORT_MAPS")
        self.seen_ips = set()  # IPs we've seen
        self.wild_ips = set()  # (sock_type, port, procname) tuples
        self.mapped_ports = set()  # Ports we've mapped
        self.active_listeners = set()  # (proto, port)

        # Check if we have CONTAINER_{IP,NAME} in env
        self.exposed_ip = env.get("CONTAINER_IP", "127.0.0.1")
        with open(f"{self.outdir}/ipaddr.txt", "w") as f:
            f.write(self.exposed_ip + "\n")
        self.container_name = env.get("CONTAINER_NAME", None)

        self.has_perms = geteuid() == 0
        if not self.has_perms:
            self.has_perms = self._can_bind_privileged()

        """
        Fixed maps:
            Map[(sock_type, guest_ip, guest_port)] = host_port
        """
        self.fixed_maps = {}

        # We prioritize the value in our config value over the environment
        # variable
        if not port_maps and "IGLOO_VPN_PORT_MAPS" in env:
            port_maps = env["IGLOO_VPN_PORT_MAPS"]

        if port_maps:
            # port mappings as a comma-separated list tcp:80:192.168.0.1:80
            for arg in port_maps.split(","):
                if m := re.search(r"(tcp|udp):(\d+):(.*):(\d+)", arg, re.IGNORECASE):
                    sock_type = m[1].lower()
                    host_port = int(m[2])
                    guest_ip = m[3]
                    guest_port = int(m[4])
                    self.seen_ips.add(guest_ip)
                    self.fixed_maps[(sock_type, guest_ip, guest_port)] = host_port
                else:
                    raise ValueError(f"Couldn't parse port map: {arg}")
            self.logger.info(f"VPN loaded fixed port assingments: {self.fixed_maps}")

        """
        Source IP spoofing. E.g.,
            spoof:
              "tcp:192.168.1.1:5678":
                source: 10.10.10.1
                dev: eth1
              "udp:192.168.1.1:12345":
                source: 10.10.10.1
                dev: eth1
        """
        self.spoof = self.get_arg("spoof")
        if self.spoof and not self.get_arg("conf")["core"]["guest_cmd"]:
            self.logger.error("guest_cmd is disabled!")
            raise ValueError("Source address spoofing requires guest_cmd to be enabled")
        self.lock = threading.Lock()

        with open(join(self.outdir, BRIDGE_FILE), "w") as f:
            f.write("procname,ipvn,domain,guest_ip,guest_port,host_port\n")

        # Whenever NetBinds detects a bind, we'll set up bridges
        plugins.subscribe(plugins.NetBinds, "on_bind", self.on_bind)

    def launch_host_vpn(self, CID: int, socket_path: str, uds_path: str, log: bool = False, pcap: bool = False) -> None:
        '''
        Launch vhost-device-vsock and VPN on host.

        Args:
            CID (int): Context ID for vsock.
            socket_path (str): Path to the vsock socket.
            uds_path (str): Path to the Unix domain socket for QEMU.
            log (bool, optional): Enable logging of VPN traffic.
            pcap (bool, optional): Enable PCAP capture of VPN traffic.
        '''
        # Launch a process that listens on the file socket and forwards to the uds
        # which QEMU connects to.
        self.host_vsock_bridge = subprocess.Popen(
            [
                "vhost-device-vsock",
                "--guest-cid",
                str(CID),
                "--socket",
                socket_path,
                "--uds-path",
                uds_path,
            ]
        )

        # Launch VPN on host as panda starts. Init in the guest will launch the VPN in the guest
        self.event_file = tempfile.NamedTemporaryFile(prefix=f"/tmp/vpn_events_{CID}_")
        host_vpn_cmd = [
            join(static_dir, "vpn/vpn.x86_64"),
            "host",
            "-e",
            self.event_file.name,
            "-c",
            str(CID),
            "-u",
            uds_path,
        ]
        if log:
            host_vpn_cmd.extend(["-o", self.outdir])
        if pcap:
            pcap_path = join(self.outdir, "vpn.pcap")
            self.logger.info(f"VPN logging traffic to {pcap_path}")
            host_vpn_cmd.extend(["-l", pcap_path])
        self.host_vpn = subprocess.Popen(host_vpn_cmd, stdout=subprocess.DEVNULL, stderr=None)
        running_vpns.append(self.host_vpn)

    def on_bind(self, sock_type: str, ipvn: int, ip: str, port: int, procname: str) -> None:
        """
        Handle a new bind event from the guest, set up bridges and publish events.

        Args:
            sock_type (str): Socket type (e.g., 'tcp', 'udp').
            ipvn (int): IP version (4 or 6).
            ip (str): Guest IP address.
            port (int): Guest port.
            procname (str): Process name binding the port.
        """
        if port == 0:
            # Ephemeral ports - not sure how to handle these
            return

        listener_key = (sock_type, ip, port)
        if listener_key in self.active_listeners:
            # Already forwarding this proto+ip+port
            return

        self.active_listeners.add(listener_key)

        if ipvn == 4:  # Only handling IPv4 wildcards like this for now
            if ip == "0.0.0.0":
                # First run normal callback with 0.0.0.0 IP
                host_port = self.bridge(sock_type, ip, port, procname, ipvn)
                plugins.publish(self, "on_bind", sock_type, ip, port, host_port, self.exposed_ip, procname)

                # Add wild_ips
                self.wild_ips.add((sock_type, port, procname))

                # Bridge for each previously seen ip
                for seen_ip in self.seen_ips:
                    host_port = self.bridge(sock_type, seen_ip, port, procname, ipvn)
                    plugins.publish(self, "on_bind", sock_type, seen_ip, port, host_port, self.exposed_ip, procname)
                return  # Skip the final call to bridge / trigger ppp callback

            elif ip not in self.seen_ips:
                # Find all wild_ips, log this IP
                self.seen_ips.add(ip)

                # For any previously-wild_ip service, bridge it with this new IP
                for sock_type, seen_port, seen_procname in self.wild_ips:
                    host_port = self.bridge(
                        sock_type, ip, seen_port, seen_procname, ipvn
                    )  # If unsupported or guest-host ports actually match, we skip this
                    plugins.publish(self, "on_bind", sock_type, ip, seen_port, host_port, self.exposed_ip, procname)

        host_port = self.bridge(sock_type, ip, port, procname, ipvn)
        plugins.publish(self, "on_bind", sock_type, ip, port, host_port, self.exposed_ip, procname)

    def map_bound_socket(self, sock_type: str, ip: str, guest_port: int, procname: str) -> int:
        """
        Map a guest socket to a host port, handling privileged ports and collisions.

        Args:
            sock_type (str): Socket type.
            ip (str): Guest IP address.
            guest_port (int): Guest port.
            procname (str): Process name.
        Returns:
            int: Host port mapped to the guest socket.
        """
        host_port = guest_port
        # procname, listening, port, reason
        reason = ""
        if mapped_host_port := self.fixed_maps.get((sock_type, ip, guest_port), None):
            host_port = mapped_host_port
            if not self._is_port_available(host_port):
                raise RuntimeError(
                    f"User requested to map host port {host_port} but it is not free"
                )
            reason = "via fixed mapping"
        elif guest_port < 1024 and not self.has_perms:
            host_port = self._find_free_port(guest_port)
            reason = f"{guest_port} is privileged and user cannot bind"
        elif not self._is_port_available(guest_port):
            host_port = self._find_free_port(guest_port)
            reason = f"{guest_port} is already in use"

        if self.exposed_ip:
            connect_to = f"{self.exposed_ip}:{host_port}"
        elif self.container_name:
            connect_to = f"container {self.container_name}:{host_port}"
        else:
            connect_to = f"container on port {host_port}"

        listen_on = f"{sock_type} {ip}:{guest_port}"

        self.logger.info(
            f"{procname: >16} binds {listen_on: <20} reach it at {connect_to: <20} {reason if reason else ''}"
        )

        return host_port

    def ensure_dev_has_ip(self, ip: str, dev: str, ipvn: int) -> None:
        """
        Ensure the specified device has the given IP address.

        Args:
            ip (str): IP address to assign.
            dev (str): Device name.
            ipvn (int): IP version (4 or 6).
        Raises:
            RuntimeError: If unable to query or assign the IP address.
        """
        # No `ip addr` parser in jc, and ifconfig only shows multiple addresses when you assign an alias
        cmd = "/igloo/utils/busybox ip route show"
        result = guest_cmd(cmd)
        parsed = jc.parse("ip-route", result.stdout.decode("latin-1"))
        self.logger.debug(f"{cmd} exited with status {result.returncode}: {result.stderr}")
        if result.returncode != 0:
            self.logger.error(f"{cmd} exited with status {result.returncode}: {parsed}")
            raise RuntimeError(f"Failed to query ip addresses with {cmd}")
        for row in parsed:
            if row["dev"] == dev and row["src"] == ip:
                self.logger.debug(f"Device {dev} already has IP {ip}, skipping add")
                return
        self.logger.debug(f"Adding {ip} to {dev}")
        cmd = f"/igloo/utils/busybox ip addr add {ip}/{24 if ipvn == 4 else 64} dev {dev}"
        result = guest_cmd(cmd)
        if result.returncode != 0:
            self.logger.error(f"{cmd} exited with status {result.returncode}: {result.stderr}")
            raise RuntimeError(f"Failed to add IP {ip} to device {dev}!")

    def _do_bridge(self, sock_type: str, ip: str, guest_port: int, procname: str, ipvn: int, host_port: int) -> None:
        """
        Set up the bridge for a guest socket, handle spoofing, and log the bridge.

        Args:
            sock_type (str): Socket type.
            ip (str): Guest IP address.
            guest_port (int): Guest port.
            procname (str): Process name.
            ipvn (int): IP version.
            host_port (int): Host port.
        """
        guest_addr = f"{sock_type}:{ip}:{guest_port}"
        source_ip = ip
        with self.lock:
            if self.spoof and (spoof := self.spoof.get(guest_addr)) is not None:
                # If we have a source IP to spoof, make sure we have a device to spoof it on
                source_ip = spoof["source"]
                self.logger.debug(f"Will spoof source address for {guest_addr} with {source_ip}")
                self.ensure_dev_has_ip(source_ip, spoof["dev"], ipvn)

            with open(self.event_file.name, "a") as f:
                f.write(f"{sock_type},{ip}:{guest_port},0.0.0.0:{host_port},{source_ip}:0\n")

            with open(join(self.outdir, BRIDGE_FILE), "a") as f:
                f.write(f"{procname},ipv{ipvn},{sock_type},{ip},{guest_port},{host_port}\n")

    def bridge(self, sock_type: str, ip: str, guest_port: int, procname: str, ipvn: int) -> int:
        """
        Bridge a guest socket to the host, set up event and return host port.

        Args:
            sock_type (str): Socket type.
            ip (str): Guest IP address.
            guest_port (int): Guest port.
            procname (str): Process name.
            ipvn (int): IP version.
        Returns:
            int: Host port mapped to the guest socket.
        """
        host_port = self.map_bound_socket(sock_type, ip, guest_port, procname)
        self.mapped_ports.add(host_port)

        # Set up the event for the host vpn in the background - lets us run commands in the guest if we'd like
        threading.Thread(
            target=self._do_bridge, args=(sock_type, ip, guest_port, procname, ipvn, host_port)
        ).start()

        return host_port

    def _find_free_port(self, requested_port: int) -> int:
        '''
        Find a free port on the host, preferring deterministic offsets.

        Logic:
        1. Check strides of 1000 (port, port+1000, port+2000...)
        2. If failed, increment offset by 1 and check strides again (port+1, port+1001...)
        3. Enforce privileged port permissions.
        4. Fallback to random OS-assigned port.

        Args:
            requested_port (int): Guest port to map from.
        Returns:
            int: Free host port.
        '''
        MAX_PORT = 65535
        STRIDE = 1000
        # How many small increments to try? (e.g., try base ports x to x+65)
        MAX_OFFSET_ATTEMPTS = 66

        if requested_port > MAX_PORT:
            return self._get_random_port()

        # Outer loop: The "shift" (0, 1, 2...)
        for small_offset in range(MAX_OFFSET_ATTEMPTS):
            # Inner loop: The "stride" (0, 1000, 2000...)
            # We calculate how many 1000s fit into the remaining port space
            base_port = requested_port + small_offset

            if base_port > MAX_PORT:
                break

            current_port = base_port
            while current_port <= MAX_PORT:
                # Check 1: Privileged Port Guard
                # If port is < 1024 and we lack perms, skip it immediately.
                if current_port < 1024 and not self.has_perms:
                    current_port += STRIDE
                    continue

                # Check 2: Availability
                # We use a helper to try and bind.
                # Check if the port is available for binding.
                # This ensures the port is free and not currently in use.
                if self._is_port_available(current_port):
                    return current_port

                current_port += STRIDE

        # Fallback: Ask OS for a random ephemeral port
        return self._get_random_port()

    @staticmethod
    def _can_bind_privileged() -> bool:
        """
        Check if the process can bind to a privileged port.
        Tries multiple obscure privileged ports to distinguish between
        permission errors and port collisions.

        Returns:
            bool: True if binding is permitted, False otherwise.
        """
        # Try a few unlikely ports to rule out accidental collisions
        # 43 (WHOIS), 79 (FINGER), 113 (IDENT), 514 (SHELL)
        for port in [43, 79, 113, 514]:
            try:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
                    s.bind(("localhost", port))
                    return True
            except PermissionError:
                return False
            except OSError:
                # Likely EADDRINUSE, try next
                continue
        # If we couldn't bind to ANY of them, we assume we can't
        return False

    def _is_port_available(self, port: int) -> bool:
        """
        Check if a port is available for binding.

        Args:
            port (int): Port to check.
        Returns:
            bool: True if port is available for binding, False otherwise.
        """
        # First check our mapped ports
        if port in self.mapped_ports:
            return False
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind(("localhost", port))
                return True
            except OSError:
                return False

    @staticmethod
    def _get_random_port() -> int:
        """
        Bind to port 0 to let the OS assign an ephemeral port.

        Returns:
            int: The ephemeral port assigned by the OS.
        """
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("localhost", 0))
            return s.getsockname()[1]

    def uninit(self) -> None:
        """
        Cleanup and terminate VPN and vsock bridge processes.
        """
        self.logger.debug("Killing VPN")
        if hasattr(self, "host_vsock_bridge"):
            self.host_vsock_bridge.kill()

        if hasattr(self, "host_vpn"):
            self.host_vpn.terminate()
            self.host_vpn.wait(timeout=2)  # Wait for logged packets to flush
            self.host_vpn.kill()
            running_vpns[:] = [x for x in running_vpns if x != self.host_vpn]
        self.logger.debug("Killed VPN")
