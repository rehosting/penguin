"""
nmap.py - Nmap Plugin for Penguin

This module provides the Nmap plugin, which automatically performs service and vulnerability scans
on guest services exposed to the host via the VPN plugin. It listens for 'on_bind' events published
by the VPN plugin and launches nmap scans against the corresponding host ports. The plugin is responsible for:

- Subscribing to VPN 'on_bind' events to detect new guest services exposed to the host.
- Launching nmap scans (in a separate thread) for each new TCP service, storing results as XML files in the output directory.
- Supporting custom nmap configurations if present.
- Managing and cleaning up subprocesses for running nmap scans.

Arguments:
    - None

Plugin Interface:
    - Subscribes to the VPN plugin's 'on_bind' event to trigger scans.
    - Does not provide a direct interface for other plugins, but writes scan results to files in the output directory.

Overall Purpose:
    The Nmap plugin automates the discovery and analysis of guest services exposed to the host, aiding
    in security assessment and service enumeration during emulation.
"""

import os
import subprocess
import threading
from threading import Lock
from penguin import plugins, Plugin


class Nmap(Plugin):
    def __init__(self) -> None:
        """
        Initialize the Nmap plugin, subscribe to VPN on_bind events, and set up state.
        """
        self.outdir = self.get_arg("outdir")
        plugins.subscribe(plugins.VPN, "on_bind", self.nmap_on_bind)
        self.subprocesses = []
        self.lock = Lock()
        self.custom_nmap = os.path.isfile("/usr/local/etc/nmap/.custom")

    def nmap_on_bind(self, proto: str, guest_ip: str, guest_port: int, host_port: int, host_ip: str, procname: str) -> None:
        """
        Handle a new bind event from the VPN plugin and launch an nmap scan if appropriate.

        Args:
            proto (str): Protocol (e.g., 'tcp').
            guest_ip (str): Guest IP address.
            guest_port (int): Guest port.
            host_port (int): Host port mapped to the guest service.
            host_ip (str): Host IP address.
            procname (str): Name of the process binding the port.
        """

        if proto != "tcp":
            # We can't do UDP scans without root permissions to create raw sockets.
            # Let's just ignore entirely.
            return

        f = self.outdir + f"/nmap_{proto}_{guest_port}_{host_port}.xml"

        # Launch a thread to analyze this request
        t = threading.Thread(target=self.scan_thread, args=(host_ip, guest_port, host_port, f))
        t.daemon = True
        t.start()

    def scan_thread(self, host_ip: str, guest_port: int, host_port: int, log_file_name: str) -> None:
        """
        Run an nmap scan against the specified host port and save results.

        Args:
            host_ip (str): Host IP address.
            guest_port (int): Guest port.
            host_port (int): Host port.
            log_file_name (str): Path to the XML log file for scan results.
        """
        # nmap scan our target in service-aware mode

        if os.path.isfile(log_file_name):
            # Need a unique name - unlikely that host_port would get reused so this might just stack if it ever happens
            log_file_name += ".alt"

        if self.custom_nmap and guest_port != host_port:
            # Special: we want to scan as if we're connecting to guest_port (i.e., guest port 80 -> do webserver scans)
            # but we're actually connecting to host_port
            port_magic = [f"-p{guest_port}", "--redirect-port", str(guest_port), str(host_port)]
        else:
            # Normal, just scan the port. If it's a stock nmap the scan will be lower quality
            port_magic = [f"-p{host_port}"]

        cmd = ["nmap"] + port_magic + [
            "-unprivileged",  # Don't try anything privileged
            "-n",  # Do not do DNS resolution
            "-sT",  # TCP connect scan. XXX required for -sV to work with redirect port
            "-sV",  # Scan for service version
            "--version-intensity", "9",  # Max version intensity
            "--script=default,vuln,version",  # Run NSE scripts to enumerate service
            # "--script-timeout", "5m", # Kill nmap scripts if they take > 5m
            "--scan-delay",
            "0.1s",  # Delay between scans - allow other processes to run - toggle as needed?
            host_ip,  # Local IP address
            "-oX",
            log_file_name,  # XML output format, store in log file
        ]
        process = subprocess.Popen(cmd,
                                   # stdout=subprocess.DEVNULL,
                                   # stderr=subprocess.DEVNULL)
                                   )
        with self.lock:
            self.subprocesses.append(process)
        process.wait()
        with self.lock:
            if process in self.subprocesses:
                self.subprocesses.remove(process)

    def cleanup_subprocesses(self) -> None:
        """
        Terminate and clean up all running nmap subprocesses.
        """
        with self.lock:
            for process in self.subprocesses:
                process.terminate()  # Attempt to terminate gracefully
                process.kill()  # Force kill if terminate doesn't work
            self.subprocesses.clear()

    def uninit(self) -> None:
        """
        Cleanup subprocesses on plugin unload.
        """
        self.cleanup_subprocesses()
