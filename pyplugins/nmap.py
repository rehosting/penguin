import os
import subprocess
import threading
from threading import Lock

from pandare import PyPlugin


class Nmap(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.ppp.VsockVPN.ppp_reg_cb("on_bind", self.nmap_on_bind)
        self.subprocesses = []
        self.lock = Lock()
        self.custom_nmap = os.path.isfile("/usr/local/etc/nmap/.custom")

    def nmap_on_bind(self, proto, guest_ip, guest_port, host_port, host_ip, procname):
        """
        There was a bind - run nmap! Maybe bail if we've already seen this port
        or something for systems that repeatedly start/stop  listening?
        """

        if proto != "tcp":
            # We can't do UDP scans without root permissions to create raw sockets.
            # Let's just ignore entirely.
            return

        f = self.outdir + f"/nmap_{proto}_{guest_port}_{host_port}.log"

        # Launch a thread to analyze this request
        t = threading.Thread(target=self.scan_thread, args=(host_ip, guest_port, host_port, f))
        t.daemon = True
        t.start()

    def scan_thread(self, host_ip, guest_port, host_port, log_file_name):
        # nmap scan our target in service-aware mode

        if os.path.isfile(log_file_name):
            # Need a unique name - unlikely that host_port would get reused so this might just stack if it ever happens
            log_file_name += ".alt"

        if self.custom_nmap and guest_port != host_port:
            # Special: we want to scan as if we're connecting to guest_port (i.e., guest port 80 -> do webserver scans)
            # but we're actually connecting to host_port
            port_magic = [f"-p{guest_port}", "--redirect-port", f"{guest_port},{host_port}"]
        else:
            # Normal, just scan the port. If it's a stock nmap the scan will be lower quality
            port_magic = [f"-p{host_port}"]

        process = subprocess.Popen(
            [ "nmap" ] + port_magic
            + [
                "-unprivileged",  # Don't try anything privileged
                "-n",  # Do not do DNS resolution
                "-sT",  # TCP connect scan. XXX required for -sV to work with redirect port
                "-sV",  # Scan for service version
                "--script=default,vuln,version",  # Run NSE scripts to enumerate service
                # "--script-timeout", "5m", # Kill nmap scripts if they take > 5m
                "--scan-delay",
                "0.1s",  # Delay between scans - allow other processes to run - toggle as needed?
                host_ip, # Local IP address
                "-oX",
                log_file_name,  # XML output format, store in log file
            ],
            # stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        )
        with self.lock:
            self.subprocesses.append(process)
        process.wait()
        with self.lock:
            if process in self.subprocesses:
                self.subprocesses.remove(process)

    def cleanup_subprocesses(self):
        with self.lock:
            for process in self.subprocesses:
                process.terminate()  # Attempt to terminate gracefully
                process.kill()  # Force kill if terminate doesn't work
            self.subprocesses.clear()

    def uninit(self):
        self.cleanup_subprocesses()
