import subprocess
import time
import threading
from pandare import PyPlugin

class Nmap(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.ppp.VsockVPN.ppp_reg_cb('on_bind', self.nmap_on_bind)

    def nmap_on_bind(self, proto, guest_ip, guest_port, host_port, procname):
        '''
        There was a bind - run nmap! Maybe bail if we've already seen this port
        or something for systems that repeatedly start/stop  listening?
        '''

        if proto != 'tcp':
            # We can't do UDP scans without root permissions to create raw sockets.
            # Let's just ignore entirely.
            return

        f = self.outdir + f"/nmap_{proto}_{guest_port}.log"

        # Launch a thread to analyze this request
        t = threading.Thread(target=self.scan_thread, args=(guest_port, host_port, f))
        t.daemon = True
        t.start()

    def scan_thread(self, guest_port, host_port, log_file_name):
        # nmap scan our target in service-aware mode
        process = subprocess.Popen(
            ["nmap",
                f"-p{guest_port}", # Target guest port. XXX: redirect-port below means this actually hits host_port, but gets scanned as if it was this
                                   # port (i.e., if 80 we scan for http, even if we're going through 4321)
            ]
            + (["--redirect-port", str(guest_port), str(host_port)  # Pretend we're connecting to guest_port, but internally connect to host_port
              ] if guest_port != host_port else []) # If ports actually match, we skip this
            + [
                "-unprivileged", # Don't try anything privileged
                "-n", # Do not do DNS resolution
                "-sV", # Scan for service version
                "--script=default,vuln,version", # Run NSE scripts to enumerate service
                "-d", # Print debug info about scripts
                "127.0.0.1", # Target is localhost
                "-oG", log_file_name, # Greppable output format, store in log file
             ],
            #stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        )
        process.daemon = True
