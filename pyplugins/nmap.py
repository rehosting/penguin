import requests
import subprocess
import time
import socket
import random
import threading
import os
import tempfile
import shutil

from contextlib import closing
from pandare import PyPlugin

def customize_nmap_services(original_port, new_port):
    # Path to the original nmap-services file
    original_file_path = '/usr/share/nmap/nmap-services'
    
    # Create a temporary directory
    temp_dir = tempfile.mkdtemp()
    
    # Copy nmap-services to temporary directory
    temp_file_path = os.path.join(temp_dir, 'nmap-services')
    shutil.copy2(original_file_path, temp_file_path)
    
    # Read original nmap-services and write to a new temporary file
    with open(original_file_path, 'r') as f_orig:
        lines = f_orig.readlines()
    
    with open(temp_file_path, 'w') as f_temp:
        for line in lines:
            # Skip any line that includes the new port
            if f"{new_port}/" in line:
                continue
            
            # Change the original port to the new port
            if f"{original_port}/" in line:
                line = line.replace(f"{original_port}/", f"{new_port}/")
            
            f_temp.write(line)
    
    return temp_file_path

class Nmap(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.output_file = open(self.outdir + "/nmap.log", "w")

        self.ppp.VsockVPN.ppp_reg_cb('on_bind', self.nmap_on_bind)

    def nmap_on_bind(self, proto, guest_ip, guest_port, host_port, procname):
        '''
        There was a bind - run nmap! Maybe bail if we've already seen this port
        or something for systems that repeatedly start/stop  listening?
        '''

        if guest_port in [80] and proto != 'tcp':
            # Ignore - we'll use ZAP on this instead
            return

        f = self.outdir + f"/nmap_{proto}_{guest_port}.log"

        # Launch a thread to analyze this request
        t = threading.Thread(target=self.scan_thread, args=(guest_port, host_port, f))
        t.daemon = True
        t.start()

    def scan_thread(self, guest_port, host_port, log_file_name):
        # Make sure syscall proxy is up. Not in main thread so this is okay?
        time.sleep(5)

        # Now we need to get a nmap services file that has the right ports setup
        # since nmap will use that to determine what to scan and we have host_port
        # but we want to preserve the "guest_port" info
        custom_nmapdir_path = customize_nmap_services(guest_port, host_port)

        if self.output_file.closed:
            print(f"Output file closed, not scanning guest port {guest_port}")
            return

        try:
            self.output_file.write(f"Scanning {guest_port} via host {host_port} using nmap\n")
        except ValueError:
            # IO operation on closed file
            pass

        # nmap scan our target in service-aware mode
        env = os.environ.copy()
        env['NMAPDIR'] = custom_nmapdir_path

        #["nmap", f"-p{host_port}", "-sV", "-sC", "127.0.0.1",
        #"-oN", log_file_name],
        process = subprocess.Popen(
            ["nmap", f"-p{host_port}", "-A", "127.0.0.1", "--script=default", "-oN", log_file_name],
            env=env)
        process.wait()

        try:
            self.output_file.write(f"Finished scan of {guest_port}\n")
        except ValueError:
            # IO operation on closed file
            pass

        # Now cleanup the nmap services file
        os.remove(custom_nmapdir_path)

    def uninit(self):
        self.output_file.close()
