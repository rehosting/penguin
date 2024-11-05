import os
import subprocess
import threading
from collections import Counter
import math

from pandare import PyPlugin
from penguin import getColoredLogger

def calculate_entropy(buffer: bytes) -> float:
    # Count the frequency of each byte value
    byte_counts = Counter(buffer)
    total_bytes = len(buffer)

    # Calculate entropy
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / total_bytes
        entropy -= probability * math.log2(probability)

    return entropy


class FetchWeb(PyPlugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.shutdown_after_www = self.get_arg_bool("shutdown_after_www") # If set, we terminate the VM after fetching web pages
        self.ppp.VsockVPN.ppp_reg_cb("on_bind", self.fetchweb_on_bind)
        self.logger = getColoredLogger("plugins.fetch_web")

    def fetchweb_on_bind(self, proto, guest_ip, guest_port, host_port, host_ip, procname):
        """
        There was a bind - if it's a web port (80, 443), fetch the page with wget
        and log the entropy
        """

        if proto != "tcp" or guest_port not in [80, 443]:
            # Skip non-web
            return

        f = self.outdir + f"/web_{guest_ip}_{guest_port}"

        # Launch a thread to analyze this service
        t = threading.Thread(target=self.fetch_thread, args=(guest_ip, host_ip, guest_port, host_port, f))
        t.daemon = True
        t.start()

    def fetch_thread(self, guest_ip, host_ip, guest_port, host_port, log_file_name):
        if os.path.isfile(log_file_name):
            # Need a unique name (might stack)
            log_file_name += ".alt"

        if guest_port == 443:
            cmd = ["wget", "-q",
                f"https://{host_ip}:{host_port}",
                "--no-check-certificate",
                "-O", log_file_name]
        elif guest_port == 80:
            cmd = ["wget", "-q",
                f"http://{host_ip}:{host_port}",
                "-O", log_file_name]
        else:
            # Send 64 A's with netcat and get response (if there is one)
            #cmd = "echo " + "A"*64 + f" | nc {host_ip} {host_port} > {log_file_name}"
            raise ValueError(f"Unsupported port {guest_port}")

        try:
            if isinstance(cmd, list):
                subprocess.check_output(cmd, timeout=30)
            else:
                subprocess.run(cmd, shell=True, check=True, timeout=30)
        except subprocess.CalledProcessError as e:
            self.logger.warning(f"Error running {cmd[0]}: {e}")
            return
        except subprocess.TimeoutExpired:
            self.logger.warning(f"No response to {cmd[0] if len(cmd) else cmd.split(' ')[0]} to {host_ip}:{host_port} after 30s")
            return
        
        # Measure entropy of generated file
        with open(log_file_name, "rb") as f:
            buffer = f.read()
            size = len(buffer)
            entropy = calculate_entropy(buffer)
            self.logger.info(f"Service on {guest_ip}:{guest_port} responds with {size} bytes with entropy {entropy:.02f}")

        if self.shutdown_after_www:
            # XXX If we know of multiple guest IPs and see a bind to 0.0.0.0 netbinds triggers the callback *for each known IP*
            # it will be deterministic and trigger for 0.0.0.0 first, so we'll shutdown after that one. Which I assume goes through localhost
            self.logger.info(f"Terminating VM after fetching {guest_ip}:{guest_port} due to plugins.fetch_web.shutdown_after_www option")
            self.panda.end_analysis()