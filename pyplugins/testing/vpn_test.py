'''
This plugin checks that a specific connection to busybox's httpd server
is possible over a VPN connection established by penguin's VPN plugin.

Look for netbinds.yaml in the patches directory for the test that uses this plugin.

This validates that architectures + emulator + kernel all produce valid VPN
connections.
'''

from penguin import plugins, Plugin
import threading
import requests
import time


class VPNTest(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        plugins.subscribe(plugins.VPN, "on_bind", self.on_bind)
        self.success = False

    def on_bind(self, proto: str, guest_ip: str, guest_port: int, host_port: int, host_ip: str, procname: str) -> None:
        if guest_port == 8000 and proto == "tcp":
            if not hasattr(self, 't'):
                self.logger.info(
                    f"Starting VPN test thread to {host_ip}:{host_port}")
                self.t = threading.Thread(
                    target=self.scan_thread, args=(host_ip, host_port))
                self.t.start()

    def scan_thread(self, host_ip: str, host_port: int) -> None:
        while True:
            try:
                response = requests.get(
                    f"http://{host_ip}:{host_port}/igloo/boot/preinit", timeout=1)
                if "#!/igloo/boot/sh" in response.text:
                    self.success = True
                    with open(f"{self.outdir}/vpn_test.txt", "w") as f:
                        f.write("VPN connection successful!\n")
                    self.logger.info("VPN connection successful!")
                    return
            except Exception as e:
                self.logger.info(
                    f"VPN test connection failed: {e} retrying...")
            time.sleep(1)

    def uninit(self):
        if not self.success:
            with open(f"{self.outdir}/vpn_test.txt", "w") as f:
                f.write("VPN connection failed.\n")
            print("VPN connection failed.")
