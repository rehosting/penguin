'''
Exercises the vpn owned-interface datapaths end to end against a guest that owns
a tap-backed interface (`testif`, declared in patches/tests/owned_iface.yaml):

  - Inc A (TCP forward): `wan-probe --iface testif` reaches a guest httpd through
    the tap stack -> reported "open".
  - Inc B (raw L3): `raw --iface testif --proto 1` sends an ICMP echo through the
    interface; the guest kernel answers -> "echo-reply".
  - Inc C (raw L2): a self-contained ARP exchange over the raw-L2 vsock port
    (no host /dev/net/tun needed): inject an ARP request frame and read the
    guest's reply tee'd back over the bridge.

Each check writes a result file the verifier asserts on (see the patch).
'''

from penguin import plugins, Plugin
import threading
import time
import socket
import struct
import subprocess

VPN_BIN = "/igloo_static/vpn/vpn.x86_64"   # host-side vpn binary in the image
IFACE = "testif"
HOST_IP = "10.99.0.1"     # smoltcp side
GUEST_IP = "10.99.0.2"    # guest side (assigned to the tap by the agent)
HTTPD_PORT = 8010
CMD_PORT = 1234           # guest agent default; raw L3 = +1, raw L2 = +2


class OwnedIfaceTest(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.uds = str(self.get_arg("uds_path"))
        self.started = False
        self.results = {"probe": False, "raw": False, "l2": False}
        self.logger.info(f"owned_iface_test init (uds={self.uds})")
        plugins.subscribe(plugins.VPN, "on_bind", self.on_bind)

    def on_bind(self, proto, guest_ip, guest_port, host_port, host_ip, procname):
        # The httpd bind means the guest is up and the tap stack is running.
        self.logger.info(f"owned_iface_test on_bind {proto} {guest_ip}:{guest_port}")
        if proto == "tcp" and guest_port == HTTPD_PORT and not self.started:
            self.started = True
            self.logger.info("owned_iface_test: starting checks")
            threading.Thread(target=self.run_checks, daemon=True).start()

    def run_checks(self):
        self.check_probe()
        self.check_raw()
        self.check_l2()

    def _write(self, name, ok, ok_str):
        with open(f"{self.outdir}/{name}", "w") as f:
            f.write(ok_str if ok else f"{name} FAILED\n")

    # --- Inc A: TCP forward routed through the owned interface ---------------
    def check_probe(self):
        for _ in range(8):
            try:
                out = subprocess.run(
                    [VPN_BIN, "wan-probe", "-u", self.uds, "--iface", IFACE,
                     "--ports", str(HTTPD_PORT), "--timeout", "5"],
                    capture_output=True, text=True, timeout=40).stdout
                self.logger.info("wan-probe: " + " ".join(out.split()))
                if "open" in out:
                    self.results["probe"] = True
                    break
            except Exception as e:
                self.logger.info(f"wan-probe attempt failed: {e}")
            time.sleep(1)
        self._write("owned_iface_probe.txt", self.results["probe"],
                    "OWNED IFACE PROBE OK\n")

    # --- Inc B: raw L3 ICMP echo through the interface -----------------------
    def check_raw(self):
        for _ in range(6):
            try:
                out = subprocess.run(
                    [VPN_BIN, "raw", "-u", self.uds, "--iface", IFACE,
                     "--proto", "1", "--src-ip", HOST_IP, "--dst-ip", GUEST_IP,
                     "--count", "2", "--timeout", "3"],
                    capture_output=True, text=True, timeout=40).stdout
                self.logger.info("raw: " + " ".join(out.split()))
                if "echo-reply" in out:
                    self.results["raw"] = True
                    break
            except Exception as e:
                self.logger.info(f"raw attempt failed: {e}")
            time.sleep(1)
        self._write("owned_iface_raw.txt", self.results["raw"],
                    "OWNED IFACE RAW OK\n")

    # --- Inc C: raw L2 ARP exchange over the bridge --------------------------
    def check_l2(self):
        for _ in range(6):
            try:
                if self._l2_arp_once():
                    self.results["l2"] = True
                    break
            except Exception as e:
                self.logger.info(f"L2 arp attempt failed: {e}")
            time.sleep(2)
        self._write("owned_iface_l2.txt", self.results["l2"],
                    "OWNED IFACE L2 OK\n")

    def _l2_arp_once(self) -> bool:
        l2_port = CMD_PORT + 2
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(6)
        try:
            s.connect(self.uds)
            s.sendall(f"CONNECT {l2_port}\n".encode())
            if not self._readline(s).startswith(b"OK"):
                return False
            # RawL2{iface}: bincode enum variant 2 (u32 LE) + String (u64 LE len
            # + bytes); framed by a u16 BE length prefix (matches wan_probe/host).
            payload = struct.pack("<I", 2) + struct.pack("<Q", len(IFACE)) + IFACE.encode()
            s.sendall(struct.pack(">H", len(payload)) + payload)

            my_mac = bytes.fromhex("020000000050")
            frame = self._arp_request(my_mac, "10.99.0.50", GUEST_IP)
            s.sendall(struct.pack(">H", len(frame)) + frame)

            deadline = time.time() + 5
            while time.time() < deadline:
                hdr = self._recvn(s, 2)
                if not hdr:
                    break
                (flen,) = struct.unpack(">H", hdr)
                fr = self._recvn(s, flen)
                if not fr or len(fr) < 42:
                    continue
                # Ethertype ARP, opcode reply, sender protocol addr == GUEST_IP.
                if fr[12:14] == b"\x08\x06" and fr[20:22] == b"\x00\x02" \
                        and fr[28:32] == socket.inet_aton(GUEST_IP):
                    return True
            return False
        finally:
            s.close()

    @staticmethod
    def _arp_request(my_mac: bytes, spa: str, tpa: str) -> bytes:
        eth = b"\xff" * 6 + my_mac + b"\x08\x06"
        arp = struct.pack(">HHBBH", 1, 0x0800, 6, 4, 1)  # ether/IPv4, request
        arp += my_mac + socket.inet_aton(spa)
        arp += b"\x00" * 6 + socket.inet_aton(tpa)
        return eth + arp

    @staticmethod
    def _recvn(s, n):
        buf = b""
        while len(buf) < n:
            try:
                chunk = s.recv(n - len(buf))
            except socket.timeout:
                return None
            if not chunk:
                return None
            buf += chunk
        return buf

    @staticmethod
    def _readline(s):
        buf = b""
        while b"\n" not in buf:
            c = s.recv(1)
            if not c:
                break
            buf += c
        return buf

    def uninit(self):
        # Ensure a definite result file exists for each check.
        for key, name in (("probe", "owned_iface_probe.txt"),
                          ("raw", "owned_iface_raw.txt"),
                          ("l2", "owned_iface_l2.txt")):
            try:
                open(f"{self.outdir}/{name}", "x").close()
                # Newly created (check never wrote it): mark failed.
                with open(f"{self.outdir}/{name}", "w") as f:
                    f.write(f"{name} FAILED (no result)\n")
            except FileExistsError:
                pass
