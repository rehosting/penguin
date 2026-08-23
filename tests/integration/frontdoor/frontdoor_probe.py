"""
Front-door integration-test probe plugin.

A project-local pyplugin that exercises the telnet + SSH front doors of the
vsock root-shell console through a real ``penguin run``. Both doors are
host-side gateways (in the penguin container) that bridge a TCP client to the
guest's vsock ``open-pty`` session; this probe, from a background host thread,
connects to them exactly as a user would and drives an interactive command --
so the run exercises the full path end-to-end over real vsock:

    telnet/ssh client -> host gateway (telnet_gateway.py / ssh_gateway.py)
      -> vhost-device-vsock -> guesthopper agent (open-pty) -> guest shell

That also gives the (new) Rust guest agent's pty path a real-vsock workout in
CI, which the exec-only ``test_target`` runs never reach.

On success (both doors round-trip a marker) it writes a marker file the
``verifier`` plugin checks; the run ends when the condition passes.

The gateways bind their standard privileged ports (telnet 23, ssh 22) as the
non-root container user, so a green run also confirms NET_BIND_SERVICE is
effective and the SSH gateway's asyncssh import path works on the image.
"""
import asyncio
import os
import socket
import threading
import time

from penguin import plugins, Plugin  # noqa: F401 (Plugin base)

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

MARKER_NAME = "frontdoor_result"
# Marker echoed through each door; the guest shell echoes it back (pty) and runs
# it, so we expect to see it more than once on a working interactive session.
TELNET_MARK = "TELNET_MARK_42"
SSH_MARK = "SSH_MARK_42"
SSH_ERR = "SSH_ERR_LINE"


class FrontdoorProbe(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self._thread = threading.Thread(target=self._probe, daemon=True)
        self._thread.start()

    # -- port discovery --------------------------------------------------- #
    def _ports(self):
        """Read the actual telnet/ssh ports from runtime.yaml (they self-heal to
        a high port if 23/22 are unbindable); default to the standard ports."""
        telnet_port, ssh_port = 23, 22
        rt = os.path.join(self.outdir, "runtime.yaml")
        if yaml is not None and os.path.exists(rt):
            try:
                with open(rt) as f:
                    meta = yaml.safe_load(f) or {}
                telnet_port = int(meta.get("telnet_port") or telnet_port)
                if meta.get("ssh_port"):
                    ssh_port = int(meta["ssh_port"])
            except Exception:  # noqa: BLE001
                pass
        return telnet_port, ssh_port

    # -- telnet ----------------------------------------------------------- #
    def _telnet_once(self, port):
        """One telnet attempt: connect, ignore IAC negotiation, run a marker
        command, confirm the guest pty echoed *and* ran it (marker seen >= 2x)."""
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=8)
        except OSError:
            return False
        try:
            s.settimeout(8)
            time.sleep(0.5)
            try:
                s.recv(4096)  # drain initial IAC negotiation
            except OSError:
                pass
            s.sendall(b"echo " + TELNET_MARK.encode() + b"\n")
            acc = b""
            deadline = time.time() + 10
            while time.time() < deadline:
                try:
                    chunk = s.recv(4096)
                except OSError:
                    break
                if not chunk:
                    break
                acc += chunk
                if acc.count(TELNET_MARK.encode()) >= 2:
                    return True
            return acc.count(TELNET_MARK.encode()) >= 2
        finally:
            s.close()

    # -- ssh -------------------------------------------------------------- #
    async def _ssh_once(self, port):
        """One ssh attempt: open auth, exec (`ssh host CMD`) with stderr
        separation, then an interactive pty. Returns True only if both work."""
        import asyncssh

        async with asyncssh.connect(
            "127.0.0.1", port=port, username="root", known_hosts=None,
            client_keys=[], password="", preferred_auth=["none", "password"],
        ) as conn:
            # exec path: stdout carries the marker, stderr stays separate.
            r = await asyncio.wait_for(
                conn.run(f"echo {SSH_MARK}; echo {SSH_ERR} 1>&2"), timeout=15
            )
            exec_ok = (SSH_MARK in (r.stdout or "")) and (SSH_ERR in (r.stderr or ""))
            # interactive pty path.
            proc = await conn.create_process(term_type="xterm", term_size=(100, 40))
            proc.stdin.write(f"echo {SSH_MARK}\n")
            proc.stdin.write("exit\n")
            out = await asyncio.wait_for(proc.stdout.read(), timeout=15)
            pty_ok = SSH_MARK in out
            return exec_ok and pty_ok

    def _ssh_try(self, port):
        loop = asyncio.new_event_loop()
        try:
            os.environ.setdefault("USER", "root")  # asyncssh client username fallback
            return loop.run_until_complete(self._ssh_once(port))
        except Exception:  # noqa: BLE001
            return False
        finally:
            loop.close()

    # -- driver ----------------------------------------------------------- #
    def _probe(self) -> None:
        telnet_port, ssh_port = self._ports()
        self.logger.info(
            "frontdoor probe: telnet 127.0.0.1:%d, ssh 127.0.0.1:%d", telnet_port, ssh_port
        )
        # The doors bind quickly, but a door session only completes once the
        # guest agent is up (post-boot), so retry the whole round-trip until both
        # pass or we give up. Guest boot under emulation is slow -> generous.
        deadline = time.time() + 240
        telnet_ok = ssh_ok = False
        while time.time() < deadline and not (telnet_ok and ssh_ok):
            if not telnet_ok:
                telnet_ok = self._telnet_once(telnet_port)
                if telnet_ok:
                    self.logger.info("telnet front door: PASS")
            if not ssh_ok:
                ssh_ok = self._ssh_try(ssh_port)
                if ssh_ok:
                    self.logger.info("ssh front door: PASS")
            if not (telnet_ok and ssh_ok):
                time.sleep(3)

        if telnet_ok and ssh_ok:
            marker = os.path.join(self.outdir, MARKER_NAME)
            with open(marker, "w") as f:
                f.write("telnet-ok ssh-ok frontdoor-ok")
            self.logger.info("front doors passed; wrote marker %s", marker)
        else:
            self.logger.error(
                "front door probe failed: telnet_ok=%s ssh_ok=%s", telnet_ok, ssh_ok
            )
