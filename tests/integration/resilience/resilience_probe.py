"""
Resilience integration-test probe plugin.

A project-local pyplugin that abuses the guesthopper vsock command channel from a
background host thread during a real ``penguin run`` and proves the agent never
falls over: it does not orphan guest commands on disconnect, does not leak its
concurrency permits under connect/abort churn, and keeps serving after a burst of
malformed/oversize/silent connections.

It talks the raw frame protocol straight to the vhost-device-vsock unix socket
(the same socket guest_cmd.py uses), so the whole path is exercised live:

    probe (raw frames) -> vhost-device-vsock -> guesthopper agent -> guest shell

The frame codec is reimplemented inline (a few lines) so the test has no import
dependency on the in-image client.

On success it writes a marker file the ``verifier`` plugin checks; the run ends
when the condition passes.
"""
import glob
import json
import os
import socket
import struct
import threading
import time

from penguin import plugins, Plugin  # noqa: F401 (Plugin base)

MARKER_NAME = "resilience_result"

# Frame protocol (mirrors guest_cmd.py / frame.rs).
FRAME_REQUEST, FRAME_STDIN, FRAME_STDIN_EOF, FRAME_PING, FRAME_RESIZE = 1, 2, 3, 4, 5
FRAME_STDOUT, FRAME_STDERR, FRAME_EXIT, FRAME_ERROR = 16, 17, 18, 19
VSOCK_PORT = 12341234
MARK = "RESIL_MARK_42"
# Sequential connect/abort iterations: more than GUESTHOPPER_MAX_SESSIONS (64) so
# that if an aborted session leaked its permit the agent would run out of slots
# and the final normal command would hang -- the definitive no-leak / no-wedge
# check.
CHURN = 80


class ResilienceProbe(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self._thread = threading.Thread(target=self._probe, daemon=True)
        self._thread.start()

    # -- raw frame codec over the vhost unix socket ----------------------- #
    def _vsocket(self):
        m = glob.glob("/tmp/*/vsocket")
        return m[0] if m else None

    def _connect(self, timeout=15):
        """Open a vsock session: connect the unix socket + hybrid CONNECT/OK.

        Returns None on any error -- the socket may not exist yet (boot), or the
        agent may RST an early/handshaking connection. The probe must tolerate
        that (and the resets its own abrupt-close scenarios provoke) rather than
        letting an exception kill the probe thread.
        """
        path = self._vsocket()
        if not path:
            return None
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            s.settimeout(timeout)
            s.connect(path)
            s.sendall(f"CONNECT {VSOCK_PORT}\n".encode())
            line = b""
            while not line.endswith(b"\n"):
                c = s.recv(1)
                if not c:
                    s.close()
                    return None
                line += c
            if not line.startswith(b"OK"):
                s.close()
                return None
            return s
        except OSError:
            try:
                s.close()
            except OSError:
                pass
            return None

    def _wf(self, s, ftype, payload=b""):
        if isinstance(payload, str):
            payload = payload.encode()
        s.sendall(bytes([ftype]) + struct.pack(">I", len(payload)) + payload)

    def _rf(self, s):
        hdr = b""
        while len(hdr) < 5:
            c = s.recv(5 - len(hdr))
            if not c:
                return None
            hdr += c
        n = struct.unpack(">I", hdr[1:5])[0]
        p = b""
        while len(p) < n:
            c = s.recv(n - len(p))
            if not c:
                return None
            p += c
        return hdr[0], p

    def _abrupt_close(self, s):
        """RST on close (SO_LINGER 0): models an abruptly-killed client."""
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except OSError:
            pass
        try:
            s.close()
        except OSError:
            pass

    def _exec_req(self, cmd, deadline=None):
        d = {"verb": "exec", "cmd": cmd}
        if deadline is not None:
            d["deadline"] = deadline
        return json.dumps(d).encode()

    def _oneshot(self, cmd, deadline=10, read_secs=20):
        """Run a one-shot command cleanly; return (exit_code, stdout) or (None, '')."""
        s = self._connect()
        if s is None:
            return None, ""
        try:
            self._wf(s, FRAME_REQUEST, self._exec_req(cmd, deadline))
            self._wf(s, FRAME_STDIN_EOF)
            out = b""
            end = time.time() + read_secs
            while time.time() < end:
                fr = self._rf(s)
                if fr is None:
                    break
                ft, p = fr
                if ft == FRAME_STDOUT:
                    out += p
                elif ft == FRAME_EXIT:
                    return json.loads(p or b"{}").get("code"), out.decode(errors="replace")
                elif ft == FRAME_ERROR:
                    return None, out.decode(errors="replace")
            return None, out.decode(errors="replace")
        except OSError:
            return None, ""
        finally:
            try:
                s.close()
            except OSError:
                pass

    def _read_file(self, path):
        _, out = self._oneshot(f"/busybox cat {path} 2>/dev/null || echo NONE")
        return out.strip()

    def _normal_command_works(self):
        code, out = self._oneshot(f"echo {MARK}")
        return code == 0 and MARK in out

    # -- scenarios -------------------------------------------------------- #
    def _scenario_disconnect_reaps_orphan(self):
        """A silent long-running command (deadline 0) must be reaped when the
        client abruptly disconnects -- not left running forever."""
        s = self._connect()
        if s is None:
            return False
        hb = "/tmp/RES_HB"
        self._wf(
            s,
            FRAME_REQUEST,
            self._exec_req(
                f"i=0; while true; do i=$((i+1)); echo $i > {hb}; /busybox sleep 1; done",
                deadline=0,
            ),
        )
        time.sleep(4)  # let the heartbeat advance
        self._abrupt_close(s)
        # After the disconnect the command must stop advancing the heartbeat.
        time.sleep(4)
        v1 = self._read_file(hb)
        time.sleep(4)
        v2 = self._read_file(hb)
        reaped = v1 == v2 and v1 not in ("", "NONE")
        self.logger.info("disconnect-reap: hb %s -> %s (%s)", v1, v2, "reaped" if reaped else "ORPHAN")
        return reaped

    def _scenario_churn_no_permit_leak(self):
        """More connect/abort cycles than the session cap: each aborted session
        must release its permit (via the disconnect reap), or the agent runs out
        of slots and the final normal command hangs."""
        for _ in range(CHURN):
            s = self._connect(timeout=8)
            if s is None:
                continue
            self._wf(
                s,
                FRAME_REQUEST,
                self._exec_req("i=0; while true; do i=$((i+1)); /busybox sleep 1; done", deadline=0),
            )
            self._abrupt_close(s)
        ok = self._normal_command_works()
        self.logger.info("churn(%d)-no-leak: normal command %s", CHURN, "works" if ok else "WEDGED")
        return ok

    def _scenario_survives_garbage(self):
        """Malformed / oversize / silent connections must not take the agent
        down; a normal command must still work afterwards."""
        path = self._vsocket()
        if not path:
            return False
        # Oversize frame header (over the 1 MiB inbound cap) with no body.
        try:
            s = self._connect(timeout=8)
            if s is not None:
                s.sendall(bytes([FRAME_REQUEST]) + struct.pack(">I", 4 * 1024 * 1024))
                self._abrupt_close(s)
        except OSError:
            pass
        # Random bytes with no valid handshake.
        for _ in range(5):
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect(path)
                s.sendall(os.urandom(64))
                self._abrupt_close(s)
            except OSError:
                pass
        # Connect, complete the handshake, then send nothing and drop.
        for _ in range(5):
            s = self._connect(timeout=8)
            if s is not None:
                self._abrupt_close(s)
        ok = self._normal_command_works()
        self.logger.info("garbage-survival: normal command %s", "works" if ok else "WEDGED")
        return ok

    # -- driver ----------------------------------------------------------- #
    def _probe(self) -> None:
        # Wait for the guest agent to come up (boot is slow under emulation).
        deadline = time.time() + 240
        while time.time() < deadline and not self._normal_command_works():
            time.sleep(3)
        if time.time() >= deadline:
            self.logger.error("resilience probe: guest command channel never came up")
            return
        self.logger.info("resilience probe: command channel up; running fault scenarios")

        def safe(name, fn):
            # A scenario raising must never kill the probe thread -- record it as
            # a failure and move on so the marker is simply never written.
            try:
                return fn()
            except Exception:  # noqa: BLE001
                self.logger.exception("resilience scenario %s raised", name)
                return False

        results = {
            "disconnect_reap": safe("disconnect_reap", self._scenario_disconnect_reaps_orphan),
            "churn_no_leak": safe("churn_no_leak", self._scenario_churn_no_permit_leak),
            "garbage_survival": safe("garbage_survival", self._scenario_survives_garbage),
        }
        # Final liveness: the agent still serves after everything above.
        results["still_serving"] = self._normal_command_works()

        if all(results.values()):
            marker = os.path.join(self.outdir, MARKER_NAME)
            with open(marker, "w") as f:
                f.write("resilience-ok " + " ".join(sorted(results)))
            self.logger.info("resilience scenarios passed; wrote marker %s", marker)
        else:
            self.logger.error("resilience probe failed: %s", results)
