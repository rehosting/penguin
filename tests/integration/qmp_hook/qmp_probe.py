"""
QMP integration-test probe plugin.

A project-local pyplugin that exercises the full QMP command hook through a
real ``penguin run``:

  1. registers a custom QMP command (``penguin-qmp-probe``) via the ``qmp``
     plugin, and
  2. from a background host thread, connects to the QMP socket that
     ``core.qmp: true`` opened at ``<results>/qmp.sock``, negotiates
     capabilities, sends the custom command, and -- if the JSON round-trips --
     writes a marker file the ``verifier`` plugin checks.

This is deliberately end-to-end: the command travels the real path
(client -> qemu qmp_dispatch -> weak penguin_handle_qmp -> CFFI trampoline ->
Qmp plugin -> handler -> strdup'd JSON -> qemu decode/g_free -> client), driven
by penguin rather than a hand-built KVMQemu.
"""
import json
import os
import socket
import threading
import time

from penguin import plugins, Plugin

PROBE_CMD = "penguin-qmp-probe"
DECLINED_CMD = "penguin-qmp-not-registered"
MARKER_NAME = "qmp_probe_result"
PROBE_ARGS = {"a": 1, "b": "two", "nested": {"x": [1, 2, 3]}}


class QmpProbe(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")

        @plugins.qmp.command(PROBE_CMD)
        def handle(args):
            return {"echo": args, "ok": True}

        self._thread = threading.Thread(target=self._probe, daemon=True)
        self._thread.start()

    def _recv_json(self, stream):
        line = stream.readline()
        if not line:
            raise AssertionError("QMP connection closed unexpectedly")
        return json.loads(line.decode())

    def _probe(self) -> None:
        sock_path = os.path.join(self.outdir, "qmp.sock")

        # Wait for QEMU to create the QMP socket, then for it to accept.
        deadline = time.time() + 60
        sock = None
        while time.time() < deadline:
            if os.path.exists(sock_path):
                try:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    sock.connect(sock_path)
                    break
                except OSError:
                    sock = None
            time.sleep(0.2)
        if sock is None:
            self.logger.error("QMP socket never became connectable: %s", sock_path)
            return

        try:
            stream = sock.makefile("rwb", buffering=0)

            def send(obj):
                stream.write((json.dumps(obj) + "\n").encode())

            greeting = self._recv_json(stream)
            assert "QMP" in greeting, f"unexpected QMP greeting: {greeting!r}"
            send({"execute": "qmp_capabilities"})
            caps = self._recv_json(stream)
            assert caps.get("return") == {}, f"qmp_capabilities failed: {caps!r}"

            # 1. Handled command: arguments + return value round-trip.
            send({"execute": PROBE_CMD, "arguments": PROBE_ARGS})
            resp = self._recv_json(stream)
            self.logger.info("QMP probe response: %s", resp)
            expected = {"echo": PROBE_ARGS, "ok": True}
            assert resp.get("return") == expected, (
                f"probe did not round-trip: got {resp!r}, want return={expected!r}"
            )

            # 2. Unregistered command still yields CommandNotFound.
            send({"execute": DECLINED_CMD})
            resp2 = self._recv_json(stream)
            self.logger.info("QMP declined response: %s", resp2)
            assert "error" in resp2 and resp2["error"].get("class") == "CommandNotFound", (
                f"unregistered command should be CommandNotFound, got {resp2!r}"
            )
        except Exception:
            self.logger.exception("QMP probe failed")
            return
        finally:
            sock.close()

        # Success: write the marker the verifier checks.
        marker = os.path.join(self.outdir, MARKER_NAME)
        with open(marker, "w") as f:
            f.write("qmp-probe-ok")
        self.logger.info("QMP probe passed; wrote marker %s", marker)
