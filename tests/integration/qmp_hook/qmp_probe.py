"""
QMP integration-test probe plugin.

A project-local pyplugin that exercises the full QMP command hook through a
real ``penguin run``:

  1. registers a custom QMP command (``penguin-qmp-probe``) via the ``qmp``
     plugin,
  2. from a background host thread, connects to the QMP socket that the
     ``qmp`` plugin opened at ``<results>/qmp.sock``, negotiates
     capabilities, sends the custom command, and
  3. asks the guest-facing side to emit QMP *events* and asserts they arrive
     unsolicited on the same connection -- covering the outbound direction.

If both directions check out it writes a marker file the ``verifier`` plugin
checks.

This is deliberately end-to-end. The inbound command travels the real path
(client -> qemu qmp_dispatch -> weak penguin_handle_qmp -> CFFI trampoline ->
Qmp plugin -> handler -> strdup'd JSON -> qemu decode/g_free -> client), and
the outbound event travels its own real path (plugin emit_event -> CFFI ->
penguin_qmp_emit_event -> main-loop bottom half -> qobject_from_json ->
qmp_event_build_dict -> penguin_monitor_broadcast_event -> monitor write ->
client), driven by penguin rather than a hand-built KVMQemu.
"""
import json
import os
import socket
import threading
import time

from penguin import plugins, Plugin

PROBE_CMD = "penguin-qmp-probe"
DECLINED_CMD = "penguin-qmp-not-registered"
# Asking for an event over QMP proves the emit path works while the main loop
# is servicing a command -- the realistic case for a host-driven trigger.
EMIT_CMD = "penguin-qmp-emit"
MARKER_NAME = "qmp_probe_result"
PROBE_ARGS = {"a": 1, "b": "two", "nested": {"x": [1, 2, 3]}}
# An arbitrary event name: it becomes the QMP "event" member verbatim, with no
# QAPI schema entry and no PENGUIN_EVENT wrapper.
EVENT_NAME = "PENGUIN_PROBE_EVENT"
EVENT_DATA = {"n": 42, "s": "payload", "nested": {"y": [4, 5]}}
# No-payload events must arrive with no "data" member at all, rather than a
# null -- the None vs "" distinction in emit_qmp_event().
BARE_EVENT_NAME = "penguin-probe-bare-event"


class QmpProbe(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")

        @plugins.qmp.command(PROBE_CMD)
        def handle(args):
            return {"echo": args, "ok": True}

        @plugins.qmp.command(EMIT_CMD)
        def emit(args):
            # Emit both a payload event and a bare one, then confirm to the
            # caller. emit_event() is fire-and-forget and returns nothing, so
            # this only reports that the calls completed without raising --
            # actual delivery is proven by the events arriving client-side.
            # They ride a bottom half, so they may arrive before or after this
            # command's reply; the client tolerates either ordering.
            plugins.qmp.emit_event(EVENT_NAME, EVENT_DATA)
            plugins.qmp.emit_event(BARE_EVENT_NAME)
            return {"emit_returned": True}

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

            # 3. Outbound: ask the plugin to emit events, then collect them.
            # Events are delivered from a main-loop bottom half, so they can
            # interleave with the command reply in either order. Read until we
            # have both the reply and both events (or time out).
            send({"execute": EMIT_CMD})
            reply = None
            events = {}
            sock.settimeout(30)
            deadline = time.time() + 30
            while (reply is None or len(events) < 2) and time.time() < deadline:
                msg = self._recv_json(stream)
                if "event" in msg:
                    # Key by the QMP event name itself -- there is no wrapper
                    # event type any more.
                    events[msg["event"]] = msg
                    self.logger.info("QMP event: %s", msg)
                else:
                    reply = msg
                    self.logger.info("QMP emit reply: %s", reply)

            assert reply is not None, "emit command never replied"
            assert reply.get("return", {}).get("emit_returned") is True, (
                f"emit_event() raised inside the handler: {reply!r}"
            )

            assert EVENT_NAME in events, (
                f"never received {EVENT_NAME!r}; got {sorted(events)}"
            )
            ev = events[EVENT_NAME]
            assert ev.get("data") == EVENT_DATA, (
                f"event payload did not round-trip: {ev!r}"
            )
            # QMP events carry a timestamp; its absence means we built the dict
            # by hand somewhere instead of going through the QAPI sender.
            assert "timestamp" in ev, f"event missing timestamp: {ev!r}"

            assert BARE_EVENT_NAME in events, (
                f"never received {BARE_EVENT_NAME!r}; got {sorted(events)}"
            )
            bare = events[BARE_EVENT_NAME]
            assert "data" not in bare, (
                f"no-payload event should omit the data member, got {bare!r}"
            )

            # The old PENGUIN_EVENT wrapper must be gone entirely.
            assert "PENGUIN_EVENT" not in events, (
                f"PENGUIN_EVENT wrapper should no longer exist: {events!r}"
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
