import os
from os.path import join

from penguin import Plugin, plugins


class Readiness(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.init_seen = False
        self.netbind_seen = False
        # Exact marker payloads (with trailing newline) so a snapshot restore can
        # re-create them; out_dir is wiped on the restore run and the guest is
        # past these events, so nothing else re-writes them. See save_state.
        self._init_marker = None
        self._netbind_marker = None

        # Broadcast a steady-state signal other plugins can observe (the raw
        # send_hypercall "readiness" event is single-subscriber and owned here).
        plugins.register(self, "ready")

        plugins.send_hypercall.subscribe("readiness", self.on_readiness)
        plugins.subscribe(plugins.NetBinds, "on_bind", self.on_netbind)

    def _write_marker(self, filename: str, contents: str) -> None:
        os.makedirs(self.outdir, exist_ok=True)
        with open(join(self.outdir, filename), "w") as f:
            f.write(contents)

    def _guest_ip(self) -> str:
        return os.environ.get("CONTAINER_IP") or "127.0.0.1"

    def on_readiness(self, kind: str, value: str = ""):
        if kind != "igloo_init" or self.init_seen:
            return 0, ""

        self.init_seen = True
        self._init_marker = value + "\n"
        self._write_marker("igloo_init.ready", self._init_marker)
        plugins.publish(self, "ready", "igloo_init")

        guest = self._guest_ip()
        port = self.get_arg("telnet_port") or 23
        ready_line = f"READY guest={guest} shell=telnet {guest} {port} results={self.outdir}"
        print(ready_line, flush=True)
        self.logger.info(ready_line)
        return 0, ""

    def on_netbind(self, sock_type: str, ipvn: int, ip: str, port: int, procname: str) -> None:
        if self.netbind_seen:
            return
        self.netbind_seen = True
        self._netbind_marker = f"{procname},{ipvn},{sock_type},{ip},{port}\n"
        self._write_marker("netbind.ready", self._netbind_marker)
        plugins.publish(self, "ready", "netbind")

    # --- snapshot / restore ------------------------------------------------- #
    def save_state(self):
        """Carry the readiness markers across a snapshot restore.

        The ``*.ready`` marker files are the steady-state signal external
        orchestration polls for (see tests/integration snapshot helpers). They
        live in ``out_dir``, which ``penguin_run`` wipes on the restore run, and
        the restored guest is already past ``igloo_init`` / its first bind so it
        never re-issues the events that would re-create them. Without this a
        restored run would look like it never became ready. Returns None when
        nothing has been seen yet (nothing to carry)."""
        if not (self.init_seen or self.netbind_seen):
            return None
        state = {}
        if self.init_seen:
            state["init_marker"] = self._init_marker
        if self.netbind_seen:
            state["netbind_marker"] = self._netbind_marker
        return state

    def load_state(self, data) -> None:
        """Restore phase one: apply the saved markers to our own state. No side
        effects here — the marker files and the ``ready`` broadcast happen in
        on_restore, once every plugin has loaded."""
        if not data:
            return
        if "init_marker" in data:
            self.init_seen = True
            self._init_marker = data["init_marker"]
        if "netbind_marker" in data:
            self.netbind_seen = True
            self._netbind_marker = data["netbind_marker"]

    def on_restore(self, tag: str) -> None:
        """Restore phase two: re-create the readiness markers (out_dir was wiped)
        and re-broadcast ``ready`` so the restored run reports the steady state it
        reached before the snapshot.

        Re-publishing is ground-truth replay that no downstream plugin saved
        (Readiness is the sole owner of the ``ready`` event); the only
        subscriber, the Snapshot plugin, only listens when ``save_at:
        readiness``, which is never set on a restore run — so there is no
        re-save loop and no double-actuation."""
        if self.init_seen and self._init_marker is not None:
            self._write_marker("igloo_init.ready", self._init_marker)
            plugins.publish(self, "ready", "igloo_init")
        if self.netbind_seen and self._netbind_marker is not None:
            self._write_marker("netbind.ready", self._netbind_marker)
            plugins.publish(self, "ready", "netbind")
