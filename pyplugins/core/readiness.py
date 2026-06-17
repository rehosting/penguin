import os
from os.path import join

from penguin import Plugin, plugins


class Readiness(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.init_seen = False
        self.netbind_seen = False

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
        self._write_marker("igloo_init.ready", value + "\n")
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
        self._write_marker("netbind.ready", f"{procname},{ipvn},{sock_type},{ip},{port}\n")
        plugins.publish(self, "ready", "netbind")
