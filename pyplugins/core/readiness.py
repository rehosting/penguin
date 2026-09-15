import os
from os.path import join

from penguin import Plugin, plugins


class Readiness(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.init_seen = False
        self.netbind_seen = False
        # Whether the vsock front-door gateways actually launched. penguin_run
        # sets these after launching them (None == not yet known / not applicable,
        # in which case we still advertise). Gating the READY line on real
        # liveness stops us announcing a door that failed to bind, which would
        # otherwise leave the user with connection-refused and only a buried WARN.
        self.telnet_up = None
        self.ssh_up = None

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

    def _shell_endpoints(self) -> str:
        """Connect endpoints for the root shell, or '' if the run has no shell.

        Mirrors the front doors penguin actually brought up: the vsock console
        exposes both a telnet and an ssh door (see penguin_run._launch_gateway);
        the legacy telnet backend is the serial console, telnet only. This is the
        single user-facing "you can connect now" announcement -- the per-gateway
        launch logs are kept at debug so this line isn't drowned out.
        """
        if not self.get_arg("root_shell_enabled"):
            return ""
        guest = self._guest_ip()
        backend = self.get_arg("root_shell_backend") or "vsock"
        tport = self.get_arg("telnet_port") or 23
        sport = self.get_arg("ssh_port")

        def telnet_ep():
            return f"telnet={guest}" if tport == 23 else f"telnet={guest}:{tport}"

        def ssh_ep():
            return f"ssh=root@{guest}" if sport == 22 else f"ssh=root@{guest}:{sport}"

        if backend != "vsock":
            # Legacy telnet backend = the in-guest serial console (no gateway),
            # always advertised.
            return telnet_ep()

        # vsock backend: the doors are host-side gateways that may have failed to
        # launch. Advertise a door only when we didn't observe it die
        # (`*_up is False`); None (unknown) still advertises.
        endpoints = []
        if self.telnet_up is not False:
            endpoints.append(telnet_ep())
        if sport and self.ssh_up is not False:
            endpoints.append(ssh_ep())
        return " ".join(endpoints)

    def on_readiness(self, kind: str, value: str = ""):
        if kind != "igloo_init" or self.init_seen:
            return 0, ""

        self.init_seen = True
        self._write_marker("igloo_init.ready", value + "\n")
        plugins.publish(self, "ready", "igloo_init")

        parts = [f"READY guest={self._guest_ip()}"]
        shells = self._shell_endpoints()
        if shells:
            parts.append(shells)
        parts.append(f"results={self.outdir}")
        ready_line = " ".join(parts)
        print(ready_line, flush=True)
        self.logger.info(ready_line)
        return 0, ""

    def on_netbind(self, sock_type: str, ipvn: int, ip: str, port: int, procname: str) -> None:
        if self.netbind_seen:
            return
        self.netbind_seen = True
        self._write_marker("netbind.ready", f"{procname},{ipvn},{sock_type},{ip},{port}\n")
        plugins.publish(self, "ready", "netbind")
