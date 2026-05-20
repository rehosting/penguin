"""
Implementation of `penguin utils <subcommand>`.

The compose commands inspect compose_results metadata and, when run inside the
active compose container, /proc. They are intentionally filesystem based so the
same command still gives useful connection details after a compose run exits.
"""
import json
import os
import re
import socket

import click
import yaml


_TELNET_RE = re.compile(r"telnet:0\.0\.0\.0:(\d+)")
_RUNNER_RE = re.compile(r"penguin\.penguin_run\s+\S+\s+\S+\s+(\S+)")
_CONSOLE_RE = re.compile(r"(?:file:|logfile=)(\S*/console\.log)")


def _load_yaml(path: str) -> dict:
    if not path or not os.path.isfile(path):
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _container_ip() -> str | None:
    if ip := os.environ.get("CONTAINER_IP"):
        return ip
    try:
        # No packet is sent; this asks the kernel which local address it would use.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            return s.getsockname()[0]
    except OSError:
        return None


def _find_compose_results(start: str) -> str | None:
    """Search cwd, the mapped workspace, and obvious parents for compose_results."""
    candidates = [
        os.path.join(start, "compose_results"),
        os.path.join(start, "../compose_results"),
    ]
    project_dir = os.environ.get("PENGUIN_PROJECT_DIR")
    if project_dir:
        candidates.extend([
            os.path.join(project_dir, "compose_results"),
        ])
    candidates.append(start)

    for candidate in candidates:
        path = os.path.realpath(candidate)
        if not os.path.isdir(path) or not os.path.isfile(os.path.join(path, "compose.yaml")):
            continue
        if os.path.basename(path) == "compose_results" or os.path.isfile(os.path.join(path, "compose_summary.yaml")):
            return path
    return None


def _scan_qemu_processes() -> list[dict]:
    """Return live runner/qemu processes with any out_dir and telnet metadata."""
    procs = []
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", "replace")
        except OSError:
            continue
        if "qemu-system-" not in cmdline and "penguin.penguin_run" not in cmdline:
            continue

        telnet_match = _TELNET_RE.search(cmdline)
        telnet_port = int(telnet_match.group(1)) if telnet_match else None

        kind = "qemu" if "qemu-system-" in cmdline else "runner"
        out_dir = None
        runner_match = _RUNNER_RE.search(cmdline)
        if runner_match:
            out_dir = runner_match.group(1)
        else:
            console_match = _CONSOLE_RE.search(cmdline)
            if console_match:
                out_dir = os.path.dirname(console_match.group(1))

        procs.append({
            "pid": int(pid),
            "kind": kind,
            "cmdline": cmdline.strip(),
            "telnet_port": telnet_port,
            "out_dir": os.path.realpath(out_dir) if out_dir else None,
        })
    return procs


def _load_instance(device_dir: str) -> dict:
    info = _load_yaml(os.path.join(device_dir, "instance.yaml"))
    if info:
        return info

    info = {
        "name": os.path.basename(device_dir),
        "output": os.path.join(device_dir, "output"),
        "networks": [],
    }
    derived = _load_yaml(os.path.join(device_dir, "derived_config.yaml"))
    extra = derived.get("core", {}).get("extra_qemu_args", "")
    for match in re.finditer(r"mcast=([\d.]+:\d+)", extra):
        info["networks"].append({"mcast": match.group(1)})
    return info


def _merge_runtime(info: dict, device_dir: str) -> dict:
    candidates = [
        info.get("runtime_metadata"),
        os.path.join(device_dir, "runtime.yaml"),
        os.path.join(device_dir, "output", "runtime.yaml"),
    ]
    runtime = {}
    for path in candidates:
        runtime = _load_yaml(path)
        if runtime:
            break
    if not runtime:
        return info

    for key in (
        "pid",
        "container_ip",
        "container_name",
        "root_shell",
        "guest_cmd",
        "telnet_port",
        "vpn_enabled",
        "vsock_cid",
        "vsock_socket_path",
        "vsock_uds_path",
    ):
        if key in runtime:
            info[key] = runtime[key]
    info["runtime_metadata"] = path
    return info


def _matching_processes(output_dir: str, live_procs: list[dict]) -> list[dict]:
    real_output = os.path.realpath(output_dir)
    return [p for p in live_procs if p["out_dir"] == real_output]


def _device_status(output_dir: str, live_procs: list[dict]) -> tuple[str, int | None, list[dict]]:
    matches = _matching_processes(output_dir, live_procs)
    if matches:
        qemu = next((p for p in matches if p["kind"] == "qemu"), None)
        chosen = qemu or matches[0]
        return "running", chosen["pid"], matches
    if os.path.isfile(os.path.join(output_dir, ".ran")):
        return "ok", None, []
    return "failed", None, []


def list_instances(compose_dir: str) -> list[dict]:
    """Inventory devices under a compose_results directory."""
    live = _scan_qemu_processes()
    devices = []
    for entry in sorted(os.listdir(compose_dir)):
        device_dir = os.path.join(compose_dir, entry)
        if not os.path.isdir(device_dir):
            continue
        if not os.path.isfile(os.path.join(device_dir, "derived_config.yaml")):
            continue

        info = _merge_runtime(_load_instance(device_dir), device_dir)
        output_dir = info.get("output") or os.path.join(device_dir, "output")
        status, pid, procs = _device_status(output_dir, live)

        qemu = next((p for p in procs if p["kind"] == "qemu"), None)
        if qemu and qemu.get("telnet_port"):
            info["telnet_port"] = qemu["telnet_port"]

        info["status"] = status
        info["pid"] = pid
        info["output"] = output_dir
        info["processes"] = procs
        devices.append(info)
    return devices


def _resolve_compose_dir(compose_dir: str | None) -> str:
    if compose_dir is not None:
        return os.path.realpath(compose_dir)
    found = _find_compose_results(os.getcwd())
    if found is None:
        raise click.ClickException("No compose_results/ found under cwd. Pass --dir.")
    return found


def _network_text(device: dict) -> str:
    nets = []
    for net in device.get("networks") or []:
        if isinstance(net, dict):
            bits = [net.get("name") or "", net.get("ip") or "", net.get("mcast") or ""]
            nets.append("/".join(bit for bit in bits if bit))
    return ",".join(nets) or "-"


def _send_guest_command(unix_socket: str, port: int, command: str) -> tuple[int, str, str]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(unix_socket)
        s.sendall(f"CONNECT {port}\n".encode("utf-8"))
        response = s.recv(4096).decode("utf-8", "replace")
        if f"OK {port}" not in response:
            return 1, "", f"OK not received from vsock unix socket (got: {response})"
        s.sendall(command.encode("utf-8"))
        data = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
    result = json.loads(data.decode("utf-8"))
    return result["exit_code"], result.get("stdout", ""), result.get("stderr", "")


@click.group()
def utils():
    """Inspect and interact with a penguin compose session."""


@utils.command("list")
@click.option(
    "--dir", "compose_dir", type=click.Path(),
    default=None,
    help="Path to compose_results/ (default: search cwd).",
)
def list_cmd(compose_dir):
    """List compose devices with PID, shell port, vsock CID, networks, and status."""
    compose_dir = _resolve_compose_dir(compose_dir)
    devices = list_instances(compose_dir)
    if not devices:
        click.echo(f"No devices found under {compose_dir}")
        return

    header = ["DEVICE", "STATUS", "PID", "SHELL", "CID", "NETWORKS", "OUTPUT"]
    rows = [header]
    for device in devices:
        rows.append([
            device.get("name", "?"),
            device.get("status", "?"),
            str(device.get("pid") or "-"),
            str(device.get("telnet_port") or "-"),
            str(device.get("vsock_cid") or "-"),
            _network_text(device),
            device.get("output", "-"),
        ])
    widths = [max(len(row[i]) for row in rows) for i in range(len(header))]
    for row in rows:
        click.echo("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))

    connectable = [
        d for d in devices
        if d.get("status") == "running" and d.get("telnet_port") and d.get("root_shell") is not False
    ]
    if connectable:
        click.echo()
        click.echo("Root shells:")
        for device in connectable:
            ip = device.get("container_ip") or _container_ip() or "<container-ip>"
            click.echo(f"  {device['name']}: telnet {ip} {device['telnet_port']}")
            if name := (device.get("container_name") or os.environ.get("CONTAINER_NAME")):
                click.echo(
                    f"  {device['name']} (inside container): "
                    f"docker exec -it {name} telnet localhost {device['telnet_port']}"
                )

    guest_cmd_devices = [
        d for d in devices
        if d.get("status") == "running" and d.get("guest_cmd") and d.get("vsock_uds_path")
    ]
    if guest_cmd_devices:
        click.echo()
        click.echo("Guest commands:")
        for device in guest_cmd_devices:
            click.echo(
                f"  {device['name']}: penguin utils guest-cmd "
                f"--dir {compose_dir} {device['name']} -- '<command>'"
            )


@utils.command("guest-cmd", context_settings={"ignore_unknown_options": True})
@click.option(
    "--dir", "compose_dir", type=click.Path(),
    default=None,
    help="Path to compose_results/ (default: search cwd).",
)
@click.argument("device_name")
@click.argument("command", nargs=-1, type=click.UNPROCESSED)
def guest_cmd(compose_dir, device_name, command):
    """Run a command through a compose device's guesthopper vsock."""
    if not command:
        raise click.ClickException("Missing guest command.")

    compose_dir = _resolve_compose_dir(compose_dir)
    devices = {d.get("name"): d for d in list_instances(compose_dir)}
    device = devices.get(device_name)
    if device is None:
        raise click.ClickException(f"No device named {device_name!r} under {compose_dir}")
    if not device.get("guest_cmd"):
        raise click.ClickException(f"Device {device_name!r} does not have core.guest_cmd enabled")
    if not device.get("vsock_uds_path"):
        raise click.ClickException(f"Device {device_name!r} has no vsock UDS path in runtime metadata")

    exit_code, stdout, stderr = _send_guest_command(
        device["vsock_uds_path"],
        12341234,
        " ".join(command),
    )
    if stdout:
        click.echo(stdout, nl=False)
    if stderr:
        click.echo(stderr, nl=False, err=True)
    raise SystemExit(exit_code)
