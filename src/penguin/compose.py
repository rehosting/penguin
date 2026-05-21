"""
penguin.compose — multi-system firmware rehosting orchestration.

Reads a compose.yaml that describes multiple devices and the virtual networks
connecting them, then starts all devices in parallel. Devices communicate via
QEMU's socket/mcast backend: each compose network is a UDP multicast group
that provides a true L2 broadcast domain with no host privileges required.
"""
import hashlib
import logging
import os
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

import yaml

logger = logging.getLogger("penguin.compose")

MCAST_GROUP = "230.0.0.1"
MCAST_BASE_PORT = 11000


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class NetworkSpec:
    name: str
    subnet: str | None = None
    port: int = 0  # assigned during load_compose


@dataclass
class DeviceNetAttachment:
    network_name: str
    iface: str
    ip: str | None = None
    mac: str | None = None  # None → auto-generated


@dataclass
class DeviceConfig:
    name: str
    proj_dir: str
    config_path: str
    networks: list[DeviceNetAttachment] = field(default_factory=list)
    config_overrides: dict = field(default_factory=dict)


@dataclass
class ComposeConfig:
    version: int
    networks: dict[str, NetworkSpec]
    devices: dict[str, DeviceConfig]
    output_base_dir: str | None = None


@dataclass(frozen=True)
class RuntimeEndpointSpec:
    telnet_port_base: int
    telnet_port_count: int
    vsock_cid: int


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def load_compose(compose_path: str) -> ComposeConfig:
    """Parse and validate a compose.yaml. Raises ValueError on bad input."""
    compose_path = os.path.realpath(compose_path)
    base_dir = os.path.dirname(compose_path)

    with open(compose_path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError("compose.yaml must be a YAML mapping")

    version = data.get("version", 1)
    if version != 1:
        raise ValueError(f"Unsupported compose version: {version!r}")

    # Networks
    networks: dict[str, NetworkSpec] = {}
    for net_name, net_data in (data.get("networks") or {}).items():
        net_data = net_data or {}
        networks[net_name] = NetworkSpec(
            name=net_name,
            subnet=net_data.get("subnet"),
        )
    # Assign ports in sorted order so they're stable across edits
    for idx, name in enumerate(sorted(networks)):
        networks[name].port = MCAST_BASE_PORT + idx

    # Devices
    devices: dict[str, DeviceConfig] = {}
    for dev_name, dev_data in (data.get("devices") or {}).items():
        if not dev_data:
            raise ValueError(f"Device '{dev_name}' has no configuration")

        raw_proj = dev_data.get("project")
        if not raw_proj:
            raise ValueError(f"Device '{dev_name}' is missing required 'project' field")

        proj_dir = os.path.realpath(os.path.join(base_dir, raw_proj))
        if not os.path.isdir(proj_dir):
            raise ValueError(
                f"Device '{dev_name}': project directory not found: {proj_dir}"
            )

        config_path = dev_data.get("config") or os.path.join(proj_dir, "config.yaml")
        if not os.path.isfile(config_path):
            raise ValueError(f"Device '{dev_name}': config not found: {config_path}")

        net_attachments: list[DeviceNetAttachment] = []
        for net_name, att_data in (dev_data.get("networks") or {}).items():
            if net_name not in networks:
                raise ValueError(
                    f"Device '{dev_name}' references unknown network '{net_name}'"
                )
            att_data = att_data or {}
            iface = att_data.get("iface")
            if not iface:
                raise ValueError(
                    f"Device '{dev_name}', network '{net_name}': 'iface' is required"
                )
            net_attachments.append(DeviceNetAttachment(
                network_name=net_name,
                iface=iface,
                ip=att_data.get("ip"),
                mac=att_data.get("mac"),
            ))

        devices[dev_name] = DeviceConfig(
            name=dev_name,
            proj_dir=proj_dir,
            config_path=config_path,
            networks=net_attachments,
            config_overrides=dev_data.get("config_overrides") or {},
        )

    if not devices:
        raise ValueError("compose.yaml must define at least one device")

    return ComposeConfig(
        version=version,
        networks=networks,
        devices=devices,
        output_base_dir=(data.get("output") or {}).get("base_dir"),
    )


# ---------------------------------------------------------------------------
# Patch generation — pure logic, no penguin deps
# ---------------------------------------------------------------------------

def _generate_mac(compose_path: str, device_name: str, network_name: str) -> str:
    """Deterministically generate a locally-administered unicast MAC."""
    seed = f"{compose_path}:{device_name}:{network_name}"
    digest = hashlib.sha256(seed.encode()).digest()
    # Locally administered (bit 1 set) and unicast (bit 0 clear) in first octet
    b0 = (digest[0] & 0xFE) | 0x02
    return ":".join(f"{b:02x}" for b in [b0, *digest[1:6]])


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base in-place and return base."""
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val
    return base


def _build_compose_patch(
    device: DeviceConfig,
    networks: dict[str, NetworkSpec],
    compose_path: str,
) -> dict:
    """
    Build the patch dict that injects compose networking into a device's config.

    extra_qemu_args uses StrSepSpace so it concatenates (not replaces) with any
    existing value the project config already has.
    """
    qemu_arg_parts: list[str] = []
    ip_lines: list[str] = []

    for idx, att in enumerate(device.networks):
        net = networks[att.network_name]
        mac = att.mac or _generate_mac(compose_path, device.name, att.network_name)
        netdev_id = f"compose.{idx}"
        qemu_arg_parts.append(
            f"-netdev socket,id={netdev_id},mcast={MCAST_GROUP}:{net.port}"
            f" -device virtio-net-pci,netdev={netdev_id},mac={mac}"
        )
        if att.ip:
            ip_lines.append(f"ip link set {att.iface} up")
            ip_lines.append(f"ip addr add {att.ip} dev {att.iface}")

    patch: dict = {}

    if qemu_arg_parts:
        patch.setdefault("core", {})["extra_qemu_args"] = " ".join(qemu_arg_parts)

    if ip_lines:
        # Use static_files so we don't clobber any startup_script the user set
        script = "#!/igloo/utils/sh\n" + "\n".join(ip_lines) + "\n"
        patch["static_files"] = {
            "/igloo/init.d/zz_compose_net": {
                "type": "inline_file",
                "contents": script,
                "mode": 0o755,
            }
        }

    # config_overrides from compose.yaml are the final layer
    if device.config_overrides:
        _deep_merge(patch, device.config_overrides)

    return patch


# ---------------------------------------------------------------------------
# Per-device run — requires full penguin environment
# ---------------------------------------------------------------------------

def _prepare_device_run(
    device: DeviceConfig,
    networks: dict[str, NetworkSpec],
    compose_path: str,
    device_out_dir: str,
) -> str:
    """
    Write the compose patch and a derived config for this device.
    The derived config is a copy of the project's config.yaml with the compose
    patch appended to its patches list (using an absolute path so load_config
    can find it regardless of proj_dir).
    Returns the path to the derived config.
    """
    os.makedirs(device_out_dir, exist_ok=True)

    # Write the compose networking patch
    patch = _build_compose_patch(device, networks, compose_path)
    patch_path = os.path.join(device_out_dir, "patch_compose_net.yaml")
    with open(patch_path, "w") as f:
        yaml.dump(patch, f, default_flow_style=False)

    # Read the project's original config
    with open(device.config_path) as f:
        original = yaml.safe_load(f) or {}

    # Append our patch using an absolute path.
    # load_config resolves patches via Path(proj_dir, patch); when patch is
    # absolute, Path ignores proj_dir and returns the absolute path unchanged.
    patches_list = list(original.get("patches") or [])
    patches_list.append(patch_path)
    original["patches"] = patches_list

    derived_path = os.path.join(device_out_dir, "derived_config.yaml")
    with open(derived_path, "w") as f:
        yaml.dump(original, f, default_flow_style=False)

    return derived_path


DEFAULT_TELNET_PORT_BASE = 20000
DEFAULT_TELNET_PORT_BLOCK_SIZE = 100
DEFAULT_VSOCK_CID_BASE = 16


def _next_numbered_output_dir(base_dir: str) -> str:
    """
    Allocate base_dir/<N> and update base_dir/latest -> ./<N>.

    This mirrors `penguin run`'s default results layout: user-provided
    --output paths are exact destinations, while default/configured compose
    output bases get monotonically increasing numeric children.
    """
    if os.path.exists(base_dir) and not os.path.isdir(base_dir):
        raise RuntimeError(f"Output base exists and is not a directory: {base_dir}")

    os.makedirs(base_dir, exist_ok=True)

    def getint(name: str) -> int:
        try:
            return int(name)
        except ValueError:
            return -1

    existing = [
        getint(name)
        for name in os.listdir(base_dir)
        if os.path.isdir(os.path.join(base_dir, name))
    ]
    idx = max(existing) + 1 if existing else 0
    output_dir = os.path.join(base_dir, str(idx))
    os.makedirs(output_dir)

    latest_dir = os.path.join(base_dir, "latest")
    if os.path.lexists(latest_dir):
        if not os.path.islink(latest_dir):
            raise RuntimeError(
                f"Cannot update latest symlink because path exists and is not a symlink: {latest_dir}"
            )
        os.unlink(latest_dir)
    os.symlink(f"./{idx}", latest_dir)

    return output_dir


def _env_int(name: str, default: int, min_value: int = 0) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as e:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from e
    if value < min_value:
        raise ValueError(f"{name} must be >= {min_value}, got {value}")
    return value


def _runtime_endpoint_spec(idx: int) -> RuntimeEndpointSpec:
    """Return the reserved host-facing endpoint block for one compose device."""
    telnet_base = _env_int(
        "PENGUIN_COMPOSE_TELNET_BASE",
        DEFAULT_TELNET_PORT_BASE,
        min_value=1,
    )
    telnet_block = _env_int(
        "PENGUIN_COMPOSE_TELNET_BLOCK_SIZE",
        DEFAULT_TELNET_PORT_BLOCK_SIZE,
        min_value=1,
    )
    vsock_base = _env_int(
        "PENGUIN_COMPOSE_VSOCK_CID_BASE",
        DEFAULT_VSOCK_CID_BASE,
        min_value=3,
    )
    port = telnet_base + idx * telnet_block
    if port > 65535:
        raise ValueError(
            "compose telnet port allocation exceeded 65535; lower "
            "PENGUIN_COMPOSE_TELNET_BASE or PENGUIN_COMPOSE_TELNET_BLOCK_SIZE"
        )
    return RuntimeEndpointSpec(
        telnet_port_base=port,
        telnet_port_count=min(telnet_block, 65536 - port),
        vsock_cid=vsock_base + idx,
    )


def _write_instance_yaml(
    device: DeviceConfig,
    networks: dict[str, NetworkSpec],
    device_out_dir: str,
    endpoints: RuntimeEndpointSpec,
    runtime_metadata_path: str,
) -> None:
    """Record per-device runtime metadata so `penguin utils list` can show it."""
    nets = []
    for att in device.networks:
        net = networks[att.network_name]
        nets.append({
            "name": att.network_name,
            "iface": att.iface,
            "ip": att.ip,
            "mac": att.mac,
            "mcast": f"{MCAST_GROUP}:{net.port}",
        })
    data = {
        "name": device.name,
        "project": device.proj_dir,
        "output": os.path.join(device_out_dir, "output"),
        "telnet_port": endpoints.telnet_port_base,
        "telnet_port_range": [
            endpoints.telnet_port_base,
            endpoints.telnet_port_base + endpoints.telnet_port_count - 1,
        ],
        "vsock_cid": endpoints.vsock_cid,
        "runtime_metadata": runtime_metadata_path,
        "networks": nets,
        "compose_pid": os.getpid(),
    }
    with open(os.path.join(device_out_dir, "instance.yaml"), "w") as f:
        yaml.dump(data, f, default_flow_style=False)


def _run_device(
    idx: int,
    device: DeviceConfig,
    networks: dict[str, NetworkSpec],
    compose_path: str,
    device_out_dir: str,
    timeout: int | None,
    verbose: bool,
) -> dict:
    """Prepare, run, and score a single device. Returns score dict."""
    from penguin.penguin_config import load_config
    from .manager import PandaRunner, calculate_score
    from .common import get_inits_from_proj

    derived_config_path = _prepare_device_run(
        device, networks, compose_path, device_out_dir
    )

    out_dir = os.path.join(device_out_dir, "output")
    os.makedirs(out_dir, exist_ok=True)

    config = load_config(device.proj_dir, derived_config_path, verbose=verbose)

    specified_init = None
    if config.get("env", {}).get("igloo_init") is None:
        options = get_inits_from_proj(device.proj_dir)
        if options:
            specified_init = options[0]
        else:
            raise RuntimeError(
                f"Device '{device.name}': no init found. "
                "Set env.igloo_init in your project config."
            )

    endpoints = _runtime_endpoint_spec(idx)
    runtime_metadata_path = os.path.join(device_out_dir, "runtime.yaml")
    _write_instance_yaml(
        device, networks, device_out_dir, endpoints, runtime_metadata_path
    )

    try:
        PandaRunner().run(
            derived_config_path,
            device.proj_dir,
            out_dir,
            init=specified_init,
            timeout=timeout,
            show_output=False,  # each device writes to its own console.log
            verbose=verbose,
            resolved_kernel=config["core"]["kernel"],
            extra_env={
                "PENGUIN_TELNET_PORT_BASE": endpoints.telnet_port_base,
                "PENGUIN_TELNET_PORT_RANGE": endpoints.telnet_port_count,
                "PENGUIN_VSOCK_CID": endpoints.vsock_cid,
                "PENGUIN_RUNTIME_METADATA": runtime_metadata_path,
            },
        )
    except RuntimeError as e:
        logger.error(f"Device '{device.name}' run failed: {e}")
        return {}

    try:
        return calculate_score(out_dir)
    except Exception as e:
        logger.warning(f"Device '{device.name}' score calculation failed: {e}")
        return {}


# ---------------------------------------------------------------------------
# Orchestration entry point
# ---------------------------------------------------------------------------

def run_compose(
    compose_path: str,
    output_dir: str | None,
    timeout: int | None,
    force: bool,
    verbose: bool,
) -> None:
    """
    Parse compose.yaml, start all devices in parallel, and collect results.
    """
    # Wire up colored logging once we're inside the penguin environment
    try:
        from penguin import getColoredLogger
        global logger
        logger = getColoredLogger("penguin.compose")
    except ImportError:
        pass

    compose_path = os.path.realpath(compose_path)
    cfg = load_compose(compose_path)

    # Resolve output directory
    if output_dir is None:
        if cfg.output_base_dir:
            output_base_dir = os.path.realpath(
                os.path.join(os.path.dirname(compose_path), cfg.output_base_dir)
            )
        else:
            output_base_dir = os.path.join(os.path.dirname(compose_path), "compose_results")
        output_dir = _next_numbered_output_dir(output_base_dir)
    else:
        if os.path.exists(output_dir):
            if force:
                shutil.rmtree(output_dir)
            else:
                raise RuntimeError(
                    f"Output directory already exists: {output_dir}. "
                    "Use --force to overwrite."
                )
        os.makedirs(output_dir)

    shutil.copy(compose_path, os.path.join(output_dir, "compose.yaml"))

    logger.info(f"Compose: starting {len(cfg.devices)} device(s)")
    for name, net in cfg.networks.items():
        logger.info(f"  network '{name}': {MCAST_GROUP}:{net.port}")
    for name, dev in cfg.devices.items():
        logger.info(f"  device  '{name}': {dev.proj_dir}")

    results: dict[str, dict] = {}
    errors: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=len(cfg.devices)) as executor:
        futures = {
            executor.submit(
                _run_device,
                idx,
                device,
                cfg.networks,
                compose_path,
                os.path.join(output_dir, name),
                timeout,
                verbose,
            ): name
            for idx, (name, device) in enumerate(cfg.devices.items())
        }
        for future in as_completed(futures):
            name = futures[future]
            try:
                results[name] = future.result()
                logger.info(f"Device '{name}' complete. Scores: {results[name]}")
            except Exception as e:
                errors[name] = str(e)
                logger.error(f"Device '{name}' failed: {e}")

    summary = {
        "devices": {
            name: {
                "scores": results.get(name, {}),
                "error": errors.get(name),
            }
            for name in cfg.devices
        }
    }
    summary_path = os.path.join(output_dir, "compose_summary.yaml")
    with open(summary_path, "w") as f:
        yaml.dump(summary, f, default_flow_style=False)

    if errors:
        logger.error(
            f"Compose finished with errors in: {', '.join(errors.keys())}"
        )
    else:
        logger.info(f"Compose complete. Results in: {output_dir}")
