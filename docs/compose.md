# `penguin compose` — Multi-System Firmware Rehosting

`penguin compose compose.yaml` brings up a network of rehosted firmware systems
that communicate at L2 — think docker-compose but for emulated firmware devices.

## Networking backend: QEMU socket/mcast

Each compose network is a UDP multicast group. QEMU wraps raw Ethernet frames in
UDP, so ARP, DHCP, and NDP all work. Multiple QEMU instances that join the same
`mcast=<group>:<port>` share a full L2 broadcast domain.

No tap devices, no Linux bridge, no `CAP_NET_ADMIN` — works inside an ordinary
unprivileged Docker container. No new Python dependencies either; the args are
injected via the existing `core.extra_qemu_args` config field.

QEMU args injected per NIC:
```
-netdev socket,id=compose.0,mcast=230.0.0.1:11000
-device virtio-net-pci,netdev=compose.0,mac=52:54:00:aa:01:01
```

Port = `11000 + network_index`. MAC is deterministically derived from
`(compose_file_path, device_name, network_name)` so it is stable across re-runs.

## compose.yaml format

Place `compose.yaml` alongside your project directories (e.g., next to `projects/`).

```yaml
version: 1

networks:
  lan:
    subnet: 192.168.1.0/24    # optional — used only for startup_script IP config

devices:
  router:
    project: ./projects/router_fw   # path to penguin project dir (required)
    networks:
      lan:
        iface: eth0                 # guest interface name
        ip: 192.168.1.1/24          # optional: static IP via startup_script
        mac: "52:54:00:aa:01:01"    # optional: auto-generated if absent
    config_overrides:               # optional: merged as a final patch layer
      core:
        guest_cmd_timeout: 120

  client:
    project: ./projects/client_fw
    networks:
      lan:
        iface: eth0
        ip: 192.168.1.100/24

output:
  base_dir: ./compose_results       # optional; default ./compose_results
```

**`iface`** — the guest Linux interface name. The compose-generated virtio-net
device is assigned the specified MAC so the firmware can identify it. Ensure
your firmware names the interface as expected (normally `eth0`, `eth1`, etc.).

**`ip`** — if set, writes `ip link set <iface> up; ip addr add <ip> dev <iface>`
to the compose-generated `/igloo/init.d/zz_compose_net` startup script.

**`config_overrides`** — merged as the final patch layer on top of the project's
own `config.yaml` and any `patch_*.yaml` files.

## Usage

```sh
# Run all devices in parallel
./penguin compose compose.yaml

# Specify output directory and timeout
./penguin compose compose.yaml --output ./my_results --timeout 120

# Force-overwrite existing results
./penguin compose compose.yaml --force
```

## Results structure

```
compose_results/
  compose.yaml               # copy of input for reproducibility
  router/
    derived_config.yaml      # config actually used (with compose patch applied)
    patch_compose_net.yaml   # auto-generated network patch
    instance.yaml            # planned metadata: name, endpoint block, networks
    runtime.yaml             # actual runner metadata: shell port, vsock CID, sockets
    output/                  # PandaRunner output (console.log, health_final.yaml, ...)
    score.txt
  client/
    ...
  compose_summary.yaml       # aggregated scores across all devices
```

## Inspecting a running compose session

`penguin utils list` walks `compose_results/` and reports each device's
connection info: PID, root-shell port, vsock CID, mcast endpoint, output
directory, and status (`running`, `ok`, or `failed`):

```sh
./penguin utils list
# or, if compose_results/ lives somewhere unusual:
./penguin utils list --dir /path/to/compose_results
```

When run from the host, the wrapper execs the command into the active container
for the current workspace when exactly one is running. That lets `list` see
live QEMU processes as well as the result files. If no compose container is
running, it starts a short-lived utility container and reports what is available
from `compose_results/`.

For devices whose firmware exposes a guest root shell, the command also prints
ready-to-paste `telnet <container-ip> <port>` commands. Compose reserves a
bounded root-shell port block per device, using these defaults:

```sh
PENGUIN_COMPOSE_TELNET_BASE=20000
PENGUIN_COMPOSE_TELNET_BLOCK_SIZE=100
```

So device `idx` searches `base + idx*block_size` through the end of that block.
The runner records the actual selected port in `runtime.yaml`, and `list`
prefers live `/proc` data while the guest is running.

Compose also assigns a unique vsock CID per device so multiple guests can use
`plugins.vpn.enabled: true` or `core.guest_cmd: true` in the same container:

```sh
PENGUIN_COMPOSE_VSOCK_CID_BASE=16
```

For devices with `core.guest_cmd: true`, `penguin utils list` prints a
`penguin utils guest-cmd ...` command, and the command can be run directly:

```sh
./penguin utils guest-cmd router -- 'ip addr'
```

## Known limitations (multi-device in one container)

All compose devices run as parallel QEMU subprocesses inside a single Docker
container. Host-facing firmware services exposed by the VPN plugin still share
that container namespace, so two devices that both expose the same guest service
may race for the same host port. The VPN plugin will usually pick a free
alternate port, but explicit fixed maps must still be unique.

## Layout convention

All project directories must share a common parent with `compose.yaml`:

```
workspace/
  compose.yaml
  projects/
    router_fw/
      config.yaml
      base/
        fs.tar.gz
    client_fw/
      config.yaml
      base/
        fs.tar.gz
```

Run from `workspace/`: `./penguin compose compose.yaml`

The wrapper mounts the `compose.yaml` parent directory into the container, so
all relative `project:` paths resolve correctly.

## Internals

`penguin compose` is implemented in `src/penguin/compose.py`. It:

1. Parses and validates `compose.yaml`
2. Assigns a unique UDP multicast port per network (`11000 + index`)
3. Generates or uses explicit MAC addresses per device/network pair
4. For each device, writes a `patch_compose_net.yaml` with the socket netdev args
5. Writes a `derived_config.yaml` that extends the project config with that patch
6. Assigns each device a root-shell port block and vsock CID
7. Fans out via `ThreadPoolExecutor` — all devices start in parallel
8. Each device calls `PandaRunner().run(derived_config, proj_dir, out_dir, ...)`
9. Collects results into `compose_summary.yaml`

## Future: TAP backend

For higher throughput or firmware that probes link carrier state, a `backend: tap`
option can be added. This requires `CAP_NET_ADMIN` (the wrapper would add
`--cap-add=NET_ADMIN` for that case) and creates Linux tap devices bridged via
`ip link type bridge`. The socket/mcast backend covers the common research case
without privilege.
