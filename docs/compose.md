# `penguin compose` — Multi-Device Firmware Rehosting

`penguin compose` runs multiple firmware guests in parallel and wires them
together over a shared L2 broadcast domain. Each device runs as its own
PANDA-QEMU guest with its own project config; the only thing compose adds is
the virtual network glue.

The networking backend is QEMU's `socket,mcast=...` netdev. No tap devices,
no Linux bridge, no `CAP_NET_ADMIN` — everything works inside an ordinary
unprivileged container.

## Invocation

### Form 1: run an existing compose project

Pass a directory containing a `compose.yaml`, or the YAML file directly:

```sh
./penguin compose ./compose_projects/my_setup
./penguin compose ./compose_projects/my_setup/compose.yaml
```

Results land in `<compose-dir>/results/<N>/`, with `results/latest` updated
to point at the most recent numbered run.

### Form 2: scaffold and run from device projects

Pass two or more device project directories. Compose generates a fresh
compose project, then runs it:

```sh
./penguin compose ./projects/fw1 ./projects/fw2
./penguin compose ./projects/fw1 ./projects/fw2 ./projects/fw3
```

The scaffolded directory is placed alongside the device projects' parent —
if the device projects live in `./projects/`, compose writes the new
project under `./compose_projects/<YYYY-MM-DD_HHMMSS>/`. Each device is
attached to a single `lan` network (`192.168.1.0/24`) on `eth0`, with IPs
assigned in argument order: the first project gets `192.168.1.1`, the
second `192.168.1.2`, and so on.

Re-running the same arguments produces a different timestamp, so the second
invocation creates a new scaffolded directory rather than overwriting the
first. To re-run an already-scaffolded setup (and keep its IP assignments
and numbered results history), pass that directory to Form 1.

## YAML schema

```yaml
version: 1

networks:
  lan:
    subnet: 192.168.1.0/24       # optional; informational only

devices:
  server:
    project: ./projects/fw1      # path to a penguin project (required)
    networks:
      lan:
        iface: eth0              # guest interface name (required)
        ip: 192.168.1.1/24       # optional: static IP via startup script
        mac: "52:54:00:aa:01:01" # optional: auto-generated if omitted
    config_overrides:            # optional: merged as a final patch layer
      core:
        guest_cmd_timeout: 120

  client:
    project: ./projects/fw2
    networks:
      lan:
        iface: eth0
        ip: 192.168.1.2/24

output:
  base_dir: ./results            # optional; default ./results next to compose.yaml
```

Field notes:

- **`project`** — path to a device project directory containing `config.yaml`,
  resolved relative to `compose.yaml`.
- **`iface`** — the Linux interface name the guest is expected to use for
  this attachment. The compose-generated NIC's MAC is set so the firmware
  can pin the interface; verify your firmware actually names it as
  declared (typically `eth0` for a single attachment).
- **`ip`** — if set, compose writes `ip link set <iface> up; ip addr add
  <ip> dev <iface>` into `/igloo/init.d/zz_compose_net` so traffic flows
  at boot.
- **`mac`** — if omitted, a stable locally-administered MAC is derived
  from `(compose path, device name, network name)`.
- **`config_overrides`** — merged as the final patch layer on top of the
  device project's own `config.yaml` and any `patch_*.yaml` files.
- **`output.base_dir`** — base directory for numbered runs, resolved
  relative to `compose.yaml`.

The authoritative schema lives in `src/penguin/compose.py` (`load_compose`,
`DeviceConfig`, `NetworkSpec`, `DeviceNetAttachment`).

## Output layout

```
<compose-project>/
  compose.yaml
  results/
    latest -> ./0
    0/
      compose.yaml                  # copy of the input for reproducibility
      compose_summary.yaml          # per-device scores and errors
      server/                       # runner's output dir for this device
        console.log
        netbinds.csv
        ...
      client/
        console.log
        ...
      .compose/
        server/
          derived_config.yaml       # device config + injected compose patch
          patch_compose_net.yaml    # auto-generated net patch
          instance.yaml             # planned metadata (endpoints, networks)
          runtime.yaml              # actual runtime metadata from the runner
          qemu_stdout.txt
          qemu_stderr.txt
        client/
          ...
```

Per-device analysis output (`console.log`, `netbinds.csv`, `health_final.yaml`,
etc.) sits directly under `<device_name>/`, exactly as a single-device
`penguin run` would write it. Compose-specific bookkeeping (derived
configs, generated patches, QEMU stdio, runtime metadata) is tucked under
`.compose/<device_name>/` so it doesn't clutter the analysis tree.

`compose_summary.yaml` aggregates each device's score dict and any
top-level error from its run.

## Inspecting a running compose session

`penguin utils list` prints a table of the devices in a compose run. With
no `--dir`, it searches the current directory for a `results/latest` (or
numbered run) layout.

```
$ penguin utils list
DEVICE    STATUS   PID    SHELL  CID  NETWORKS         OUTPUT
device_a  running  12345  20000  16   lan(192.168.1.2) results/latest/device_a
device_b  running  12346  20100  17   lan(192.168.1.3) results/latest/device_b
```

Columns are: device name, runner status, runner PID, per-device telnet port
on the docker container, vsock CID for `guest_cmd`, attached networks with
the assigned guest IP, and the device's output directory. When devices are
running, the command also prints ready-to-paste telnet and
`penguin utils guest-cmd` lines.

If `core.core_shell` is enabled, each device exposes a root shell on its
telnet port. From the docker host:

```
telnet 192.168.0.2 20000
```

or, from inside the penguin container:

```
docker exec -it <container-name> telnet localhost 20000
```

Endpoint allocation is controlled by three env vars (read at compose-start
time):

| Var                                | Default | Effect                              |
|------------------------------------|---------|-------------------------------------|
| `PENGUIN_COMPOSE_TELNET_BASE`      | `20000` | Telnet port for the first device.   |
| `PENGUIN_COMPOSE_TELNET_BLOCK_SIZE`| `100`   | Port stride between devices.        |
| `PENGUIN_COMPOSE_VSOCK_CID_BASE`   | `16`    | vsock CID for the first device.     |

Bump these when running multiple compose sessions on the same host (so
their port/CID blocks don't collide) or when the default block runs into
the 65535 cap with very large device counts.

The source-of-truth files behind `penguin utils list` are
`.compose/<device>/instance.yaml` (planned endpoints + networks, written
before the runner starts) and `.compose/<device>/runtime.yaml` (actual
PID, status, and endpoints from the runner). If a session crashes, those
two files plus `qemu_stdout.txt` / `qemu_stderr.txt` next to them are the
right place to start.

## How it works

Each entry under `networks:` is assigned a UDP multicast port, and every
device attached to that network gets matching QEMU args injected via
`core.extra_qemu_args`:

```
-netdev socket,id=compose.0,mcast=230.0.0.1:<port>
-device virtio-net-pci,netdev=compose.0,mac=<mac>
```

All QEMU processes that join the same `mcast=<group>:<port>` share one L2
broadcast domain — ARP, DHCP, and link-local discovery all work because
QEMU just wraps raw Ethernet frames in UDP. The kernel inside each guest
enumerates the injected NIC normally (typically as `eth0` for a single
attachment), and the compose-generated `/igloo/init.d/zz_compose_net`
script brings it up and assigns the static IP. The multicast plumbing is
internal to the QEMU processes; the host does not need any privileges or
network configuration.

## Caveats

- **No boot ordering.** All devices start in parallel. If a client probes
  a server's port before the server has bound it, the probe will fail —
  application-level retry is on you.
- **L2 only.** Compose provides a shared broadcast domain and (optionally)
  static IPs. There is no DHCP server, no default gateway, no NAT, and no
  routing between compose networks. Devices that need DHCP must serve it
  themselves from one of the guests.
- **Single container, shared host ports.** All compose devices run as
  parallel QEMU subprocesses inside one Penguin container. Plugins that
  expose host-facing ports (e.g. the VPN plugin) share that namespace, so
  fixed host-port mappings must not collide across devices.
- **Scaffolded directories are timestamped, not idempotent.** Form 2
  always creates a new directory. Use Form 1 against the scaffolded
  directory to re-run a setup.
