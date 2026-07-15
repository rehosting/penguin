# `penguest` — the in-guest Python binding

`penguest` is a small Python module shipped **into the emulated guest** so that
Python scripts running inside the target can talk back to the Penguin host. It
is the guest-side complement to the host's portalcall dispatcher
(`pyplugins/apis/portalcall.py`) and reuses the exact ABI the C helpers already
use (`guest-utils/native/portal_call.h`) — it does not invent a new mechanism.

## What's in the guest

Penguin ships a **full CPython** interpreter into the guest as a pristine
nixpkgs glibc runtime closure (via `penguin-tools`), reachable through the
wrapper `/igloo/utils/python3`. Because it is a real CPython, the **entire
standard library is available** — this is not a cut-down or static build.

Guidance for scripts (and for anything the AI-rehosting loop authors):

- **Rely on the pure-Python stdlib + `ctypes`.** `os`, `sys`, `struct`, `json`,
  `socket`, `ctypes`, etc. are always present and portable across the target
  architectures. `penguest` itself uses only `ctypes`/`os` (portal) and
  `socket`/`json`/`struct` (vsock).
- Avoid pinning behaviour to CPython internals or optional C extensions that may
  vary; keep probe scripts to the batteries above so they run identically on
  every arch.

## `penguest.portal_call`

```python
import penguest

# Lands at the host handler registered with @plugins.portalcall.portalcall(M).
result = penguest.portal_call(M, arg0, arg1, ...)   # up to 10 integer args
```

`portal_call` lowers to `syscall(SYS_sendto, PORTAL_MAGIC, user_magic, argc,
&args, 0, 0)` — identical to `portal_call.h`. The host intercepts the `sendto`
syscall (filtered on `PORTAL_MAGIC = 0xc1d1e1f1`), reads the argument array, and
dispatches to the matching `@portalcall(M)` handler; its integer return value
comes back as `portal_call`'s result. Arguments are register-width integers; to
pass a buffer, pass its address and length and have the host handler read guest
memory (this is what `penguest.log` does).

## `penguest.log` / `penguest.report`

Typed helpers built on `portal_call` for the common case of handing text to the
host:

```python
penguest.log("boot reached stage 2", level="warning")
penguest.report("suspicious write to /dev/mtd0")   # == log(..., level="finding")
```

Each packs the message into a buffer and makes a `portal_call` carrying
`(pointer, length, level)`. The **host bridge** (`pyplugins/apis/penguest.py`,
on by default) reads the string out of guest memory and emits it into the run's
penguin log, prefixed `[guest]` (or `[guest finding]` for `report`, the hook the
#835 AI-rehosting loop consumes). Levels: `debug`/`info`/`warning`/`error`/
`finding`. Guest log lines are also persisted (lazily, on first use) to
`<results>/…/penguest_guest.log` as `level<TAB>message`, so they survive the run
for tooling and the AI loop to read back.

## `penguest.vsock` — AF_VSOCK request/response

For payloads bigger or streamier than a portalcall's register args, connect to
the host over vsock (from a guest, the host is always CID `2`):

```python
with penguest.vsock.connect() as c:        # -> host penguest endpoint (CID 2)
    c.send_json({"op": "ping"})
    reply = c.recv_json()                  # {"pong": True}
```

`VsockConn` frames messages as a 4-byte big-endian length prefix + JSON, so a
receiver recovers message boundaries on the byte stream. `connect()` defaults to
`PENGUEST_VSOCK_PORT`, the port of the host endpoint below.

### Host endpoint

`pyplugins/apis/penguest_vsock.py` (on by default) is the host side. With
vhost-device-vsock a guest-initiated connection to `(CID 2, port P)` is forwarded
to a host Unix socket at `<uds_path>_<P>`, so the endpoint **listens** there and
serves framed JSON on a background thread. It ships `ping` and `echo`; any plugin
can register more:

```python
@plugins.penguest_vsock.endpoint("whoami")
def _whoami(req):
    return {"pid": req.get("pid")}
```

The endpoint is a no-op on runs without vsock (`vpn` disabled). The transport
itself is already wired — the custom QEMU builds `CONFIG_AF_VSOCK` and Penguin
launches `vhost-device-vsock` (pinned **v0.2.0**) for the guest.

Typed convenience wrappers over more portal ops (read/write mem, osi_proc, …)
remain a follow-on (draft 16 Slice 1+).

### Architecture note

`portal_call.h` gets `SYS_sendto` from the C toolchain at compile time; the
ctypes shim resolves it at runtime. The authoritative source is the
`PENGUEST_SYS_SENDTO` environment variable; absent that, `penguest` derives it
from `os.uname().machine` via a built-in per-arch table. It issues the raw
`sendto` syscall (not libc's `sendto()` wrapper) to mirror `portal_call.h`
exactly and to avoid arches that might route `sendto()` through the legacy
`socketcall` multiplexer.

## Staging

- **Interpreter:** the CPython closure is baked into the base image at
  `/igloo/nix/store/...`; the per-run wrapper `/igloo/utils/python3` runs it
  inside a private mount namespace (see `pyplugins/core/live_image.py`).
- **Module:** the `penguest` package is installed into the guest at
  `/igloo/pylib/penguest/` via `static_files` (see
  `penguin_config/__init__.py`), and the `/igloo/utils/python3` wrapper puts
  `/igloo/pylib` on `PYTHONPATH`. So any script run through that interpreter —
  including a `.py` [init drop-in](init_dropins.md) — can `import penguest`
  with no extra setup. `PYTHONPATH` is scoped to the wrapper and is **not**
  leaked into the firmware's own environment.

> **Don't name your script `penguest.py`.** CPython puts a script's own
> directory first on `sys.path`, so a script literally named `penguest.py`
> shadows the staged package and `import penguest` imports the script itself.
> Name drivers/probes something else (e.g. `penguest_probe.py`).

## Testing

- **Host unit tests** (`tests/unit/test_penguest.py`): the `portal_call` packing
  matches `portal_call.h`, a two-sided round-trip through the real
  `portalcall.py`, the `vsock` JSON framing, `log`/`report` packing, the host
  bridge reading guest memory + persisting the log file, and the host vsock
  endpoint (dispatch, a guest `VsockConn` ↔ host round-trip over a socket pair,
  and a live listener bind/serve/teardown).
- **In-guest integration test** (`tests/integration/test_target/patches/tests/penguest.yaml`):
  a `.py` driver exec'd via its `#!/igloo/utils/python3` shebang that imports
  `penguest`, makes a `portal_call` to a host handler, calls `log`/`report`, and
  does a `vsock.connect()` round-trip to the host endpoint (guest →
  vhost-device-vsock → `penguest_vsock`). This is the one place the daemon's
  guest→host forwarding is exercised end-to-end. It proves the whole path on real
  guest CPython and runs on the full arch matrix. (The 32-bit guest-python3 hang/ENOSYS, penguin#876, is fixed in
  the pinned penguin-tools via penguin-tools#20's glibc vDSO runtime-gate for
  mipsel/mipseb/armel; 64-bit arches were never affected.)

## Security

The guest is untrusted firmware, so these are host-facing channels. Notes:

- The `portal_call` transport is already always-on (any guest process can make
  the raw `sendto`); the `penguest` binding adds no new transport, only handlers.
- **Two handlers are on by default** (`default_plugins`): the `penguest` log
  bridge and the `penguest_vsock` endpoint. Both take untrusted guest input, so
  they are hardened: the log bridge caps the read (64 KiB), strips control chars
  from the message (no log-line forgery / terminal-escape injection), and bounds
  the persisted log file; the vsock endpoint serves each connection on a capped
  pool of workers with a per-connection recv timeout, so a stalled or flooding
  guest can't wedge it, and rejects oversize frames.
- **Disable per run** (e.g. for adversarial-firmware analysis):

  ```yaml
  plugins:
    penguest: { enabled: false }        # drop the guest -> host log handler
    penguest_vsock: { enabled: false }  # no host vsock listener
  ```

  `penguest_vsock` is also inherently a no-op when `vpn`/vsock is off. Tunables:
  `vsock_max_conns`, `vsock_conn_timeout`, `guest_log_max_bytes`.

## Follow-ons (not yet implemented)

Draft 16 Slices 2 & 4:

- **Host-driven guest execution** — `run_guest_python(script, args)` over
  guesthopper's vsock command channel (guesthopper isn't checked out in this
  worktree).
- **Binding to the live cartography model / the #835 loop** — as vsock endpoint
  ops (`@plugins.penguest_vsock.endpoint(...)`) that query the model and report
  findings.

These build on `portal_call`, the `vsock` client + host endpoint, and the
staging above.
