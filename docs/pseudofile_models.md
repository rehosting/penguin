# Pseudofile model catalog

Penguin emulates device files (`/dev`, `/proc`, `/sys`, `/proc/sys`) by
attaching **models** to them in the `pseudofiles` config section. Each node
configures one or more **domains** — `read`, `write`, `ioctl`, `poll`, and the
lifecycle/seek ops `lseek`, `mmap`, `open`, `release` — and each domain selects
a named model with `model:` plus that model's fields.

This page is the catalog: every built-in model, what it does, when to use it,
and a copy-paste snippet. The goal is that most devices can be modeled in YAML
alone — no Python. When you do need Python, see
[Custom models](#custom-models-register_model) below; the rest of the plugin
authoring surface is in [pyplugin_architecture.md](pyplugin_architecture.md).

The full field reference is auto-generated in
[schema_doc.md](schema_doc.md#pseudofiles); this page is the human/AI-facing
how-to. Everything here is backwards compatible: omitting a domain keeps the
default behavior.

```yaml
pseudofiles:
  /dev/example:
    read:  {model: const_buf, val: "hello\n"}
    write: {model: discard}
    ioctl:
      "*": {model: return_const, val: 0}
```

---

## Read models

| `model:` | Behavior | Use when |
|----------|----------|----------|
| `zero` | Reads return the byte `0`. | Stub a node that just needs to be non-empty. |
| `one`  | Reads return the byte `1`. | A flag/gpio that should read high. |
| `empty` | Immediate EOF. | A readable node that should look empty. |
| `const_buf` | Return a fixed buffer. | A node with fixed contents (version string, status). |
| `cycle` | Repeat a buffer forever (never EOF). | An endless stream (entropy-like, repeating pattern). |
| `const_map` | Sparse offset→value buffer of a given size. | A register/struct image with values at known offsets. |
| `const_map_file` | `const_map` persisted to a host file. | Same, but you want the rendered image on disk. |
| `from_file` | Serve bytes from a host file. | Back the node with a real file you provide. |
| `stateful` | Read back whatever was last **written** to this node. | A read/write register or scratch node. |
| `sequence` | Return each entry of a list on successive reads. | "busy… busy… ready" status polling. |
| `from_plugin` | Call a plugin function. | Logic that can't be expressed declaratively. |
| `custom` | A model registered via `@register_model`. | Reusable Python model, selected by name. |
| `default` | Return `-EINVAL`. | Explicitly reject reads. |

```yaml
# Fixed contents
/proc/version_stub:
  read: {model: const_buf, val: "Linux 4.10\n"}

# Read-after-write register (pair stateful read + recording write)
/dev/scratch:
  read:  {model: stateful, initial: "0"}
  write: {model: default}

# Status that becomes ready after two polls, then stays ready
/proc/device_status:
  read: {model: sequence, vals: ["busy\n", "busy\n", "ready\n"]}
```

## Write models

| `model:` | Behavior | Use when |
|----------|----------|----------|
| `discard` | Accept and drop writes (returns count). | Writes you can safely ignore. |
| `default` | Record writes into an in-memory buffer. | Pair with `read: stateful` for a register. |
| `to_file` | Append/write to a host file. | Capture what the guest writes for inspection. |
| `return_const` | Return a fixed value/errno from `write()`. | Force a specific write result (e.g. an errno). |
| `unhandled` | Return `-EINVAL`. | Explicitly reject writes. |
| `from_plugin` | Call a plugin function. | Custom write logic. |
| `custom` | A model registered via `@register_model`. | Reusable Python model. |

```yaml
/dev/logsink:
  write: {model: to_file, filename: "./results/latest/guest_writes.bin"}
```

## ioctl models

`ioctl` is a map from command number (or `"*"` for the wildcard) to a model.
A bare model (no command map) applies to every command.

| `model:` | Behavior | Use when |
|----------|----------|----------|
| `return_const` | Return a fixed value. | The driver just checks the return code. |
| `zero` | Return 0 (success). | Acknowledge any ioctl. |
| `write_data` | Write a constant buffer to the `arg` pointer, then return `val`. | An ioctl that fills a caller-supplied struct. |
| `unhandled` | Return `-ENOTTY`. | Explicitly reject an ioctl. |
| `from_plugin` | Call a plugin function. | Command-dependent logic. |

```yaml
/dev/widget:
  ioctl:
    0x1234: {model: write_data, data: "\x01\x00\x00\x00", val: 0}
    "*":    {model: return_const, val: 0}
```

## poll models

| `model:` | Behavior | Use when |
|----------|----------|----------|
| `always_ready` | Report readable+writable (legacy default for `/dev`). | Node is always ready. |
| `from_plugin` | Plugin returns a data-aware poll mask. | Readiness depends on state. |

## Other VFS operations

Beyond read/write/ioctl/poll you can model the rest of the `file_operations`
surface. Omit a domain to keep the kernel default. Most are plugin-driven; the
plugin function takes that op's native VFS arguments.

| domain | `model:` | Behavior |
|--------|----------|----------|
| `lseek` | `default` | Standard offset arithmetic against the node's size. |
| `lseek` | `unsupported` | Return `-ESPIPE` (pipe/stream-like node). |
| `lseek` | `from_plugin` | Plugin `lseek(ptregs, file, offset, whence)`. |
| `mmap` | `from_plugin` | Plugin `mmap(ptregs, file, vm_area_struct)`. |
| `open` | `from_plugin` | Fire a plugin function when the node is opened. |
| `release` | `from_plugin` | Fire a plugin function when the node is closed. |
| `compat_ioctl` | `same_as_ioctl` | Route 32-bit compat ioctls through the `ioctl` model. |
| `compat_ioctl` | `from_plugin` | Plugin `compat_ioctl(ptregs, file, cmd, arg)`. |
| `flush` | `from_plugin` | `/dev`-only. Plugin `flush(ptregs, file, owner)`. |
| `fsync` | `from_plugin` | `/dev`-only. Plugin `fsync(ptregs, file, start, end, datasync)`. |
| `fasync` | `from_plugin` | `/dev`-only. Plugin `fasync(ptregs, fd, file, on)`. |
| `lock` | `from_plugin` | `/dev`-only. Plugin `lock(ptregs, file, cmd, file_lock)`. |
| `read_iter` | `from_plugin` | Plugin `read_iter(ptregs, kiocb, iov_iter)`. |
| `write_iter` | `from_plugin` | Plugin `write_iter(ptregs, kiocb, iov_iter)`. |
| `get_unmapped_area` | `from_plugin` | Plugin `get_unmapped_area(ptregs, file, addr, len, pgoff, flags)`. |

> `flush`/`fsync`/`fasync`/`lock`/`write_iter` are character-device fops: valid
> only on `/dev` nodes. `lseek`/`mmap`/`open`/`release`/`compat_ioctl`/`read_iter`/
> `get_unmapped_area` are valid on `/dev` and `/proc` but not `/proc/sys`
> (sysctl) or `/sys` (sysfs), which only service reads/writes. Config validation
> **rejects** an op attached to a node whose filesystem can't service it.

```yaml
/dev/stream:
  read:  {model: sequence, vals: ["a", "b", "c"]}
  lseek: {model: unsupported}
  open:  {model: from_plugin, plugin: my_plugin, function: on_open}

/dev/widget64:
  ioctl: {"*": {model: return_const, val: 0}}
  compat_ioctl: {model: same_as_ioctl}   # 32-bit callers get the same handlers
```

## MTD flash devices

MTD nodes (`/dev/mtdN`, `/proc/mtd`) are **not** modeled through `pseudofiles`
— they have a dedicated native subsystem with its own `devices:` config block
(geometry, personality, backing). Legacy `pseudofiles: /dev/mtdN` entries are
auto-migrated into it.

```yaml
devices:
  flash0:
    id: 0
    model: backing_file        # or 'zeros' (blank flash) / 'const_buf'
    backing_file: ./flash0.bin
    mode: rw                   # 'ro' for read-only
    personality:
      type: nor                # 'nand' or 'nor' (sets erase/write/oob defaults)
      erase_size: 64k
```

Models: `zeros` (RAM-backed blank flash), `const_buf` (in-RAM initial image),
`backing_file` (host file). For fully custom flash physics (read/write/erase),
register an `MtdDevice` subclass in Python via `plugins.mtd.register_mtd(dev)`.

> Note: the `devices:` block is currently a free-form mapping in the schema
> (not yet a typed/validated structure), so consult this section for field
> names. Geometry units accept suffixes (`k`/`m`/`g`).

---

## Provenance (discovered defaults)

Every model takes an optional `provenance:` tag. During `init`, the
`pseudofiles.dynamic` patch auto-generates **stub** models (`read: zero`,
`write: discard`, `ioctl "*": return_const 0`) for every discovered pseudofile
and tags them `provenance: default`. A tagged-default model reports its own
activity into `pseudofiles_failures.yaml` (events `default_read`,
`default_write`, `default_ioctl`, with captured write payloads and ioctl
commands), so a stub that is actively shaping guest behavior shows up as
"needs a real model" instead of silently succeeding with garbage.

Leave `provenance` unset on models you author intentionally — only tagged
defaults self-report.

```yaml
/dev/discovered:
  read:  {model: zero,    provenance: default}
  write: {model: discard, provenance: default}
```

---

## Custom models (`@register_model`)

When declarative models aren't enough, register a Python mixin under a name and
select it from YAML with `model: custom`. This is the low-friction "expand with
Python" path — far less boilerplate than a full backing class.

Drop a file in the project's `plugins.d/` (auto-loaded — see
[local_plugins.md](local_plugins.md)):

```python
# plugins.d/my_models.py
from hyperfile.models.registry import register_model
from hyperfile.models.read import ReadBufWrapper

@register_model("read", "my_sensor")
class MySensorRead(ReadBufWrapper):
    def __init__(self, *, scale=1, **kwargs):
        super().__init__(buffer=str(42 * scale).encode(), **kwargs)
```

Then in `config.yaml` — `model_name` selects the registered model and any extra
keys are forwarded to its constructor:

```yaml
pseudofiles:
  /dev/sensor:
    read: {model: custom, model_name: my_sensor, scale: 10}
```

`register_model(domain, name)` supports the `read`, `write`, `poll`, `lseek`,
`mmap`, `open`, and `release` domains. The mixin follows the same VFS contract
as the built-ins (generator methods, `ptregs.retval`, `super().__init__(**kwargs)`).
For a model that owns the *entire* file-operations surface in one class, use a
backing class instead (`plugin: file:ClassName`) — see
[plugins.md](plugins.md#pseudofiles).
