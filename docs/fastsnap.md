# Fastsnap: fast in-process guest reset

Rewind a booted guest to a recorded instant in a few hundred microseconds,
instead of the tens of milliseconds a `savevm`/`loadvm` round trip costs. This
is what makes a fuzzing or search loop viable inside Penguin: the same code
path, run thousands of times a second, from the same state every time.

Measured end to end on a real firmware target: **1,381 iterations/second** with
a 348 µs reset, verified byte-identical to an independently forked reference on
every check.

## When you want it

Anything that runs the same guest code many times from one state: fuzzing a
parser, sweeping inputs through a request handler, re-running one operation
under varying conditions. Without a reset, every iteration pays for a process
restart — measured, that is where a crash-dense workload spends nearly all its
budget, and it is enough to make a working fuzzer look weak.

## When you do not

It is not a general-purpose snapshot. It restores **device state and guest
RAM**, and deliberately not:

- anything living outside the VM. Host-side backends move on: the network
  backend, a block device's host file, an open socket.
- devices whose state is co-located with guest RAM plus a host-side backend.
  virtio is the case that matters, and it is denied by default — restoring the
  model's `last_avail_idx` while the backend has moved on makes `virtio_load()`
  reject the block outright.

Use `plugins.snapshot` for a real snapshot you want to keep.

## Quick start

```python
from penguin import plugins, Plugin
from penguin import plugins as _p
syscalls = _p.syscalls


class MyLoop(Plugin):
    def __init__(self):
        missing = plugins.fastsnap.missing_symbols()
        if missing:
            raise RuntimeError(f"stale QEMU image, missing: {missing}")
        self.ticket = None
        self.n = 0

    @syscalls.syscall("on_sys_read_enter")
    def on_read(self, regs, proto, sc, *args):
        if self.ticket is None:
            # Arm ONCE, where the guest is about to do the work you want to
            # repeat. See "the arming point" below -- this line is worth more
            # than any other tuning you can do here.
            self.ticket = plugins.fastsnap.arm()
            return
        if not self.ticket.done():
            return                          # the bottom half has not run yet

        self.n += 1
        r = self.ticket.result()
        if r.get("diff_pages", 0) > 0:
            self.logger.error(f"reset left {r['diff_pages']} pages wrong")

        # ... deliver the next input here ...
        self.ticket = plugins.fastsnap.reset(verify=(self.n % 50 == 0))
```

Enable it like any other plugin:

```yaml
plugins:
  fastsnap:
    deny: auto        # the default
  myloop: {}
```

## Scheduling is not doing

Every operation runs in a QEMU bottom half on the main loop, while your plugin
callback runs on a vCPU thread. Blocking on completion from that callback
deadlocks. So each call returns a **ticket**, and you poll it from a later
callback:

```python
t = plugins.fastsnap.arm()
...
if t.done():
    r = t.result()
```

`result()` raises if the operation has not completed. That is deliberate: the
accessors behind it are single-slot, so the alternative to raising is returning
the *previous* operation's timings and diffs — which is indistinguishable from
a real answer and has produced entire result sets that were fiction.

## The arming point is yours, and it is the biggest lever

Nothing here decides when to arm.

An iteration costs the span **from the armed instant to the next detector hit**,
because that is exactly what a reset rewinds. Arming at "the next convenient
callback" therefore draws a random sample from that detector's interval
distribution, and if the guest happens to be doing something slow at that
moment — generating an SSH host key, say — every subsequent iteration replays
it. Measured on real firmware, the gap between a well-chosen arming point and a
blind one was **29x**. That is larger than the reset, larger than the device
allowlist, larger than anything else in this document.

Arm where the guest is about to do the work you want to repeat, and not before.

## Scoping the device block

The device half of a reset is the expensive half; the RAM half is tens of
microseconds for an ordinary working set.

| scope | sections | restore |
|---|---|---|
| all | 17 | 0.752 ms |
| `{cpu, timer}` | 2 | 0.043 ms |

`deny` leaves sections out and is conservative — anything nobody named is still
restored. `allow` keeps **only** what is named, and is the only setting here
whose failure mode is silence: a section left out is not restored, nothing
errors, and the guest misbehaves thousands of iterations later with nothing
pointing back at the configuration.

So run an allowlist with verification on, and read `dev_sections`.

```python
plugins.fastsnap.scope(allow="cpu,timer")
```

Section ids are not unique — some machines register two sections with the same
name — and both lists match by name, so naming one matches every section that
carries it. `plugins.fastsnap.sections()` lists what this machine has.

## Checking that the reset is correct

`reset(verify=True)` runs two independent oracles in the same bottom half as the
reset, so nothing executes in between and any difference found is the reset's
rather than the guest's:

- **RAM**, against a child forked at the arm, parked in `pause()`, read back
  with `process_vm_readv()` and compared page by page. It shares no code with
  the restore — which reads an in-process copy — so neither can launder the
  other's mistakes.
- **Devices**, per section, against a reference covering the *full* section set
  whatever the block was scoped to. This is what sees a section an allowlist
  dropped; the RAM oracle cannot, it only sees the guest damage that eventually
  follows.

```python
r = ticket.result()
r["diff_pages"]    # 0 = every byte back.   -1 = the oracle could not look.
r["dev_sections"]  # 0 = every section back. -1 = could not compare.
r["dev_report"]    # names of the sections that did not come back
r["us"]            # the reset alone
r["diff_us"]       # the oracle, ~80x the reset -- verify on a schedule
```

**`-1` is not `0`.** It means the oracle was blind, and the run says nothing in
either direction. Treating it as a pass is how an instrument that reported its
own blindness got believed for an entire run.

Verification reads all of guest RAM back, so verify every Nth iteration, not
every one. `us` is always the reset alone; the oracle's cost is its own field,
because folding them together makes every verified reset look two orders of
magnitude more expensive while looking entirely plausible.

## `state_digest()`

Digests the whole guest — every RAM block, then the device block — with the
vCPUs stopped. Two runs that executed the same thing from the same state must
agree.

This is the health signal that does not depend on the guest being well enough
to report. Userspace crash reporting is blind to kernel-side damage: measured,
a run with 98 lines of kernel panic, `swap_dup` errors and OOM kills produced a
`crashes.yaml` identical in shape to a healthy one, because a panic is not a
userspace fatal signal.

## Requirements

A QEMU image built from a `qemu_builder` tree carrying the fastsnap patch set.
`plugins.fastsnap.missing_symbols()` returns the ABI entry points this image
does not export; check it **before** a run. A missing symbol is not an
exception at the call site — it reads as a plausible default, and a run against
a stale image produces a complete, plausible, entirely fictional result set.

Exercised so far on armel and mipsel guests under TCG, plus an aarch64
selftest. Other targets are expected to work and have not been measured; KVM
links but has never been run, and both the kernel-sourced dirty bitmap and
forking a process that holds KVM vcpu descriptors are open questions there.

## See also

- `docs/plugins.md` — the plugin system generally
- `docs/pyplugin_architecture.md` — how plugins are discovered and wired
- `pyplugins/apis/fastsnap.py` — the API, with the reasoning inline
