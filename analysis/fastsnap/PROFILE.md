# Is Python the slow part of a uprobe iteration?

Partly. **~86 us of the ~262 us probe round trip is host-side Python -- about
31%** -- and it is concentrated in one place rather than spread thin.

## The measurement, and two wrong answers before it

`_uprobe_event` in `apis/uprobes.py` is a **generator**: it ends in
`yield from fn_ret`. Calling it constructs a generator object and executes
none of the body; the portal drives it afterwards. Two instruments failed on
this before one worked:

1. Timing `self._uprobe_event(...)` as a call measured generator construction:
   0.8 us. Read naively that says "Python is 0.3% of the probe" -- wrong.
2. Timing only the user callback body measured 1.4 us, and appeared *larger*
   than the enclosing dispatcher, which is impossible for real nesting. That
   contradiction is what exposed the generator.

The instrument that works drives the generator and times that:

```python
_t0 = perf_counter()
_r = yield from self._uprobe_event_inner(cpu, is_enter)
...
self.body_ms.append((perf_counter() - _t0) * 1000.0)
```

| | median | n |
|---|---|---|
| probe interval (enter -> return) | 0.262 ms | 1701 |
| host-side generator body | **0.086 ms** | 27620 |
| ...caller-side span, event arrival -> callback end | 0.086 ms | 27620 |
| user callback body | 0.0015 ms | 27620 |

Body time and caller-side span agree, so the 86 us is work, not queue wait.

**A clock note.** `time.time()` returns seconds since the epoch, so a float64
holding 1.79e9 has ~21 fractional bits and quantizes differences to ~477 ns --
visible as `p10 = 0.000477` in an earlier run, exactly one ULP. At the us scale
these measurements need `perf_counter()`, which starts near zero.

## Where the 86 us goes

py-spy cannot attach here: penguin runs under dockerd, `ptrace_scope=1`
restricts ptrace to descendants, and this host has no passwordless sudo. So
cProfile is enabled from *inside the first uprobe callback*, which guarantees
it lands on the thread the portal drives callbacks on -- a plugin-init enable
would profile the wrong thread.

```
cumulative   ncalls    frame
   1.658 s     7998    apis/uprobes.py:212(_uprobe_event_inner)
   1.087 s    16677      apis/kffi.py:227(read_type_panda)        <- 66%
   0.698 s    21458        apis/mem.py:271(read_bytes_panda)
   0.375 s    23509          qemu_compat.py:974(_cpu_memory_rw_debug)
   0.217 s    23509          qemu_compat.py:959(_call_with_bql)
   0.381 s    17362        dwarffi/dffi.py:875(from_buffer)
   0.257 s    17366          dwarffi/dffi.py:364(_create_instance)
   0.296 s    38297      dwarffi/instances.py:709(__getattr__)
   0.194 s   117545      cffi/api.py:293(cast)
   0.255 s   774875      isinstance
```

Two thirds of the body is `read_type_panda`, pulling `portal_event` and
`pt_regs` out of guest memory through the dwarffi typed-struct layer. Per
event that is ~15 CFFI casts and **~97 `isinstance` calls** to service one
uprobe.

`pt_regs` on ARM is 18 words, 72 bytes. One bulk `read_bytes` plus
`struct.unpack` would replace the whole marshalling path, and the same shape
hands cleanly to a C helper: Python resolves symbols, owns the corpus and
arms the probe; C does the per-iteration struct read and buffer write.

## The marshalling cut, implemented and measured

`_FastArrayRegs` in `apis/uprobes.py` replaces the dwarffi `pt_regs` instance
with one `struct.unpack`. PtRegsWrapper only ever reaches the underlying
object through `getattr(obj, attr)[i]`, the matching `__setitem__`, and
`bytes(obj)` (`ptregs_wrap.py:95-100,157`), so a list plus a format string
satisfies it completely. Modification is detected by comparing a tuple instead
of serialising twice per event.

Gated on `plugins.uprobes.fast_ptregs`, and cross-checked against kffi on the
first N events (`fast_ptregs_verify`) -- a fast path returning subtly wrong
registers would not fail loudly, it would surface as an inexplicable result
several runs later.

    uprobes: fast_ptregs ENABLED (arm, 72 bytes, <18I, .uregs)
    uprobes: fast_ptregs verified against kffi on 500 events, 0 mismatches

| | fast off | fast on | delta |
|---|---|---|---|
| host-side body per event | 0.0900 ms | 0.0764 ms | -13.6 us |
| probe interval (read-only bracket) | 0.2618 ms | 0.2532 ms | -8.6 us |
| **persist lap (register-writing)** | **0.4213 ms** | **0.3896 ms** | **-31.7 us** |
| **persist exec/s** | **2,374** | **2,567** | **+8.1%** |

The writing path gains far more than the read-only path because the old code
serialised `pt_regs` twice per event (`original_bytes`, then `new_bytes`)
where the fast path compares a tuple.

**Against prediction.** ~57 us of saving was predicted, 31.7 us delivered --
1.8x optimistic, and the resulting rate is 7% below the predicted 2,750/s. The
shortfall is visible in the profile that motivated it: `read_type_panda` is
called *twice* per event (16677 calls / 7998 events) and only the `pt_regs`
one was cut. `portal_event` still goes through dwarffi, as do its four field
accesses.

**Ceiling of this lever.** Host-side is now 76 us of a 253 us interval.
Removing *all* remaining Python -- not achievable, but a bound -- gives a
177 us interval, a ~335 us lap, and **~2,985 exec/s**. So the whole Python
lever is worth at most +26% over today, of which 8.1% is realised. Cutting the
second `read_type_panda` buys roughly 5% of the remaining gap. That is why the
guest trap, not the language, is where the next factor is.

## Arch scope

The fast path applies only where every register is a uniform word in one array
field: `arm*` (32-bit, `.uregs`) and `loongarch64` (`.regs`). x86, aarch64,
ppc, riscv and mips mix named fields and fall back to kffi. Note `arch_name`
is `armel`/`armhf`, never bare `arm`, so the match is a `startswith` -- an
exact-match table silently disables the fast path with no error, which is how
the first version of this failed.

## What each lever is worth

| lever | removes | lap | exec/s |
|---|---|---|---|
| today (`persist.py`, measured) | -- | 421 us | 2,374 |
| `fast_ptregs`, **measured** | 32 us | 390 us | **2,567** |
| all remaining host Python removed (bound, not reachable) | ~76 us | ~335 us | ~2,985 |
| eliminate the guest trap (snapshot restore, no uprobe) | ~177 us | ~181 us | ~5,525 |

Python is worth ~16%. The guest-side trap -- breakpoint, kernel uprobe
handler, XOL single-step, hypercall, all executing as emulated ARM -- is worth
~2.3x. Both are real, and the Python one is much cheaper and does not block on
the reset work.

**Correction to an earlier claim in this lane.** `EXEC-RATE.md` first argued
the iteration loop "cannot live in a pyplugin" because the portal costs
0.255 ms. The premise was wrong: the 0.255 ms is mostly guest-side, and the
Python share is 86 us. The design conclusion is milder than stated -- a
Python-armed loop with a C fast path for the per-iteration struct read is a
reasonable architecture, and the reason to avoid a per-iteration guest trap is
the trap, not the language.

## Instrument left in place

`apis/uprobes.py` carries two `perf_counter()` calls and a capped
`self.body_ms` list per dispatch. Cheap, but it is measurement scaffolding in
a shared API file, not something to land.

## The guest-trap side

With the fast path on, a probe event costs 253 us of which 76 us is host-side
Python. **The remaining ~177 us (70%) is guest-side**: the breakpoint trap, the
kernel's uprobe handler, execute-out-of-line single-step, and the hypercall out
to QEMU -- all running as emulated ARM under TCG. At ~117 MIPS that is roughly
20,000 guest instructions to service one probe, which is the right order for
that kernel path.

Two independent observations support treating it as a fixed per-trap cost
rather than something proportional to the probed code:

- `connection_set_state` (12 bytes, 12109 calls) and `get_http_method_key`
  (16 bytes, 1701 calls) produce intervals within 0.006 ms of each other,
  across a 7x difference in call count.
- The interval tracks the probe, not the function: adding the parser's real
  work moves it by exactly G (0.111 ms).

**Why there is no end-to-end A/B here.** The obvious check -- run the same
workload with probes armed and disarmed, and difference the wall clock -- is
not resolvable on this target with n=1. Two runs of *identical* configuration
gave drive windows of 41.21 s and 34.69 s, a 6.52 s band, against an expected
total probe cost of 27620 x 253 us = 6.99 s. Signal and noise are the same
size; it would take ~10 repeats per arm to say anything, and the within-run
medians over thousands of samples are a far better instrument for the same
quantity.

**The lever, and what it costs to pull.** Nothing here is fixed by making the
callback faster; the cost is taking a guest trap at all. A fastsnap iteration
avoids it by construction -- restore a snapshot whose saved PC is already at
the injection point, so the guest resumes inside the parser with no
breakpoint, no kernel handler and no hypercall. That is worth ~177 us, taking
the lap to ~181 us and **~5,525 exec/s**, an order of magnitude the Python
lever cannot reach.

Scoping note for that build: penguin's `Snapshot` pyplugin already exposes
`request_save(when='symbol', symbol=...)` and `request_restore(tag)`, but
`request_restore` is **asynchronous** -- it calls
`panda.schedule_snapshot(tag, load=True)`, which queues a main-loop bottom-half
(`qemu/system/penguin.c:304`) and returns immediately. Timing a restore
therefore needs a completion signal, not a return value; the natural one is the
next hit of a probe placed at the resume point. That, plus the fact that the
existing path is a full `savevm`/`loadvm` rather than the `{cpu,timer}`
allowlist plus dirty-RAM restore measured in `ALLOWLIST.md`, is why the real
reset cost on this firmware is still unmeasured.
