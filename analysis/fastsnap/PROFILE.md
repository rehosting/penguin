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

## What each lever is worth

| lever | removes | lap | exec/s |
|---|---|---|---|
| today (`persist.py`, measured) | -- | 421 us | 2,374 |
| strip the typed-struct marshalling | ~57 us | ~364 us | ~2,750 |
| eliminate the guest trap (snapshot restore, no uprobe) | ~176 us | ~181 us | ~5,525 |

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
