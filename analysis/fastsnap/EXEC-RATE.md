# Where the time actually goes, measured

G -- the guest work per fuzz iteration -- is now measured rather than bounded.
It is the number that sizes every exec/s claim in this lane, since a fast
iteration costs `reset + G`.

**G = 0.111 ms.** The parse is 0.8% of what an HTTP request costs today.

## How it was measured

lighttpd exports 420 FUNCs in `.dynsym`, so the parser is reachable by name:

    http_request_parse     0x192f0 (file offset 0x112f0), 7652 bytes   target
    get_http_method_key    0x15d98,                         16 bytes   control
    connection_set_state   0x1c85c,                         12 bytes   control

A uprobe/uretprobe bracket costs a guest trap, a hypercall, a portal round trip
into host Python and a return -- plausibly more than the function it measures.
So the same bracket is placed on functions whose bodies are a handful of
instructions; their measured interval *is* the probe round trip.

| run | probed | n | median | p10 | p90 |
|---|---|---|---|---|---|
| 16 | `http_request_parse` | 1701 | **0.3662 ms** | 0.3529 | 0.3927 |
| 18 | `get_http_method_key` | 1701 | **0.2553 ms** | 0.2496 | 0.2761 |
| 18 | `connection_set_state` | 12109 | 0.2611 ms | 0.2477 | 0.2854 |

    G  =  0.3662 - 0.2553  =  0.111 ms

**Why this subtraction is sound.**

- *Two independent controls agree.* Different call sites, a 7x difference in
  call count, medians 0.006 ms apart. That is the portal, not the bodies.
- *The distributions do not overlap.* The target's p10 (0.353) is above both
  controls' p90 (0.276, 0.285). The 0.111 ms gap is roughly 3x the width of
  either distribution.
- *The two runs saw identical workloads.* `get_http_method_key` fired 1701
  times in run 18 and `http_request_parse` fired 1701 times in run 16 -- the
  same 2000-request driver, the same reachable parses.
- *An independent estimate agrees.* At the ~117 MIPS TCG rate from
  `THROUGHPUT.md`, 0.111 ms is ~13,000 guest instructions, which is the right
  order for a request line plus three headers through 7652 bytes of ARM code.

**Why they are separate runs.** `get_http_method_key` is called *from inside*
`http_request_parse`. Probing both at once puts the probe pair in the middle of
the interval being measured and inflates it by exactly the quantity being
isolated. Run 16 timed the target with nothing else armed; run 18 timed the
overhead alone.

The plugin's own guard (`overhead_fraction > 0.5` -> "not resolvable") fires
here, at 70%. That guard is a heuristic for a *within-run* subtraction and it
is too strict for this case: the criterion that matters is the gap relative to
the spread, and the distributions are tight and disjoint.

## What an iteration costs

Reset is measured in `ALLOWLIST.md`: 0.043 ms device restore on the `{cpu,
timer}` allowlist plus ~0.027 ms for the RAM term, so ~0.07 ms, or 0.11 ms on
the conservative full-allowlist figure.

| loop lives in | per iteration | exec/s |
|---|---|---|
| **QEMU (C)** | 0.111 + 0.07 | **5,525** |
| QEMU (C), conservative reset | 0.111 + 0.11 | 4,525 |
| host Python, via the portal | 0.255 + 0.111 + 0.07 | 2,294 |
| host Python, **measured** (`persist.py`, no reset) | 0.421 | **2,374** |
| today, full HTTP request | ~14.3 | 70 |

## Demonstrated today: 2,374 exec/s

`persist.py` implements AFL's persistent-mode loop (`__AFL_LOOP`) as a
pyplugin. At `http_request_parse` entry -- before the prologue has run -- LR
still holds the caller's return address; overwrite it with the function's own
entry address and the standard ARM epilogue (`pop {r4-r11, pc}`) pops that
value instead, so the function returns into itself and re-triggers the same
uprobe. r0-r3 are restored from the entry snapshot each lap. No uretprobe, so
there is no return-trampoline bookkeeping to corrupt.

    laps_per_entry : 20
    fresh_calls    : 101
    rewinds        : 2020        errors: []
    lap interval   : median 0.4213 ms   n=2020   p10 0.4113   p90 0.4873
    lap rate       : 2,374 /s

**34x today's 70 exec/s, with no QEMU changes.** The rate was predicted at
2,294 /s from the independently measured probe cost and G *before* this run;
measured 2,374 /s, within 3.5%.

The three measurements trilaterate:

| what ran | interval | difference |
|---|---|---|
| probe round trip alone | 0.255 ms | -- |
| probe + parse | 0.366 ms | **G = 0.111 ms** |
| probe + parse + register writeback | 0.421 ms | **+0.055 ms writeback** |

The writeback term is independently attributable rather than a fitted
residual: `parsecost` never modifies registers and `persist` does, so
`apis/uprobes.py:221-223` copies the whole modified `pt_regs` back into guest
memory on every lap. The two runs differ in exactly that.

**What this is not.** State is not reset between laps. `fresh_calls` is 101,
not 1701: after ~20 laps the connection state is corrupted enough that
lighttpd drops the connection, so only the first request of each of the 100
connections ever reaches the parser. That is persistent mode's known
unsoundness, demonstrated rather than assumed, and it is exactly the gap a
real reset fills. The number is a ceiling for portal-driven iteration, not a
usable fuzzer.

## The finding that changes the design

**The iteration loop cannot live in a pyplugin.** The portal round trip is
0.255 ms -- more than twice G, and 58% of the total budget of a
Python-driven iteration. Driving injection and restore from host Python caps
the design at ~2,300 exec/s no matter how fast reset becomes; moving the same
loop into the emulator reaches ~5,500.

This was not obvious in advance and it is cheap to get wrong: the pyplugin API
is the natural place to write a fuzz harness, and it is the wrong place.
Python may *arm* the loop and collect its results, but the per-iteration path
-- fill the buffer, run, observe, restore -- has to be C inside QEMU.

The measured persistent loop puts a number on the gap: of its 0.421 ms lap,
0.310 ms (74%) is portal round trip plus `pt_regs` writeback, and only
0.111 ms is the target doing work.

## What today's 70 exec/s is made of

The in-guest driver (2000 pipelined requests over 100 connections, no host
harness in the datapath) took 28.644 s of host wall clock, giving 69.8 exec/s
and ~14.3 ms per request. Of that, **0.111 ms is parsing** -- 0.8%. The other
99.2% is guest TCP loopback, the socket read, the response `writev`, and
lighttpd's event loop, none of which a fastsnap iteration pays.

That ratio, not the reset cost, is the reason the tight snapshot is the lever.

## Instrument notes

**Run-to-run variance is large.** The same 2000-request driver took 28.6 s,
21 s and 17 s across three runs -- a 1.6x spread. Single-run exec/s figures
from this target should be read as draws from a wide distribution. The G
measurement is not exposed to this: it is a median over 1701 samples within a
run, and its two controls came from the same run as each other.

**Penguin's instrumentation tax is ~2%, not a lever.** Measured on the host
clock over intervals bounded by identical guest events (`dsa.ko` ->
`at91_udc`, `dsa.ko` -> `ppp_async`): lean 43 s / 49 s, full profile 44 s /
50 s, full plus live uprobes 46 s / 52 s. This closes the "instrumentation
tax" question negatively, which is useful -- it removes a candidate lever.

**The guest clock is adequate, contrary to an earlier claim in this lane.**
Guest `date +%s` and the host clock agreed to 2.3% over the same 28 s window
(28 s vs 28.644 s), within the +/-1 s quantization of `date`. An earlier run
appeared to show the heavier profile finishing *faster*, which was read as
tick loss under `clocksource=jiffies nohz=off`; it is better explained by the
run-to-run variance above.

## Superseded

An earlier version of this file solved a two-depth fit for `C = 434 ms` of
per-connection cost and attributed it to guest `fork`+`exec` of `nc`. That fit
was taken on runs driven by a host-side `connect.sh` over telnet, so `C`
absorbed host harness overhead. With the driver moved in-guest, per-connection
cost is ~36 ms. The conclusion drawn from it -- that most of an execution is
not parsing -- survives, and is now stated directly as the 0.8% figure above.
