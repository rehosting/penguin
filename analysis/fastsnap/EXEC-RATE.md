# Where the time actually goes, measured

Two fuzz runs on stridelinx at different pipelining depths decompose the cost
of an execution. This is the first time G -- guest work per iteration -- has
been bounded by measurement rather than assumed.

## The runs

| run | depth | connections | HTTP reads | span | exec/s |
|---|---|---|---|---|---|
| 1 | 8 | 25 | 190 | 12.502 s | 15.2 |
| 2 | 10 | ~66 | 658 | 34.279 s | 19.2 |

Run 2's controls both passed:

    passthrough    : 79
    response codes : {400: 96, 200: 59, 401: 13, 404: 13, 501: 3, 411: 1, 505: 1}

Seven distinct status codes. `505` (version not supported), `411` (length
required), `401` (auth) and `404` (path resolution) are only reachable *after*
the request line and headers parse, so the mutants are exercising the parser
rather than being rejected at the first byte.

## The decomposition

Per-connection overhead `C` and per-request cost `R`, solved from the two
depths:

    C + 8R  = 500 ms/connection
    C + 10R = 521 ms/connection
    -------------------------------
    C = 434 ms   guest fork+exec of nc, plus TCP setup and teardown
    R = 8.7 ms   loopback network stack + parse + response writev

**87% of an execution today is connection setup that a fastsnap iteration
would not pay at all.** And R is an *upper bound* on G, because it still
contains the guest's loopback TCP path and the response.

## What that does to the headline number

exec/s after a fast reset is `1000 / (0.11 + G_ms)`:

| G | fastsnap exec/s | vs 19.2 today |
|---|---|---|
| 8.7 ms (all of R is parse) | 114 | 6x |
| 1.0 ms | 901 | 47x |
| 0.3 ms | 2,439 | 127x |
| 0.1 ms | 4,762 | 248x |

This lane has been quoting ~1,100 exec/s. That is only correct if G lands near
1 ms, and until now there was **no evidence either way**. The spread between
the top and bottom rows of that table is 40x, and it is entirely a property of
the target, not of the reset design.

## Measuring G directly

lighttpd keeps its dynamic symbols (420 exported FUNCs), so the parser is
reachable by name rather than by a reversed offset:

    http_request_parse            0x192f0, 7652 bytes   target
    http_request_header_finished  0x19290,   96 bytes   overhead control

`parsecost.py` brackets both with uprobe/uretprobe. The control is load-bearing:
a uprobe costs a guest trap, a hypercall, a portal round trip into host Python
and a return, which can easily exceed the function being measured. Bracketing a
96-byte function measures that overhead directly, and

    G ~= dt(http_request_parse) - dt(http_request_header_finished)

If the control is not small relative to the target, the plugin reports that G
is not resolvable with this instrument instead of printing a number.

## Note on the first attempt

The first parsecost run reported `CONTROL FAILED - no samples for the target
probe` for both probes. No traffic had been driven into it -- an operational
mistake, not an instrument fault. The controls behaved correctly: they refused
to report a number rather than printing a zero that would have read as "the
parse is free".
