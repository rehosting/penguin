#!/usr/bin/env python3
"""Hold one HTTP connection open into a BYOK guest, from outside it.

WHY THIS EXISTS. The in-guest driver (`/igloo/init.d/zz_fastsnap_drive` in
`patch_zzz_fastloop.yaml`) needs `/igloo/utils/{sh,busybox,nc}`, and a BYOK
rootfs is vendor firmware plus `igloo.ko` with none of penguin's guest
utilities. So the connection has to come from the host, over the slirp
hostfwd that already exists for driving the guest's web server.

That works because **snapfeed's hooks are host-side and do not care where the
connection came from**. Once `accept` returns, the fd is learned, and from
then on every `read` on it is answered out of guest RAM by snapfeed rather
than from the socket. The far end only has to exist and stay open.

WHAT THE JOB ACTUALLY IS, which is smaller than it looks. This does NOT need
to send a stream of requests to keep the victim busy. It needs to get exactly
one connection accepted and then stay out of the way: snapfeed generates all
subsequent traffic by answering reads, the detector fires on the victim's
writev, fastloop's warmup fills, and the arm follows. A driver that kept
sending real requests would be competing with snapfeed for the same fd.

THREE THINGS THAT COST RUNS IN THE IN-GUEST VERSION, NOT REPEATED HERE
----------------------------------------------------------------------

1. **A readiness probe that cannot observe readiness.** The old driver waited
   for `nc | grep -q HTTP` to see a response -- but `swallow_writes` is on, so
   the victim's reply is skipped at the syscall and never reaches the client.
   The probe could not succeed by construction; every connector burned all 400
   iterations as a fork+exec storm straight through the arming window. A check
   that cannot observe the thing it checks is not a slow check, it is a fixed
   cost pretending to be one. Here readiness is "connect() succeeded", which
   is observable whether or not anything is swallowed.

2. **A holder that only sleeps cannot notice the far end going away.** Run 103
   held the connection with `sleep 3600`; lighttpd closed it after one feed,
   the guest sat in CLOSE_WAIT at 2% CPU, and the run was lost. So the holder
   WRITES on a timer. The point is not the bytes -- `\r\n` before a request
   line is ignored by HTTP/1.1 and snapfeed skips the real read anyway -- the
   point is that a write to a closed peer raises, and that is the only signal
   that arrives on time.

3. **The send buffer fills, because nobody is reading.** snapfeed skips the
   real `read()`, so these keepalive bytes accumulate in the guest's receive
   buffer forever. Two bytes every two seconds against a typical buffer is
   many hours, but "many hours" is the length of a campaign, so the socket is
   non-blocking and a full buffer is treated as healthy rather than as an
   error. A blocking write here would wedge the driver silently at exactly
   the point a long run starts paying off.
"""

import argparse
import errno
import socket
import sys
import time

REQUEST = (b"GET / HTTP/1.1\r\n"
           b"Host: x\r\n"
           b"Connection: keep-alive\r\n"
           b"\r\n")


def log(msg):
    print(f"[byok_drive {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def hold_one(host, port, poke_s, connect_timeout):
    """One connection, held until it dies. Returns seconds it survived."""
    t0 = time.time()
    s = socket.create_connection((host, port), timeout=connect_timeout)
    # Non-blocking from here on: see note 3 in the module docstring. Every
    # send below may legitimately return EWOULDBLOCK and that is not an error.
    s.setblocking(False)
    try:
        s.sendall(REQUEST)
    except BlockingIOError:
        # The request itself did not fit. Vanishingly unlikely on a fresh
        # socket, but if it happens the connection is still established and
        # still worth holding -- the victim will read what did land.
        pass
    log(f"connected {host}:{port}, request sent")

    while True:
        time.sleep(poke_s)
        try:
            s.send(b"\r\n")
        except BlockingIOError:
            # Receive buffer full because snapfeed is skipping the real read.
            # This is the EXPECTED steady state on a working run, not a fault.
            continue
        except OSError as e:
            if e.errno in (errno.EPIPE, errno.ECONNRESET, errno.ENOTCONN):
                return time.time() - t0
            raise


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=10080,
                    help="hostfwd port onto the guest's :80")
    ap.add_argument("--poke-s", type=float, default=2.0,
                    help="seconds between keepalive writes; the only thing "
                         "that notices the far end closing")
    ap.add_argument("--connect-timeout", type=float, default=10.0)
    ap.add_argument("--retry-s", type=float, default=2.0,
                    help="wait before reconnecting after a drop")
    ap.add_argument("--max-s", type=float, default=0.0,
                    help="stop after this many seconds (0 = forever)")
    a = ap.parse_args()

    started = time.time()
    conns = 0
    recent = []
    short_hold = max(3.0 * a.poke_s, 5.0)
    while True:
        if a.max_s and (time.time() - started) >= a.max_s:
            log(f"done: {conns} connection(s) over {time.time()-started:.0f}s")
            return 0
        try:
            held = hold_one(a.host, a.port, a.poke_s, a.connect_timeout)
            conns += 1
            log(f"connection {conns} closed by peer after {held:.1f}s")
            # RECONNECTING FAST IS A FAILURE, NOT A RECOVERY, and it is the
            # one this driver most needs to shout about.
            #
            # snapfeed cannot synthesise accept(). A connection boundary
            # inside a replayed span is therefore a wait for something only
            # the guest can produce -- a fork+exec under emulation, measured
            # at ~1.05 s against a ~3.5 ms ordinary lap. Run 99 armed on such
            # a span and reported 0.94 exec/s for a reset that was working
            # perfectly. A victim that hangs up after every feed turns the
            # whole run into that, and the symptom here is exactly this loop
            # turning over quickly while looking busy.
            #
            # Two short holds in a row is enough to say so: keep-alive either
            # works or it does not, so this does not need a long baseline.
            recent.append(held)
            del recent[:-2]
            if len(recent) == 2 and all(h < short_hold for h in recent):
                log(f"WARNING: last 2 connections lasted {recent[0]:.1f}s and "
                    f"{recent[1]:.1f}s (< {short_hold}s). The victim is not "
                    f"holding the connection open, so every lap will replay a "
                    f"connection boundary -- a guest fork+exec, ~1.05 s under "
                    f"emulation against a ~3.5 ms ordinary lap. Check that "
                    f"snapfeed keepalive is on and that the payloads are not "
                    f"asking the victim to hang up. A rate measured in this "
                    f"state is not the loop's rate.")
        except (ConnectionRefusedError, socket.timeout, OSError) as e:
            # The victim is not up yet, or the container is not forwarding.
            # Say so every time rather than once: a driver that goes quiet
            # while failing is indistinguishable from one that is working,
            # and that ambiguity has cost this lane runs before.
            log(f"connect failed ({e}); retrying in {a.retry_s}s")
        time.sleep(a.retry_s)


if __name__ == "__main__":
    sys.exit(main())
