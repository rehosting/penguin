"""Feed the victim from INSIDE the snapshot boundary, so a reset can rewind it.

WHY THIS EXISTS
---------------
`fastloop` resets the guest and replays a span. Three real targets were
measured replaying a span that was not the one they armed on:

    target A   forward     3.79 ms -> replayed 14,949 ms    3,945x SLOWER
    target B   forward   476.59 ms -> replayed      6.28 ms     76x FASTER
    target C   forward     1.64 ms -> replayed    160.02 ms     97x SLOWER

The oracle certified every one of those restores byte for byte -- 2.16 GB on
target B, ten times over -- so the divergence is not in the guest state. It is
in the world OUTSIDE it. The reset rewinds guest RAM and devices; it does not
rewind the host-side socket. When the armed span ends in a `read()` on a TCP
connection, replaying it means reading data that was already consumed and will
never be delivered again, so the guest waits on a timer (A and C); or reading
data that arrived DURING the forward traversal and is still queued, so the
guest never waits at all (B).

`fuzzdrive` does not fix this and was never meant to: it rewrites the buffer at
the read RETURN, so the read has already completed and the host-side data still
had to arrive. It is a mutator, not a feeder.

This plugin closes the loop by making the read never reach the host:

    on read ENTER for a connection fd
        write the payload into the guest's buffer
        syscall.retval      = len(payload)
        syscall.skip_syscall = True        <- the real read() never runs

Everything the guest consumes now comes from guest RAM, written by us, inside
the snapshot boundary. There is no host-side state left in the iteration for
the reset to fail to rewind.

WHICH READS
-----------
At the read RETURN you can tell an HTTP request by looking at the bytes, which
is what `fuzzdrive` does. At ENTER the buffer is empty and that is not
available, so the connection fds are learned from `accept`/`accept4` returns
instead. That is target-agnostic -- every TCP server accepts before it reads --
and it stays host-side, with nothing instrumented inside the guest.

The learned set lives in host Python and is NOT rewound by a reset. That is
correct rather than a bug: the guest's fd table IS rewound, so after a restore
the guest re-reads the same fd it held at the armed instant, and a set that is
a superset of the live fds still matches it.

CONTROLS
--------
A feeder that silently feeds nothing looks exactly like a fast loop, and that
failure has already happened once in this lane: 200,000 laps at 0.294 ms and
3,396 exec/s, for a guest nothing was being injected into. So:

  n_sent        every delivery, for `fastloop`'s arm_progress -- the idle axis
                refuses a draw where this does not advance.
  n_unmatched   reads on fds we never learned. If this is large and n_sent is
                zero, the accept hook never fired and the run is measuring an
                unfed guest. Reported, and warned about once.
  responses     status codes the victim wrote back. A feeder whose payloads are
                all rejected at byte one is reaching none of the parser, and a
                run that cannot tell that apart from "no crashes" is not a
                measurement.
"""

import json
import os
import random
import time

from penguin import Plugin, plugins

syscalls = plugins.syscalls

SEEDS = [
    b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET /index.html HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n",
    b"GET /cgi-bin/sysinfo.cgi HTTP/1.1\r\nHost: x\r\n"
    b"Authorization: Basic QUFBQUFBQUE=\r\n\r\n",
    b"POST /cgi-bin/login.cgi HTTP/1.1\r\nHost: x\r\n"
    b"Content-Length: 4\r\n\r\nAAAA",
    b"GET /../../etc/passwd HTTP/1.0\r\n\r\n",
]

HEADERS = [b"Host", b"Authorization", b"Connection", b"Content-Length",
           b"Range", b"If-Modified-Since", b"Cookie", b"Referer",
           b"Transfer-Encoding", b"Expect", b"User-Agent"]


class SnapFeed(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.comm = self.get_arg("comm") or "lighttpd"
        # `x or default` is wrong for any arg whose meaningful value is 0 or
        # "": `mutate: 0` became `0 or 1` and mutation could not be switched
        # off at all. Caught by the host test before a boot was spent on a
        # "control" run that was still mutating.
        self.rng = random.Random(int(self._arg("seed", 1337)))
        # Off by default. A passthrough read is a read that goes to the host,
        # which is the single thing this plugin exists to remove -- in a loop
        # it reintroduces exactly the unrewindable state the reset cannot
        # handle. It stays available because a snapshot-free control run wants
        # it, and it is reported so a loop run cannot use it without saying so.
        self.passthrough = float(self._arg("passthrough", 0.0))
        self.mutate_on = bool(int(self._arg("mutate", 1)))
        # On by default: without it, exclusive mode (which freezes the peer)
        # wedges the victim in writev the first time a send buffer fills.
        self.swallow_writes = bool(int(self._arg("swallow_writes", 1)))
        # iovec is two pointer-sized fields; 4 on every target in this lane.
        self.ptr_size = int(self._arg("ptr_size", 4))
        self.pin_filter = bool(int(self._arg("pin_filter", 0)))

        self.n_sent = 0          # deliveries -- fastloop's arm_progress
        self.n_pass = 0          # CONTROL: reads left to the host
        self.n_unmatched = 0     # CONTROL: reads on fds we never learned
        self.n_accept = 0        # connection fds learned
        self.n_writes = 0        # responses seen
        self.n_swallowed = 0     # responses that never reached the socket
        self.fds = set()
        self.responses = {}      # CONTROL: status codes written back
        self.t_first = None
        self.t_last = None
        self._warned_unmatched = False

        # `comm` alone would also feed a forked worker carrying the same
        # name, which is a different process than the loop armed in. pin_filter
        # confines every one of these to the pinned subtree once a pin exists,
        # and is inert before that.
        pf = self.pin_filter
        syscalls.syscall("on_sys_accept_return", comm_filter=self.comm,
                         pin_filter=pf)(self.on_accept)
        syscalls.syscall("on_sys_accept4_return", comm_filter=self.comm,
                         pin_filter=pf)(self.on_accept)
        syscalls.syscall("on_sys_read_enter", comm_filter=self.comm,
                         pin_filter=pf)(self.on_read_enter)
        syscalls.syscall("on_sys_writev_enter", comm_filter=self.comm,
                         pin_filter=pf)(self.on_writev_enter)
        self.logger.info(
            f"snapfeed: armed on comm={self.comm!r}, passthrough="
            f"{self.passthrough} (0.0 means nothing reaches the host), "
            f"mutate={self.mutate_on}, seeds={len(SEEDS)}")

    def _arg(self, name, default):
        v = self.get_arg(name)
        return default if v is None or v == "" else v

    # ---- learning the connection fds --------------------------------------

    def on_accept(self, regs, proto, syscall, *a):
        fd = int(syscall.retval)
        if fd >= 0:
            self.fds.add(fd)
            self.n_accept += 1

    # ---- mutation ---------------------------------------------------------

    def mutate(self, base, limit):
        if not self.mutate_on:
            return base[:limit]
        r = self.rng
        out = bytearray(base)
        for _ in range(r.randint(1, 3)):
            op = r.randrange(5)
            if op == 0 and out:
                out[r.randrange(len(out))] ^= 1 << r.randrange(8)
            elif op == 1:
                h = r.choice(HEADERS)
                out = out.replace(
                    b"\r\n\r\n",
                    b"\r\n" + h + b": " + bytes([r.randrange(33, 127)]) *
                    r.choice([64, 512, 3000]) + b"\r\n\r\n", 1)
            elif op == 2:
                h = r.choice(HEADERS)
                out = out.replace(b"\r\n\r\n",
                                  b"\r\n" + h + b": a,,b,,,c\r\n\r\n", 1)
            elif op == 3 and len(out) > 8:
                out = out[:r.randrange(4, len(out))]
            else:
                out = out.replace(b"\r\n\r\n",
                                  b"\r\nRange: bytes=0-,-1,0-0\r\n\r\n", 1)
        return bytes(out)[:limit]

    # ---- the feed ---------------------------------------------------------

    def on_read_enter(self, regs, proto, syscall, fd, buf, count):
        limit = int(count)
        if limit <= 0:
            return
        if int(fd) not in self.fds:
            self.n_unmatched += 1
            if self.n_unmatched == 2000 and not self.n_sent:
                self._warned_unmatched = True
                self.logger.warning(
                    f"snapfeed: {self.n_unmatched} reads by {self.comm!r} and "
                    f"NOT ONE on a learned connection fd -- {self.n_accept} "
                    f"accepts seen. Nothing is being fed, so any rate below is "
                    f"the rate of an unfed guest. Check that the victim accepts "
                    f"before it reads, and that comm= names the right process.")
            return

        if self.passthrough and self.rng.random() < self.passthrough:
            self.n_pass += 1
            return                      # goes to the host -- see __init__

        payload = self.mutate(self.rng.choice(SEEDS), limit)
        if not payload:
            return
        yield from plugins.mem.write_bytes(buf, payload)
        syscall.retval = len(payload)
        # THE POINT. Without this the real read() still runs, the guest still
        # depends on host-side data, and the reset still cannot rewind it.
        syscall.skip_syscall = True

        self.n_sent += 1
        now = time.time()
        if self.t_first is None:
            self.t_first = now
        self.t_last = now

    def _tally(self, data):
        if not data.startswith(b"HTTP/"):
            return
        parts = data.split(b" ")
        code = (parts[1][:3].decode("latin-1", "replace")
                if len(parts) > 1 else "???")
        self.responses[code] = self.responses.get(code, 0) + 1

    def on_writev_enter(self, regs, proto, syscall, fd, iov, iovcnt):
        """Swallow the response, and tally what it was.

        Two jobs, and the second is what makes exclusive mode survivable.

        With the other userspace tasks stopped, the peer on the far end of
        this socket is frozen and will never read again. Let the write through
        and the send buffer fills, the victim blocks in writev() forever, and
        the loop stalls -- exclusive mode would have deadlocked the thing it
        was meant to make deterministic. Skipping the syscall means the
        response never has to go anywhere and a frozen peer cannot matter.

        `iov` is an ARRAY OF IOVECS, not the payload: read the first entry's
        base through read_ptr and then read from THERE. Reading `iov`
        directly returns the struct's own bytes, which never start with
        "HTTP/" -- so the tally is silently always empty and the control that
        catches a wedged victim reads as "no responses" on a perfectly
        healthy one.
        """
        if int(iovcnt) <= 0 or int(fd) not in self.fds:
            return
        try:
            base = yield from plugins.mem.read_ptr(iov)
            data = yield from plugins.mem.read_bytes(base, size=16)
        except Exception:                                   # noqa: BLE001
            data = b""
        self._tally(data)
        self.n_writes += 1
        if self.swallow_writes:
            # Claim the whole write succeeded. A short count would send the
            # victim back for the remainder and cost a lap to a retry loop.
            total = yield from self._iov_total(iov, int(iovcnt))
            syscall.retval = total
            syscall.skip_syscall = True
            self.n_swallowed += 1

    def _iov_total(self, iov, iovcnt):
        """Sum iov_len across the array, so the faked return is the length the
        guest actually asked to write rather than a guess."""
        total = 0
        ptr = int(self.ptr_size)
        for i in range(min(iovcnt, 64)):
            try:
                ln = yield from plugins.mem.read_ptr(int(iov) + i * 2 * ptr + ptr)
            except Exception:                               # noqa: BLE001
                break
            total += int(ln)
        return total

    # ---- report -----------------------------------------------------------

    def uninit(self) -> None:
        dur = ((self.t_last - self.t_first)
               if (self.t_first and self.t_last) else None)
        out = {
            "comm": self.comm,
            "n_sent": self.n_sent,
            "n_pass": self.n_pass,
            "n_unmatched": self.n_unmatched,
            "n_accept": self.n_accept,
            "fds_learned": sorted(self.fds),
            "responses": self.responses,
            "n_writes": self.n_writes,
            "n_swallowed": self.n_swallowed,
            "swallow_writes": self.swallow_writes,
            "passthrough": self.passthrough,
            "mutate": self.mutate_on,
            "feed_wall_s": round(dur, 4) if dur else None,
            "sent_per_s": (round(self.n_sent / dur, 2)
                           if dur and dur > 0 else None),
        }
        # The one thing this file must never do quietly.
        if not self.n_sent:
            out["verdict"] = (
                f"FED NOTHING: {self.n_unmatched} reads by {self.comm!r} on "
                f"unlearned fds, {self.n_accept} accepts. Any loop rate "
                f"measured alongside this is the rate of an unfed guest.")
        elif not self.responses:
            out["verdict"] = (
                f"FED {self.n_sent} inputs but the victim wrote NO parseable "
                f"response. It may be wedged; a clean crash count here means "
                f"nothing.")
        else:
            out["verdict"] = (
                f"fed {self.n_sent} inputs to {self.comm!r} from inside the "
                f"snapshot boundary ({self.n_pass} passed through to the host)"
                f", responses {self.responses}")
        self.logger.info(f"snapfeed: {out['verdict']}")
        if self.outdir:
            with open(os.path.join(self.outdir, "snapfeed.json"), "w") as fh:
                json.dump(out, fh, indent=2)
