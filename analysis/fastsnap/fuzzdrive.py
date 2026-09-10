"""Fuzz lighttpd's request parser by rewriting the buffer at the read() return.

This is the harness Luke described, minus the fast reset: snapshot-free, but
otherwise the real shape. At every read() that returns an HTTP request to the
target process we overwrite the guest's buffer with a mutated request and set
the syscall return value to the new length. The guest parses our bytes instead
of the ones the network delivered.

The whole injection is two API calls, and neither needs a QEMU change:

    yield from plugins.mem.write_bytes(buf, payload)
    syscall.retval = len(payload)

CONTROLS. A fuzzer is an instrument that can return "nothing", so:

  PASSTHROUGH  -- a configurable fraction of reads are left untouched. If the
                  passthrough responses stop being 200s, the target is wedged
                  and later "no crashes" means nothing.
  BUFFER BOUND -- payloads are truncated to `count`, the size the guest asked
                  for. Writing past it would corrupt the heap and manufacture
                  crashes that are our fault, not the target's.
  RESPONSE MIX -- response status codes are tallied. If every mutant is a 400
                  the parser is rejecting at the first byte and we are not
                  reaching the code we think we are.

Deterministic: mutations come from a seeded RNG, so a run replays exactly.
"""

import json
import os
import random
import time

from penguin import Plugin, plugins

syscalls = plugins.syscalls

VERBS = (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"DELE", b"TRAC", b"PROP")

SEEDS = [
    b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
    b"GET /cgi-bin/sysinfo.cgi HTTP/1.1\r\nHost: x\r\n"
    b"Authorization: Basic QUFBQUFBQUE=\r\n\r\n",
    b"POST /cgi-bin/netstat.cgi HTTP/1.1\r\nHost: x\r\n"
    b"Content-Length: 4\r\n\r\nAAAA",
    b"GET / HTTP/1.1\r\nHost: x\r\nConnection: TE,,Keep-Alive\r\n\r\n",
    b"GET /../../etc/passwd HTTP/1.0\r\n\r\n",
]

HEADERS = [b"Host", b"Authorization", b"Connection", b"Content-Length",
           b"Range", b"If-Modified-Since", b"Cookie", b"Referer",
           b"Transfer-Encoding", b"Expect", b"User-Agent"]


class FuzzDrive(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.comm = self.get_arg("comm") or "lighttpd"
        self.passthrough = float(self.get_arg("passthrough") or 0.1)
        self.rng = random.Random(int(self.get_arg("seed") or 1337))

        self.n_seen = 0        # HTTP reads observed
        self.n_fuzzed = 0      # reads we rewrote
        self.n_pass = 0        # CONTROL: reads left alone
        self.t_first = None
        self.t_last = None
        self.status = {}       # CONTROL: response code histogram
        self.corpus = list(SEEDS)

        syscalls.syscall("on_sys_read_return", comm_filter=self.comm)(self.on_read)
        # lighttpd answers with writev(), not write() -- hooking only write()
        # left the response-code control empty on the first run, so it could
        # not distinguish "parsed deeply" from "rejected at byte one".
        syscalls.syscall("on_sys_write_return", comm_filter=self.comm)(self.on_write)
        syscalls.syscall("on_sys_writev_return", comm_filter=self.comm)(self.on_writev)
        self.logger.info(
            f"fuzzdrive: armed on comm={self.comm!r}, "
            f"passthrough={self.passthrough}, seed corpus={len(SEEDS)}")

    # ---- mutation ---------------------------------------------------------

    def mutate(self, base: bytes, limit: int) -> bytes:
        r = self.rng
        out = bytearray(base)
        for _ in range(r.randint(1, 4)):
            op = r.randrange(6)
            if op == 0 and out:                      # byte flip
                i = r.randrange(len(out))
                out[i] ^= 1 << r.randrange(8)
            elif op == 1:                            # long header value
                h = r.choice(HEADERS)
                out = out.replace(
                    b"\r\n\r\n",
                    b"\r\n" + h + b": " + bytes([r.randrange(33, 127)]) *
                    r.choice([64, 512, 4000]) + b"\r\n\r\n", 1)
            elif op == 2:                            # empty list element
                h = r.choice(HEADERS)
                out = out.replace(b"\r\n\r\n",
                                  b"\r\n" + h + b": a,,b,,,c\r\n\r\n", 1)
            elif op == 3 and len(out) > 8:           # truncate
                out = out[:r.randrange(4, len(out))]
            elif op == 4:                            # duplicate a header block
                out = out.replace(b"\r\n\r\n", b"\r\nRange: bytes=0-,-1,0-0\r\n\r\n", 1)
            else:                                    # splice another seed
                other = r.choice(self.corpus)
                cut = r.randrange(1, max(2, len(other)))
                out = bytearray(bytes(out)[:r.randrange(1, max(2, len(out)))]
                                + other[:cut])
        return bytes(out)[:limit]

    # ---- hooks ------------------------------------------------------------

    def on_read(self, regs, proto, syscall, fd, buf, count):
        rv = int(syscall.retval)
        limit = int(count)
        if rv <= 0 or limit <= 0:
            return
        head = yield from plugins.mem.read_bytes(buf, size=min(rv, 4))
        if head[:4] not in VERBS:
            return

        self.n_seen += 1
        now = time.time()
        if self.t_first is None:
            self.t_first = now
        self.t_last = now

        if self.rng.random() < self.passthrough:      # CONTROL
            self.n_pass += 1
            return

        payload = self.mutate(self.rng.choice(self.corpus), limit)
        if not payload:
            return
        yield from plugins.mem.write_bytes(buf, payload)
        syscall.retval = len(payload)                  # BUFFER BOUND respected
        self.n_fuzzed += 1

    def on_write(self, regs, proto, syscall, fd, buf, count):
        rv = int(syscall.retval)
        if rv <= 0:
            return
        data = yield from plugins.mem.read_bytes(buf, size=min(rv, 16))
        if data.startswith(b"HTTP/"):
            code = data.split(b" ")[1][:3].decode("latin-1", "replace") \
                if b" " in data else "???"
            self.status[code] = self.status.get(code, 0) + 1

    def on_writev(self, regs, proto, syscall, fd, iov, iovcnt):
        """Response path: read the first iovec's base/len and sniff the status."""
        if int(syscall.retval) <= 0 or int(iovcnt) <= 0:
            return
        try:
            base = yield from plugins.mem.read_ptr(iov)
            data = yield from plugins.mem.read_bytes(base, size=16)
        except Exception:
            return
        if data.startswith(b"HTTP/"):
            parts = data.split(b" ")
            code = parts[1][:3].decode("latin-1", "replace") if len(parts) > 1 else "???"
            self.status[code] = self.status.get(code, 0) + 1

    # ---- report -----------------------------------------------------------

    def uninit(self) -> None:
        span = (self.t_last - self.t_first) if (self.t_first and self.t_last
                                                and self.t_last > self.t_first) else 0.0
        rate = (self.n_seen / span) if span > 0 else 0.0
        self.logger.info("fuzzdrive: RESULTS")
        self.logger.info(f"  HTTP reads seen : {self.n_seen}")
        self.logger.info(f"  fuzzed          : {self.n_fuzzed}")
        self.logger.info(f"  passthrough     : {self.n_pass}   <- CONTROL")
        self.logger.info(f"  wall span       : {span:.3f} s")
        self.logger.info(f"  executions/s    : {rate:.2f}")
        self.logger.info(f"  response codes  : {self.status}   <- CONTROL")

        if self.n_seen == 0:
            self.logger.error(
                "fuzzdrive: CONTROL FAILED - no HTTP reads intercepted; this "
                "run says nothing about the target.")
        elif self.n_pass == 0 and self.passthrough > 0:
            self.logger.warning(
                "fuzzdrive: no passthrough samples - cannot tell a wedged "
                "server from a robust one.")

        if self.outdir:
            p = os.path.join(self.outdir, "fuzzdrive.json")
            with open(p, "w") as fh:
                json.dump({
                    "comm": self.comm,
                    "http_reads": self.n_seen,
                    "fuzzed": self.n_fuzzed,
                    "passthrough_control": self.n_pass,
                    "span_s": span,
                    "exec_per_s": rate,
                    "response_codes_control": self.status,
                }, fh, indent=2)
            self.logger.info(f"fuzzdrive: wrote {p}")
