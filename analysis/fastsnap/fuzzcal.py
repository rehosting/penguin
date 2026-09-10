"""Locate the fuzz-injection point on a real target: the read() that takes a
request off the wire.

The fastsnap harness Luke described is: snapshot where the guest reads the
packet, capture (buffer address, size), then on each restore fill that buffer
and observe. This plugin measures whether that point exists on stridelinx and
what it looks like -- it does NOT inject anything yet.

Everything the injection step needs is already in penguin's shipped API:

    yield from plugins.mem.write_bytes(buf, payload)   # fill the buffer
    syscall.retval = len(payload)                      # tell the guest how much

so the harness half needs no QEMU change. Only the *reset* half does.

CONTROL. "No lighttpd reads were seen" and "the hook never armed" produce
identical output, so a write hook is registered on the same process with the
same mechanism. lighttpd certainly writes (logs, responses). If writes are
nonzero and reads are zero, the read result is a real negative; if both are
zero, the instrument is what failed and the run says nothing.
"""

import json
import os
import time

from penguin import Plugin, plugins

syscalls = plugins.syscalls

_HTTP_VERBS = (b"GET ", b"POST", b"HEAD", b"PUT ", b"OPTI", b"DELE", b"TRAC",
               b"CONN", b"PROP", b"PATC")


class FuzzCal(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.comm = self.get_arg("comm") or "lighttpd"
        self.max_records = int(self.get_arg("max_records") or 400)
        self.peek = int(self.get_arg("peek") or 96)

        self.t0 = time.time()
        self.reads = []          # recorded read() returns
        self.n_reads = 0         # every read return seen for self.comm
        self.n_writes = 0        # CONTROL
        self.n_http = 0
        self.cbs = []

        self.cbs.append(syscalls.syscall(
            "on_sys_read_return", comm_filter=self.comm)(self.on_read))
        self.cbs.append(syscalls.syscall(
            "on_sys_write_return", comm_filter=self.comm)(self.on_write))
        self.logger.info(
            f"fuzzcal: watching read()/write() returns in comm={self.comm!r}")

    def on_write(self, regs, proto, syscall, fd, buf, count):
        self.n_writes += 1
        return
        yield  # keep this a generator, as the syscalls API expects

    def on_read(self, regs, proto, syscall, fd, buf, count):
        rv = int(syscall.retval)
        self.n_reads += 1
        if rv <= 0 or len(self.reads) >= self.max_records:
            return

        try:
            data = yield from plugins.mem.read_bytes(buf, size=min(rv, self.peek))
        except Exception as e:
            data = b""
            self.logger.debug(f"fuzzcal: read_bytes({buf:#x}) failed: {e}")

        try:
            fname = (yield from plugins.osi.get_fd_name(fd)) or "?"
        except Exception:
            fname = "?"

        is_http = data[:4] in _HTTP_VERBS
        if is_http:
            self.n_http += 1

        self.reads.append({
            "t": round(time.time() - self.t0, 3),
            "fd": int(fd),
            "fdname": fname,
            "buf": f"{int(buf):#x}",
            "count": int(count),      # size the guest asked for
            "retval": rv,             # size it got -- what we override
            "http": is_http,
            "head": data[:self.peek].decode("latin-1"),
        })

        if is_http:
            first = data.split(b"\r\n", 1)[0].decode("latin-1")
            self.logger.info(
                f"fuzzcal: HTTP READ fd={int(fd)} ({fname}) buf={int(buf):#x} "
                f"count={int(count)} retval={rv} :: {first!r}")

    def uninit(self) -> None:
        sockets = sorted({r["fdname"] for r in self.reads
                          if r["fdname"].startswith("socket")})
        self.logger.info("fuzzcal: RESULTS")
        self.logger.info(f"  read() returns  in {self.comm}: {self.n_reads}")
        self.logger.info(f"  write() returns in {self.comm}: {self.n_writes}"
                         "   <- CONTROL")
        self.logger.info(f"  recorded reads (retval>0): {len(self.reads)}")
        self.logger.info(f"  HTTP-looking reads: {self.n_http}")
        self.logger.info(f"  distinct socket fds read: {len(sockets)}")

        if self.n_reads == 0 and self.n_writes == 0:
            self.logger.error(
                "fuzzcal: CONTROL FAILED - no read AND no write hooks fired "
                f"for comm={self.comm!r}. This run says nothing about whether "
                "an injection point exists; the instrument did not arm.")
        elif self.n_reads == 0:
            self.logger.warning(
                "fuzzcal: control passed (writes seen) but zero reads - "
                "the negative is real.")

        for r in self.reads:
            if r["http"]:
                self.logger.info(f"  candidate: {r}")
                break

        if self.outdir:
            p = os.path.join(self.outdir, "fuzzcal.json")
            with open(p, "w") as fh:
                json.dump({
                    "comm": self.comm,
                    "n_read_returns": self.n_reads,
                    "n_write_returns_control": self.n_writes,
                    "n_http_reads": self.n_http,
                    "socket_fds": sockets,
                    "reads": self.reads,
                }, fh, indent=2)
            self.logger.info(f"fuzzcal: wrote {p}")
