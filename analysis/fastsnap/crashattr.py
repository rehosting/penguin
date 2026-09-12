"""crashattr -- the missing join between an input and a crash record.

`fuzzdrive` injects inputs and counts them. `crashes` records fatal signal
deliveries. Neither knows about the other, so a crashes.yaml row can never name
the input that produced it. This plugin is the smallest thing that closes that:

  1. It owns the injection point, so every payload gets a monotonically
     increasing `seq`, is hashed, and is written to a corpus directory.
  2. It remembers, per pid, the last seq delivered to that pid.
  3. It subscribes to the SAME `signal_deliver` event the crashes plugin
     subscribes to, and on a fatal signal joins the delivery to that pid's
     last input.

The join key is (pid, last input delivered). It is exact for a single-threaded
victim that parses each input before reading the next -- the case a snapshot
fuzzing loop constructs on purpose. It is a heuristic for a threaded or
pipelined server, and the output says so on every row.

Output: `crashes_attributed.yaml` (one row per attributed delivery) and
`corpus/<seq>.bin` (the exact bytes, byte-for-byte replayable).

Replay: `replay_file: <path>` injects only those bytes, every read, and asserts
the same crash comes back. That is the reproducer half of the pipeline.
"""

import hashlib
import os
import random
import time
from os.path import join

import yaml

from penguin import Plugin, plugins

syscalls = plugins.syscalls

FATAL = ["SIGSEGV", "SIGBUS", "SIGILL", "SIGABRT", "SIGFPE"]


class CrashAttr(Plugin):
    def __init__(self) -> None:
        self.outdir = self.get_arg("outdir")
        self.comm = self.get_arg("comm") or "parsed"
        self.rng = random.Random(int(self.get_arg("seed") or 1337))
        self.bad_seq = int(self.get_arg("bad_seq") or 42)
        replay_file = self.get_arg("replay_file")
        self.replay = None
        self.replay_path = None
        if replay_file:
            if not os.path.isabs(replay_file):
                replay_file = join(self.get_arg("proj_dir") or ".", replay_file)
            self.replay_path = replay_file
            with open(replay_file, "rb") as fh:
                self.replay = fh.read()

        self.corpus_dir = join(self.outdir, "corpus")
        os.makedirs(self.corpus_dir, exist_ok=True)

        self.fd_suffix = self.get_arg("fd_suffix") or "/zero"
        self._fdnames = {}
        self.n_skipped = 0
        self.seq = 0
        self.last_by_pid = {}     # pid -> input record
        self.sent = []            # every input record, in order
        self.attributed = []      # joined crash rows
        self.t0 = time.time()

        self.signames = {}
        for name in FATAL:
            num = plugins.signals.signal_name_to_num(name)
            if num is not None:
                self.signames.setdefault(num, name)

        syscalls.syscall("on_sys_read_return", comm_filter=self.comm)(self.on_read)
        plugins.subscribe(plugins.signal_monitor, "signal_deliver",
                          self.on_signal_deliver)
        for num in self.signames:
            plugins.signal_monitor.register_hook(sig=num)

        self.write_report()
        mode = (f"REPLAY {self.replay_path} ({len(self.replay)} B, "
                f"sha256={hashlib.sha256(self.replay).hexdigest()[:16]})"
                if self.replay is not None else f"FUZZ bad_seq={self.bad_seq}")
        self.logger.info(f"crashattr: armed on comm={self.comm!r} mode={mode}")

    # ---- input generation -------------------------------------------------

    def make_payload(self, seq: int, limit: int) -> bytes:
        if self.replay is not None:
            return self.replay[:limit]
        if seq == self.bad_seq:
            # Length byte 0x60 (96) against a 16-byte stack buffer. The filler
            # is word-aligned 0x44444440 so the smashed return address is a
            # 4-aligned unmapped value: the faulting pc is literally a function
            # of these bytes, which is what makes the attribution checkable
            # from the outside.
            out = bytearray(0x44 for _ in range(96))
            for i in range(0, 96, 4):
                out[i] = 0x40
            out[0] = 0x60
            return bytes(out)[:limit]
        # A benign request: declared length within the buffer.
        n = self.rng.randrange(1, 16)
        body = bytes(self.rng.randrange(0x20, 0x7f) for _ in range(n))
        return (bytes([n]) + body)[:limit]

    # ---- hooks ------------------------------------------------------------

    def on_read(self, regs, proto, syscall, fd, buf, count):
        rv = int(syscall.retval)
        limit = min(int(count), rv if rv > 0 else int(count))
        if limit <= 0:
            return

        # DISCRIMINATE THE INJECTION POINT. comm_filter alone is not enough:
        # the dynamic loader runs under the victim's comm, so an unfiltered
        # "rewrite every read by this process" clobbers the loader's read of
        # its own ELF headers and the victim never starts. (Observed: run 0,
        # "Error loading shared library libgcc_s.so.1: Exec format error".)
        # Only the request descriptor is fuzzed.
        # Resolved on EVERY read, not cached by fd number: the loader closes
        # its library descriptors before the victim opens the request one, so
        # a (fd -> name) cache hands back a stale .so path and the harness
        # silently injects nothing. (Observed: run 1, inputs_delivered=0.)
        try:
            name = (yield from plugins.osi.get_fd_name(fd)) or "?"
        except Exception:
            name = "?"
        self._fdnames[name] = self._fdnames.get(name, 0) + 1
        if not name.endswith(self.fd_suffix):
            self.n_skipped += 1
            return

        payload = self.make_payload(self.seq, limit)
        if not payload:
            return
        yield from plugins.mem.write_bytes(buf, payload)
        syscall.retval = len(payload)

        pid = None
        try:
            proc = yield from plugins.osi.get_proc()
            pid = int(proc.pid)
        except Exception:
            pid = None

        rec = {
            "seq": self.seq,
            "pid": pid,
            "comm": self.comm,
            "len": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "t": round(time.time() - self.t0, 3),
            "head_hex": payload[:16].hex(),
        }
        with open(join(self.corpus_dir, f"{self.seq:06d}.bin"), "wb") as fh:
            fh.write(payload)
        self.sent.append(rec)
        if pid is not None:
            self.last_by_pid[pid] = rec
        self.seq += 1

    def on_signal_deliver(self, cpu, event):
        sig = int(event.sig)
        signame = self.signames.get(sig)
        if signame is None or event.drop:
            return
        pid = int(event.pid)
        rec = self.last_by_pid.get(pid)
        pc = int(event.pc)
        if pc == 0 and event.regs:
            pc = event.regs.get_pc()
        row = {
            "proc": event.comm,
            "pid": pid,
            "signal": sig,
            "signame": signame,
            "pc": f"0x{pc:08x}",
            "t": round(time.time() - self.t0, 3),
            "attributed": rec is not None,
            "join": "last-input-to-pid",
            "join_exact": rec is not None and event.comm == self.comm,
        }
        if rec is not None:
            row.update({
                "input_seq": rec["seq"],
                "input_sha256": rec["sha256"],
                "input_len": rec["len"],
                "input_head_hex": rec["head_hex"],
                "input_file": f"corpus/{rec['seq']:06d}.bin",
                "input_to_crash_ms": round((row["t"] - rec["t"]) * 1000.0, 1),
            })
            self.logger.info(
                f"crashattr: {signame} in {event.comm} (pid {pid}) at {row['pc']} "
                f"<- input seq={rec['seq']} sha256={rec['sha256'][:16]} "
                f"({row['input_to_crash_ms']} ms after delivery)")
        else:
            self.logger.warning(
                f"crashattr: {signame} in {event.comm} (pid {pid}) at {row['pc']} "
                "- UNATTRIBUTED: no input was ever delivered to this pid")
        self.attributed.append(row)
        self.write_report()

    # ---- report -----------------------------------------------------------

    def write_report(self):
        with open(join(self.outdir, "crashes_attributed.yaml"), "w") as fh:
            yaml.safe_dump({
                "comm": self.comm,
                "inputs_delivered": len(self.sent),
                "crashes": self.attributed,
            }, fh, sort_keys=False)

    def uninit(self):
        self.write_report()
        with open(join(self.outdir, "crashattr_inputs.yaml"), "w") as fh:
            yaml.safe_dump({"inputs": self.sent}, fh, sort_keys=False)
        n_att = sum(1 for r in self.attributed if r["attributed"])
        self.logger.info(
            f"crashattr: RESULTS inputs={len(self.sent)} "
            f"crashes={len(self.attributed)} attributed={n_att} "
            f"reads_skipped_wrong_fd={self.n_skipped}   <- CONTROL")
        self.logger.info(f"crashattr: fd names seen: {self._fdnames}   <- CONTROL")
        if not self.sent:
            self.logger.error(
                "crashattr: CONTROL FAILED - zero inputs delivered; this run "
                f"says nothing about comm={self.comm!r}.")
